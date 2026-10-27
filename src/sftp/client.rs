//! Request-Multiplexer: Anfragen tragen eine ID, ein Lese-Task ordnet Antworten zu.
//! So können viele Anfragen gleichzeitig offen sein (Pipelining) und Antworten
//! in beliebiger Reihenfolge eintreffen.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;

use super::proto::{self, FXP_INIT, FXP_VERSION, MAX_PACKET, Response};
use crate::error::{Error, Result};
use crate::wire::{Reader, Writer};

/// Grund, aus dem der Multiplexer nicht mehr arbeitet.
#[derive(Clone)]
enum Fatal {
    Violation(&'static str),
    Lost(String),
}

impl Fatal {
    fn error(&self) -> Error {
        match self {
            Fatal::Violation(what) => Error::ProtocolViolation(what),
            Fatal::Lost(reason) => Error::ConnectionLost(reason.clone()),
        }
    }

    fn from_error(err: Error) -> Self {
        match err {
            Error::ProtocolViolation(what)
            | Error::InvalidPacket(what)
            | Error::Malformed(what) => Fatal::Violation(what),
            other => Fatal::Lost(other.to_string()),
        }
    }
}

struct Table {
    next_id: u32,
    waiting: HashMap<u32, oneshot::Sender<Result<Response>>>,
    fatal: Option<Fatal>,
}

struct Inner {
    table: Mutex<Table>,
    out: mpsc::UnboundedSender<Vec<u8>>,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn fatal_error(&self) -> Error {
        self.lock()
            .fatal
            .as_ref()
            .map_or_else(|| Error::ConnectionLost("sftp closed".into()), Fatal::error)
    }

    /// Beendet alle wartenden Anfragen mit dem Fehlergrund.
    fn fail(&self, reason: Fatal) {
        let waiting = {
            let mut table = self.lock();
            table.fatal.get_or_insert(reason.clone());
            std::mem::take(&mut table.waiting)
        };
        for (_, tx) in waiting {
            let _ = tx.send(Err(reason.error()));
        }
    }
}

struct Guard(Vec<AbortHandle>);

impl Drop for Guard {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

/// Eine noch nicht beantwortete Anfrage. Fallen lassen ist erlaubt; die Antwort
/// wird dann verworfen.
pub(crate) struct Pending {
    rx: oneshot::Receiver<Result<Response>>,
    inner: Arc<Inner>,
}

impl Pending {
    pub async fn wait(self) -> Result<Response> {
        match self.rx.await {
            Ok(result) => result,
            Err(_) => Err(self.inner.fatal_error()),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Client {
    inner: Arc<Inner>,
    _guard: Arc<Guard>,
}

/// Liest ein Paket (ohne Längenfeld).
async fn read_packet<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let len = r.read_u32().await? as usize;
    if len == 0 || len > MAX_PACKET {
        return Err(Error::ProtocolViolation("sftp packet size out of range"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

impl Client {
    /// Version aushandeln und Hintergrund-Tasks starten.
    ///
    /// Jeder Fehler vor dem Abschluss des Handshakes bedeutet „SFTP nicht verfügbar“.
    pub async fn connect<S>(mut stream: S) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let unavailable = |what: String| Error::SftpUnavailable(what);

        let mut init = Writer::new();
        init.put_u8(FXP_INIT).put_u32(proto::VERSION);
        let handshake = async {
            stream.write_all(&frame(init.as_slice())).await?;
            stream.flush().await?;
            read_packet(&mut stream).await
        };
        let reply = handshake.await.map_err(|e| {
            unavailable(format!(
                "the server closed the channel during the SFTP handshake ({e})"
            ))
        })?;

        let mut r = Reader::new(&reply);
        if r.get_u8().ok() != Some(FXP_VERSION) {
            return Err(unavailable(
                "the server did not answer with SSH_FXP_VERSION".into(),
            ));
        }
        let version = r.get_u32().map_err(|e| unavailable(e.to_string()))?;
        if version != proto::VERSION {
            return Err(unavailable(format!(
                "the server speaks SFTP version {version}, only version 3 is supported"
            )));
        }
        // Es folgen optionale Erweiterungen (Name/Wert-Paare); wir nutzen keine.

        let (rd, wr) = tokio::io::split(stream);
        let (out, queue) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            table: Mutex::new(Table {
                next_id: 0,
                waiting: HashMap::new(),
                fatal: None,
            }),
            out,
        });
        let reader = tokio::spawn(reader_task(rd, inner.clone())).abort_handle();
        let writer = tokio::spawn(writer_task(wr, queue, inner.clone())).abort_handle();
        Ok(Self {
            inner,
            _guard: Arc::new(Guard(vec![reader, writer])),
        })
    }

    /// Stellt eine Anfrage in die Sendewarteschlange. `fill` schreibt alles nach der ID.
    /// Kehrt sofort zurück (kein `await`), ist also unbedenklich abbrechbar.
    pub fn start(&self, kind: u8, fill: impl FnOnce(&mut Writer)) -> Result<Pending> {
        let (tx, rx) = oneshot::channel();
        let id = {
            let mut table = self.inner.lock();
            if let Some(fatal) = &table.fatal {
                return Err(fatal.error());
            }
            let mut id = table.next_id;
            while table.waiting.contains_key(&id) {
                id = id.wrapping_add(1);
            }
            table.next_id = id.wrapping_add(1);
            table.waiting.insert(id, tx);
            id
        };
        let mut w = Writer::new();
        w.put_u8(kind).put_u32(id);
        fill(&mut w);
        if self.inner.out.send(frame(w.as_slice())).is_err() {
            self.inner.lock().waiting.remove(&id);
            return Err(self.inner.fatal_error());
        }
        Ok(Pending {
            rx,
            inner: self.inner.clone(),
        })
    }

    /// Anfrage senden und auf die Antwort warten.
    pub async fn call(&self, kind: u8, fill: impl FnOnce(&mut Writer)) -> Result<Response> {
        self.start(kind, fill)?.wait().await
    }
}

async fn reader_task<R: AsyncRead + Unpin>(mut rd: R, inner: Arc<Inner>) {
    let err = loop {
        let packet = match read_packet(&mut rd).await {
            Ok(p) => p,
            Err(e) => break e,
        };
        let (id, response) = match proto::parse_response(&packet) {
            Ok(parsed) => parsed,
            Err(e) => break e,
        };
        let waiter = inner.lock().waiting.remove(&id);
        match waiter {
            Some(tx) => {
                let _ = tx.send(Ok(response));
            }
            None => break Error::ProtocolViolation("sftp response with unknown request id"),
        }
    };
    inner.fail(Fatal::from_error(err));
}

async fn writer_task<W: AsyncWrite + Unpin>(
    mut wr: W,
    mut queue: mpsc::UnboundedReceiver<Vec<u8>>,
    inner: Arc<Inner>,
) {
    while let Some(packet) = queue.recv().await {
        let result = async {
            wr.write_all(&packet).await?;
            wr.flush().await
        }
        .await;
        if let Err(e) = result {
            inner.fail(Fatal::Lost(e.to_string()));
            return;
        }
    }
}
