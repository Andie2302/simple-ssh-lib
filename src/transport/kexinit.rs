//! SSH_MSG_KEXINIT (RFC 4253 §7.1) mit unserem festen Algorithmensatz.

use crate::error::{Error, Result};
use crate::wire::{Reader, Writer};

pub const MSG_KEXINIT: u8 = 20;

pub const KEX_ALGORITHM: &str = "curve25519-sha256";
pub const HOST_KEY_ALGORITHM: &str = "ssh-ed25519";
pub const CIPHER: &str = "chacha20-poly1305@openssh.com";
pub const COMPRESSION: &str = "none";
/// Bei AEAD-Chiffren ungenutzt, muss aber ausgehandelt werden.
pub const MAC_PLACEHOLDER: &str = "hmac-sha2-256";
pub const STRICT_KEX_CLIENT: &str = "kex-strict-c-v00@openssh.com";
pub const STRICT_KEX_SERVER: &str = "kex-strict-s-v00@openssh.com";

/// Baut unser KEXINIT mit zufälligem Cookie. Der Strict-KEX-Marker gehört nur in
/// den ersten Austausch (`initial`), nicht in spätere (Rekeying).
pub fn build_client_kexinit(initial: bool) -> Result<Vec<u8>> {
    let mut cookie = [0u8; 16];
    getrandom::fill(&mut cookie).map_err(|_| Error::ProtocolViolation("rng failure"))?;
    if initial {
        Ok(build(&cookie, &[KEX_ALGORITHM, STRICT_KEX_CLIENT]))
    } else {
        Ok(build(&cookie, &[KEX_ALGORITHM]))
    }
}

/// Gemeinsamer Baustein für Client und (Test-)Server.
pub fn build(cookie: &[u8; 16], kex_algorithms: &[&str]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(MSG_KEXINIT)
        .put_raw(cookie)
        .put_name_list(kex_algorithms)
        .put_name_list(&[HOST_KEY_ALGORITHM])
        .put_name_list(&[CIPHER])
        .put_name_list(&[CIPHER])
        .put_name_list(&[MAC_PLACEHOLDER])
        .put_name_list(&[MAC_PLACEHOLDER])
        .put_name_list(&[COMPRESSION])
        .put_name_list(&[COMPRESSION])
        .put_name_list(&[])
        .put_name_list(&[])
        .put_bool(false)
        .put_u32(0);
    w.into_vec()
}

fn require(list: &[&str], wanted: &str, category: &'static str) -> Result<()> {
    if list.contains(&wanted) {
        Ok(())
    } else {
        Err(Error::NoCommonAlgorithm(category))
    }
}

/// Prüft das KEXINIT des Servers gegen unseren festen Satz. Im ersten Austausch
/// (`initial`) muss der Server Strict KEX anbieten, beim Rekeying nicht mehr.
pub fn check_server_kexinit(payload: &[u8], initial: bool) -> Result<()> {
    let mut r = Reader::new(payload);
    if r.get_u8()? != MSG_KEXINIT {
        return Err(Error::ProtocolViolation("expected KEXINIT"));
    }
    r.get_raw(16)?; // Cookie
    let kex = r.get_name_list()?;
    let host_key = r.get_name_list()?;
    let enc_c2s = r.get_name_list()?;
    let enc_s2c = r.get_name_list()?;
    let _mac_c2s = r.get_name_list()?;
    let _mac_s2c = r.get_name_list()?;
    let comp_c2s = r.get_name_list()?;
    let comp_s2c = r.get_name_list()?;
    let _lang_c2s = r.get_name_list()?;
    let _lang_s2c = r.get_name_list()?;
    let first_kex_follows = r.get_bool()?;
    r.get_u32()?; // reserved
    r.finish()?;

    require(&kex, KEX_ALGORITHM, "key exchange")?;
    if initial {
        require(&kex, STRICT_KEX_SERVER, "strict kex")?;
    }
    require(&host_key, HOST_KEY_ALGORITHM, "host key")?;
    require(&enc_c2s, CIPHER, "cipher client->server")?;
    require(&enc_s2c, CIPHER, "cipher server->client")?;
    require(&comp_c2s, COMPRESSION, "compression client->server")?;
    require(&comp_s2c, COMPRESSION, "compression server->client")?;
    if first_kex_follows {
        return Err(Error::ProtocolViolation("kex guess packets not supported"));
    }
    Ok(())
}
