#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tokio::runtime::{Builder, Runtime};

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Builder::new_current_thread().enable_all().build().expect("runtime"))
}

fuzz_target!(|data: &[u8]| {
    runtime().block_on(simple_ssh_lib::fuzz_api::banner(data));
});
