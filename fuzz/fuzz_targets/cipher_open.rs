#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    simple_ssh_lib::fuzz_api::cipher_open(data);
});
