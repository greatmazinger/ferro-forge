#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let token = String::from_utf8_lossy(data);
    let _ = ferro_forge::decode_and_verify(&token, b"fuzz-target-fixed-key");
});
