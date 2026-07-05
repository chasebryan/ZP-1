#![no_main]

use libfuzzer_sys::fuzz_target;
use zp1::object::Zp1Object;

fuzz_target!(|data: &[u8]| {
    let _ = Zp1Object::decode(data);
});
