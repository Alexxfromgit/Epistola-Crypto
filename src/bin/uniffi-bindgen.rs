//! Binding generator. UniFFI's proc-macro mode reads metadata out of the built
//! library, so bindings are produced by running this against the compiled
//! artifact rather than from a .udl file.
//!
//!     cargo run --bin uniffi-bindgen -- generate \
//!         --library target/debug/libepistola_crypto.dylib \
//!         --language kotlin --out-dir bindings/kotlin

fn main() {
    uniffi::uniffi_bindgen_main()
}
