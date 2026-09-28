//! `wasm_browser`: wasm32 with no operating system, the build a web page
//! loads.  The same alias quinn uses, so the two agree on what a browser is.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(wasm_browser)");
    let family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if family.split(',').any(|f| f == "wasm") && os == "unknown" {
        println!("cargo::rustc-cfg=wasm_browser");
    }
}
