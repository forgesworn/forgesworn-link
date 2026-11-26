#![cfg(not(all(target_family = "wasm", target_os = "unknown")))]

// Exercise the same source developers copy, against the workspace's current Link.
mod starter {
    include!("../../../examples/paired-echo/src/main.rs");

    #[test]
    fn runs_the_paired_echo() -> Result<()> {
        main()
    }
}
