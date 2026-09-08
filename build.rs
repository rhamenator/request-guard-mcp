use std::{env, path::PathBuf};

fn main() {
    for asset in [
        "assets/app-icon.ico",
        "assets/app-icon.rc",
        "assets/app-icon.res",
    ] {
        println!("cargo:rerun-if-changed={asset}");
    }

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        let resource = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest directory"))
            .join("assets/app-icon.res");
        println!(
            "cargo:rustc-link-arg-bin=request-guard-mcp=\"{}\"",
            resource.display()
        );
    }
}
