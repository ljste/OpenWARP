fn main() {
    cc::Build::new()
        .file("dns.m")
        .flag("-fobjc-arc")
        .compile("openwarp_dns");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=SystemConfiguration");
    println!("cargo:rerun-if-changed=dns.m");
}
