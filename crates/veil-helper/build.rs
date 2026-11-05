// Each build gets a distinct id so the app notices an outdated installed helper.
fn main() {
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("cargo:rustc-env=VEIL_BUILD_ID={id}");
    println!("cargo:rerun-if-changed=src");
}
