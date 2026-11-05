# Vendored crates

- `ipstack` 1.0.1 — unchanged except that `build.rs` is removed. On Windows targets
  it runs `cargo metadata` to copy `wintun.dll` next to ipstack's own examples,
  which fails inside a normal (or cross) build of a dependent crate. Veil ships
  `wintun.dll` itself, next to `veil-helper.exe`.
