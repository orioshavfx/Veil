fn main() {
    let t = std::time::Instant::now();
    println!("primary service: {:?} ({:?})", veil_sysproxy::primary_service(), t.elapsed());
}
