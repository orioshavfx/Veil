fn main() {
    let t = std::time::Instant::now();
    let apps = veil_engine::process::all_apps();
    let running = apps.iter().filter(|a| a.running).count();
    println!("{} apps ({} running) in {:?}", apps.len(), running, t.elapsed());
    println!("sample: {:?}", apps.iter().take(12).map(|a| &a.name).collect::<Vec<_>>());
}
