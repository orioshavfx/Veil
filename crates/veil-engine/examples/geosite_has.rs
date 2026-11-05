//! geosite_has <geosite.dat> <code>...: prints which codes exist and their size.
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let codes: Vec<String> = a[2..].iter().map(|c| c.to_uppercase()).collect();
    let m = veil_engine::geo::load_geosite(std::path::Path::new(&a[1]), &codes).unwrap();
    for c in &codes {
        let n = m.get(c).map_or(0, |v| v.len());
        let has_cdn = m.get(c).is_some_and(|v| v.iter().any(|(_, d)| d.contains("phncdn") || d.contains("googlevideo") || d.contains("cdninstagram")));
        println!("{c:<12} {n:>4} domains{}", if has_cdn { "  (includes CDN domains)" } else { "" });
    }
}
