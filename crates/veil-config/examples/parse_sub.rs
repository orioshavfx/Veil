//! Prints what veil would import from a saved subscription body (no secrets).
fn main() {
    let path = std::env::args().nth(1).expect("usage: parse_sub <file>");
    let body = std::fs::read_to_string(path).unwrap();
    let profiles = veil_config::subscription::parse_body(&body);
    println!("supported: {}", profiles.len());
    for p in &profiles {
        let sec = match p.server.security {
            veil_config::Security::None => "none",
            veil_config::Security::Tls(_) => "tls",
            veil_config::Security::Reality(_) => "reality",
        };
        let net = match p.server.transport {
            veil_config::Transport::Tcp => "tcp",
            veil_config::Transport::Ws { .. } => "ws",
            veil_config::Transport::Grpc { .. } => "grpc",
        };
        println!("  {:<34} {}/{net}/{sec}", p.name, p.server.protocol.name());
    }
    if let Some(parsed) = veil_config::xray_json::parse(&body) {
        for s in parsed.skipped {
            println!("skipped: {s}");
        }
    }
}
