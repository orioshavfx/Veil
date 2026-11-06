//! ping_servers <state.json>: the app's ping, over the physical interface.
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() {
    let path = std::env::args().nth(1).unwrap();
    let state: veil_config::store::AppState = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let (iface, pin) = veil_engine::tun::physical_bypass().unwrap();
    println!("interface {iface}, dns {:?}", pin.dns);
    for p in state.profiles.iter().filter(|p| p.name.contains("Нидерланды") || p.name.contains("Швейцария")) {
        let s = &p.server;
        let rtt = if let veil_config::Protocol::Hysteria2 { .. } = s.protocol {
            let c = veil_proto::hysteria::HysteriaClient::new(s).unwrap().pinned(pin.clone());
            tokio::time::timeout(Duration::from_secs(5), c.probe()).await.ok().and_then(Result::ok)
        } else {
            let addr = veil_proto::Address::from_host(&s.address, s.port);
            let ip = *veil_proto::dial::resolve_with(&addr, Some(&pin)).await.unwrap().first().unwrap();
            let t = Instant::now();
            veil_proto::dial::tcp_connect_with(&veil_proto::Address::Socket(ip), Some(&pin)).await.ok().map(|_| t.elapsed())
        };
        println!("{:<28} {:<12} {}", p.name, s.protocol.name(), rtt.map_or("no response".into(), |d| format!("{} ms", d.as_millis())));
    }
}
