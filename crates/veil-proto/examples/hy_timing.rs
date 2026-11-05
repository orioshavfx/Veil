//! hy_timing <hysteria2 link>: where does the time go?
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
    let link = std::env::args().nth(1).unwrap();
    let p = veil_config::parse_link(&link).unwrap();
    let addr = veil_proto::Address::from_host(&p.server.address, p.server.port);
    let t = Instant::now();
    let ips = veil_proto::dial::resolve(&addr).await.unwrap();
    println!("dns:                {:>5} ms", t.elapsed().as_millis());
    let _ = ips;
    let c = veil_proto::hysteria::HysteriaClient::new(&p.server).unwrap();
    let dst = veil_proto::Address::Domain("example.com".into(), 80);
    for i in 1..=4 {
        let t = Instant::now();
        let mut s = c.connect_tcp(&dst).await.unwrap();
        let open = t.elapsed();
        s.write_all(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut b = [0u8; 12];
        s.read_exact(&mut b).await.unwrap();
        println!("stream {i}: open {:>5} ms, first HTTP byte {:>5} ms, QUIC rtt {:?}",
            open.as_millis(), t.elapsed().as_millis(), c.rtt().await.unwrap());
    }
    println!("ping (QUIC rtt):    {:>5} ms", c.probe().await.unwrap().as_millis());
}
