//! Reproduces TUN-mode dialing: pinned to an interface, resolving via given DNS.
//! Usage: bypass_dial <iface> <dns-ip> <host> <port>
use std::num::NonZeroU32;

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let idx = unsafe { libc::if_nametoindex(std::ffi::CString::new(a[1].clone()).unwrap().as_ptr()) };
    veil_proto::dial::set_bypass(Some(veil_proto::dial::Bypass {
        if_index: NonZeroU32::new(idx).unwrap(),
        dns: a[2].split(",").map(|s| s.parse().unwrap()).collect(),
    }));
    let addr = veil_proto::Address::from_host(&a[3], a[4].parse().unwrap());
    match veil_proto::dial::resolve(&addr).await {
        Ok(ips) => println!("resolved: {} v4, {} v6", ips.iter().filter(|s| s.is_ipv4()).count(), ips.iter().filter(|s| s.is_ipv6()).count()),
        Err(e) => println!("resolve error: {e}"),
    }
    match veil_proto::dial::tcp_connect(&addr).await {
        Ok(s) => println!("connect OK, local {}", s.local_addr().unwrap()),
        Err(e) => println!("connect error: {e}"),
    }
}
