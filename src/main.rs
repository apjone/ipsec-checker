use clap::{Parser, ValueEnum};
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, ValueEnum)]
enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(Debug, PartialEq)]
enum PortStatus {
    Open,
    Closed,
    Filtered,
}

impl fmt::Display for PortStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortStatus::Open => write!(f, "OPEN"),
            PortStatus::Closed => write!(f, "CLOSED"),
            PortStatus::Filtered => write!(f, "FILTERED"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "ipsec-checker", version, about = "Check if a remote IPsec VPN service is listening")]
struct Args {
    /// Remote host: IP address or FQDN
    #[arg(short = 'H', long)]
    host: String,

    /// Protocol to probe with
    #[arg(short, long)]
    protocol: Protocol,

    /// Remote port number
    #[arg(short = 'P', long)]
    port: u16,

    /// Timeout per attempt in seconds
    #[arg(short, long, default_value = "5")]
    timeout: u64,

    /// Extra UDP probe attempts (retries=1 means 2 total sends)
    #[arg(short, long, default_value = "1")]
    retries: u32,
}

fn resolve_host(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = format!("{}:{}", host, port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "host resolved to no addresses",
        ))
    } else {
        Ok(addrs)
    }
}

fn check_tcp(addr: SocketAddr, timeout: Duration) -> PortStatus {
    let start = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => PortStatus::Open,
        Err(e) => match e.kind() {
            io::ErrorKind::ConnectionRefused => PortStatus::Closed,
            io::ErrorKind::TimedOut => PortStatus::Filtered,
            _ if start.elapsed() >= timeout => PortStatus::Filtered,
            _ => PortStatus::Closed,
        },
    }
}

/// Build a minimal IKEv2 IKE_SA_INIT probe packet.
///
/// For NAT-T (UDP 4500) the IKE payload is prefixed with a 4-byte
/// non-ESP marker (all zeros) so the responder can distinguish IKE
/// traffic from ESP traffic.
fn build_ikev2_probe(nat_t: bool) -> Vec<u8> {
    let mut pkt: Vec<u8> = Vec::with_capacity(80);

    if nat_t {
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // non-ESP marker
    }

    // ── IKE Header (28 bytes) ──────────────────────────────────────────────
    pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]); // initiator SPI
    pkt.extend_from_slice(&[0x00u8; 8]); // responder SPI = 0 (initial)
    pkt.push(33);   // next payload: SA (33)
    pkt.push(0x20); // version: IKEv2 (major=2, minor=0)
    pkt.push(34);   // exchange type: IKE_SA_INIT (34)
    pkt.push(0x08); // flags: Initiator bit set
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // message ID: 0
    let total_len_offset = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // total length (filled below)

    // ── SA Payload ─────────────────────────────────────────────────────────
    let sa_start = pkt.len();
    pkt.push(0x00); // next payload: none (last payload)
    pkt.push(0x00); // reserved
    let sa_len_offset = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00]); // payload length (filled below)

    // Proposal substructure
    let prop_start = pkt.len();
    pkt.push(0x00); // last substructure: last/only proposal
    pkt.push(0x00); // reserved
    let prop_len_offset = pkt.len();
    pkt.extend_from_slice(&[0x00, 0x00]); // proposal length (filled below)
    pkt.push(0x01); // proposal #1
    pkt.push(0x01); // protocol: IKE
    pkt.push(0x00); // SPI size: 0 (IKE SPI lives in the header)
    pkt.push(0x04); // number of transforms: 4

    // Transform 1 – ENCR_AES_CBC with 128-bit key (length=12)
    pkt.push(0x03); // more transforms follow
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x0C]); // transform length: 12
    pkt.extend_from_slice(&[0x00, 0x01]); // type: ENCR (1)
    pkt.extend_from_slice(&[0x00, 0x0C]); // ID: ENCR_AES_CBC (12)
    pkt.extend_from_slice(&[0x80, 0x0E, 0x00, 0x80]); // KeyLength attr: TV format, 128 bits

    // Transform 2 – PRF_HMAC_SHA2_256 (length=8)
    pkt.push(0x03);
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x08]);
    pkt.extend_from_slice(&[0x00, 0x02]); // type: PRF (2)
    pkt.extend_from_slice(&[0x00, 0x05]); // ID: PRF_HMAC_SHA2_256 (5)

    // Transform 3 – AUTH_HMAC_SHA2_256_128 (length=8)
    pkt.push(0x03);
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x08]);
    pkt.extend_from_slice(&[0x00, 0x03]); // type: INTEG (3)
    pkt.extend_from_slice(&[0x00, 0x0C]); // ID: AUTH_HMAC_SHA2_256_128 (12)

    // Transform 4 – DH Group 14 / MODP-2048 (length=8, last)
    pkt.push(0x00); // last transform
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x08]);
    pkt.extend_from_slice(&[0x00, 0x04]); // type: D-H (4)
    pkt.extend_from_slice(&[0x00, 0x0E]); // ID: MODP_2048 (14)

    // ── Fix up lengths ─────────────────────────────────────────────────────
    let prop_len = (pkt.len() - prop_start) as u16;
    pkt[prop_len_offset..prop_len_offset + 2].copy_from_slice(&prop_len.to_be_bytes());

    let sa_len = (pkt.len() - sa_start) as u16;
    pkt[sa_len_offset..sa_len_offset + 2].copy_from_slice(&sa_len.to_be_bytes());

    // IKE total length excludes the NAT-T marker prefix
    let ike_start = if nat_t { 4 } else { 0 };
    let ike_total = (pkt.len() - ike_start) as u32;
    pkt[total_len_offset..total_len_offset + 4].copy_from_slice(&ike_total.to_be_bytes());

    pkt
}

fn check_udp(addr: SocketAddr, port: u16, timeout: Duration, retries: u32) -> PortStatus {
    let probe: Vec<u8> = match port {
        500 => build_ikev2_probe(false),
        4500 => build_ikev2_probe(true),
        _ => vec![0x00], // generic single-byte probe for non-IKE UDP ports
    };

    let bind_addr: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    for attempt in 0..=retries {
        let socket = match UdpSocket::bind(bind_addr) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  bind error: {}", e);
                return PortStatus::Filtered;
            }
        };
        let _ = socket.set_read_timeout(Some(timeout));

        if let Err(e) = socket.send_to(&probe, addr) {
            eprintln!("  send error: {}", e);
            if attempt == retries {
                return PortStatus::Filtered;
            }
            continue;
        }

        let mut buf = [0u8; 2048];
        match socket.recv_from(&mut buf) {
            Ok(_) => return PortStatus::Open,
            Err(e) => match e.kind() {
                // ICMP port-unreachable arrives as ECONNREFUSED (Linux) / WSAECONNRESET (Windows)
                io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => {
                    return PortStatus::Closed;
                }
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                    if attempt == retries {
                        return PortStatus::Filtered;
                    }
                }
                _ => {
                    if attempt == retries {
                        return PortStatus::Filtered;
                    }
                }
            },
        }
    }

    PortStatus::Filtered
}

fn main() {
    let args = Args::parse();
    let timeout = Duration::from_secs(args.timeout);

    println!(
        "Checking {}:{}/{} (timeout {}s, retries {})",
        args.host, args.port, args.protocol, args.timeout, args.retries
    );

    let addrs = match resolve_host(&args.host, args.port) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: failed to resolve '{}': {}", args.host, e);
            std::process::exit(2);
        }
    };

    // Show resolved IPs when an FQDN was given
    if args.host.parse::<IpAddr>().is_err() {
        let ips: Vec<String> = addrs.iter().map(|a| a.ip().to_string()).collect();
        println!("Resolved:  {}", ips.join(", "));
    }

    let mut overall = PortStatus::Filtered;

    for addr in &addrs {
        let status = match args.protocol {
            Protocol::Tcp => check_tcp(*addr, timeout),
            Protocol::Udp => check_udp(*addr, args.port, timeout, args.retries),
        };

        println!("  [{}] → {}", addr, status);

        match status {
            PortStatus::Open => {
                overall = PortStatus::Open;
                break; // first Open wins
            }
            PortStatus::Closed if overall != PortStatus::Open => {
                overall = PortStatus::Closed;
            }
            _ => {}
        }
    }

    println!("\nResult: {}:{}/{} is {}", args.host, args.port, args.protocol, overall);

    std::process::exit(match overall {
        PortStatus::Open => 0,
        _ => 1,
    });
}
