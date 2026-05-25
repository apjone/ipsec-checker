# ipsec-checker

A lightweight command-line tool that checks whether a remote IPsec VPN service is reachable and listening on a given host, protocol, and port.

Works on **Linux** and **Windows** (x86-64).

## Features

- TCP connect check — definitive OPEN / CLOSED / FILTERED result
- UDP probe with IKEv2 `IKE_SA_INIT` packet for ports 500 and 4500
- NAT-T aware: automatically prepends the non-ESP marker on UDP port 4500
- FQDN resolution with per-address reporting
- Scriptable exit codes: `0` = OPEN, `1` = CLOSED/FILTERED, `2` = error

## Installation

### Pre-built binaries

Download the latest release for your platform from the [Releases](../../releases) page:

| File | Platform |
|------|----------|
| `ipsec-checker-linux-x86_64` | Linux x86-64 (static musl) |
| `ipsec-checker-linux-aarch64` | Linux ARM64 (static musl) |
| `ipsec-checker-windows-x86_64.exe` | Windows x86-64 |

### Build from source

Requires [Rust](https://rustup.rs/) 1.70+.

```bash
git clone https://github.com/apjone/ipsec-checker.git
cd ipsec-checker
cargo build --release
# binary at: target/release/ipsec-checker
```

#### Cross-compile for Windows from Linux

```bash
# Install the Windows target and MinGW linker
rustup target add x86_64-pc-windows-gnu
sudo apt-get install gcc-mingw-w64-x86-64

cargo build --release --target x86_64-pc-windows-gnu
# binary at: target/x86_64-pc-windows-gnu/release/ipsec-checker.exe
```

## Usage

```
ipsec-checker -H <HOST> -p <tcp|udp> -P <PORT> [OPTIONS]

Options:
  -H, --host <HOST>          Remote host: IP address or FQDN
  -p, --protocol <PROTOCOL>  Protocol to probe with [possible values: tcp, udp]
  -P, --port <PORT>          Remote port number
  -t, --timeout <TIMEOUT>    Timeout per attempt in seconds [default: 5]
  -r, --retries <RETRIES>    Extra UDP probe attempts (retries=1 means 2 total sends) [default: 1]
  -h, --help                 Print help
  -V, --version              Print version
```

## Examples

```bash
# Check IKEv2 (UDP 500)
ipsec-checker -H vpn.example.com -p udp -P 500

# Check IKEv2 with NAT-T (UDP 4500)
ipsec-checker -H 203.0.113.10 -p udp -P 4500 --timeout 3 --retries 2

# Check SSL VPN (TCP 443)
ipsec-checker -H vpn.example.com -p tcp -P 443

# Check L2TP (TCP 1701)
ipsec-checker -H 203.0.113.10 -p tcp -P 1701

# Use in a script — exit 0 means the service responded
if ipsec-checker -H vpn.example.com -p udp -P 500 --timeout 3; then
    echo "IKE service is up"
else
    echo "IKE service is unreachable"
fi
```

## How it works

### TCP
Attempts a full TCP connection. The result maps directly to socket state:

| Socket result | Reported status |
|---------------|-----------------|
| Connection accepted | `OPEN` |
| Connection refused (RST) | `CLOSED` |
| Timeout / no response | `FILTERED` |

### UDP

UDP is connectionless, so detection relies on the remote service replying.

| Port | Probe sent |
|------|-----------|
| 500 | IKEv2 `IKE_SA_INIT` (RFC 7296) |
| 4500 | IKEv2 `IKE_SA_INIT` with 4-byte non-ESP NAT-T marker |
| other | Generic single-byte probe |

| Response | Reported status |
|----------|-----------------|
| Any UDP reply received | `OPEN` |
| ICMP port unreachable | `CLOSED` |
| No response after all retries | `FILTERED` |

> **Note:** A `FILTERED` result for UDP means no response was received within the timeout. The port may still be open but silently dropping the probe (e.g. behind a stateful firewall).

## Common IPsec/VPN ports

| Port | Protocol | Usage |
|------|----------|-------|
| 500/udp | IKE | IKEv1 / IKEv2 key exchange |
| 4500/udp | IKE NAT-T | IKEv2 behind NAT |
| 1701/udp | L2TP | L2TP/IPsec |
| 1723/tcp | PPTP | PPTP VPN |
| 443/tcp | SSL | SSL VPN (Cisco, Palo Alto, etc.) |
| 10443/tcp | SSL | GlobalProtect |
| 4443/tcp | SSL | Pulse Secure |

## License

MIT — see [LICENSE](LICENSE).
