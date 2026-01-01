# tlsmith

A lab-only tool for intercepting and modifying HTTP/HTTPS traffic with dynamic TLS termination and host/IP spoofing.

## Features
- **Dynamic TLS**: On-the-fly leaf certificates for any domain or IP.
- **IP Interception**: Redirects raw IP traffic using system routing table (requires `--proxy`).
- **Loopback Bypass**: Uses DNS-over-HTTPS (DoH) to reach real upstreams.
- **Scriptable**: Python hooks for request/response modification.

## Installation
Install using `uv`:
```bash
uv tool install git+https://github.com/ogpourya/tlsmith.git
```

## Usage
```bash
# Intercept domains
sudo tlsmith example.com

# Intercept IPs (requires upstream proxy)
sudo tlsmith 1.1.1.1 --proxy http://localhost:8080
```

> [!CAUTION]
> This tool is **intrusive**. It modifies your routing table and `/etc/hosts`. If it crashes, your internet connectivity for intercepted targets **might break**. Always run `sudo tlsmith --reset` to recover.

## Options
- `--proxy <url>`: Upstream proxy for forwarding.
- `--script <path>`: Python script with `intercept_response` hook.
- `--reset`: Cleanup and exit.
- `-v`: Verbose logging.

## License
MIT
