# tlsmith

A lab-only tool for intercepting and modifying HTTP/HTTPS traffic with dynamic TLS termination and host spoofing.

## Features
- **Dynamic TLS**: Generates leaf certificates on-the-fly for any domain using a local Root CA.
- **TUI**: Simple two-pane interface (Logs & Input) for managing intercepted domains.
- **Loopback Bypass**: Intelligently bypasses local `/etc/hosts` overrides using DNS-over-HTTPS.
- **Scriptable**: Python-based proxy logic for easy request/response modification.

## Installation

Install using `uv`:

```bash
uv tool install git+https://github.com/ogpourya/tlsmith.git
```

## Usage

Run with `sudo` (required for ports 80/443 and `/etc/hosts` modification):

```bash
sudo $(which tlsmith) example.com google.com
# OR
sudo $(which tlsmith) domains.txt
```

1. **Trust CA**: On first run, a Root CA is generated at `~/.config/tlsmith/ca.crt`. Import this into your browser/OS trust store (or run on Debian/Ubuntu for auto-install).
2. **Intercepts**: `tlsmith` automatically updates `/etc/hosts` to point these domains to `127.0.0.1`.
3. **Proxies**: Traffic is decrypted, modified (e.g. Date header), and forwarded to the *real* upstream via DNS-over-HTTPS.

## Options

- `--reset`: Remove CA and configuration files, clean up `/etc/hosts`, then exit.
- `--doh <url>`: Specify a custom DNS-over-HTTPS resolver (default: `https://sky.rethinkdns.com/dns-query`).

## Safety Warning

**Use with caution.** This tool modifies `/etc/hosts` to hijack traffic.
- If the tool crashes or is killed abruptly (SIGKILL), your `/etc/hosts` file may be left in a modified state, breaking connectivity for the spoofed domains.
- **Fix:** Run `sudo tlsmith --reset` to clean up, or manually edit `/etc/hosts` to remove the `# tlsmith` entries.
- Always verify the generated Root CA is trusted only for development purposes.

## License
MIT
