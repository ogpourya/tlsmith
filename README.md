# tlsmith

A lab-only tool for intercepting and modifying HTTP/HTTPS traffic with dynamic TLS termination and host spoofing.

## Features
- **Dynamic TLS**: Generates leaf certificates on-the-fly for any domain using a local Root CA.
- **Loopback Bypass**: Intelligently bypasses local `/etc/hosts` overrides using DNS-over-HTTPS (DoH). If an upstream proxy is configured, DoH requests also use the proxy.
- **Clean Logging**: Decodes and decompresses (gzip/deflate) HTTP bodies for clear inspection when using verbose mode.
- **Proxy Support**: Supports upstream HTTP proxies for both traffic forwarding and DoH resolution.
- **Scriptable**: Python-based proxy logic for easy request/response modification.

## Installation

Install using `uv`:

```bash
uv tool install git+https://github.com/ogpourya/tlsmith.git
```

## Usage

Run with `sudo` (required for ports 80/443 and `/etc/hosts` modification). If `sudo tlsmith` is not found in your path, use the `$(which tlsmith)` subshell:

> [!IMPORTANT]
> `tlsmith` only works with domains, not raw IP addresses.

```bash
sudo tlsmith example.com
# Fallback if not in sudo path:
sudo $(which tlsmith) example.com google.com
```

1. **Trust CA**: On first run, a Root CA is generated at `~/.config/tlsmith/ca.crt`. Import this into your browser/OS trust store (or run on Debian/Ubuntu for auto-install).
2. **Intercepts**: `tlsmith` automatically updates `/etc/hosts` to point these domains to `127.0.0.1`.
3. **Proxies**: Traffic is decrypted, decompressed for logging, modified (if --script provided), and forwarded to the *real* upstream via DNS-over-HTTPS.

## Scripting

You can modify traffic by providing a Python script via `--script`:

```python
# my_hooks.py
async def intercept_response(body: bytes, headers: dict, status: int) -> tuple[bytes, dict, int]:
    # Example: Inject script into HTML
    if b"text/html" in headers.get("Content-Type", b"").lower():
        body = body.replace(b"</body>", b"<script>alert('Pwned');</script></body>")
        
    # Example: Modify headers
    headers['X-Intercepted-By'] = 'TLSmith'
    
    return body, headers, status
```

Run with: `sudo tlsmith --script my_hooks.py example.com` (or `sudo $(which tlsmith) ...`)

## Options

- `--reset`: Remove CA and configuration files, clean up `/etc/hosts`, then exit.
- `--dns <url>`: Specify a custom DoH server URL to bypass `/etc/hosts` for upstream resolution (default: Cloudflare).
- `--script <path>`: Load Python script for request/response modification.
- `-v`, `--verbose`: Enable verbose logging to see incoming and outgoing request/response headers and decompressed bodies.

## Safety Warning

**Use with caution.** This tool modifies `/etc/hosts` to hijack traffic.
- If the tool crashes or is killed abruptly (SIGKILL), your `/etc/hosts` file may be left in a modified state, breaking connectivity for the spoofed domains.
- **Fix:** Run `sudo tlsmith --reset` (or `sudo $(which tlsmith) --reset`) to clean up, or manually edit `/etc/hosts` to remove the `# tlsmith` entries.
- Always verify the generated Root CA is trusted only for development purposes.

## License
MIT
