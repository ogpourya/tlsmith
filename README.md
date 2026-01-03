# tlsmith

A lab-only tool for intercepting and modifying HTTP/HTTPS traffic with dynamic TLS termination and host/IP spoofing.

## Features
- **Dynamic TLS**: On-the-fly leaf certificates for any domain or IP.
- **IP Interception**: Redirects raw IP traffic using system routing table (supports `SO_BINDTODEVICE` to bypass loops without a proxy).
- **Host Spoofing**: Automatically updates `/etc/hosts` for domain interception.
- **Scriptable**: Python hooks for request/response modification.

## Installation
Install using `uv`:
```bash
uv tool install git+https://github.com/ogpourya/tlsmith.git
```

## Usage

**Note**: `sudo` is required for `/etc/hosts` and routing table modification.

```bash
# Intercept domains
sudo tlsmith example.com

# Intercept multiple domains
sudo tlsmith example.com google.com

# Intercept IPs (works without upstream proxy on Linux)
sudo tlsmith 1.1.1.1 8.8.8.8

# Use custom ports
sudo tlsmith example.com --port 8080 --tls-port 8443
```

> [!CAUTION]
> This tool is **intrusive**. It modifies your routing table and `/etc/hosts`. If it crashes, your internet connectivity for intercepted targets **might break**. Always run `sudo tlsmith --reset` to recover.

## Scripting Hooks

You can modify traffic on the fly using a Python script. Create a file (e.g., `my_hooks.py`) with an `intercept_response` async function:

```python
# my_hooks.py

async def intercept_response(body: bytes, headers: dict, status: int) -> tuple[bytes, dict, int]:
    # Modify headers
    headers['X-Modified-By'] = 'TLSmith'
    
    # Modify body (e.g., inject HTML)
    try:
        text = body.decode('utf-8')
        text = text.replace('Example Domain', 'Hacked Domain')
        body = text.encode('utf-8')
    except:
        pass # Ignore binary data

    return body, headers, status
```

Run with the hook:
```bash
sudo tlsmith example.com --script my_hooks.py
```

## Options
- `--proxy <url>`: Upstream proxy URL (optional, e.g., `http://localhost:8080`).
- `--script <path>`: Python script with `intercept_response` hook.
- `--port <int>`: HTTP port to listen on (default: 80).
- `--tls-port <int>`: HTTPS port to listen on (default: 443).
- `--reset`: Cleanup CA, config, hosts, and routing table, then exit.
- `-v`: Verbose logging.

## License
MIT
