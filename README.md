# tlsmith

A tool for intercepting and modifying HTTP/HTTPS traffic with dynamic TLS termination and host/IP spoofing.

## Features
- **Dynamic TLS**: On-the-fly leaf certificates for any domain or IP.
- **IP Interception**: Redirects raw IP traffic with temporary iptables DNAT rules.
- **Host Spoofing**: Automatically updates `/etc/hosts` for domain interception.
- **Scriptable**: Python hooks for request/response modification.

## Installation
Install using `uv`:
```bash
uv tool install git+https://github.com/ogpourya/tlsmith.git
```

## Usage

**Note**: tlsmith asks for `sudo` itself when it needs root (ports 80/443, `/etc/hosts`, iptables). Run it as your normal user.

```bash
# Intercept domains
tlsmith example.com

# Intercept multiple domains
tlsmith example.com google.com

# Intercept IPs
tlsmith 1.1.1.1 8.8.8.8

# Use custom ports
tlsmith example.com --port 8080 --tls-port 8443
```

> [!CAUTION]
> This tool is **intrusive**. It adds temporary iptables rules and modifies `/etc/hosts`. If it crashes, your internet connectivity for intercepted targets **might break**. Run `tlsmith --reset` to recover.

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
tlsmith example.com --script my_hooks.py
```

## Options
- `--script <path>`: Python script with `intercept_response` hook.
- `--port <int>`: HTTP port to listen on (default: 80).
- `--tls-port <int>`: HTTPS port to listen on (default: 443).
- `--reset`: Cleanup CA, config, hosts, and iptables rules, then exit.
- `-v`: Verbose logging.

## License
MIT
