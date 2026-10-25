import asyncio
import logging
import os
import ssl
import sys
import datetime
import subprocess
import tempfile
import json
from typing import Optional, Dict
from pathlib import Path
import shutil
import base64
import socket
import struct
import random
import ipaddress

import aiohttp
from aiohttp import web
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# --- Configuration ---
APP_NAME = "tlsmith"
if sys.platform == "linux":
    CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_NAME
else:
    CONFIG_DIR = Path.home() / f".{APP_NAME}"
# Set before re-executing under sudo so the CA stays in the invoking user's home.
CONFIG_DIR = Path(os.environ.get("TLSMITH_CONFIG_DIR") or CONFIG_DIR)

CONFIG_DIR.mkdir(parents=True, exist_ok=True)

CA_CERT_FILE = CONFIG_DIR / "ca.crt"
CA_KEY_FILE = CONFIG_DIR / "ca.key"
HOSTS_FILE = "/etc/hosts"
MARKER = "# tlsmith"

# Packets from tlsmith's own outbound sockets carry this mark so the
# DNAT rules that redirect intercepted IPs skip them.
DONT_INTERCEPT_MARK = 0x7473  # "ts"
IPTABLES_CHAIN = "TLSMITH"

# --- Logging Setup ---
logger = logging.getLogger("tlsmith")
logger.setLevel(logging.INFO)

# --- Certificate Authority ---
class CertificateAuthority:
    def __init__(self):
        self.cert: Optional[x509.Certificate] = None
        self.key: Optional[ec.EllipticCurvePrivateKey] = None
        self.installed = False
        self.ensure_ca()

    def install_ca_system(self):
        if not sys.platform.startswith("linux"):
            return False
        ca_dir = Path("/usr/local/share/ca-certificates")
        update_cmd = shutil.which("update-ca-certificates")
        if ca_dir.exists() and update_cmd:
            dest = ca_dir / "tlsmith.crt"
            try:
                if os.geteuid() == 0:
                    shutil.copy(CA_CERT_FILE, dest)
                    subprocess.run([update_cmd], check=True, capture_output=True)
                else:
                    subprocess.run(["sudo", "cp", str(CA_CERT_FILE), str(dest)], check=True)
                    subprocess.run(["sudo", update_cmd], check=True, capture_output=True)
                logger.info(f"Successfully installed CA to system store ({dest})")
                return True
            except Exception as e:
                logger.error(f"Failed to auto-install CA: {e}")
        return False

    def ensure_ca(self):
        if CA_CERT_FILE.exists() and CA_KEY_FILE.exists():
            try:
                with open(CA_CERT_FILE, "rb") as f:
                    self.cert = x509.load_pem_x509_certificate(f.read())
                with open(CA_KEY_FILE, "rb") as f:
                    self.key = serialization.load_pem_private_key(f.read(), password=None)
                logger.info(f"Loaded existing CA from {CA_CERT_FILE}")
                if self.install_ca_system():
                    self.installed = True
                return
            except Exception as e:
                logger.error(f"Failed to load CA, regenerating: {e}")

        logger.info(f"Generating new Root CA at {CA_CERT_FILE}...")
        self.key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MITM Lab CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"MITM Lab CA"),
        ])
        self.cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*10)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(self.key, hashes.SHA256())

        with open(CA_CERT_FILE, "wb") as f:
            f.write(self.cert.public_bytes(serialization.Encoding.PEM))
        with open(CA_KEY_FILE, "wb") as f:
            f.write(self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        if self.install_ca_system():
            self.installed = True

    def get_context_for_host(self, hostname: str) -> ssl.SSLContext:
        try:
            ip_addr = ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        san_list = [x509.IPAddress(ip_addr)] if is_ip else [x509.DNSName(hostname)]
        return self._make_context(hostname, san_list)

    def get_context_for_ips(self, ips) -> ssl.SSLContext:
        # IP clients send no SNI, so one cert must cover every intercepted IP.
        san_list = [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
        return self._make_context("tlsmith", san_list)

    def _make_context(self, common_name: str, san_list) -> ssl.SSLContext:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.cert.subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
        ).add_extension(
            x509.SubjectAlternativeName(san_list), critical=False
        ).sign(self.key, hashes.SHA256())

        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.check_hostname = False

        with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as kf:
            kf.write(key_pem)
            kpath = kf.name
        with tempfile.NamedTemporaryFile(suffix=".crt", delete=False) as cf:
            cf.write(cert_pem)
            cpath = cf.name
        try:
            ctx.load_cert_chain(cpath, kpath)
        except Exception as e:
            logger.error(f"Failed to load cert chain: {e}")
        finally:
            os.unlink(kpath)
            os.unlink(cpath)
        return ctx

# --- Routing Manager ---
class RoutingManager:
    @staticmethod
    def _iptables(*args):
        cmd = ["iptables", "-t", "nat", *args]
        if os.geteuid() != 0:
            cmd.insert(0, "sudo")
        return subprocess.run(cmd, capture_output=True, text=True)

    @staticmethod
    def setup_ip_interception(ips, http_port: int, tls_port: int):
        if not sys.platform.startswith("linux"):
            logger.error("IP interception requires Linux (iptables).")
            return
        RoutingManager.teardown_ip_interception()
        if RoutingManager._iptables("-N", IPTABLES_CHAIN).returncode != 0:
            logger.error(f"Could not create iptables chain {IPTABLES_CHAIN}; IP interception disabled.")
            return
        RoutingManager._iptables("-I", "OUTPUT", "-j", IPTABLES_CHAIN)
        for ip in ips:
            try:
                ipaddress.IPv4Address(ip)
            except ValueError:
                logger.warning(f"IP interception supports IPv4 only; skipping {ip}")
                continue
            RoutingManager.remove_ip_route(ip)
            for port in (80, 443):
                target_port = http_port if port == 80 else tls_port
                result = RoutingManager._iptables(
                    "-A", IPTABLES_CHAIN, "-d", ip, "-p", "tcp", "--dport", str(port),
                    "-m", "mark", "!", "--mark", str(DONT_INTERCEPT_MARK),
                    "-j", "DNAT", "--to-destination", f"127.0.0.1:{target_port}",
                )
                if result.returncode != 0:
                    logger.error(f"Failed to add DNAT rule for {ip}:{port}: {result.stderr.strip()}")
            logger.info(f"Redirecting {ip} to 127.0.0.1")

    @staticmethod
    def teardown_ip_interception():
        if not sys.platform.startswith("linux"):
            return
        while RoutingManager._iptables("-D", "OUTPUT", "-j", IPTABLES_CHAIN).returncode == 0:
            pass
        RoutingManager._iptables("-F", IPTABLES_CHAIN)
        RoutingManager._iptables("-X", IPTABLES_CHAIN)

    @staticmethod
    def remove_ip_route(ip: str):
        # Older versions aliased intercepted IPs onto lo; drop such leftovers.
        cmd = ["ip", "addr", "del", f"{ip}/32", "dev", "lo"]
        if os.geteuid() != 0:
            cmd.insert(0, "sudo")
        subprocess.run(cmd, capture_output=True)

# --- Hosts Manager ---
class HostsManager:
    @staticmethod
    def add_domain(domain: str):
        try:
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            domains = {domain}
        elif domain.startswith("www."):
            base = domain[4:]
            domains = {base, domain}
        else:
            domains = {domain, f"www.{domain}"}
        entry = f"127.0.0.1 {' '.join(sorted(domains))} {MARKER}\n"
        try:
            with open(HOSTS_FILE, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Failed to read hosts: {e}")
            return
        new_lines = []
        for line in lines:
            if MARKER in line:
                parts = line.split()
                if any(d in parts for d in domains):
                    continue
            new_lines.append(line)
        if new_lines and not new_lines[-1].endswith('\n'):
            new_lines.append('\n')
        new_lines.append(entry)
        HostsManager._write_hosts(new_lines)
        logger.info(f"Updated /etc/hosts for {domain}")

    @staticmethod
    def remove_all():
        try:
            # Clean up /etc/hosts
            with open(HOSTS_FILE, 'r') as f:
                lines = f.readlines()
            new_lines = [line for line in lines if MARKER not in line]
            if len(new_lines) != len(lines):
                 HostsManager._write_hosts(new_lines)
                 print(f"Removed {len(lines) - len(new_lines)} entries from {HOSTS_FILE}")
            else:
                 print(f"No {MARKER} entries found in {HOSTS_FILE}.")
        except Exception as e:
            logger.error(f"Failed to read hosts: {e}")
            return

    @staticmethod
    def _write_hosts(lines):
        content = "".join(lines)
        if os.geteuid() == 0:
            try:
                with open(HOSTS_FILE, 'w') as f:
                    f.write(content)
            except Exception as e:
                logger.error(f"Failed to write hosts: {e}")
            return
        proc = subprocess.Popen(['sudo', 'tee', HOSTS_FILE], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        out, err = proc.communicate(input=content.encode('utf-8'))
        if proc.returncode != 0:
            logger.error(f"Sudo write failed: {err.decode()}")

# --- Utils ---

# --- Traffic Hooks ---
args_script_path: Optional[str] = None
async def default_intercept_response(body: bytes, headers: dict, status: int) -> tuple[bytes, dict, int]:
    return body, headers, status

intercept_response_hook = default_intercept_response

def load_script(path: str):
    global intercept_response_hook, args_script_path
    args_script_path = path
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("user_script", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if hasattr(module, "intercept_response"):
            intercept_response_hook = module.intercept_response
            logger.info(f"Loaded response hook from {path}")
    except Exception as e:
        logger.error(f"Error in user script '{path}': {e}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

# --- Proxy Logic ---
def _marked_socket(addr_info):
    """Force tlsmith's own outbound traffic past the DNAT chain."""
    # aiohappyeyeballs passes a plain (family, type, proto, ...) tuple.
    family, type_, proto = addr_info[0], addr_info[1], addr_info[2]
    sock = socket.socket(family, type_, proto)
    sock.setsockopt(
        socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), DONT_INTERCEPT_MARK
    )
    return sock

async def proxy_handler(request: web.Request):
    host = request.host
    hostname = host.split(":")[0] if ":" in host else host
    
    try:
        ipaddress.ip_address(hostname)
        is_hostname_ip = True
    except ValueError:
        is_hostname_ip = False

    logger.info(f"{request.method} {request.url}")
    if logger.level <= logging.DEBUG:
        logger.debug(f"--- Incoming Request ---")
        logger.debug(f"Headers: {dict(request.headers)}")

    real_ip = None
    if is_hostname_ip:
        real_ip = hostname
    else:
        try:
            info = await asyncio.get_event_loop().getaddrinfo(hostname, None)
            ips = [x[4][0] for x in info]
            for ip in ips:
                if not ip.startswith("127.") and ip != "::1":
                    real_ip = ip
                    break
            if not real_ip:
                # Check pre-resolved map
                real_ip = DOMAIN_MAP.get(hostname)
            
            if not real_ip:
                return web.Response(text=f"Could not resolve {hostname}", status=502)
        except Exception as e:
            logger.error(f"Resolution error: {e}")
            return web.Response(text="DNS Error", status=502)

    scheme = request.scheme
    port = request.url.port or (443 if scheme == 'https' else 80)
    target_url = f"{scheme}://{real_ip}:{port}{request.path_qs}"

    req_headers = {k: v for k, v in request.headers.items() if k.lower() not in ('host', 'content-length', 'connection')}
    req_headers['Host'] = host
    if 'transfer-encoding' in req_headers: del req_headers['transfer-encoding']
    req_body = await request.read()
    if logger.level <= logging.DEBUG and req_body:
        try:
            logger.debug(f"Request Body: {req_body.decode('utf-8', errors='replace')}")
        except Exception:
            logger.debug(f"Request Body: <binary data {len(req_body)} bytes>")
    
    if real_ip.startswith("127."):
        logger.warning(f"Target {hostname} resolved to loopback ({real_ip}). Upstream requests may loop back.")

    ssl_ctx_upstream = None
    if scheme == 'https':
        ssl_ctx_upstream = ssl.create_default_context()
        ssl_ctx_upstream.check_hostname = False
        ssl_ctx_upstream.verify_mode = ssl.CERT_NONE

    try:
        connector = aiohttp.TCPConnector(socket_factory=_marked_socket) if INTERCEPTED_IPS else None
        async with aiohttp.ClientSession(auto_decompress=True, connector=connector) as session:
            async with session.request(
                request.method, target_url, headers=req_headers, data=req_body,
                ssl=ssl_ctx_upstream, server_hostname=hostname if scheme == 'https' else None,
                allow_redirects=False
            ) as resp:
                body = await resp.read()
                if logger.level <= logging.DEBUG:
                    logger.debug(f"--- Outgoing Response ---")
                    logger.debug(f"Status: {resp.status}")
                    logger.debug(f"Headers: {dict(resp.headers)}")
                    try:
                        logger.debug(f"Response Body: {body.decode('utf-8', errors='replace')}")
                    except Exception:
                        logger.debug(f"Response Body: <binary data {len(body)} bytes>")
                
                out_headers = {}
                for k, v in resp.headers.items():
                    k_lower = k.lower()
                    if k_lower not in ('content-length', 'content-encoding', 'transfer-encoding', 'connection', 'server'):
                        out_headers[k] = v
                
                try:
                    body, out_headers, status = await intercept_response_hook(body, out_headers, resp.status)
                except Exception as e:
                    logger.error(f"Error executing intercept_response in '{args_script_path}': {e}")
                    import traceback
                    logger.error(traceback.format_exc())
                    # Continue with original data if hook fails? Or return 500?
                    # Let's return the original data but log the error clearly.

                return web.Response(body=body, status=status, headers=out_headers)
    except Exception as e:
        logger.error(f"Upstream error: {e}")
        return web.Response(text=f"Upstream Error: {e}", status=502)

# --- Main ---
ca: Optional[CertificateAuthority] = None
DOMAIN_MAP: Dict[str, str] = {}
INTERCEPTED_IPS: set = set()

import argparse

def ensure_root():
    """Re-exec under sudo so tlsmith can be started without `sudo`."""
    if os.geteuid() == 0:
        return
    sudo = shutil.which("sudo")
    if not sudo:
        sys.exit("tlsmith needs root: install sudo or run it as root.")
    os.execvp(sudo, [
        sudo, "env", f"TLSMITH_CONFIG_DIR={CONFIG_DIR}",
        sys.executable, *sys.argv,
    ])

def main():
    global DOMAIN_MAP, INTERCEPTED_IPS, ca
    parser = argparse.ArgumentParser(description="MITM Proxy & Host Spoofer")
    parser.add_argument("--reset", action="store_true", help="Remove CA and config, then exit")
    parser.add_argument("--script", help="Path to Python script with interception hooks")
    parser.add_argument("--port", type=int, default=80, help="HTTP port to listen on (default 80)")
    parser.add_argument("--tls-port", type=int, default=443, help="HTTPS port to listen on (default 443)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose request/response logs")
    parser.add_argument("domains", nargs="*", help="Domains or IPs to intercept.")
    args = parser.parse_args()
    ensure_root()

    if args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(level=level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    logger.setLevel(level)
    
    # Initialize CA after logging is configured so user sees output
    ca = CertificateAuthority()

    if args.reset:
        RoutingManager.teardown_ip_interception()
        HostsManager.remove_all()
        if CA_CERT_FILE.exists(): CA_CERT_FILE.unlink()
        if CA_KEY_FILE.exists(): CA_KEY_FILE.unlink()
        sys.exit(0)

    if not args.domains:
        logger.error("No domains specified. Please provide at least one domain to intercept.")
        sys.exit(1)

    if args.script: load_script(args.script)

    print("\n[WARNING] Modifying /etc/hosts and iptables to intercept traffic.")
    print("[WARNING] IP interception adds temporary iptables NAT rules.")
    print("[WARNING] If this tool crashes, run with --reset to clean up.\n")
    
    global INTERCEPTED_IPS
    INTERCEPTED_IPS = set()

    try:
        domains_to_add = []
        ips_to_route = []
        
        def add_item(item):
            item = item.strip()
            if not item: return
            try:
                ipaddress.ip_address(item)
                ips_to_route.append(item)
            except ValueError:
                # Pre-resolve domain
                try:
                    resolved = socket.gethostbyname(item)
                    DOMAIN_MAP[item] = resolved
                    domains_to_add.append(item)
                    if not item.startswith("www."):
                        try:
                            wip = socket.gethostbyname(f"www.{item}")
                            DOMAIN_MAP[f"www.{item}"] = wip
                        except: pass
                except Exception as e:
                    logger.warning(f"Could not resolve {item}: {e}")

        for d in args.domains:
            path = Path(d)
            if path.exists() and path.is_file():
                with open(path, 'r') as f: 
                    for line in f: add_item(line)
            else:
                for item in d.split(","): add_item(item)

        for d in set(domains_to_add):
            HostsManager.add_domain(d)
        
        INTERCEPTED_IPS.update(ips_to_route)
        if ips_to_route:
            RoutingManager.setup_ip_interception(ips_to_route, args.port, args.tls_port)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def sni_callback(ssl_socket, server_name, initial_context):
            if not server_name:
                # No SNI: keep the listener's default cert (covers intercepted IPs).
                return
            target = server_name
            
            logger.info(f"SNI Callback: targeting {target}")
            try:
                # The issue might be that aiohttp is already deep in the handshake 
                # or caching the context. In some versions of OpenSSL/Python,
                # you must set the context on the *underlying* SSLObject or 
                # return it from the callback if using SSLContext.sni_callback
                # but Python's set_servername_callback expects the callback to 
                # modify the socket's context or return None.
                new_ctx = ca.get_context_for_host(target)
                ssl_socket.context = new_ctx
            except Exception as e:
                logger.error(f"SNI Error: {e}")

        async def run_server():
            app = web.Application()
            app.router.add_route('*', '/{path_info:.*}', proxy_handler)
            runner = web.AppRunner(app)
            await runner.setup()
            
            # Listen on all interfaces for port 80
            await web.TCPSite(runner, '0.0.0.0', args.port).start()

            # Intercepted IPs are DNATed to 127.0.0.1. Clients using an IP
            # send no SNI, so the default cert must cover them.
            if ips_to_route:
                ssl_ctx = ca.get_context_for_ips(ips_to_route)
            else:
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.load_cert_chain(CA_CERT_FILE, CA_KEY_FILE)
            ssl_ctx.set_servername_callback(sni_callback)
            await web.TCPSite(runner, '127.0.0.1', args.tls_port, ssl_context=ssl_ctx).start()
            
            logger.info(f"Listening on :{args.port} and :{args.tls_port}")
            while True: await asyncio.sleep(3600)
        
        loop.run_until_complete(run_server())
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Cleaning up iptables rules and hosts file...")
        RoutingManager.teardown_ip_interception()
        # Also clean up hosts entries
        HostsManager.remove_all()

if __name__ == "__main__":
    main()
