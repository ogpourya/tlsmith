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

CONFIG_DIR.mkdir(parents=True, exist_ok=True)

CA_CERT_FILE = CONFIG_DIR / "ca.crt"
CA_KEY_FILE = CONFIG_DIR / "ca.key"
HOSTS_FILE = "/etc/hosts"
MARKER = "# tlsmith"

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

        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        
        san_list = [x509.IPAddress(ip_addr)] if is_ip else [x509.DNSName(hostname)]
        
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
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
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
    def add_ip_route(ip: str):
        try:
            # Add IP to lo interface so we can bind to it
            subprocess.run(["sudo", "ip", "addr", "add", f"{ip}/32", "dev", "lo"], check=True, capture_output=True)
            logger.info(f"Added address {ip} to lo")
        except subprocess.CalledProcessError as e:
            if "File exists" in e.stderr.decode():
                logger.warning(f"Address {ip} already exists on lo")
            else:
                logger.error(f"Failed to add address {ip}: {e.stderr.decode()}")

    @staticmethod
    def remove_ip_route(ip: str):
        try:
            subprocess.run(["sudo", "ip", "addr", "del", f"{ip}/32", "dev", "lo"], check=True, capture_output=True)
            logger.info(f"Removed address {ip} from lo")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove address {ip}: {e.stderr.decode()}")

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

            # Clean up IP addresses from 'lo'
            try:
                result = subprocess.run(["ip", "addr", "show", "dev", "lo"], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    # Look for 'inet 1.2.3.4/32'
                    if "inet " in line and "/32" in line:
                        parts = line.split()
                        # parts[1] is '1.2.3.4/32'
                        target = parts[1].split('/')[0]
                        if target == "127.0.0.1": continue
                        
                        print(f"Removing lingering address {target} from lo...")
                        RoutingManager.remove_ip_route(target)
            except Exception as e:
                logger.error(f"Failed to cleanup addresses: {e}")
        except Exception as e:
            logger.error(f"Failed to read hosts: {e}")
            return

    @staticmethod
    def _write_hosts(lines):
        content = "".join(lines)
        proc = subprocess.Popen(['sudo', 'tee', HOSTS_FILE], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        out, err = proc.communicate(input=content.encode('utf-8'))
        if proc.returncode != 0:
            logger.error(f"Sudo write failed: {err.decode()}")

# --- DNS Helper ---
async def resolve_dns_doh(host: str, doh_url: str) -> str:
    """DNS-over-HTTPS implementation to bypass /etc/hosts."""
    for attempt in range(1, 4):
        try:
            async with aiohttp.ClientSession() as session:
                params = {"name": host, "type": "A"}
                headers = {"accept": "application/dns-json"}
                async with session.get(doh_url, params=params, headers=headers, proxy=PROXY_URL) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        if "Answer" in data:
                            for answer in data["Answer"]:
                                if answer["type"] == 1:  # A record
                                    return answer["data"]
            if attempt < 3:
                logger.warning(f"DoH attempt {attempt} failed for {host}, retrying...")
        except Exception as e:
            if attempt < 3:
                logger.warning(f"DoH attempt {attempt} failed for {host}: {e}. Retrying...")
            else:
                logger.error(f"jesuss we failed: DoH error for {host} via {doh_url}: {e}")
                logger.warning("Warning: low quality DNS detected. Consider using a more reliable DoH provider.")
    return None

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
                logger.info(f"Loopback detected for {hostname}, bypassing via DoH ({DNS_SERVER})...")
                real_ip = await resolve_dns_doh(hostname, DNS_SERVER)
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
    
    if PROXY_URL and real_ip.startswith("127."):
        logger.warning(f"Target {hostname} resolved to loopback ({real_ip}). Proxying loopback traffic may fail depending on upstream proxy configuration.")

    ssl_ctx_upstream = None
    if scheme == 'https':
        ssl_ctx_upstream = ssl.create_default_context()
        ssl_ctx_upstream.check_hostname = False
        ssl_ctx_upstream.verify_mode = ssl.CERT_NONE

    try:
        async with aiohttp.ClientSession(auto_decompress=True) as session:
            if PROXY_URL:
                logger.debug(f"Using upstream proxy: {PROXY_URL}")
            async with session.request(
                request.method, target_url, headers=req_headers, data=req_body,
                ssl=ssl_ctx_upstream, server_hostname=hostname if scheme == 'https' else None,
                allow_redirects=False,
                proxy=PROXY_URL
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
ca = CertificateAuthority()
DNS_SERVER = "https://cloudflare-dns.com/dns-query"
PROXY_URL: Optional[str] = None

import argparse

def main():
    global DNS_SERVER, PROXY_URL
    parser = argparse.ArgumentParser(description="MITM Proxy & Host Spoofer")
    parser.add_argument("--reset", action="store_true", help="Remove CA and config, then exit")
    parser.add_argument("--dns", default="https://cloudflare-dns.com/dns-query", help="DoH Server URL to bypass hosts file")
    parser.add_argument("--proxy", help="Upstream proxy URL (e.g. http://localhost:3333)")
    parser.add_argument("--script", help="Path to Python script with interception hooks")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose request/response logs")
    parser.add_argument("domains", nargs="*", help="Domains to intercept.")
    args = parser.parse_args()

    if args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(level=level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    logger.setLevel(level)

    if args.reset:
        HostsManager.remove_all()
        if CA_CERT_FILE.exists(): CA_CERT_FILE.unlink()
        if CA_KEY_FILE.exists(): CA_KEY_FILE.unlink()
        sys.exit(0)

    if not args.domains:
        logger.error("No domains specified. Please provide at least one domain to intercept.")
        sys.exit(1)

    DNS_SERVER = args.dns
    PROXY_URL = args.proxy
    if args.script: load_script(args.script)

    print("\n[WARNING] Modifying /etc/hosts and routing table to intercept traffic.")
    print("[WARNING] IP support requires an upstream --proxy to reach the original destination.")
    print("[WARNING] If this tool crashes, run with --reset to clean up.\n")
    
    intercepted_ips = []

    try:
        domains_to_add = []
        ips_to_route = []
        for d in args.domains:
            path = Path(d)
            if path.exists() and path.is_file():
                with open(path, 'r') as f: 
                    for line in f:
                        item = line.strip()
                        if item:
                            try:
                                ipaddress.ip_address(item)
                                ips_to_route.append(item)
                            except ValueError:
                                domains_to_add.append(item)
            else:
                for item in d.split(","):
                    item = item.strip()
                    if item:
                        try:
                            ipaddress.ip_address(item)
                            ips_to_route.append(item)
                        except ValueError:
                            domains_to_add.append(item)

        if ips_to_route and not PROXY_URL:
            logger.error("IP interception requires an upstream --proxy. Exit.")
            sys.exit(1)

        for d in set(domains_to_add):
            HostsManager.add_domain(d)
        
        for ip in set(ips_to_route):
            RoutingManager.add_ip_route(ip)
            intercepted_ips.append(ip)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def sni_callback(ssl_socket, server_name, initial_context):
            target = server_name
            if not target:
                try:
                    # Use the socket's own address if SNI is missing
                    sockname = ssl_socket.getsockname()
                    target = sockname[0]
                    # If target is 0.0.0.0, we can't do much without SNI
                    if target == "0.0.0.0":
                        logger.warning("SNI missing and socket bound to 0.0.0.0, cannot determine target IP")
                        return
                    logger.info(f"SNI missing, using socket IP: {target}")
                except Exception as e:
                    logger.error(f"Failed to get sockname: {e}")
                    return
            
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
            await web.TCPSite(runner, '0.0.0.0', 80).start()
            
            # For each intercepted IP, we use a custom context immediately 
            # if we want to be sure it works without SNI-to-IP resolution issues.
            for ip in set(ips_to_route):
                try:
                    ip_ctx = ca.get_context_for_host(ip)
                    # We still set the SNI callback just in case someone uses a hostname 
                    # that points to this IP.
                    ip_ctx.set_servername_callback(sni_callback)
                    await web.TCPSite(runner, ip, 443, ssl_context=ip_ctx).start()
                    logger.info(f"Dedicated listener started for intercepted IP: {ip}")
                except Exception as e:
                    logger.error(f"Failed to start listener for {ip}: {e}")

            # For general domain traffic via 127.0.0.1
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(CA_CERT_FILE, CA_KEY_FILE)
            ssl_ctx.set_servername_callback(sni_callback)
            await web.TCPSite(runner, '127.0.0.1', 443, ssl_context=ssl_ctx).start()
            
            logger.info("Listening on :80 and :443")
            while True: await asyncio.sleep(3600)
        
        loop.run_until_complete(run_server())
    except KeyboardInterrupt:
        pass
    finally:
        for ip in intercepted_ips:
            RoutingManager.remove_ip_route(ip)

if __name__ == "__main__":
    main()
