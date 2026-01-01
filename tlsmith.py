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
# Queue handler removed as we are CLI only now

# --- Certificate Authority ---
class CertificateAuthority:
    def __init__(self):
        self.cert: Optional[x509.Certificate] = None
        self.key: Optional[ec.EllipticCurvePrivateKey] = None
        self.installed = False
        self.ensure_ca()

    def install_ca_system(self):
        """Attempts to install CA on Debian/Ubuntu systems automatically."""
        if not sys.platform.startswith("linux"):
            return False
            
        # Check for Debian/Ubuntu style ca-certificates
        ca_dir = Path("/usr/local/share/ca-certificates")
        update_cmd = shutil.which("update-ca-certificates")
        
        if ca_dir.exists() and update_cmd:
            dest = ca_dir / "tlsmith.crt"
            try:
                # Copy cert
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
        ca_exists = CA_CERT_FILE.exists() and CA_KEY_FILE.exists()
        
        if ca_exists:
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
            logger.info("Auto-installed CA to system trust store.")
            self.installed = True
        else:
            logger.info("Could not auto-install CA (system not supported or permission denied).")

    def get_context_for_host(self, hostname: str) -> ssl.SSLContext:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
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
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
        ).sign(self.key, hashes.SHA256())

        key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        # Create generic SSL context
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.check_hostname = False

        # Use temp files for SSLContext loading
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

# --- Hosts Manager ---
class HostsManager:
    @staticmethod
    def add_domain(domain: str):
        if domain.startswith("www."):
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
            with open(HOSTS_FILE, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Failed to read hosts: {e}")
            return

        new_lines = [line for line in lines if MARKER not in line]
        
        if len(new_lines) != len(lines):
             HostsManager._write_hosts(new_lines)
             print(f"Removed {len(lines) - len(new_lines)} entries from {HOSTS_FILE}")
        else:
             print(f"No {MARKER} entries found in {HOSTS_FILE}.")

    @staticmethod
    def _write_hosts(lines):
        content = "".join(lines)
        proc = subprocess.Popen(['sudo', 'tee', HOSTS_FILE], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        out, err = proc.communicate(input=content.encode('utf-8'))
        if proc.returncode != 0:
            logger.error(f"Sudo write failed: {err.decode()}")

# --- DNS Helper ---
def make_dns_query(host: str) -> bytes:
    import struct
    import random
    
    tid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    
    qname = b""
    for part in host.split("."):
        qname += bytes([len(part)]) + part.encode("ascii")
    qname += b"\x00"
    
    qtype = 1 # A
    qclass = 1 # IN
    
    return header + qname + struct.pack("!HH", qtype, qclass)

def parse_dns_response(data: bytes) -> str:
    import struct
    idx = 12
    while True:
        length = data[idx]
        if length == 0:
            idx += 1
            break
        idx += length + 1
    idx += 4
    
    ancount = struct.unpack("!H", data[6:8])[0]
    if ancount == 0:
        return ""
        
    for _ in range(ancount):
        if data[idx] & 0xC0 == 0xC0:
            idx += 2
        else:
            while data[idx] != 0:
                idx += data[idx] + 1
            idx += 1
            
        type, _class, ttl, rdlength = struct.unpack("!HHIH", data[idx:idx+10])
        idx += 10
        if type == 1 and _class == 1 and rdlength == 4:
            ip_bytes = data[idx:idx+4]
            return ".".join(str(b) for b in ip_bytes)
        idx += rdlength
    return ""

async def resolve_doh(host: str, doh_url: str) -> str:
    query = make_dns_query(host)
    async with aiohttp.ClientSession() as session:
        headers = {"Accept": "application/dns-message", "Content-Type": "application/dns-message"}
        try:
            async with session.post(doh_url, data=query, headers=headers, timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.read()
                    return parse_dns_response(data)
        except Exception as e:
            logger.error(f"DoH error for {host} via {doh_url}: {e}")
    return ""

# --- Proxy Logic ---
async def proxy_handler(request: web.Request):
    host = request.host
    if ":" in host:
        hostname = host.split(":")[0]
    else:
        hostname = host
    
    logger.info(f"{request.method} {request.url}")

    real_ip = None
    try:
        info = await asyncio.get_event_loop().getaddrinfo(hostname, None)
        ips = [x[4][0] for x in info]
        
        for ip in ips:
            if not ip.startswith("127.") and ip != "::1":
                real_ip = ip
                break
        
        if not real_ip:
            logger.info(f"Loopback detected for {hostname}, bypassing local hosts via DoH ({DOH_URL})...")
            real_ip = await resolve_doh(hostname, DOH_URL)
            
        if not real_ip:
            return web.Response(text=f"Could not resolve {hostname}", status=502)
            
    except Exception as e:
        logger.error(f"Resolution error: {e}")
        return web.Response(text="DNS Error", status=502)

    scheme = request.scheme
    port = request.url.port or (443 if scheme == 'https' else 80)
    target_url = f"{scheme}://{real_ip}:{port}{request.path_qs}"
    
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ('host', 'content-length')}
    headers['Host'] = host
    
    ssl_ctx = None
    if scheme == 'https':
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    try:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                request.method, 
                target_url, 
                headers=headers, 
                data=request.content,
                ssl=ssl_ctx,
                server_hostname=hostname if scheme == 'https' else None,
                allow_redirects=False
            ) as resp:
                body = await resp.read()
                out_headers = {k: v for k, v in resp.headers.items() 
                               if k.lower() not in ('content-length', 'content-encoding', 'transfer-encoding', 'connection')}
                out_headers['Date'] = "Sat, 01 Jan 2099 00:00:00 GMT"
                return web.Response(body=body, status=resp.status, headers=out_headers)
    except Exception as e:
        logger.error(f"Upstream error: {e}")
        return web.Response(text=f"Upstream Error: {e}", status=502)

def sni_callback(ssl_socket, server_name, initial_context):
    if not server_name: return
    try:
        ctx = ca.get_context_for_host(server_name)
        ssl_socket.context = ctx
    except Exception as e:
        logger.error(f"SNI Error: {e}")

# --- Main ---
ca = CertificateAuthority()
DOH_URL = "https://sky.rethinkdns.com/dns-query"

import argparse

def main():
    global DOH_URL
    parser = argparse.ArgumentParser(description="MITM Proxy & Host Spoofer")
    parser.add_argument("--reset", action="store_true", help="Remove CA and config, then exit")
    parser.add_argument("--doh", default="https://sky.rethinkdns.com/dns-query", help="DoH Resolver URL")
    parser.add_argument("domains", nargs="*", help="Domains to intercept (e.g. example.com). Can also be a file path containing domains.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
    
    if args.reset:
        print(f"Resetting configuration in {CONFIG_DIR}...")
        HostsManager.remove_all()
        if CA_CERT_FILE.exists(): CA_CERT_FILE.unlink()
        if CA_KEY_FILE.exists(): CA_KEY_FILE.unlink()
        print("Done.")
        sys.exit(0)

    DOH_URL = args.doh

    # Process domains
    domains_to_add = []
    if args.domains:
        print("\n[WARNING] Modifying /etc/hosts to intercept traffic.")
        print("[WARNING] If this tool crashes, run with --reset to clean up.")
        print("[WARNING] Sudo privileges are required for port binding and hosts modification.\n")
    
    for d in args.domains:
        path = Path(d)
        if path.exists() and path.is_file():
             with open(path, 'r') as f:
                 domains_to_add.extend([line.strip() for line in f if line.strip()])
        else:
             domains_to_add.extend(d.split(","))
    
    for d in set(domains_to_add):
        if d:
            HostsManager.add_domain(d.strip())

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def run_server():
        app = web.Application()
        app.router.add_route('*', '/{path_info:.*}', proxy_handler)
        runner = web.AppRunner(app)
        await runner.setup()
        
        site = web.TCPSite(runner, '0.0.0.0', 80)
        
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(CA_CERT_FILE, CA_KEY_FILE)
        ssl_ctx.set_servername_callback(sni_callback)
        site_tls = web.TCPSite(runner, '0.0.0.0', 443, ssl_context=ssl_ctx)
        
        try:
            await site.start()
            logger.info("Listening HTTP on :80")
            await site_tls.start()
            logger.info("Listening HTTPS on :443")
            
            if ca.installed:
                logger.info("CA Auto-Installed to system trust store.")
            else:
                logger.info(f"CA Cert: {CA_CERT_FILE}")
                logger.info("To trust on Debian/Ubuntu:")
                logger.info(f"  sudo cp {CA_CERT_FILE} /usr/local/share/ca-certificates/tlsmith.crt && sudo update-ca-certificates")
            
            while True:
                await asyncio.sleep(3600)
        except PermissionError:
            logger.error("Permission denied binding ports. Run with sudo!")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Server start failed: {e}")
            sys.exit(1)

    try:
        loop.run_until_complete(run_server())
    except KeyboardInterrupt:
        print("\nShutting down...")
        pass

if __name__ == "__main__":
    main()
