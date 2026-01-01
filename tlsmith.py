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
def resolve_dns(host: str, server: str) -> str:
    """Pure DNS implementation to bypass /etc/hosts."""
    def make_query(hostname):
        tid = random.randint(0, 65535)
        header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        qname = b""
        for part in hostname.split("."):
            qname += bytes([len(part)]) + part.encode("ascii")
        qname += b"\x00"
        return header + qname + struct.pack("!HH", 1, 1)

    def parse_response(data):
        idx = 12
        while idx < len(data):
            length = data[idx]
            if length == 0:
                idx += 1
                break
            idx += length + 1
        idx += 4
        ancount = struct.unpack("!H", data[6:8])[0]
        for _ in range(ancount):
            if idx >= len(data): break
            if data[idx] & 0xC0 == 0xC0: idx += 2
            else:
                while idx < len(data) and data[idx] != 0:
                    idx += data[idx] + 1
                idx += 1
            if idx + 10 > len(data): break
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[idx:idx+10])
            idx += 10
            if rtype == 1 and rclass == 1 and rdlength == 4:
                return ".".join(str(b) for b in data[idx:idx+4])
            idx += rdlength
        return None

    try:
        query = make_query(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(512)
        return parse_response(data)
    except Exception as e:
        logger.error(f"DNS error for {host} via {server}: {e}")
    return None

# --- Traffic Hooks ---
async def default_intercept_response(body: bytes, headers: dict, status: int) -> tuple[bytes, dict, int]:
    return body, headers, status

intercept_response_hook = default_intercept_response

def load_script(path: str):
    global intercept_response_hook
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("user_script", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if hasattr(module, "intercept_response"):
            intercept_response_hook = module.intercept_response
            logger.info(f"Loaded response hook from {path}")
    except Exception as e:
        logger.error(f"Failed to load script {path}: {e}")
        sys.exit(1)

# --- Proxy Logic ---
async def proxy_handler(request: web.Request):
    host = request.host
    hostname = host.split(":")[0] if ":" in host else host
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
            logger.info(f"Loopback detected for {hostname}, bypassing via DNS ({DNS_SERVER})...")
            real_ip = await asyncio.get_event_loop().run_in_executor(None, resolve_dns, hostname, DNS_SERVER)
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
    
    ssl_ctx_upstream = None
    if scheme == 'https':
        ssl_ctx_upstream = ssl.create_default_context()
        ssl_ctx_upstream.check_hostname = False
        ssl_ctx_upstream.verify_mode = ssl.CERT_NONE

    try:
        async with aiohttp.ClientSession(auto_decompress=False) as session:
            async with session.request(
                request.method, target_url, headers=req_headers, data=req_body,
                ssl=ssl_ctx_upstream, server_hostname=hostname if scheme == 'https' else None,
                allow_redirects=False
            ) as resp:
                body = await resp.read()
                out_headers = {}
                for k, v in resp.headers.items():
                    k_lower = k.lower()
                    if k_lower not in ('content-length', 'content-encoding', 'transfer-encoding', 'connection', 'server'):
                        out_headers[k] = v
                body, out_headers, status = await intercept_response_hook(body, out_headers, resp.status)
                return web.Response(body=body, status=status, headers=out_headers)
    except Exception as e:
        logger.error(f"Upstream error: {e}")
        return web.Response(text=f"Upstream Error: {e}", status=502)

def sni_callback(ssl_socket, server_name, initial_context):
    if not server_name: return
    try:
        ssl_socket.context = ca.get_context_for_host(server_name)
    except Exception as e:
        logger.error(f"SNI Error: {e}")

# --- Main ---
ca = CertificateAuthority()
DNS_SERVER = "8.8.8.8"

import argparse

def main():
    global DNS_SERVER
    parser = argparse.ArgumentParser(description="MITM Proxy & Host Spoofer")
    parser.add_argument("--reset", action="store_true", help="Remove CA and config, then exit")
    parser.add_argument("--dns", default="8.8.8.8", help="DNS Server to bypass hosts file")
    parser.add_argument("--script", help="Path to Python script with interception hooks")
    parser.add_argument("domains", nargs="*", help="Domains to intercept.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
    if args.reset:
        HostsManager.remove_all()
        if CA_CERT_FILE.exists(): CA_CERT_FILE.unlink()
        if CA_KEY_FILE.exists(): CA_KEY_FILE.unlink()
        sys.exit(0)

    DNS_SERVER = args.dns
    if args.script: load_script(args.script)

    if args.domains:
        print("\n[WARNING] Modifying /etc/hosts to intercept traffic.")
        print("[WARNING] If this tool crashes, run with --reset to clean up.\n")
        domains_to_add = []
        for d in args.domains:
            path = Path(d)
            if path.exists() and path.is_file():
                with open(path, 'r') as f: domains_to_add.extend([line.strip() for line in f if line.strip()])
            else: domains_to_add.extend(d.split(","))
        for d in set(domains_to_add):
            if d: HostsManager.add_domain(d.strip())

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    async def run_server():
        app = web.Application()
        app.router.add_route('*', '/{path_info:.*}', proxy_handler)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, '0.0.0.0', 80).start()
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(CA_CERT_FILE, CA_KEY_FILE)
        ssl_ctx.set_servername_callback(sni_callback)
        await web.TCPSite(runner, '0.0.0.0', 443, ssl_context=ssl_ctx).start()
        logger.info("Listening on :80 and :443")
        while True: await asyncio.sleep(3600)
    try:
        loop.run_until_complete(run_server())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
