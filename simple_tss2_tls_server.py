#!/usr/bin/env python3
"""
Minimal HTTPS server for testing an OpenSSL TPM/TSS2 private key.

By default, this creates a TPM-backed TSS2 key reference and matching self-signed
certificate if either file is missing, then starts HTTPS with them.
"""

import argparse
import os
import base64
import json
import subprocess
import tempfile
import textwrap
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class RestCallError(Exception):
    def __init__(self, url, status_code, detail):
        super().__init__(f"REST call failed: {url}: HTTP {status_code}: {detail}")
        self.url = url
        self.status_code = status_code
        self.detail = detail


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} - {fmt % args}")


def rest_post(api_base, path, payload):
    """Call one TPM REST endpoint and return its JSON response."""
    url = f"{api_base.rstrip('/')}{path}"
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=120) as response:
            response_body = response.read().decode("utf-8")
    except HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        try:
            detail = json.loads(error_body)
        except ValueError:
            detail = error_body
        raise RestCallError(url, e.code, detail) from e
    except URLError as e:
        raise SystemExit(f"REST call failed: {url}: {e}") from e

    try:
        return json.loads(response_body) if response_body else {}
    except ValueError:
        return {"raw": response_body}


def download_generated_file(args, remote_path, local_path):
    """Copy a generated file from the TPM REST API working directory."""
    try:
        result = rest_post(args.api_base, "/tpm2/read-file", {
            "file_path": remote_path,
        })
    except RestCallError as e:
        if e.status_code == 404:
            raise SystemExit(
                f"{e}\n\n"
                "The TPM REST API needs the /tpm2/read-file endpoint so the local "
                "HTTPS server can download files generated inside Docker. Rebuild "
                "and restart the Docker image from the updated code."
            ) from e
        raise SystemExit(str(e)) from e
    try:
        content = base64.b64decode(result["content_base64"])
    except KeyError as e:
        raise SystemExit(f"REST API did not return file content for {remote_path}: {result}") from e

    with open(local_path, "wb") as f:
        f.write(content)
    print(f"Downloaded {remote_path} -> {local_path}")


def ensure_tls_material(args):
    """Step 1: generate/download the TSS2 key, public key, and certificate."""
    key_exists = os.path.exists(args.key)
    cert_exists = os.path.exists(args.cert)

    if args.no_generate:
        return

    if args.force_generate or not key_exists:
        print(f"Creating TPM-backed TSS2 key through REST API: {args.key}")
        rest_post(args.api_base, "/tpm2/create-openssl-tls-key", {
            "private_key_file": args.key,
            "public_key_file": args.public_key,
            "key_type": args.key_type,
            "key_size": args.key_size,
            "password": args.password,
        })
        download_generated_file(args, args.key, args.key)
        download_generated_file(args, args.public_key, args.public_key)
        cert_exists = False
    else:
        print(f"Using existing TSS2 key: {args.key}")

    if args.force_generate or not cert_exists:
        print(f"Creating self-signed certificate through REST API: {args.cert}")
        try:
            rest_post(args.api_base, "/tpm2/create-openssl-tls-certificate", {
                "private_key_file": args.key,
                "cert_file": args.cert,
                "subject": args.subject,
                "days": args.days,
                "password": args.password,
            })
            download_generated_file(args, args.cert, args.cert)
        except RestCallError as e:
            if e.status_code == 404:
                raise SystemExit(
                    f"{e}\n\n"
                    "The TPM REST API is running, but it does not expose "
                    "/tpm2/create-openssl-tls-certificate. Restart the REST API "
                    "from the updated tpm2_rest_api.py, then rerun this server."
                ) from e
            raise SystemExit(str(e)) from e
    else:
        print(f"Using existing certificate: {args.cert}")


def candidate_openssl_modules_dirs():
    candidates = []

    env_path = os.environ.get("OPENSSL_MODULES")
    if env_path:
        candidates.append(env_path)

    try:
        result = subprocess.run(
            ["openssl", "version", "-a"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "MODULESDIR:" in line:
                    modules_dir = line.split("MODULESDIR:", 1)[1].strip().strip('"')
                    if modules_dir:
                        candidates.append(modules_dir)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        pass

    candidates.extend([
        "/opt/homebrew/lib/ossl-modules",
        "/usr/local/lib/ossl-modules",
        "/usr/lib/ossl-modules",
        "/usr/lib64/ossl-modules",
    ])
    return candidates


def resolve_openssl_modules_path(modules_path):
    if modules_path:
        if os.path.isdir(modules_path):
            return modules_path
        raise SystemExit(f"OpenSSL modules directory not found: {modules_path}")

    for candidate in candidate_openssl_modules_dirs():
        if candidate and os.path.isdir(candidate):
            return candidate

    searched = ", ".join(candidate_openssl_modules_dirs())
    raise SystemExit(
        "Could not locate an OpenSSL provider modules directory. "
        f"Set OPENSSL_MODULES or pass --openssl-modules. Searched: {searched}"
    )


def configure_openssl_provider(args):
    """Prepare OpenSSL provider environment before Python loads the TLS key."""
    modules_path = resolve_openssl_modules_path(args.openssl_modules)
    provider_module = os.path.join(modules_path, "tpm2.so")
    if not os.path.exists(provider_module):
        provider_module = "tpm2"

    openssl_conf = f"""
    openssl_conf = openssl_init

    [openssl_init]
    providers = provider_sect

    [provider_sect]
    default = default_sect
    tpm2 = tpm2_sect

    [default_sect]
    activate = 1

    [tpm2_sect]
    activate = 1
    module = {provider_module}
    """

    fd, conf_path = tempfile.mkstemp(prefix="openssl-tpm2-", suffix=".cnf")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(openssl_conf))

    os.environ["OPENSSL_CONF"] = conf_path
    os.environ["OPENSSL_MODULES"] = modules_path
    os.environ["TPM2OPENSSL_TCTI"] = args.tcti

    return conf_path


def create_ssl_context(args):
    """Create the HTTPS server TLS context using the TPM-backed key."""
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(
            certfile=args.cert,
            keyfile=args.key,
            password=args.password,
        )
    except ssl.SSLError as e:
        print(
            f"Python ssl could not load {args.cert} with {args.key} from "
            f"OPENSSL_CONF alone: {e}"
        )
        print("Retrying with programmatic OpenSSL provider initialization...")

        try:
            from tpm2_api import TPM2API

            tpm = TPM2API.for_ssl(tcti_name=args.tcti)
            return tpm.create_ssl_context(
                certfile=args.cert,
                keyfile=args.key,
                password=args.password,
                modules_path=args.openssl_modules,
                purpose="server",
            )
        except Exception as fallback_error:
            raise SystemExit(
                f"Python ssl could not load {args.cert} with {args.key}: {e}\n"
                f"Provider bootstrap fallback also failed: {fallback_error}\n\n"
                "The files were downloaded, but this Python/OpenSSL runtime could "
                "not load the TPM provider-backed TSS2 key for TLS."
            ) from fallback_error
    return context


def verify_openssl_can_load_key(args):
    """Step 2: confirm OpenSSL can load the downloaded TSS2 key."""
    env = os.environ.copy()
    cmd = [
        "openssl",
        "pkey",
        "-provider",
        "tpm2",
        "-provider",
        "default",
        "-in",
        args.key,
        "-pubout",
        "-out",
        os.devnull,
    ]
    if args.password:
        cmd.extend(["-passin", f"pass:{args.password}"])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    if result.returncode != 0:
        raise SystemExit(
            "OpenSSL could not load the downloaded TSS2 key before Python tried "
            f"to start TLS.\n\nCommand: {' '.join(cmd)}\n"
            f"TCTI: {args.tcti}\n"
            f"stderr:\n{result.stderr.strip() or result.stdout.strip()}\n\n"
            "If the TPM REST API is running in Docker, rebuild/restart it with "
            "the swtpm port published too: -p 8001:8000 -p 2321:2321. The local "
            "HTTPS server must reach the same TPM that created server-key.tss2."
        )


def main():
    parser = argparse.ArgumentParser(
        description="Generate a TPM/TSS2 key if needed, then run a tiny HTTPS server."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", default="server-cert.pem")
    parser.add_argument("--key", default="server-key.tss2")
    parser.add_argument("--public-key", default="server-key.pub.pem")
    parser.add_argument("--password", default=None)
    parser.add_argument(
        "--api-base",
        default=os.environ.get("TPM2_TLS_API_BASE", "http://127.0.0.1:8001"),
    )
    parser.add_argument(
        "--tcti",
        default=os.environ.get(
            "TPM2OPENSSL_TCTI",
            os.environ.get(
                "TPM2_TCTI",
                os.environ.get("TSS2_TCTI", "swtpm:host=127.0.0.1,port=2321"),
            ),
        ),
    )
    parser.add_argument("--openssl-modules", default=None)
    parser.add_argument("--key-type", choices=["rsa", "ecc"], default="rsa")
    parser.add_argument("--key-size", type=int, default=2048)
    parser.add_argument("--subject", default="/CN=localhost")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument(
        "--force-generate",
        action="store_true",
        help="Regenerate the TSS2 key and certificate even if files already exist.",
    )
    parser.add_argument(
        "--no-generate",
        action="store_true",
        help="Skip key/certificate generation and only load the existing files.",
    )
    args = parser.parse_args()

    # Step 1: ask the TPM REST API to create TLS material and download it locally.
    conf_path = configure_openssl_provider(args)
    ensure_tls_material(args)

    # Step 2: verify OpenSSL can load the downloaded TSS2 private key reference.
    verify_openssl_can_load_key(args)
    context = create_ssl_context(args)

    # Step 3: start the HTTPS server with the TPM-backed TLS key.
    server = HTTPServer((args.host, args.port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"Listening on https://{args.host}:{args.port}")
    print(f"Certificate: {args.cert}")
    print(f"TSS2 key: {args.key}")
    print(f"TPM REST API: {args.api_base}")
    print(f"TCTI: {args.tcti}")
    print(f"OpenSSL config: {conf_path}")
    server.serve_forever()


if __name__ == "__main__":
    main()
