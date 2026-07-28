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
import shlex
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
    upstream_base = None

    def _proxy_request(self):
        upstream_base = getattr(self, "upstream_base", None)
        if not upstream_base:
            return False

        upstream_url = f"{upstream_base.rstrip('/')}{self.path}"
        content_length = int(self.headers.get("Content-Length", "0"))
        request_body = self.rfile.read(content_length) if content_length else None

        forwarded_headers = {}
        for header, value in self.headers.items():
            normalized = header.lower()
            if normalized in {"host", "connection", "content-length"}:
                continue
            forwarded_headers[header] = value

        # Preserve the original HTTPS-facing request details so the upstream app
        # can reconstruct client context even though it only sees plain HTTP.
        forwarded_headers["X-Forwarded-Proto"] = "https"
        forwarded_headers["X-Forwarded-Host"] = self.headers.get("Host", "")
        forwarded_headers["X-Forwarded-Port"] = str(self.server.server_port)
        forwarded_headers["X-Forwarded-For"] = self.client_address[0]
        forwarded_headers["X-Forwarded-Uri"] = self.path

        request = Request(
            upstream_url,
            data=request_body,
            headers=forwarded_headers,
            method=self.command,
        )

        try:
            with urlopen(request, timeout=30) as response:
                body = response.read()
                status = response.status
                response_headers = response.headers.items()
        except HTTPError as e:
            body = e.read()
            status = e.code
            response_headers = e.headers.items()
        except URLError as e:
            error_body = json.dumps({
                "error": "upstream unavailable",
                "upstream": upstream_url,
                "detail": str(e),
            }).encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(error_body)))
            self.end_headers()
            self.wfile.write(error_body)
            return True

        self.send_response(status)
        sent_length = False
        for header, value in response_headers:
            normalized = header.lower()
            if normalized in {"connection", "transfer-encoding", "server", "date"}:
                continue
            if normalized == "content-length":
                sent_length = True
            self.send_header(header, value)
        if not sent_length:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return True

    def do_GET(self):
        if self.path == "/gateway-health":
            status = 200
            content_type = "application/json"
            body = b'{"status": "ok", "gateway": true}\n'
        elif self._proxy_request():
            return
        else:
            if self.path == "/":
                status = 200
                content_type = "text/plain"
                body = b"TPM-backed HTTPS server is running\n"
            elif self.path == "/health":
                status = 200
                content_type = "application/json"
                body = b'{"status": "ok"}\n'
            else:
                status = 404
                content_type = "application/json"
                body = json.dumps({"error": "not found", "path": self.path}).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self._proxy_request():
            return

        body = json.dumps({
            "error": "not found",
            "path": self.path,
        }).encode("utf-8")
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        self.do_POST()

    def do_PATCH(self):
        self.do_POST()

    def do_DELETE(self):
        self.do_POST()

    def do_HEAD(self):
        if self._proxy_request():
            return

        if self.path == "/":
            status = 200
            content_type = "text/plain"
            body = b"TPM-backed HTTPS server is running\n"
        elif self.path == "/health":
            status = 200
            content_type = "application/json"
            body = b'{"status": "ok"}\n'
        else:
            status = 404
            content_type = "application/json"
            body = json.dumps({"error": "not found", "path": self.path}).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} - {fmt % args}")


def rest_post(api_base, path, payload, timeout=120):
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
        with urlopen(request, timeout=timeout) as response:
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
        }, timeout=args.api_timeout)
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

    local_dir = os.path.dirname(os.path.abspath(local_path))
    if local_dir:
        os.makedirs(local_dir, exist_ok=True)

    with open(local_path, "wb") as f:
        f.write(content)
    print(f"Downloaded {remote_path} -> {local_path}")


def default_remote_path(local_path):
    """Return a Docker/API working-directory path for a local output path."""
    return os.path.basename(local_path)


def remote_paths(args):
    return {
        "key": args.remote_key or default_remote_path(args.key),
        "public_key": args.remote_public_key or default_remote_path(args.public_key),
        "cert": args.remote_cert or default_remote_path(args.cert),
    }


def container_path(remote_path):
    if os.path.isabs(remote_path):
        return remote_path
    return os.path.join("/opt/shared", remote_path)


def docker_https_command_hint(args):
    paths = remote_paths(args)
    cmd = [
        "docker",
        "exec",
        "-it",
        args.docker_container,
        "python3",
        "/opt/simple_tss2_tls_server.py",
        "--no-generate",
        "--host",
        "0.0.0.0",
        "--port",
        str(args.port),
        "--key",
        container_path(paths["key"]),
        "--cert",
        container_path(paths["cert"]),
        "--public-key",
        container_path(paths["public_key"]),
    ]
    return " ".join(shlex.quote(part) for part in cmd)


def write_rest_provider_key_reference(args):
    paths = remote_paths(args)
    reference_path = args.rest_key or args.key
    reference = {
        "api_base": args.api_base.rstrip("/"),
        "private_key_file": paths["key"],
        "public_key_file": paths["public_key"],
        "certificate_file": paths["cert"],
        "sign_endpoint": "/tpm2/openssl-provider/sign",
        "key_info_endpoint": "/tpm2/openssl-provider/key-info",
        "password": args.password,
    }
    local_dir = os.path.dirname(os.path.abspath(reference_path))
    if local_dir:
        os.makedirs(local_dir, exist_ok=True)

    with open(reference_path, "w", encoding="utf-8") as f:
        f.write("-----BEGIN REST TPM2 PRIVATE KEY-----\n")
        f.write(base64.b64encode(json.dumps(reference, sort_keys=True).encode("utf-8")).decode("ascii"))
        f.write("\n-----END REST TPM2 PRIVATE KEY-----\n")

    print(f"Wrote REST TPM2 key reference: {reference_path}")
    return reference_path


def ensure_tls_material(args):
    """Step 1: generate/download the TSS2 key, public key, and certificate."""
    key_exists = os.path.exists(args.key)
    cert_exists = os.path.exists(args.cert)
    paths = remote_paths(args)
    remote_key = paths["key"]
    remote_public_key = paths["public_key"]
    remote_cert = paths["cert"]

    if args.no_generate:
        return

    if args.force_generate or not key_exists:
        print(
            f"Creating TPM-backed TSS2 key through REST API: "
            f"{remote_key} -> {args.key}"
        )
        try:
            rest_post(args.api_base, "/tpm2/create-openssl-tls-key", {
                "private_key_file": remote_key,
                "public_key_file": remote_public_key,
                "key_type": args.key_type,
                "key_size": args.key_size,
                "password": args.password,
            }, timeout=args.api_timeout)
        except RestCallError as e:
            raise SystemExit(
                f"{e}\n\n"
                "The REST API runs inside Docker, so generation paths must be "
                "visible inside that container. This script now sends remote "
                "working-directory filenames by default; pass --remote-key and "
                "--remote-public-key only if you need different container paths."
            ) from e

        download_generated_file(args, remote_key, args.key)
        download_generated_file(args, remote_public_key, args.public_key)
        cert_exists = False
    else:
        print(f"Using existing TSS2 key: {args.key}")

    if args.force_generate or args.force_cert_generate or not cert_exists:
        print(
            f"Creating self-signed certificate through REST API: "
            f"{remote_cert} -> {args.cert}"
        )
        try:
            rest_post(args.api_base, "/tpm2/create-openssl-tls-certificate", {
                "private_key_file": remote_key,
                "cert_file": remote_cert,
                "subject": args.subject,
                "days": args.days,
                "password": args.password,
            }, timeout=args.api_timeout)
            download_generated_file(args, remote_cert, args.cert)
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


def validate_tls_material_files(args):
    """Fail early for common file-shape mistakes before OpenSSL/provider setup."""
    key_path = args.rest_key or args.key
    missing = [path for path in [key_path, args.cert] if not os.path.exists(path)]
    if missing:
        raise SystemExit(
            "Missing TLS material:\n"
            + "\n".join(f"  - {path}" for path in missing)
            + "\n\nRun without --no-generate, or pass key/cert paths that exist."
        )

    with open(key_path, "r", encoding="utf-8", errors="replace") as f:
        key_prefix = f.read(256)
    if args.key_provider == "rest":
        if "BEGIN REST TPM2 PRIVATE KEY" not in key_prefix:
            raise SystemExit(
                f"{key_path} is not a REST TPM2 key reference file. "
                "Expected BEGIN REST TPM2 PRIVATE KEY."
            )
    elif "BEGIN TSS2 PRIVATE KEY" not in key_prefix:
        raise SystemExit(
            f"{key_path} is not a TSS2 private key reference file. "
            "Expected a PEM block beginning with BEGIN TSS2 PRIVATE KEY."
        )

    with open(args.cert, "r", encoding="utf-8", errors="replace") as f:
        cert_prefix = f.read(256)
    if "BEGIN CERTIFICATE REQUEST" in cert_prefix:
        raise SystemExit(
            f"{args.cert} is a CSR, not a certificate. HTTPS needs an X.509 "
            "certificate beginning with BEGIN CERTIFICATE.\n\n"
            "Generate one with --force-cert-generate, or pass --cert pointing "
            "at a real self-signed/server certificate for this key."
        )
    if "BEGIN CERTIFICATE" not in cert_prefix:
        raise SystemExit(
            f"{args.cert} is not a PEM X.509 certificate. Expected a PEM block "
            "beginning with BEGIN CERTIFICATE."
        )


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
    if args.key_provider == "rest":
        provider_name = args.rest_provider_name
        provider_module = args.rest_provider_module
        if provider_module is None:
            provider_module = os.path.join(modules_path, f"{provider_name}.so")
            if not os.path.exists(provider_module):
                provider_module = os.path.join(modules_path, f"{provider_name}.dylib")
            if not os.path.exists(provider_module):
                provider_module = provider_name
        provider_entry = f"{provider_name} = rest_tpm2_sect"
        provider_section = f"""
        [rest_tpm2_sect]
        activate = 1
        module = {provider_module}
        """
    else:
        provider_name = "tpm2"
        provider_module = os.path.join(modules_path, "tpm2.so")
        if not os.path.exists(provider_module):
            provider_module = "tpm2"
        provider_entry = f"{provider_name} = tpm2_sect"
        provider_section = f"""
        [tpm2_sect]
        activate = 1
        module = {provider_module}
        """

    openssl_conf = f"""
    openssl_conf = openssl_init

    [openssl_init]
    providers = provider_sect

    [provider_sect]
    default = default_sect
    {provider_entry}

    [default_sect]
    activate = 1

    {textwrap.dedent(provider_section).strip()}
    """

    fd, conf_path = tempfile.mkstemp(prefix="openssl-tpm2-", suffix=".cnf")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(openssl_conf))

    os.environ["OPENSSL_CONF"] = conf_path
    os.environ["OPENSSL_MODULES"] = modules_path
    os.environ["TPM2OPENSSL_TCTI"] = args.tcti
    os.environ["TSS2_TCTI"] = args.tcti
    os.environ["TPM2TOOLS_TCTI"] = args.tcti

    return conf_path


def create_ssl_context(args):
    """Create the HTTPS server TLS context using the TPM-backed key."""
    import ssl

    keyfile = args.rest_key or args.key
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(
            certfile=args.cert,
            keyfile=keyfile,
            password=args.password,
        )
    except ssl.SSLError as e:
        if args.key_provider == "rest":
            raise SystemExit(
                f"Python ssl could not load {args.cert} with REST key reference "
                f"{keyfile}: {e}\n\n"
                "REST signing endpoints are available on the TPM API, but local "
                "Python ssl still needs an OpenSSL provider module that can read "
                "BEGIN REST TPM2 PRIVATE KEY files and call those endpoints during "
                "the TLS handshake.\n\n"
                f"Expected provider name: {args.rest_provider_name}\n"
                f"Expected provider module: {args.rest_provider_module or args.rest_provider_name}\n"
                "Provider REST endpoints:\n"
                f"  {args.api_base.rstrip('/')}/tpm2/openssl-provider/key-info\n"
                f"  {args.api_base.rstrip('/')}/tpm2/openssl-provider/sign"
            ) from e

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
                keyfile=keyfile,
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
    if args.key_provider == "rest":
        return

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
            "The local HTTPS server must reach the same TPM that created the "
            "TSS2 key. If the TPM REST API is running in Docker, confirm the "
            "swtpm port is published and that the host OpenSSL/tpm2-openssl "
            "build can initialize this TCTI. If host OpenSSL cannot use the "
            "provider, run the HTTPS smoke test inside the TPM API container.\n\n"
            f"Container command:\n{docker_https_command_hint(args)}"
        )


def check_tpm_key_available(args):
    """Ask the TPM API to verify that the generated artifacts are TPM-backed."""
    if args.key_provider != "tss2":
        return

    paths = remote_paths(args)
    try:
        result = rest_post(args.api_base, "/tpm2/check-key-available", {
            "private_key_file": paths["key"],
            "public_key_file": paths["public_key"],
            "certificate_file": paths["cert"],
            "password": args.password,
        }, timeout=args.api_timeout)
    except RestCallError as e:
        print(f"TPM-backed verification check skipped: {e}")
        return

    if not result.get("success"):
        print(f"TPM-backed verification check failed: {result}")
        return

    print(f"TPM-backed key verification: stored_in_tpm={result.get('stored_in_tpm')}")
    if result.get("private_key_file"):
        print(f"Verified key reference in TPM API workspace: {result['private_key_file']}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a TPM/TSS2 key if needed, then run a tiny HTTPS server."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--cert", default="server-cert.pem")
    parser.add_argument("--key", default="server-key.tss2")
    parser.add_argument("--public-key", default="server-key.pub.pem")
    parser.add_argument("--password", default=None)
    parser.add_argument(
        "--upstream-base",
        default=os.environ.get("UPSTREAM_BASE_URL"),
        help="Optional HTTP upstream base URL to proxy requests to, e.g. http://app:8080",
    )
    parser.add_argument(
        "--key-provider",
        choices=["tss2", "rest"],
        default="tss2",
        help="Use a local TSS2 key directly, or write/use a REST TPM2 provider key reference.",
    )
    parser.add_argument(
        "--rest-key",
        default=None,
        help="Local REST TPM2 provider key reference file. Defaults to --key in rest mode.",
    )
    parser.add_argument("--rest-provider-name", default="tpm2-rest")
    parser.add_argument("--rest-provider-module", default=None)
    parser.add_argument(
        "--remote-key",
        default=None,
        help="Container/API path for generated key material; defaults to basename of --key.",
    )
    parser.add_argument(
        "--remote-public-key",
        default=None,
        help="Container/API path for generated public key; defaults to basename of --public-key.",
    )
    parser.add_argument(
        "--remote-cert",
        default=None,
        help="Container/API path for generated certificate; defaults to basename of --cert.",
    )
    parser.add_argument(
        "--api-base",
        default=os.environ.get("TPM2_TLS_API_BASE", "http://127.0.0.1:8001"),
    )
    parser.add_argument("--api-timeout", type=int, default=30)
    parser.add_argument("--docker-container", default="tpm2-api-node1")
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
        "--force-cert-generate",
        action="store_true",
        help="Regenerate only the self-signed certificate even if --cert exists.",
    )
    parser.add_argument(
        "--no-generate",
        action="store_true",
        help="Skip key/certificate generation and only load the existing files.",
    )
    parser.add_argument(
        "--setup-only",
        action="store_true",
        help="Generate and validate key/certificate files, then exit without starting HTTPS.",
    )
    args = parser.parse_args()

    # Step 1: ask the TPM REST API to create TLS material and download it locally.
    conf_path = configure_openssl_provider(args)
    ensure_tls_material(args)
    if args.key_provider == "rest" and (
        not args.no_generate or not os.path.exists(args.rest_key or args.key)
    ):
        write_rest_provider_key_reference(args)
    validate_tls_material_files(args)
    check_tpm_key_available(args)

    if args.setup_only:
        print("Setup complete. Start the server by running this script without --setup-only.")
        return

    # Step 2: verify OpenSSL can load the downloaded TSS2 private key reference.
    verify_openssl_can_load_key(args)
    context = create_ssl_context(args)

    # Step 3: start the HTTPS server with the TPM-backed TLS key.
    Handler.upstream_base = args.upstream_base
    server = HTTPServer((args.host, args.port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"Listening on https://{args.host}:{args.port}")
    print(f"Certificate: {args.cert}")
    print(f"Key provider: {args.key_provider}")
    print(f"Key: {args.rest_key or args.key}")
    print(f"TPM REST API: {args.api_base}")
    print(f"Upstream app: {args.upstream_base or 'none'}")
    print(f"TCTI: {args.tcti}")
    print(f"OpenSSL config: {conf_path}")
    server.serve_forever()


if __name__ == "__main__":
    main()
