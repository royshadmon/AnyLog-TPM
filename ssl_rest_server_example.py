#!/usr/bin/env python3

import os
import tempfile
import textwrap
import json
from http.server import HTTPServer, BaseHTTPRequestHandler


def configure_tpm_openssl(
    *,
    tpm_host="tpm",
    tpm_port=2321,
    tcti="swtpm",
    provider_module="/usr/lib/ossl-modules/tpm2.so",
    modules_dir="/usr/lib/ossl-modules",
):
    openssl_conf = f"""
    openssl_conf = openssl_init

    [openssl_init]
    providers = provider_sect

    [provider_sect]
    default = default_sect
    base = base_sect
    tpm2 = tpm2_sect

    [default_sect]
    activate = 1

    [base_sect]
    activate = 1

    [tpm2_sect]
    activate = 1
    module = {provider_module}
    """

    fd, conf_path = tempfile.mkstemp(prefix="openssl-tpm2-", suffix=".cnf")
    with os.fdopen(fd, "w") as f:
        f.write(textwrap.dedent(openssl_conf))

    os.environ["OPENSSL_CONF"] = conf_path
    os.environ["OPENSSL_MODULES"] = modules_dir
    os.environ["TPM2OPENSSL_TCTI"] = (
        f"{tcti}:host={tpm_host},port={tpm_port}"
    )

    return conf_path


# Must happen before importing ssl.
configure_tpm_openssl(
    tpm_host=os.environ.get("TPM_HOST", "tpm"),
    tpm_port=int(os.environ.get("TPM_PORT", "2321")),
    tcti=os.environ.get("TPM_TCTI", "swtpm"),
    provider_module=os.environ.get(
        "TPM2_PROVIDER_MODULE",
        "/usr/lib/ossl-modules/tpm2.so",
    ),
    modules_dir=os.environ.get(
        "OPENSSL_MODULES_DIR",
        "/usr/lib/ossl-modules",
    ),
)

import ssl  # noqa: E402


class RestHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code, payload):
        body = json.dumps(payload, indent=2).encode("utf-8")

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._send_json(200, {
                "message": "HTTPS REST server is running",
                "tls": True,
            })
        elif self.path == "/health":
            self._send_json(200, {
                "status": "ok",
            })
        else:
            self._send_json(404, {
                "error": "not found",
                "path": self.path,
            })

    def do_POST(self):
        if self.path != "/echo":
            self._send_json(404, {
                "error": "not found",
                "path": self.path,
            })
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length)

        try:
            data = json.loads(raw_body.decode("utf-8")) if raw_body else None
        except json.JSONDecodeError:
            self._send_json(400, {
                "error": "invalid JSON",
            })
            return

        self._send_json(200, {
            "received": data,
        })


def create_ssl_context(cert_file, key_file, ca_file=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("DEFAULT@SECLEVEL=1")

    # cert_file is your server certificate.
    # key_file can be a TPM/TSS2 key file or provider-loadable key reference.
    context.load_cert_chain(
        certfile=cert_file,
        keyfile=key_file,
    )

    if ca_file:
        context.load_verify_locations(cafile=ca_file)
        context.verify_mode = ssl.CERT_OPTIONAL
    else:
        context.verify_mode = ssl.CERT_NONE

    context.check_hostname = False

    return context


def run_server(
    host="0.0.0.0",
    port=8443,
    cert_file="server.crt",
    key_file="server-key.tss2",
    ca_file=None,
):
    server = HTTPServer((host, port), RestHandler)
    context = create_ssl_context(cert_file, key_file, ca_file)

    server.socket = context.wrap_socket(
        server.socket,
        server_side=True,
    )

    print(f"HTTPS REST server listening on https://{host}:{port}")
    print(f"Certificate: {cert_file}")
    print(f"Key reference: {key_file}")

    server.serve_forever()


if __name__ == "__main__":
    run_server(
        host=os.environ.get("SERVER_HOST", "0.0.0.0"),
        port=int(os.environ.get("SERVER_PORT", "8443")),
        cert_file=os.environ.get("SERVER_CERT", "server.crt"),
        key_file=os.environ.get("SERVER_KEY", "server-key.tss2"),
        ca_file=os.environ.get("CA_CERT"),
    )