# TPM HTTPS Demo Environment

This demo has two valid ways to run:

1. Reuse an existing TPM REST API container.
2. Start a fresh standalone demo TPM container.

There is now a third, and preferred, deployment pattern for application use:

3. Run a plain HTTP app container behind a TPM-aware HTTPS gateway container.

The important thing to keep straight is that the HTTPS demo does not talk
directly to the TPM device from your macOS shell. It talks to a Docker
container that is already running the TPM REST API and has access to the TPM
state plus the shared output directory.

## The Moving Parts

- Host TPM API URL:
  `http://127.0.0.1:8001`
- TPM API URL from inside the TPM container:
  `http://127.0.0.1:8000`
- Host shared directory:
  `/Users/roy/Github-Repos/AnyLog-TPM/multiple-instances/tpm_shared_dir1`
- Container shared directory:
  `/opt/shared`

Files created for the demo:

- TPM-backed key reference:
  `/opt/shared/server-key.tss2`
- Public key:
  `/opt/shared/server-key.pub.pem`
- Certificate:
  `/opt/shared/server.crt`

`server-key.tss2` is not a normal PEM private key. It is a TSS2 reference file
that tells OpenSSL how to use the TPM-backed key.

## Recommended Deployment Shape

For real application use, the clean pattern is:

```text
client -> HTTPS TPM gateway container -> HTTP app container
```

In that shape:

- the app container does not talk to the TPM
- the gateway container owns TLS termination
- the gateway container uses the TPM-backed key locally
- the gateway container forwards traffic to the app over the Docker network

This works with both `swtpm` and hardware TPMs. The app stays the same; only
the TPM-aware container configuration changes.

## Gateway Demo

Start the two-container demo:

```bash
docker compose -f docker-compose.tpm-gateway-demo.yaml up --build
```

That compose file starts:

- `app`: a plain HTTP demo app on internal port `8080`
- `tpm-gateway`: a TPM-aware container that runs the REST API and the HTTPS
  gateway on the same container

Test through the gateway:

```bash
curl -k https://127.0.0.1:8443/
curl -k https://127.0.0.1:8443/health
curl -k https://127.0.0.1:8443/gateway-health
curl -k https://127.0.0.1:8443/request-info
curl -k -X POST https://127.0.0.1:8443/echo \
  -H "Content-Type: application/json" \
  -d '{"hello":"world"}'
```

Notes:

- `/gateway-health` is the HTTPS gateway’s own local health endpoint
- `/health` and `/echo` are proxied to the HTTP app container
- `/request-info` shows what the HTTP app learns from the HTTPS gateway through
  `X-Forwarded-*` headers
- the TLS private-key operations still happen inside the TPM-aware gateway container

## Normal Workflow

If you already have a TPM API container running on host port `8001`, use:

```bash
./scripts/run_tpm_https_server.sh
```

Or point explicitly at a host and port:

```bash
./scripts/run_tpm_https_server.sh --tpm-ip 192.168.0.138 --port 8001
```

That script will:

- find a matching TPM API container
- confirm it mounts the expected shared directory
- wait for `http://127.0.0.1:8001/health`
- reuse `server-key.tss2` and `server.crt` if they exist
- generate missing TLS material if needed
- start the HTTPS server

Test it with:

```bash
curl -k https://127.0.0.1:8443/
curl -k https://127.0.0.1:8443/health
```

## Strict Mode

If you want the server to refuse startup unless the key and cert already exist:

```bash
./scripts/run_tpm_https_server.sh --no-generate
```

That is useful when you want to verify reuse behavior instead of generation.

## Standalone Demo Mode

If no TPM API container is running and you intentionally want this demo to start
its own TPM stack:

```bash
START_TPM_CONTAINER=1 ./scripts/run_tpm_https_server.sh
```

Or run the setup helper directly:

```bash
./scripts/setup_tpm_https_example.sh
```

That path creates a container named `tpm2-https-example`.

## Hardware TPM Variant

The same gateway pattern can run against a hardware TPM instead of `swtpm`.

At a high level:

- mount the TPM device into the gateway container, usually `/dev/tpmrm0`
- set `USE_SWTPM=0`
- set `TSS2_TCTI=device:/dev/tpmrm0`
- keep the app container unchanged

The key architectural point is that the gateway container remains TPM-aware,
while the app container remains TPM-agnostic.

## Why The "No TPM API Container Found" Error Happens

This error means the script could not map your host API URL and shared directory
back to a Docker container it recognized:

```text
TPM API readiness failed: no TPM API container was found and START_TPM_CONTAINER is not set to 1
```

Usually one of these is true:

- the TPM API container is not running
- the container name is different from what the script expects
- the host API URL is wrong
- the container is mounted to a different shared directory than the script expects

In your case, the conceptual gap is:

- `http://127.0.0.1:8001` is a host-side port mapping
- the script still needs to identify which Docker container owns that mapping
- if its container-name detection is too narrow, it can say "no container found"
  even though the API URL itself is real

## Quick Checks

See which container owns the API port:

```bash
docker ps --format 'table {{.Names}}\t{{.Ports}}'
```

Check the API health:

```bash
curl http://127.0.0.1:8001/health
```

Confirm the `/opt/shared` mount:

```bash
docker inspect -f '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}' tpm2-https-example
```

Inspect logs:

```bash
docker logs --tail 100 tpm2-https-example
```

## Common Failure Modes

- `no TPM API container was found`:
  The script could not identify the container behind the host API port and shared
  directory.
- `TPM2 API not available`:
  The container is up, but the TPM REST API inside it has not connected to the
  TPM backend yet.
- `DA lockout mode`:
  The TPM has temporarily blocked signing operations after too many failed auth
  attempts, so certificate creation fails.
