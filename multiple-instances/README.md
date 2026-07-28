# Running Multiple Independent TPM Instances

Run any number of TPM instances (1, 5, 10, 100+) for different nodes, each with its own isolated state and API endpoint.

## Quick Reference

### Setup
```bash
# From project root:
cd multiple-instances
./setup-multiple-instances.sh 5

# Or from project root in one step:
./multiple-instances/setup-multiple-instances.sh 1

# Set folder prefix and parent path (writes .instances-prefix and .instances-path), then set up N instances:
./multiple-instances/setup-multiple-instances.sh --name tpm_shared_dir --path ../docs 3
./multiple-instances/setup-multiple-instances.sh --help

# Start all instances (run from project root):
docker-compose -f multiple-instances/docker-compose.instances.yaml up -d

# Run the TPM-backed HTTPS smoke test for node 1:
docker exec tpm2-api-node1 \
  python3 /opt/simple_tss2_tls_server.py \
  --host 0.0.0.0 \
  --force-generate

curl -k https://127.0.0.1:8443/
```

To run node containers in TPM HTTPS gateway mode, where the TPM-aware container
terminates HTTPS and forwards traffic to a plain HTTP app container, regenerate
the compose file with:

```bash
ENABLE_TPM_GATEWAY=1 \
TPM_GATEWAY_UPSTREAM_BASE_URL=http://app:8080 \
./multiple-instances/setup-multiple-instances.sh 1

docker compose -f multiple-instances/docker-compose.instances.yaml up -d
```

If you use Roy's shell helper, the same flow is:

```bash
build tpm run 1 http://app:8080
```

To publish node 1 on a different HTTPS host port:

```bash
build tpm run 1 http://app:8080 9443
```

To run multiple TPM gateways with different upstream AnyLog nodes and different
HTTPS host ports, pass comma-separated lists:

```bash
build tpm run 2 http://app1:8080,http://app2:8080 9443,9444
```

Validation rules:

- if `count` is `2`, the upstream list must contain exactly `2` values
- if an HTTPS host-port list is provided, it must also contain exactly `2` values

In gateway mode:

- `http://127.0.0.1:8001` is still the TPM REST API
- `https://127.0.0.1:8443` is the TPM-backed HTTPS gateway
- requests to `/health`, `/request-info`, and `/echo` are forwarded to the HTTP app

Each instance's SWTPM server/control ports are published to the host by default,
so host-side OpenSSL TPM provider tests can use the generated TSS2 keys. To
disable SWTPM port publishing:

```bash
export SWTPM_EXPOSE_PORTS=false
./multiple-instances/generate-docker-compose.sh 1
docker-compose -f multiple-instances/docker-compose.instances.yaml up -d
```

You can also persist this behavior by writing `false` into `multiple-instances/.instances-expose-ports`.

### Management
```bash
# All management commands (run from project root or multiple-instances/):
./multiple-instances/manage-instances.sh list
./multiple-instances/manage-instances.sh clear-tpm 1,2
./multiple-instances/manage-instances.sh clear-tpm all
./multiple-instances/manage-instances.sh clear-all 1
./multiple-instances/manage-instances.sh delete 3
./multiple-instances/manage-instances.sh reset      # Full wipe: containers + all dirs + generated files
./multiple-instances/manage-instances.sh stop all
./multiple-instances/manage-instances.sh start 1,2
./multiple-instances/manage-instances.sh restart all
```

### Custom parent directory for instance folders

By default, instance folders are created **under** `multiple-instances/` (unless you change the data root). To put them elsewhere on the host:

1. **Environment variable** (highest priority): set `SWTPM_SHARED_DATA_ROOT` to the **parent directory** that will contain the per-instance folders (`<prefix>1`, `<prefix>2`, …).  
   Use an **absolute** path for any location on the host. If you use a relative value, it is resolved from **`multiple-instances/`** (same as the file below).

2. **File** `multiple-instances/.instances-path`: one line with that parent path. Use an **absolute** path to place data outside the repo (recommended for arbitrary locations). If the line is not absolute, it is resolved from **`multiple-instances/`** (e.g. `../docs` for the project’s `docs/` folder). Lines starting with `#` are ignored.

### Custom folder name prefix (default `shared_dir_node`)

Each instance uses a directory named **`<prefix><instance_number>`** (no separator), e.g. `shared_dir_node1`, `mytpm1`. To change the prefix:

1. **Environment variable**: `SWTPM_SHARED_DIR_PREFIX` (must be a single path component — no `/`).

2. **File** `multiple-instances/.instances-prefix`: one non-comment line with that prefix. Default if unset is `shared_dir_node`.

3. **Setup CLI**: `setup-multiple-instances.sh --name PREFIX` writes `.instances-prefix`; `--path PATH` writes `.instances-path` (same rules as the files above). You can pass both in one command before the instance count.

After changing the prefix, run **`setup-multiple-instances.sh`** again and regenerate compose so volume paths match. Add a **`.gitignore`** rule for your pattern if needed (the repo only ignores the default `shared_dir_node*` under `multiple-instances/` and `docs/`).

Scripts (`setup-multiple-instances`, `generate-docker-compose`, `manage-instances`), AnyLog node mounts (`multiple-nodes/manage-anylog-nodes.sh`), and `test-multiple-instances.py` all use the same resolution for both data root and prefix.

## Directory Structure

All multiple-instance files live in `multiple-instances/`:

```
multiple-instances/
├── setup-multiple-instances.sh    # Create dirs and generate compose
├── generate-docker-compose.sh     # Generate docker-compose.instances.yaml
├── manage-instances.sh            # List, clear, start, stop instances
├── test-multiple-instances.py    # Test script
├── README.md                     # This file
├── docker-compose.instances.yaml # Generated (do not edit)
├── .num_instances                # Generated (instance count)
└── shared_dir_node1/             # Default prefix; see .instances-prefix
    ├── tpm_state/
    ├── key_backups/
    └── signing_keys_metadata.json
    shared_dir_node2/             # Or mytpm2/, etc.
    ...
```

## Quick Start

### 1. Setup
```bash
./multiple-instances/setup-multiple-instances.sh 5
```

Creates `<prefix>1` … `<prefix>5` under the configured data root (default prefix `shared_dir_node`, default root `multiple-instances/`) and generates the compose file.

### 2. Start
```bash
docker-compose -f multiple-instances/docker-compose.instances.yaml up -d
```

### 3. Verify
```bash
./multiple-instances/manage-instances.sh list
python multiple-instances/test-multiple-instances.py
```

## Port Allocation

| Instance | API Port | SWTPM Server | SWTPM Control |
|----------|----------|--------------|----------------|
| Node 1   | 8001     | 2321         | 2322           |
| Node 2   | 8002     | 2323         | 2324           |
| Node N   | 8000+N   | 2321+2(N-1)  | 2322+2(N-1)    |

The generated compose file also publishes HTTPS test ports as `8442+N`, so node 1
is available on host port `8443` after running `/opt/simple_tss2_tls_server.py`
inside the container.

By default, the API port, HTTPS test port, and SWTPM server/control ports are
published to the host. Set `SWTPM_EXPOSE_PORTS=false` or create
`multiple-instances/.instances-expose-ports` with `false` to hide the SWTPM
server/control ports.

## Changing Instance Count

```bash
# Scale up
./multiple-instances/setup-multiple-instances.sh 10

# Scale down
./multiple-instances/manage-instances.sh delete 8,9,10
./multiple-instances/generate-docker-compose.sh 7
```

## Manual Docker Commands

```bash
COMPOSE_CMD="docker-compose -f multiple-instances/docker-compose.instances.yaml"
$COMPOSE_CMD up -d tpm2-api-node1
$COMPOSE_CMD stop tpm2-api-node1
$COMPOSE_CMD logs -f tpm2-api-node1
```

For AnyLog nodes, see **[multiple-nodes/README.md](../multiple-nodes/README.md)**.

## Notes

- After **clear-tpm** or **clear-all**, the containers are removed so that the next **start** or **restart** creates fresh containers. This ensures swtpm reinitializes and repopulates `tpm_state/` with new TPM state files.

## Troubleshooting

- **Port conflicts**: `netstat -tuln | grep -E '800[0-9]|232[0-9]'`
- **Permissions**: `chmod -R 777` on your instance directories (e.g. `multiple-instances/shared_dir_node*/` with defaults)
- **Logs**: `$COMPOSE_CMD logs tpm2-api-node1`
