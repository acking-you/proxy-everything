---
name: azure-student-proxy-server
description: Use when provisioning Azure for Students VMs with Azure CLI for this proxy-everything project, deploying proxy-server, opening ICMP/TCP 1081, and registering nodes or groups in lb7666.top.
---

# Azure Student Proxy Server

## Core Principle

Provision each Azure student account as an independent proxy node using the cheapest/free student VM shape available, deploy `proxy-server` with the repository default key, then register the node in `lb7666.top` under the `azure` group.

Do not generate a random `SECRET_KEY` for these nodes. They must use:

```text
my-secret-key123my-secret-key123
```

## Account Login

1. Start device-code login:

```bash
az login --use-device-code
```

2. Have the user complete `https://login.microsoft.com/device`.
3. Accept the default subscription unless the user chooses another.
4. Verify the active account before creating resources:

```bash
az account show --query "{subscription:id,name:name,user:user.name,tenant:tenantDisplayName,isDefault:isDefault,state:state}" --output json
az group list --output table
```

Never continue if the active `user` or subscription is not the newly intended student account.

## Region Selection

For a user located in Guangzhou, prefer regions in this order, subject to the subscription policy and SKU availability:

1. `eastasia`, `southeastasia`, `japaneast`, `koreacentral`
2. If US-only: `westus2`, `westus3`, `westus`, `southcentralus`, `centralus`, `northcentralus`, `eastus2`, `eastus`
3. Use `canadacentral` only if better choices are blocked

Read the real allowed-region policy first:

```bash
SUB="$(az account show --query id -o tsv)"
az policy assignment list \
  --query "[?contains(displayName, 'Allowed resource deployment regions') || name=='sys.regionrestriction'].{name:name,displayName:displayName,parameters:parameters}" \
  --output json
```

If Azure returns `RequestDisallowedByAzure`, the region is blocked by policy. Choose the best remaining allowed region rather than retrying the same location.

## SKU Selection

Prefer student-free shapes in this order:

1. `Standard_B2ats_v2` (x86_64, preferred)
2. `Standard_B1s` (x86_64, smaller fallback)
3. `Standard_B2pts_v2` (ARM64 fallback; requires ARM64 binary/build)

Azure CLI preflight/create errors are authoritative. If a SKU returns `SkuNotAvailable` or policy restrictions, try the next preferred region/SKU combination.

## VM Creation

Use a deterministic resource-group and VM name based on the chosen region. Example for `westus2`:

```bash
RG=proxy-us-wus2-rg
VM=proxy-us-wus2-vm
REGION=westus2
SIZE=Standard_B2ats_v2

az group create --name "$RG" --location "$REGION" --output json

az vm create \
  --resource-group "$RG" \
  --name "$VM" \
  --location "$REGION" \
  --image Ubuntu2204 \
  --size "$SIZE" \
  --admin-username azureuser \
  --generate-ssh-keys \
  --public-ip-sku Standard \
  --nsg-rule SSH \
  --storage-sku Standard_LRS \
  --os-disk-size-gb 30 \
  --output json
```

Fetch the assigned IP:

```bash
IP="$(az vm show --resource-group "$RG" --name "$VM" --show-details --query publicIps -o tsv)"
az vm show --resource-group "$RG" --name "$VM" --show-details \
  --query "{name:name,location:location,size:hardwareProfile.vmSize,power:powerState,publicIp:publicIps,privateIp:privateIps}" \
  --output json
```

If a failed attempt left an empty resource group, delete it after the working VM is confirmed:

```bash
az group delete --name <empty-rg> --yes --no-wait
```

## Network Rules

Open proxy and ping:

```bash
az network nsg rule create \
  --resource-group "$RG" \
  --nsg-name "${VM}NSG" \
  --name AllowProxy1081 \
  --priority 1010 \
  --access Allow \
  --protocol Tcp \
  --direction Inbound \
  --source-address-prefixes Internet \
  --source-port-ranges '*' \
  --destination-address-prefixes '*' \
  --destination-port-ranges 1081 \
  --output json

az network nsg rule create \
  --resource-group "$RG" \
  --nsg-name "${VM}NSG" \
  --name AllowICMPPing \
  --priority 1020 \
  --access Allow \
  --protocol Icmp \
  --direction Inbound \
  --source-address-prefixes Internet \
  --source-port-ranges '*' \
  --destination-address-prefixes '*' \
  --destination-port-ranges '*' \
  --output json
```

## Deploy `proxy-server`

Prefer reusing a known-good Linux x86_64 binary from an existing node when deploying another x86_64 node:

```bash
scp azureuser@<existing-node-ip>:/opt/proxy-everything/http-proxy-server /tmp/http-proxy-server-azure-x86_64
file /tmp/http-proxy-server-azure-x86_64
scp /tmp/http-proxy-server-azure-x86_64 azureuser@"$IP":/tmp/http-proxy-server
```

If no reusable binary exists, build on the VM:

```bash
ssh azureuser@"$IP" 'sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile && echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab'

tar --exclude='./target' --exclude='./.git' --exclude='./deps/uni-stream/target' --exclude='*/.git' -czf - . \
  | ssh azureuser@"$IP" 'rm -rf ~/proxy-everything && mkdir -p ~/proxy-everything && tar -xzf - -C ~/proxy-everything'

ssh azureuser@"$IP" 'set -e; sudo apt-get update; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential pkg-config cmake curl ca-certificates; if ! command -v cargo >/dev/null 2>&1; then curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain stable; fi; cd ~/proxy-everything; ~/.cargo/bin/cargo build -p proxy-server --bin http-proxy-server --release; cp target/release/http-proxy-server /tmp/http-proxy-server'
```

Install the service:

```bash
ssh azureuser@"$IP" "set -e
sudo mkdir -p /opt/proxy-everything/conf/.proxy-everything
sudo install -m 0755 /tmp/http-proxy-server /opt/proxy-everything/http-proxy-server
sudo tee /etc/systemd/system/proxy-server.service >/dev/null <<EOF
[Unit]
Description=proxy-everything server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/proxy-everything
Environment=HOME=/opt/proxy-everything/conf
Environment=RUST_LOG=info
Environment=SECRET_KEY=my-secret-key123my-secret-key123
Environment=SERVER_PORT=1081
Environment=PROXY_DATA_DIR=/opt/proxy-everything/conf/.proxy-everything
Environment=NODE_ADVERTISE_ADDR=${IP}:1081
ExecStart=/opt/proxy-everything/http-proxy-server -H 0.0.0.0 -p 1081
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
PrivateNetwork=no
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
IPAddressAllow=any

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now proxy-server.service
rm -f /tmp/http-proxy-server
"
```

## Verify Node Health

Run all checks before registering the node:

```bash
ping -c 3 "$IP"
nc -vz -w 5 "$IP" 1081

ssh azureuser@"$IP" "set -e
sudo systemctl is-active proxy-server
sudo systemctl is-enabled proxy-server
sudo grep -q '^Environment=SECRET_KEY=my-secret-key123my-secret-key123$' /etc/systemd/system/proxy-server.service && echo default-key-ok
sudo grep -q '^Environment=NODE_ADVERTISE_ADDR=${IP}:1081$' /etc/systemd/system/proxy-server.service && echo advertise-ok
sudo ss -ltnp | grep 1081
"
```

Treat `Server read header fail` after an `nc` probe as expected noise from a raw TCP check, not as a service failure.

## Register in `lb7666.top`

Register the node with the default control session key and add it to the `azure` group.

Prefer the repo-native admin CLI:

```bash
cargo build -p proxy-server --bin http-proxy-admin
ADMIN=target/debug/http-proxy-admin
KEY=my-secret-key123my-secret-key123

"$ADMIN" -H lb7666.top -p 1081 -k "$KEY" ping
"$ADMIN" -H lb7666.top -p 1081 -k "$KEY" nodes list
"$ADMIN" -H lb7666.top -p 1081 -k "$KEY" nodes add "${IP}:1081"
"$ADMIN" -H lb7666.top -p 1081 -k "$KEY" groups list
"$ADMIN" -H lb7666.top -p 1081 -k "$KEY" groups create --id azure --name Azure || true
"$ADMIN" -H lb7666.top -p 1081 -k "$KEY" groups add-node --group-id azure --node-id "${IP}:1081"
"$ADMIN" -H lb7666.top -p 1081 -k "$KEY" groups list
```

If idempotent helper binaries already exist, they are also acceptable:

```bash
target/debug/add-node-once --host lb7666.top --port 1081 --node "${IP}:1081"
target/debug/group-node-once --host lb7666.top --port 1081 --node "${IP}:1081" --group-id azure --group-name Azure
```

If neither path exists, create temporary Rust bins in `crates/proxy-server/src/bin/` that use `proxy_core::control::ControlClient` to:

- `ping`
- `list_nodes`
- `add_node` only when missing
- `list_groups`
- `create_group("azure", "Azure")` only when missing
- `add_node_to_group("azure", "${IP}:1081")`
- verify the node is present in the group

Run the helpers with `cargo run -p proxy-server --bin <helper> -- ...`, then delete the temporary source files with `apply_patch`. Do not leave helper source files in the repository unless the user asks to keep them.

## Final Report

Report these fields:

- Azure account user and subscription ID
- Resource group, VM name, region, SKU
- Public node address
- Ping average and TCP 1081 result
- systemd `active` / `enabled`
- nodes count change or `existed: true`
- `azure` group membership and group node count
- cleanup performed
- `git status --short` result

## Common Mistakes

| Mistake | Fix |
|---|---|
| Deploying in the previous account | Run `az account show` before every provisioning sequence. |
| Retrying a policy-blocked region | Read `sys.regionrestriction`; choose a permitted region. |
| Generating a new `SECRET_KEY` | Use `my-secret-key123my-secret-key123` for compatibility. |
| Forgetting `NODE_ADVERTISE_ADDR` | Set it to the public `${IP}:1081` in systemd. |
| Assuming x86 binary works on ARM | Use `file`, `uname -m`, and build/copy the correct architecture. |
| Leaving temporary helper sources | Delete temp bins and verify `git status --short`. |
