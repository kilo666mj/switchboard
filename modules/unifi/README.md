# UniFi Network module

A read-only stdio MCP module for **UniFi OS Server** using the official local
Network Integration API. Switchboard calls the configured server directly:

```text
Agent → Switchboard → switchboard-module-unifi
                    → https://<local-server>/proxy/network/integration/v1/...
```

There is no cloud connector, UI account login, discovery probe, or fallback to
the classic controller API. All upstream requests are GET requests authenticated
with `X-API-Key`. Network access begins only when a tool is called.

## Connection and credentials

In the local UniFi console, open Network's **Integrations** settings (the exact
navigation depends on version) and create a local integration key. Use the
documentation displayed there to check endpoint availability for the installed
Network version. A Site Manager cloud key is not a substitute for the local key.

Provision these values in Switchboard's protected environment:

| Variable | Meaning |
| --- | --- |
| `UNIFI_URL` | HTTPS origin of the local UniFi OS Server, including its configured port; for example `https://unifi.example.com:11443`. No API path or query. |
| `UNIFI_API_KEY` | Local Network integration key. Never place its value in manifests or tool arguments. |
| `UNIFI_TLS_SERVER_NAME` | Optional certificate DNS identity when different from the connection hostname. Requires an explicit `UNIFI_CA_FILE`; add both names to the manifest environment allowlist. Signature, expiry and hostname verification remain enabled. |
| `UNIFI_CA_FILE` | Optional PEM CA bundle readable by the module process, appended to system roots. If used, also add this variable name to the manifest's environment allowlist. |

TLS certificate verification is mandatory. There is no insecure TLS option.
Redirects and environment proxies are disabled. The required Switchboard
egress policy ensures both the configured destination and the addresses resolved at
connection time are allowed. Allow the local controller's exact host and
port and the appropriate address range.

The key is shared by this capability's callers. Switchboard retains caller/tool
policy and audit; UniFi enforces the key's own permissions. The module itself
has no write tools or arbitrary HTTP request tool, even if the key permits writes.

## Tools

| Tools | Data |
| --- | --- |
| `unifi_get_info`, `unifi_list_sites` | Network application version and accessible site UUIDs |
| `unifi_list_networks`, `unifi_get_network` | Networks, VLANs, DHCP, IPv4/IPv6 and isolation configuration |
| `unifi_list_wifi`, `unifi_get_wifi` | Wi-Fi broadcasts, network assignment, security modes and radio-related settings |
| `unifi_list_firewall_zones`, `unifi_list_firewall_policies` | Zones, network membership, policy matches and actions |
| `unifi_list_acl_rules` | Switch ACL configuration |
| `unifi_list_devices`, `unifi_get_device` | Device inventory, state, ports and radios |
| `unifi_list_clients` | Connected client inventory |

Start with `unifi_get_info` and `unifi_list_sites`. Site-scoped tools require
`site_id`, the site's UUID rather than its legacy internal name. Detail tools
also require `id`, obtained from the corresponding list tool. Lists accept
`offset` (default 0, maximum 100000) and `limit` (default 100, range 1–200),
passed to UniFi. Use returned `offset`, `count`, and `totalCount` to page onward.

Responses contain `result` (the projected UniFi JSON) and `projection` (a reminder
that it is partial). The checked-in `projections.json` is a recursive allowlist
of reviewed fields from the official Network **v10.4.57** OpenAPI specification.
Wi-Fi passphrases and preshared keys are excluded. Unknown fields and unexpected
object shapes are omitted at every level, including objects inside arrays.
This is an inspection interface, not a complete configuration export or backup.
Review and test projection changes when adopting newer API fields.

In Network 10.x, Integrations is a separate entry in the main navigation; the
local page is commonly `/network/default/integrations`.

Endpoint availability depends on the installed Network application version and
hardware features. Older versions may return 404 for newer endpoints, such as
firewall policies. A missing endpoint produces an error, never an empty success
or a fallback to another API. Each request has a 15-second timeout and a 4 MiB
response limit; use a smaller page size if needed. Upstream error bodies are not
returned because they may contain secrets.

## Build and install

```sh
go build -o switchboard-module-unifi ./modules/unifi
```

Review archives also include `modules/switchboard-module-unifi`. Install it as
a root-owned executable at the path in `capabilities/unifi.example.json`, install
that manifest as `unifi.json`, provision the environment, and add `unifi` to the
intended profiles and exact-tool policies. Deployment automation must build and install the binary and provision its
configuration from protected deployment variables.
For a private CA, trust it in the host's system certificate store, or configure
`UNIFI_CA_FILE` and its manifest allowlist entry explicitly.

Adding the example manifest to the repository does not enable access in an
existing deployment. Verify the live application version, enumerate sites, and
read a representative network and Wi-Fi object after deployment.

## Validation and references

Tests cover MCP discovery and schemas, fixed local GET routes, pagination,
credential omission, untrusted TLS, redirect rejection, egress restrictions,
bounded/malformed responses and clean stdin-EOF shutdown. Release smoke tests
initialize the packaged binary and verify its exact tool inventory offline.
Live compatibility still needs verification against the operator's controller.

- [Ubiquiti API setup](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API)
- [Network v10.4.57 OpenAPI specification](https://developer.ui.com/network/v10.4.57/openapi.json)
