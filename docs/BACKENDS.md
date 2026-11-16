# Backends: Shepherd as a dashboard over your router

Shepherd started as a DNS server with a portal on top. A **backend** lets the same portal sit on
top of a router or firewall you already run, read what it sees and change what it enforces, instead
of (or beside) answering DNS itself. `internal/backends` defines the contract and one package per
product implements it.

## One contract, many abilities

Products disagree about what they expose, so a backend is not one big interface. Each ability is its
own small interface (`DeviceReader`, `FlowReader`, `AlarmReader`, `RuleManager`, `DeviceRenamer`,
`AlarmDismisser`) and a backend implements the ones its API really supports.
`backends.Capabilities` reports the result, and the portal shows only what is on that list.

Write abilities (`rules:write`, `devices:rename`, `alarms:dismiss`) are advertised only when the
owner has not marked the credential read-only. A write through a read-only connection returns
`ErrReadOnly` before any request is made.

| Ability | Firewalla MSP | UniFi (Integration API) | Shepherd's own DNS |
|---|---|---|---|
| Devices | `GET /v2/devices` | clients and adopted devices | registry |
| Requests (flows) | `GET /v2/flows`, with destination domain, bytes, blocked | **none documented** | DNS query history |
| Alarms | `GET /v2/alarms` | **none documented** | alarm engine |
| Rules (list) | `GET /v2/rules` | firewall policies, ACL rules, DNS policies | allow and block lists |
| Rules (change) | create block or allow, pause, resume, delete | create, update, delete firewall policies | policy store |
| Rename device | `PATCH /v2/boxes/:gid/devices/:id` | not documented | registry |
| Dismiss alarm | `DELETE /v2/alarms/:gid/:aid` | n/a | alarm engine |

UniFi's documented API manages the network (devices, clients, firewall and DNS policy) but does not
report requests or raise alarms. That is the case for pairing: with a UniFi network, Shepherd's DNS
history supplies the requests, and the backend supplies the controls.

## Status

- **Built:** the contract and its tests; the Firewalla MSP backend (`internal/backends/firewalla`)
  with every read and write above, tested against a fake MSP. The bandwidth reader
  (`internal/routerusage`, [TRAFFIC.md](TRAFFIC.md#firewalla-msp)) uses the same token.
- **Next:** ingestion (flows into the history store, alarms into the alarm engine, devices into the
  registry), the portal's rule and device controls with preview, confirmation and an audit trail,
  the `dashboard` mode that turns the DNS engine off, and a UniFi backend.

## Not verified

Everything here was written from Firewalla's published documentation and run against a fake. Not yet
confirmed against a live account: the query syntax for filtering flows by device, the exact
`status` values on rules, how a network-wide rule is expressed, and the period `totalDownload`
covers. Where Shepherd had to guess it says so in the code, and nothing writes to a box until the
owner turns writes on.
