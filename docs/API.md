# The router API

One small REST API over whatever router or firewall Shepherd is connected to. The calls are the
same for every product; what differs is which of them each product can serve, and the API says so.
It is what to build against if you want to script your network without caring whether it is a
Firewalla or a UniFi console underneath.

It is described by an **OpenAPI 3.1 document** that Shepherd serves about itself:

```
GET /api/v1/openapi.json
```

The document is generated from the same table the routes are registered from, so it cannot describe
a call that is not there. Point a client generator or an API explorer at it.

## Calling it

- **Token.** Send the portal token as `Authorization: Bearer <token>`. It is the file `portal-token`
  in Shepherd's data directory.
- **Changes.** A call that changes something must also carry the header `X-Shepherd: 1`, like the
  rest of the portal's API, and is refused while **Allow changes** is off on the Router screen.
- **Devices are identified by MAC address**, in any common form (`02:00:5e:00:00:01`,
  `02005e000001`). Answers use lower-case hexadecimal with no separators.

```sh
TOKEN=$(cat data/portal-token)
curl -H "Authorization: Bearer $TOKEN" http://192.0.2.1:8787/api/v1/router
curl -H "Authorization: Bearer $TOKEN" http://192.0.2.1:8787/api/v1/devices
curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "X-Shepherd: 1" \
     -d '{"name":"Den TV","group":"Smart Home"}' \
     http://192.0.2.1:8787/api/v1/devices/02005e000001
```

## The calls

| Call | Does | Needs |
|---|---|---|
| `GET /api/v1/router` | what is connected, and its capabilities | |
| `GET /api/v1/devices` | every device | `devices` |
| `GET /api/v1/devices/{mac}` | one device | `devices` |
| `PATCH /api/v1/devices/{mac}` | `name`, `group`, `blocked`: any of them | `devices:rename`, `groups:write`, `devices:block` |
| `GET /api/v1/groups` | device groups, with how many devices each holds | `groups` |
| `GET /api/v1/rules` | access rules | `rules` |
| `POST /api/v1/rules` | create a block or allow rule | `rules:create` |
| `PATCH /api/v1/rules/{id}` | `paused`: true or false | `rules:write` |
| `DELETE /api/v1/rules/{id}` | delete a rule | `rules:write` |
| `GET /api/v1/alarms` | active alarms | `alarms` |
| `DELETE /api/v1/alarms/{id}` | dismiss an alarm | `alarms:dismiss` |
| `GET /api/v1/flows` | recent requests; `device`, `limit`, `cursor` | `flows` |

Moving a device into a group that does not exist yet makes the group. An empty `group` takes the
device out of its group.

## What each product can serve

`GET /api/v1/router` returns the connected product's `capabilities`. A write capability is absent
while changes are switched off. Roughly:

| | Firewalla, on the box | Firewalla, through MSP | UniFi console |
|---|---|---|---|
| devices, rules, pause and delete a rule | yes | yes | yes |
| flows, alarms | yes | yes | no |
| rename a device, dismiss an alarm | yes | yes | no |
| create a rule | no | yes | no |
| groups, move a device | yes | no | no |
| block a device | no | no | yes |

See [BACKENDS.md](BACKENDS.md) for why each gap is there. An eero account is not a router Shepherd
can control, so it does not appear here; it supplies names and bandwidth only.

## Errors

Every failure has the same shape, with a stable `code`:

```json
{"error": "the connected unifi cannot do this (groups)", "code": "unsupported"}
```

| Code | Status | Means |
|---|---|---|
| `not_connected` | 404 | no router or firewall is connected |
| `unsupported` | 501 | this product cannot do that |
| `read_only` | 403 | Allow changes is off |
| `invalid` | 400 | the request itself is wrong; the message says how |
| `not_found` | 404 | no device, rule or alarm by that ID |
| `rate_limited` | 429 | the product's own service is limiting requests |
| `credential_refused` | 502 | the product refused Shepherd's credential |
| `router_error` | 502 | anything else the product answered |

## What it is not

- It is not the portal's own API. `/api/backend` and the rest serve the screens, return records in
  the shapes the screens want, and may change with them. `/api/v1` is the one to depend on.
- It reads what Shepherd last read from the router (every 30 seconds), not the router live, except
  `GET /api/v1/flows`, which asks the router each time.
- It does not cover Shepherd's own features (DNS filtering, the device registry, history). Those are
  on the portal API.
