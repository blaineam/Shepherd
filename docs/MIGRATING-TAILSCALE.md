# Migrating an existing Tailscale container into Shepherd

Move the node's state, don't create a new node. The node keeps its identity, tailnet name,
IP and approved routes, so nothing needs re-approval in the admin console.

## Rules

- **Never run both containers at once.** Two processes with the same node key fight each other.
- **Pin the same Tailscale version** the old container runs (`docker exec <old> tailscale version`).
  Older software can mishandle state written by a newer version.
- **Keep the node's hostname** (`TS_HOSTNAME`) so MagicDNS names don't change.
- **Keep the old compose project** until the new node has been verified. Rollback is stopping
  the new container and running `docker compose up -d` in the old directory.

## Steps

1. Note the old settings: image version, hostname, routes (`TS_ROUTES`), extra args.
2. Set the same values in Shepherd's `.env` (`TS_HOSTNAME`, `LAN_ROUTES`) and pin the same image tag in `compose.yaml`.
3. Stop the old container (do not delete its directory).
4. Copy its state directory into `./data/tailscale`. If the state is root-owned, copy it through
   a throwaway container: `docker run --rm -v <old-state>:/src -v $PWD/data/tailscale:/dst alpine cp -a /src/. /dst/`
5. `docker compose up -d tailscale`
6. Verify: `docker exec shepherd-tailscale tailscale status` shows the node online with the same
   IP, and other devices on the tailnet still reach it and its advertised routes.
7. Once satisfied, retire the old compose project (keep its state directory as a backup for a while).

## Why bother

State on a NAS system disk can be lost in an OS update. Shepherd keeps its state next to its
config on the data volume, where it is backed up and restored with the rest of the stack.
