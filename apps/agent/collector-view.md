# Viewing a Tier fleet

`tier-agent-view` is an optional, read-only web view for the local collector.
The overview shows discovered and configured nodes. A node page shows all
current gauge values, including strings, and up to 50 recent events for that
sender. The overview columns match the packaged `host-metrics.sh` source.

## Start monitoring a fleet

Install the Tier `.deb` and start `tierd` on the collector host and on each
monitored host. Use the same Tier network for all of them.

1. On the collector host, run `sudo tier-agent bootstrap collector --view`.
   Copy the `tier1…` address printed on stdout. The command creates
   `/etc/tier/collector.toml` with the local store, seven days of event
   retention, and the query socket. It enables `tier-agent@collector.service`
   and, with `--view`, `tier-agent-view.service`.
2. On each monitored host, run
   `sudo tier-agent bootstrap client --collector=<ADDRESS>`, replacing
   `<ADDRESS>` with that Tier address. The command creates
   `/etc/tier/agent.toml` and enables `tier-agent@agent.service`. The default
   source is `host-metrics.sh` with a 15-second reporting interval.
3. Forward the viewer port from your workstation and open
   `http://127.0.0.1:8080/` in a browser.

```sh
ssh -N -L 8080:127.0.0.1:8080 operator@collector
```

Bootstrap uses the packaged templates under `/usr/share/tier/agent/` on first
setup. Copies are also available in the package documentation. Subsequent runs
reuse existing configs and identity seeds.
Omit `--view` to run the collector alone. Pass it later to enable the viewer.
If an existing config names a different collector, edit `/etc/tier/agent.toml`
and restart `tier-agent@agent.service` to change the destination.

The viewer discovers senders as data arrives. You can check what reached the
collector directly with `sudo tier-agent query /run/tier-agent/agent-query.sock`.

## Run the viewer

Enable the query socket in the collector's configuration:

```toml
[collector]
query_socket = "/run/tier-agent/agent-query.sock"
```

Run the viewer on the collector host with an account that can connect to the
socket. The `.deb` installs the C++ binary with the web assets embedded.
From a checkout, build the `tier-agent-view` target and run
`build/apps/agent/tier-agent-view`.

```sh
tier-agent-view --socket /run/tier-agent/agent-query.sock --port 8080
```

The viewer listens on `127.0.0.1`. From another machine, forward the port
over SSH, then open `http://127.0.0.1:8080/` in a browser with JavaScript
enabled.

```sh
ssh -N -L 8080:127.0.0.1:8080 operator@collector
```

## Run the viewer with systemd

The package installs `tier-agent-view.service`. It runs
under a dynamic user with access to the query socket through the
`tier-monitor` group. For manual setup, create the group and add
`query_socket_group = "tier-monitor"` to the existing `[collector]` section
of `/etc/tier/collector.toml`. The collector sets the socket's group and mode
when it creates the socket. This grants group access only to the query socket.

```sh
getent group tier-monitor || sudo groupadd --system tier-monitor
sudo systemctl restart tier-agent@collector.service
sudo systemctl enable --now tier-agent-view.service
```

For a custom socket, HTTP port, or fleet configuration, use
`sudo systemctl edit tier-agent-view.service` to override the command,
then restart the viewer. Put the fleet file at a path readable by the
service user, such as `/etc/tier/fleet.json`.

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/tier-agent-view --config /etc/tier/fleet.json
```

## Name nodes and set freshness

Pass `--config /path/to/fleet.json` to show friendly names, tags, and expected
nodes. The keys are the 64-digit hex user IDs printed as `tier-agent: user`
by the sending agents. The viewer discovers senders from the collector's
snapshot and displays configured senders even before their first sample.
The viewer sends this display configuration to the browser.

```json
{
  "stale_after_seconds": 60,
  "refresh_seconds": 10,
  "nodes": {
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": {
      "name": "edge-01",
      "tags": ["edge", "production"]
    }
  }
}
```

The example uses the default freshness and refresh intervals. Set the
freshness threshold above the agents' normal reporting interval. The status
reflects the collector's last receipt of telemetry, so a stale node may
still be running. After a collector restart, restored values remain visible
with `Awaiting update` until a new sample arrives. Both the source timestamp
and the collector's receipt time are shown in UTC.

The local store replaces gauge values in place. Use a time-series collector
if you need historical graphs or alert rules.

## Structured query protocol

Connect to the existing collector Unix socket and send one of these lines:

```text
TIER-QUERY/1
TIER-QUERY/1 <64-digit lowercase hex sender ID>
```

The collector returns one UTF-8 JSON object terminated by a newline, then
closes the connection. `version` is `1`. Each item in `nodes` has a
`sender`, `received_unix` in seconds or `null`, and a `gauges` array.
Each gauge has a string `key`, a string `value`, and the sender's
`ts_unix` in seconds. The top-level `events` array uses the same sample
fields plus `sender`, ordered newest first by receipt order and capped at
50 entries. The sender-scoped request filters both arrays to that sender.
Invalid UTF-8 in a sample is displayed with replacement characters.

Use `tier-agent query <socket> [filter]` for the terminal snapshot.
