#!/bin/sh
# tier-agent exec source: emit this host's current state as tier-agent
# line-protocol on stdout, one sample per line. tier-agent runs this script once
# per `interval` (see the [agent] exec = ... config key) and ships the result.
#
# Format: "<gauge|event> <key> <value>". Gauges are rewritable (last value wins),
# so re-emitting the same keys each tick just refreshes them on the collector.
# Dependency-light: /proc and coreutils only. Keys are namespaced "host.*".
set -eu

# Load average (1-minute) and running/total process counts.
if [ -r /proc/loadavg ]; then
  set -- $(cat /proc/loadavg)
  echo "gauge host.load1 $1"
  echo "gauge host.load5 $2"
  echo "gauge host.procs $4"   # e.g. "2/431" running/total
fi

# Memory: used percentage from MemTotal/MemAvailable.
if [ -r /proc/meminfo ]; then
  total=$(awk '/^MemTotal:/{print $2}' /proc/meminfo)
  avail=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
  if [ -n "${total:-}" ] && [ -n "${avail:-}" ] && [ "$total" -gt 0 ]; then
    used_pct=$(awk "BEGIN{printf \"%.1f\", (($total-$avail)/$total)*100}")
    echo "gauge host.mem_used_pct $used_pct"
  fi
fi

# Root filesystem usage percentage.
if command -v df >/dev/null 2>&1; then
  root_pct=$(df -P / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')
  [ -n "${root_pct:-}" ] && echo "gauge host.disk_root_pct $root_pct"
fi

# Uptime in whole seconds.
if [ -r /proc/uptime ]; then
  up=$(awk '{printf "%d", $1}' /proc/uptime)
  echo "gauge host.uptime_s $up"
fi

# systemd unit states as gauges (1 = active, 0 = not). Extend UNITS as needed.
# These make a good at-a-glance fleet health view on the collector.
if command -v systemctl >/dev/null 2>&1; then
  for unit in sshd tierd; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
      echo "gauge host.unit.$unit 1"
    else
      echo "gauge host.unit.$unit 0"
    fi
  done
fi
