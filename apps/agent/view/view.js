"use strict";

const senderId = /^[0-9a-f]{64}$/;
const columns = [
  ["Load (1m)", "host.load1", ""],
  ["Memory used", "host.mem_used_pct", "%"],
  ["Root disk used", "host.disk_root_pct", "%"],
  ["Uptime", "host.uptime_s", " s"],
  ["tierd", "host.unit.tierd", null],
  ["sshd", "host.unit.sshd", null],
];
const view = document.getElementById("view");
const message = document.getElementById("message");
const sender = location.pathname.startsWith("/nodes/") ? location.pathname.slice(7) : "";

function element(tag, text = "", className = "") {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) node.className = className;
  return node;
}

function link(label, path) {
  const anchor = element("a", label);
  anchor.href = path;
  return anchor;
}

function table(headers, rows, empty) {
  if (!rows.length) return element("p", empty, "quiet");
  const wrapper = element("div", "", "table");
  const grid = element("table");
  const header = grid.createTHead().insertRow();
  for (const label of headers) {
    const cell = element("th", label);
    cell.scope = "col";
    header.append(cell);
  }
  const body = grid.createTBody();
  for (const cells of rows) {
    const row = body.insertRow();
    for (const content of cells) row.insertCell().append(content);
  }
  wrapper.append(grid);
  return wrapper;
}

function formatTime(seconds) {
  if (seconds == null) return "—";
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) return String(seconds);
  return date.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, "");
}

function status(node, now, staleAfter) {
  if (!node) return element("span", "Awaiting telemetry", "status quiet");
  if (node.received_unix == null) return element("span", "Awaiting update", "status quiet");
  if (now - node.received_unix >= staleAfter) return element("span", "Stale", "status stale");
  return element("span", "Receiving", "status fresh");
}

function tags(entry) {
  const wrapper = element("div");
  for (const tag of entry?.tags ?? []) wrapper.append(element("span", tag, "tag"));
  return wrapper;
}

function presetValue(value, suffix) {
  if (value == null) return "—";
  if (suffix != null) return value + suffix;
  if (value === "0") return "Inactive";
  if (value === "1") return "Active";
  return value;
}

function nodeName(id, inventory) {
  return inventory.get(id)?.name || id.slice(0, 12);
}

function fleetPage(nodes, inventory, now, staleAfter) {
  const senders = [...new Set([...nodes.keys(), ...inventory.keys()])];
  senders.sort((a, b) => nodeName(a, inventory).localeCompare(nodeName(b, inventory)) ||
                         a.localeCompare(b));
  const rows = senders.map(id => {
    const node = nodes.get(id);
    const gauges = new Map(node?.gauges.map(sample => [sample.key, sample.value]) ?? []);
    const identity = element("div");
    identity.append(link(nodeName(id, inventory), "/nodes/" + id), tags(inventory.get(id)));
    return [identity, status(node, now, staleAfter), formatTime(node?.received_unix),
            ...columns.map(([, key, suffix]) => presetValue(gauges.get(key), suffix))];
  });
  const headers = ["Node", "Telemetry", "Last received (UTC)", ...columns.map(([title]) => title)];
  document.title = "Tier fleet";
  view.replaceChildren(element("h1", "Tier fleet"),
    table(headers, rows, "Waiting for telemetry from the first node."));
}

function sampleTable(samples, empty) {
  const rows = samples.map(sample => [
    formatTime(sample.ts_unix), element("code", sample.key),
    element("div", sample.value, "value"),
  ]);
  return table(["Source time (UTC)", "Key", "Value"], rows, empty);
}

function nodePage(nodes, events, inventory, now, staleAfter) {
  const node = nodes.get(sender);
  const nav = element("nav");
  nav.append(link("Fleet overview", "/"));
  if (!node && !inventory.has(sender)) {
    document.title = "Unknown sender";
    view.replaceChildren(nav, element("h1", "Unknown sender"));
    return;
  }
  const name = nodeName(sender, inventory);
  const id = element("p");
  id.append(element("code", sender));
  const state = element("p");
  state.append(status(node, now, staleAfter), " · Last received (UTC) " + formatTime(node?.received_unix));
  document.title = name;
  view.replaceChildren(nav, element("h1", name), id, tags(inventory.get(sender)), state,
    element("h2", "Current values"), sampleTable(node?.gauges ?? [], "No gauges received."),
    element("h2", "Recent events"), sampleTable(events, "No recent events."));
}

async function getJson(path) {
  const reply = await fetch(path);
  if (!reply.ok) throw new Error(`HTTP ${reply.status}`);
  return reply.json();
}

function readConfig(config) {
  const isObject = value => value != null && typeof value === "object" && !Array.isArray(value);
  if (!isObject(config) || Object.keys(config).some(
      key => !["nodes", "stale_after_seconds", "refresh_seconds"].includes(key))) {
    throw new Error("Expected nodes, stale_after_seconds or refresh_seconds.");
  }
  const {nodes = {}, stale_after_seconds: staleAfter = 60, refresh_seconds: refresh = 10} = config;
  if (![staleAfter, refresh].every(value => Number.isSafeInteger(value) && value > 0)) {
    throw new Error("Freshness and refresh intervals must be positive integers.");
  }
  if (!isObject(nodes)) throw new Error("Nodes must map sender IDs to names and tags.");
  for (const [id, entry] of Object.entries(nodes)) {
    if (!senderId.test(id) || !isObject(entry)) throw new Error("Invalid sender ID or entry.");
    const {name = "", tags: labels = []} = entry;
    if (Object.keys(entry).some(key => !["name", "tags"].includes(key)) ||
        typeof name !== "string" || !Array.isArray(labels) ||
        labels.some(tag => typeof tag !== "string")) {
      throw new Error(`Invalid name or tags for ${id}.`);
    }
  }
  return {inventory: new Map(Object.entries(nodes)), staleAfter, refresh};
}

async function start() {
  let config;
  try {
    config = readConfig(await getJson("/api/config"));
  } catch (error) {
    message.textContent = `Cannot load viewer configuration. ${error.message}`;
    return;
  }

  async function refresh() {
    try {
      const snap = await getJson("/api/snapshot" + (sender ? "?sender=" + sender : ""));
      if (snap.version !== 1 || !Array.isArray(snap.nodes) || !Array.isArray(snap.events) ||
          snap.nodes.some(node => !senderId.test(node.sender) || !Array.isArray(node.gauges))) {
        throw new Error("Invalid collector snapshot");
      }
      const nodes = new Map(snap.nodes.map(node => [node.sender, node]));
      const now = Date.now() / 1000;
      if (sender) nodePage(nodes, snap.events, config.inventory, now, config.staleAfter);
      else fleetPage(nodes, config.inventory, now, config.staleAfter);
      message.textContent = "";
    } catch {
      view.replaceChildren(element("h1", "Tier fleet"));
      message.textContent = "Collector unavailable. Check the query socket.";
    } finally {
      setTimeout(refresh, Math.min(config.refresh * 1000, 0x7fffffff));
    }
  }

  refresh();
}

start();
