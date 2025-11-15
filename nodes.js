/* eslint-disable */
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const net = require("net");
const http = require("http");
const https = require("https");

/* === ADDITIONS === */
const multer = require("multer");
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1024 * 1024 * 1024 } }); // up to 1GB

// --------------------
// Config de fișier/port
// --------------------
const PORT = process.env.NODES_PORT ? Number(process.env.NODES_PORT) : 3550;
const DATA_DIR = __dirname;
const NODES_FILE = path.join(DATA_DIR, "nodes.json");
const SERVERS_FILE = path.join(DATA_DIR, "servers.json"); // protecție la delete dacă sunt atașate servere

// IMPORTANT: aliniat cu UI-ul (settings.html folosește 120s TTL)
const HEARTBEAT_TTL_MS = 120_000;

// ------------- Utils -------------
function ensureFile(file, def = "[]") {
  if (!fs.existsSync(file)) fs.writeFileSync(file, def, "utf8");
}
ensureFile(NODES_FILE, "[]");

function readJson(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const raw = fs.readFileSync(file, "utf8").trim();
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch { return fallback; }
}
function writeJson(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2), "utf8");
}

function uid() { return crypto.randomUUID(); }
function randTokenId() { return "tok_" + crypto.randomBytes(6).toString("hex"); }
function randSecret() { return crypto.randomBytes(24).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); }

function sanitizeName(raw) {
  let s = String(raw || "").trim();
  if (!s) return "";
  s = s.replace(/[^\w\-. ]+/g, " ").replace(/\s+/g, " ").trim();
  s = s.replace(/\s/g, "-");
  if (s.length > 100) s = s.slice(0, 100);
  return s;
}

function isInt(n){ return Number.isInteger(n); }
function toInt(n, def=0){ const x = Number(n); return Number.isFinite(x) ? Math.round(x) : def; }

function clampPort(p) {
  const n = toInt(p, 8080);
  if (n < 1 || n > 65535) return 8080;
  return n;
}

function normalizePorts(input) {
  // Acceptă:
  // {mode:'range', start, count}  OR  {mode:'list', ports:[...]}  OR  [numbers]
  if (!input) return { mode: "range", start: 25565, count: 10 };

  if (Array.isArray(input)) {
    const ports = Array.from(new Set(input.map(p => toInt(p)).filter(p => p >= 1 && p <= 65535)));
    return { mode: "list", ports };
  }
  if (typeof input === "object") {
    if (input.mode === "range") {
      let start = toInt(input.start, 25565);
      let count = toInt(input.count, 10);
      if (start < 1 || start > 65535) start = 25565;
      if (count < 1) count = 1;
      if (start + count - 1 > 65535) count = 65535 - start + 1;
      return { mode: "range", start, count };
    }
    if (input.mode === "list") {
      const ports = Array.from(new Set((input.ports || [])
        .map(p => toInt(p))
        .filter(p => p >= 1 && p <= 65535)));
      return { mode: "list", ports };
    }
  }
  return { mode: "range", start: 25565, count: 10 };
}

function loadNodes() {
  const arr = readJson(NODES_FILE, []);
  return Array.isArray(arr) ? arr.map(hardenNode) : [];
}
function saveNodes(list) { writeJson(NODES_FILE, Array.isArray(list) ? list : []); }

function hardenNode(n) {
  const clone = Object.assign({
    id: uid(),            // în caz că lipsește
    uuid: "",             // alias la id
    name: "node",
    address: "",
    ram_mb: 0,
    disk_gb: 0,
    ports: { mode:"range", start:25565, count:10 },
    token_id: randTokenId(),
    token: randSecret(),
    createdAt: Date.now(),

    // health
    api_port: 8080,       // port API al node-ului (poate fi actualizat din heartbeat)
    port_ok: null,        // true/false/ null (necunoscut)
    last_seen: null,      // ms epoch (ultimul OK confirmat)
    last_check: null,     // ms epoch (ultima verificare făcută)

    // extra
    online: null,         // calculat la toPublic
    buildConfig: {}
  }, n || {});

  if (!clone.id) clone.id = uid();
  if (!clone.uuid) clone.uuid = clone.id;
  if (!isInt(clone.ram_mb)) clone.ram_mb = toInt(clone.ram_mb, 0);
  if (!isInt(clone.disk_gb)) clone.disk_gb = toInt(clone.disk_gb, 0);
  clone.name = sanitizeName(clone.name || "node");
  clone.address = String(clone.address || "").trim();
  clone.ports = normalizePorts(clone.ports);
  if (!clone.token_id) clone.token_id = randTokenId();
  if (!clone.token) clone.token = randSecret();
  if (!clone.createdAt) clone.createdAt = Date.now();
  clone.api_port = clampPort(clone.api_port || 8080);
  if (typeof clone.port_ok !== "boolean") clone.port_ok = null;
  if (clone.last_seen != null) clone.last_seen = Number(clone.last_seen);
  if (clone.last_check != null) clone.last_check = Number(clone.last_check);

  return clone;
}

function findNodeByIdOrName(idOrName) {
  const list = loadNodes();
  const key = String(idOrName || "").trim().toLowerCase();
  return list.find(n =>
    String(n.id).toLowerCase() === key ||
    String(n.uuid).toLowerCase() === key ||
    String(n.name).toLowerCase() === key
  ) || null;
}

function sanitizeUpdatePayload(body) {
  const out = {};
  if (typeof body.name !== "undefined") out.name = sanitizeName(body.name);
  if (typeof body.address !== "undefined") out.address = String(body.address || "").trim();

  // Acceptă ram_mb sau variante GB:
  if (typeof body.ram_mb !== "undefined") out.ram_mb = toInt(body.ram_mb, 0);
  else if (typeof body.ramMB !== "undefined") out.ram_mb = toInt(body.ramMB, 0);
  else if (typeof body.ram_gb !== "undefined") out.ram_mb = toInt(body.ram_gb, 0) * 1024;

  // Acceptă disk_gb / storage_gb:
  if (typeof body.disk_gb !== "undefined") out.disk_gb = toInt(body.disk_gb, 0);
  else if (typeof body.storage_gb !== "undefined") out.disk_gb = toInt(body.storage_gb, 0);
  else if (typeof body.storageGB !== "undefined") out.disk_gb = toInt(body.storageGB, 0);

  // Acceptă ports în orice format rezonabil
  if (typeof body.ports !== "undefined" ||
      typeof body.port_list !== "undefined" ||
      typeof body.ports_list !== "undefined" ||
      typeof body.mode !== "undefined") {
    const candidate = body.ports ?? body.ports_list ?? body;
    out.ports = normalizePorts(candidate);
  }

  // Acceptă api_port
  if (typeof body.api_port !== "undefined") out.api_port = clampPort(body.api_port);

  return out;
}

function computeOnline(n) {
  const fresh = !!(n.last_seen && (Date.now() - Number(n.last_seen)) < HEARTBEAT_TTL_MS);
  return !!(fresh && n.port_ok === true);
}

function toPublic(n) {
  return {
    id: n.id,
    uuid: n.uuid,
    name: n.name,
    address: n.address,
    ram_mb: n.ram_mb,
    disk_gb: n.disk_gb,
    ports: n.ports,
    token_id: n.token_id,   // necesar în settings.html pentru config.yml
    token: n.token,         // idem (vizibil doar în panou)
    createdAt: n.createdAt,

    // health
    api_port: n.api_port,
    port_ok: n.port_ok,
    last_seen: n.last_seen,
    online: computeOnline(n),

    buildConfig: n.buildConfig || {}
  };
}

// ---------------- Verificare activă (panel -> node) ----------------
function buildNodeBaseUrl(address, port) {
  let base = String(address || "").trim();
  if (!base) return null;

  // dacă utilizatorul a pus deja schemă, o respectăm
  if (/^https?:\/\//i.test(base)) {
    try {
      const u = new URL(base);
      if (!u.port) u.port = String(port || 8080);
      return u.toString().replace(/\/$/, "");
    } catch {
      // cădem pe http://host:port
    }
  }
  return `http://${base}:${clampPort(port || 8080)}`;
}

function httpRequestJson(fullUrl, method = "GET", headers = {}, timeoutMs = 2500) {
  return new Promise((resolve) => {
    try {
      const lib = fullUrl.startsWith("https:") ? https : http;
      const req = lib.request(fullUrl, { method, headers }, (res) => {
        const { statusCode } = res;
        const chunks = [];
        res.on("data", (d) => chunks.push(d));
        res.on("end", () => {
          const bodyStr = Buffer.concat(chunks).toString("utf8");
          try {
            const json = bodyStr ? JSON.parse(bodyStr) : null;
            resolve({ status: statusCode, json });
          } catch {
            resolve({ status: statusCode, json: null });
          }
        });
      });
      req.on("timeout", () => { try { req.destroy(); } catch {} resolve({ status: 0, json: null }); });
      req.on("error", () => resolve({ status: 0, json: null }));
      req.setTimeout(timeoutMs);
      req.end();
    } catch {
      resolve({ status: 0, json: null });
    }
  });
}

// --- Helper pentru apeluri către agentul node-ului (acceptă și body JSON la POST) ---
function callNodeApi(node, pathSuffix, method = "GET", body = null, timeoutMs = 3500) {
  return new Promise((resolve) => {
    try {
      const base = buildNodeBaseUrl(node.address, node.api_port);
      if (!base) return resolve({ status: 0, json: null });
      const fullUrl = `${base}${pathSuffix}`;
      const isHttps = fullUrl.startsWith("https:");
      const lib = isHttps ? https : http;

      const headers = {
        "Authorization": `Bearer ${node.token}`,
        "X-Node-Token": node.token || "",
        "X-Node-Token-Id": node.token_id || "",
        "Content-Type": "application/json",
      };

      const req = lib.request(fullUrl, { method, headers }, (res) => {
        const chunks = [];
        res.on("data", (d) => chunks.push(d));
        res.on("end", () => {
          const bodyStr = Buffer.concat(chunks).toString("utf8");
          try {
            const json = bodyStr ? JSON.parse(bodyStr) : null;
            resolve({ status: res.statusCode, json });
          } catch {
            resolve({ status: res.statusCode, json: null });
          }
        });
      });

      req.on("timeout", () => { try { req.destroy(); } catch {} resolve({ status: 0, json: null }); });
      req.on("error", () => resolve({ status: 0, json: null }));
      req.setTimeout(timeoutMs);

      if (body) req.write(JSON.stringify(body));
      req.end();
    } catch {
      resolve({ status: 0, json: null });
    }
  });
}

function resolveNodeForServer(serverName) {
  const name = String(serverName || "").trim();
  const servers = readJson(SERVERS_FILE, []);
  const nodes = loadNodes();

  const srv = (Array.isArray(servers) ? servers : []).find(
    s => String(s.name || "").toLowerCase() === name.toLowerCase()
  ) || null;

  if (!srv) return { server: null, node: null, nodeId: null };

  const rawNodeId = (srv.node || srv.nodeId || srv.node_id || "");
  const key = String(rawNodeId || "").trim().toLowerCase();

  const node = nodes.find(n =>
    String(n.uuid).toLowerCase() === key ||
    String(n.id).toLowerCase() === key ||
    String(n.name).toLowerCase() === key
  ) || null;

  return { server: srv, node, nodeId: node ? node.uuid : null };
}

function httpRequestJsonWithBody(fullUrl, method = "POST", body = null, headers = {}, timeoutMs = 8000) {
  return new Promise((resolve) => {
    try {
      const lib = fullUrl.startsWith("https:") ? https : http;
      const payload = body ? Buffer.from(JSON.stringify(body)) : null;
      const req = lib.request(fullUrl, {
        method,
        headers: {
          "Content-Type": "application/json",
          ...(payload ? { "Content-Length": payload.length } : {}),
          ...headers
        }
      }, (res) => {
        const { statusCode } = res;
        const chunks = [];
        res.on("data", (d) => chunks.push(d));
        res.on("end", () => {
          const bodyStr = Buffer.concat(chunks).toString("utf8");
          try {
            const json = bodyStr ? JSON.parse(bodyStr) : null;
            resolve({ status: statusCode, json });
          } catch {
            resolve({ status: statusCode, json: null });
          }
        });
      });
      req.on("timeout", () => { try { req.destroy(); } catch {} resolve({ status: 0, json: null }); });
      req.on("error", () => resolve({ status: 0, json: null }));
      req.setTimeout(timeoutMs);
      if (payload) req.write(payload);
      req.end();
    } catch {
      resolve({ status: 0, json: null });
    }
  });
}

/* === ADDITIONS: HTTP JSON cu body === */
function httpJson(fullUrl, { method = "GET", headers = {}, body = null, timeoutMs = 5000 } = {}) {
  return new Promise((resolve) => {
    try {
      const lib = fullUrl.startsWith("https:") ? https : http;
      const opts = { method, headers };
      const req = lib.request(fullUrl, opts, (res) => {
        const chunks = [];
        res.on("data", (d) => chunks.push(d));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json = null;
          try { json = text ? JSON.parse(text) : null; } catch {}
          resolve({ status: res.statusCode, json, text });
        });
      });
      req.on("timeout", () => { try { req.destroy(); } catch {} resolve({ status: 0, json: null }); });
      req.on("error", () => resolve({ status: 0, json: null }));
      req.setTimeout(timeoutMs);
      if (body != null) {
        const data = typeof body === "string" ? body : JSON.stringify(body);
        if (!headers["Content-Type"]) req.setHeader("Content-Type", "application/json");
        req.setHeader("Content-Length", Buffer.byteLength(data));
        req.write(data);
      }
      req.end();
    } catch {
      resolve({ status: 0, json: null });
    }
  });
}

function tcpCheck(host, port, timeoutMs = 2000) {
  return new Promise((resolve) => {
    try {
      const socket = new net.Socket();
      let finished = false;
      const done = (ok) => {
        if (finished) return;
        finished = true;
        try { socket.destroy(); } catch {}
        resolve(!!ok);
      };
      socket.setTimeout(timeoutMs);
      socket.once("connect", () => done(true));
      socket.once("timeout", () => done(false));
      socket.once("error", () => done(false));
      socket.connect(clampPort(port || 8080), host);
    } catch {
      resolve(false);
    }
  });
}

/**
 * Verifică nodul.
 * - Dacă opts.force === true -> ignoră rate-limit (verifică acum).
 * - True doar dacă HTTP răspunde cu uuid valid (/v1/info cu Bearer sau /health).
 * - Altfel setează port_ok = false.
 */
async function activeCheckNode(node, opts = { force: false }) {
  const now = Date.now();

  // rate-limit dacă nu e forțat
  if (!opts.force && node.last_check && (now - Number(node.last_check)) < 5000) return;

  node.last_check = now;

  // 💡 Dacă avem heartbeat recent (în TTL), considerăm nodul online
  // și NU mai stricăm starea doar pentru că panelul nu poate ieși spre agent.
  const lastSeen = Number(node.last_seen || 0);
  if (lastSeen && (now - lastSeen) < HEARTBEAT_TTL_MS) {
    node.port_ok = true;
    return;
  }

  // 🔁 Fallback: dacă heartbeat-ul e vechi/expirat, încercăm reach out strict:
  // /v1/info cu Bearer (identitate), apoi /health (cu uuid). Doar dacă reușim,
  // îl punem online; altfel îl punem offline.
  let ok = false;
  try {
    const baseUrl = buildNodeBaseUrl(node.address, node.api_port);
    if (baseUrl) {
      // /v1/info cu Bearer
      const infoRes = await httpRequestJson(
        `${baseUrl}/v1/info`,
        "GET",
        { "Authorization": `Bearer ${node.token}` },
        2500
      );
      if (infoRes.status === 200 && infoRes.json && infoRes.json.ok && infoRes.json.node) {
        const uuid = String(infoRes.json.node.uuid || "");
        if (uuid && (uuid === node.uuid || uuid === node.id)) ok = true;
      }

      // Fallback /health (doar dacă include uuid valid)
      if (!ok) {
        const healthRes = await httpRequestJson(`${baseUrl}/health`, "GET", {}, 2500);
        if (healthRes.status === 200 && healthRes.json && healthRes.json.uuid) {
          const uuid = String(healthRes.json.uuid || "");
          if (uuid && (uuid === node.uuid || uuid === node.id)) ok = true;
        }
      }
    }
  } catch {
    ok = false;
  }

  node.port_ok = !!ok;
  if (ok) {
    // dacă am reușit reach out, actualizăm și last_seen (practic tot un "proof of life")
    node.last_seen = now;
  }
}

// ------------- Config.yml + one-time command helpers -------------
function buildConfigYml(node, req) {
  const host = req.get("x-forwarded-host") || req.get("host") || "localhost";
  const proto = (req.get("x-forwarded-proto") || req.protocol || "http");
  const panelUrl = `${proto}://${host}`;

  const lines = [
    `debug: false`,
    `uuid: ${node.uuid}`,
    `token_id: ${node.token_id}`,
    `token: ${node.token}`,
    `auth:`,
    `  token_id: ${node.token_id}`,
    `  token: ${node.token}`,
    `api:`,
    `  host: 0.0.0.0`,
    `  port: ${node.api_port || 8080}`,
    `  ssl:`,
    `    enabled: false`,
    `    cert: ""`,
    `    key: ""`,
    `  upload_limit: 1024`,
    `system:`,
    `  data: /var/lib/node/volumes`,
    `  sftp:`,
    `    bind_port: 2022`,
    `allowed_mounts: []`,
    `panel:`,
    `  url: ${panelUrl}`,
    `  node_id: ${node.uuid}`
  ];
  return lines.join("\n") + "\n";
}

function oneTimeCommand(node, req) {
  const host = req.get("x-forwarded-host") || req.get("host") || "localhost";
  const proto = (req.get("x-forwarded-proto") || req.protocol || "http");
  const base = `${proto}://${host}`;
  const url = `${base}/api/nodes/${encodeURIComponent(node.uuid)}/config.yml`;
  return `mkdir -p /etc/adnode && curl -fsSL "${url}" -o /etc/adnode/config.yml && echo "Config saved to /etc/adnode/config.yml"`;
}

// ------------- App -------------
const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

// CORS light
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-Node-Token-Id");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// Health
app.get("/health", (_req, res) => res.json({ ok: true }));

// -------- LIST (rapid) + verificare forțată în fundal --------
app.get("/api/nodes", (req, res) => {
  const list = loadNodes();

  // răspundem imediat cu starea actuală…
  res.json({ nodes: list.map(toPublic) });

  // …și apoi verificăm reachability FORȚAT, fără să blocăm răspunsul
  setImmediate(async () => {
    try {
      await Promise.all(list.map(async (n) => { await activeCheckNode(n, { force: true }); }));
      saveNodes(list);
    } catch (_) {}
  });
});

// -------- GET one (rapid) --------
app.get("/api/nodes/:id", (req, res) => {
  const node = findNodeByIdOrName(req.params.id);
  if (!node) return res.status(404).json({ error: "not found" });

  // răspundem imediat
  res.json(toPublic(node));

  // după răspuns, rulăm un check 1-shot forțat
  setImmediate(async () => {
    try {
      await activeCheckNode(node, { force: true });
      const list = loadNodes();
      const idx = list.findIndex(n =>
        String(n.id) === String(node.id) ||
        String(n.uuid) === String(node.uuid) ||
        String(n.name).toLowerCase() === String(node.name).toLowerCase()
      );
      if (idx !== -1) {
        list[idx] = node;
        saveNodes(list);
      }
    } catch (_) {}
  });
});

// endpoint opțional pentru verificare manuală imediată din UI (buton “Re-check”)
app.post("/api/nodes/:id/check", async (req, res) => {
  const list = loadNodes();
  const idx = list.findIndex(n =>
    String(n.id) === String(req.params.id) ||
    String(n.uuid) === String(req.params.id) ||
    String(n.name).toLowerCase() === String(req.params.id).toLowerCase()
  );
  if (idx === -1) return res.status(404).json({ error: "not found" });

  await activeCheckNode(list[idx], { force: true });
  saveNodes(list);
  res.json({ ok: true, node: toPublic(list[idx]) });
});

// Action bridge: rulează acțiuni pe serverul de pe nod (run/stop/status/rm)
app.post("/api/nodes/:id/server/action", async (req, res) => {
  const node = findNodeByIdOrName(req.params.id);
  if (!node) return res.status(404).json({ error: "node_not_found" });

  const name = String(req.body?.name || req.body?.server || req.body?.bot || "").trim();
  const cmd  = String(req.body?.cmd  || req.body?.action || "").toLowerCase();
  if (!name || !cmd) return res.status(400).json({ error: "missing_params" });

  let path = "", method = "POST", body = {};
  if (cmd === "run" || cmd === "start") {
    path = `/v1/servers/${encodeURIComponent(name)}/start`;
    // agentul tău acceptă hostPort în body; păstrează dacă vine din UI
    if (req.body?.hostPort) body.hostPort = Number(req.body.hostPort);
  } else if (cmd === "stop") {
    path = `/v1/servers/${encodeURIComponent(name)}/stop`;
  } else if (cmd === "restart") {
    path = `/v1/servers/${encodeURIComponent(name)}/restart`;
  } else if (cmd === "status") {
    method = "GET";
    path = `/v1/servers/${encodeURIComponent(name)}`;
  } else {
    return res.status(400).json({ error: "unknown_cmd" });
  }

  const { status, json } = await callNodeApi(node, path, method, body);
  if (status === 200 && json) return res.json(json);
  return res.status(500).json({ error: "node_action_failed", status, detail: json && json.error });
});

// Command bridge: trimite o comandă în consola containerului de pe nod
app.post("/api/nodes/:id/server/command", async (req, res) => {
  const node = findNodeByIdOrName(req.params.id);
  if (!node) return res.status(404).json({ error: "node_not_found" });

  const name = String(req.body?.name || req.body?.server || req.body?.bot || "").trim();
  const command = String(req.body?.command || "").trim();
  if (!name || !command) return res.status(400).json({ error: "missing_params" });

  const { status, json } = await callNodeApi(node, "/v1/server/command", "POST", { name, command });

  if (status === 200 && json && json.ok) return res.json(json);
  return res.status(500).json({
    error: "node_command_failed",
    status,
    detail: json && (json.error || json.msg)
  });
});

// Create bridge: creează server pe nod (scrie jar/meta) și poate porni automat containerul
app.post("/api/nodes/:id/servers/create", async (req, res) => {
  const node = findNodeByIdOrName(req.params.id);
  if (!node) return res.status(404).json({ error: "node_not_found" });

  const name = String(req.body?.name || "").trim();
  const templateId = String(req.body?.templateId || "minecraft");
  const mcFork = String(req.body?.mcFork || "paper");
  const mcVersion = String(req.body?.mcVersion || "1.21.8");
  const hostPort = Number(req.body?.hostPort || 25565);
  const autoStart = !!req.body?.autoStart;

  if (!name) return res.status(400).json({ error: "missing_name" });

  const { status, json } = await callNodeApi(
    node, "/v1/servers/create", "POST",
    { name, templateId, mcFork, mcVersion, hostPort, autoStart }
  );

  if (status === 200 && json && json.ok) return res.json(json);
  return res.status(500).json({ error: "node_create_failed", status, detail: json && json.error });
});

// -------- CREATE --------
app.post("/api/nodes", (req, res) => {
  const body = req.body || {};
  const name = sanitizeName(body.name || body.node || body.id);
  const address = String(body.address || body.ip || body.fqdn || "").trim();
  if (!name) return res.status(400).json({ error: "invalid name" });
  if (!address) return res.status(400).json({ error: "invalid address" });

  const list = loadNodes();
  if (list.find(n => String(n.name).toLowerCase() === name.toLowerCase())) {
    return res.status(400).json({ error: "node already exists" });
  }

  const ram_mb =
    (typeof body.ram_mb !== "undefined") ? toInt(body.ram_mb, 0) :
    (typeof body.ramMB !== "undefined") ? toInt(body.ramMB, 0) :
    (typeof body.ram_gb !== "undefined") ? toInt(body.ram_gb, 0) * 1024 : 0;

  const disk_gb =
    (typeof body.disk_gb !== "undefined") ? toInt(body.disk_gb, 0) :
    (typeof body.storage_gb !== "undefined") ? toInt(body.storage_gb, 0) :
    (typeof body.storageGB !== "undefined") ? toInt(body.storageGB, 0) : 0;

  const ports = normalizePorts(body.ports);
  const api_port = clampPort(body.api_port || 8080);

  const node = hardenNode({
    id: uid(),
    uuid: undefined,            // se setează în hardenNode ca alias la id
    name,
    address,
    ram_mb,
    disk_gb,
    ports,
    token_id: randTokenId(),
    token: randSecret(),
    createdAt: Date.now(),

    api_port,
    port_ok: null,
    last_seen: null,
    last_check: null,

    buildConfig: {}
  });

  list.push(node);
  saveNodes(list);

  res.json(toPublic(node));
});

// -------- UPDATE --------
app.patch("/api/nodes/:id", (req, res) => {
  const list = loadNodes();
  const idx = list.findIndex(n =>
    String(n.id) === String(req.params.id) ||
    String(n.uuid) === String(req.params.id) ||
    String(n.name).toLowerCase() === String(req.params.id).toLowerCase()
  );
  if (idx === -1) return res.status(404).json({ error: "not found" });

  const current = hardenNode(list[idx]);
  const upd = sanitizeUpdatePayload(req.body || {});

  if (typeof upd.name !== "undefined" && upd.name) current.name = upd.name;
  if (typeof upd.address !== "undefined") current.address = upd.address;
  if (typeof upd.ram_mb !== "undefined" && upd.ram_mb >= 0) current.ram_mb = upd.ram_mb;
  if (typeof upd.disk_gb !== "undefined" && upd.disk_gb >= 0) current.disk_gb = upd.disk_gb;
  if (typeof upd.ports !== "undefined") current.ports = normalizePorts(upd.ports);
  if (typeof upd.api_port !== "undefined") current.api_port = clampPort(upd.api_port);

  // după update, resetăm ultimul check (forțăm o verificare proaspătă în background)
  current.last_check = null;

  list[idx] = hardenNode(current);
  saveNodes(list);
  res.json(toPublic(list[idx]));
});

// -------- DELETE --------
app.delete("/api/nodes/:id", (req, res) => {
  const list = loadNodes();
  const node = findNodeByIdOrName(req.params.id);
  if (!node) return res.status(404).json({ error: "not found" });

  // dacă există servers.json și are servere atașate la acest nod, blochează
  try {
    const servers = readJson(SERVERS_FILE, []);
    const attached = (Array.isArray(servers) ? servers : []).filter(s => {
      const v = (s && (s.node || s.nodeId || s.node_id)) || "";
      return String(v).toLowerCase() === String(node.uuid).toLowerCase() ||
             String(v).toLowerCase() === String(node.name).toLowerCase();
    });
    if (attached.length > 0) {
      return res.status(400).json({ error: "cannot delete node with servers attached", servers: attached.map(s => s.name).filter(Boolean) });
    }
  } catch {}

  const after = list.filter(n => String(n.id) !== String(node.id));
  saveNodes(after);
  res.json({ ok: true });
});

// -------- BUILD CONFIG --------
app.get("/api/nodes/:id/build", (req, res) => {
  const node = findNodeByIdOrName(req.params.id);
  if (!node) return res.status(404).json({ error: "not found" });
  res.json({ build: node.buildConfig || {} });
});
app.post("/api/nodes/:id/build", (req, res) => {
  const list = loadNodes();
  const idx = list.findIndex(n =>
    String(n.id) === String(req.params.id) ||
    String(n.uuid) === String(req.params.id) ||
    String(n.name).toLowerCase() === String(req.params.id).toLowerCase()
  );
  if (idx === -1) return res.status(404).json({ error: "not found" });
  const incoming = (req.body && typeof req.body === "object") ? req.body : {};
  list[idx].buildConfig = incoming;
  saveNodes(list);
  res.json({ ok: true });
});

// -------- CONFIG.YML + one-time command --------
app.get("/api/nodes/:id/config.yml", (req, res) => {
  const node = findNodeByIdOrName(req.params.id);
  if (!node) return res.status(404).send("not found");
  const yml = buildConfigYml(node, req);
  res.setHeader("Content-Type", "text/yaml; charset=utf-8");
  res.send(yml);
});

app.get("/api/nodes/:id/one-time-command", (req, res) => {
  const node = findNodeByIdOrName(req.params.id);
  if (!node) return res.status(404).json({ error: "not found" });
  res.json({ command: oneTimeCommand(node, req) });
});

// -------- Heartbeat (node -> panel) + verificare reachability strictă --------
app.post("/api/nodes/:id/heartbeat", async (req, res) => {
  try {
    const list = loadNodes();
    const idx = list.findIndex(n =>
      String(n.id) === String(req.params.id) ||
      String(n.uuid) === String(req.params.id) ||
      String(n.name).toLowerCase() === String(req.params.id).toLowerCase()
    );
    if (idx === -1) return res.status(404).json({ error: "not found" });

    const node = hardenNode(list[idx]);

    // Validare token (header sau body) — dacă e greșit, respingem heartbeat-ul
    const authHeader = req.get("authorization") || "";
    const bearer = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    const body = req.body || {};
    const bodyToken = body.token || null;
    const bodyTokenId = body.token_id || null;

    if (bearer && bearer !== node.token) return res.status(401).json({ error: "invalid token" });
    if (!bearer && bodyToken && bodyToken !== node.token) return res.status(401).json({ error: "invalid token" });
    if (bodyTokenId && bodyTokenId !== node.token_id) {
      // nu rupem pentru token_id nepotrivit, dar ai opțiunea să faci return 401 aici
    }

    // Agentul poate raporta/actualiza portul API
    if (typeof body.api_port !== "undefined") node.api_port = clampPort(body.api_port);

    // 💚 Heartbeat primit + token valid => considerăm nodul online ACUM
    node.last_seen = Date.now();
    node.port_ok = true;        // <— AICI era problema: îl puneai pe false după un call nereușit de la panel spre node
    node.last_check = Date.now();

    list[idx] = node;
    saveNodes(list);

    return res.json({
      ok: true,
      now: node.last_seen,
      port_ok: node.port_ok,
      online: computeOnline(node) // true dacă last_seen e în TTL și port_ok=true
    });
  } catch (e) {
    console.error("[heartbeat] failed:", e && e.message);
    return res.status(500).json({ error: "heartbeat failed" });
  }
});

// -------- Watchdog periodic (la 5s) care ACTUALIZEAZĂ port_ok în nodes.json --------
setInterval(async () => {
  try {
    const list = loadNodes();
    await Promise.all(list.map(async (n) => { await activeCheckNode(n, { force: true }); }));
    saveNodes(list);
  } catch (_) {}
}, 5000);

/* ====================== */
/* === NEW: BRIDGE API ===*/
/* ====================== */

// Baza de date pe nod pentru volume servere
const NODE_VOLUME_ROOT = "/var/lib/node/volumes/volumes";

// servers.json helpers
function loadServers() {
  const arr = readJson(SERVERS_FILE, []);
  return Array.isArray(arr) ? arr : [];
}
function findServerByNameOrId(name) {
  const list = loadServers();
  const key = String(name || "").trim();
  const lower = key.toLowerCase();
  return list.find(s =>
    String(s.name || "").toLowerCase() === lower ||
    String(s.id || "").toLowerCase() === lower
  ) || null;
}
function serverNodeRef(srv) {
  return (srv && (srv.node || srv.nodeId || srv.node_id)) || null;
}
function buildServerInfo(srv) {
  if (!srv) return {};
  const ip = srv.ip || srv.host || srv.address || srv.hostname || null;
  const port = srv.port || srv.server_port || srv.bind_port || null;
  const start = srv.start || srv.startFile || srv.entry || null;
  return { ip, port, start };
}
function nodeHeaders(node) {
  return {
    "Authorization": `Bearer ${node.token || ""}`,
    "X-Node-Token": node.token || "",
    "X-Node-Token-Id": node.token_id || ""
  };
}
function nodeUrl(node, suffix) {
  const base = buildNodeBaseUrl(node.address, node.api_port);
  return `${base}${suffix}`;
}
function safeJoinUnix(base, rel) {
  const b = base.endsWith("/") ? base.slice(0, -1) : base;
  const raw = String(rel || "").replace(/\\/g, "/");
  const norm = path.posix.normalize("/" + raw).replace(/^\/+/, ""); // relative, no leading /
  const joined = `${b}/${norm}`;
  // ensure within base
  if (!joined.startsWith(b + "/") && joined !== b) throw new Error("path traversal");
  return joined;
}
function mapFsEntries(entries) {
  // normalize răspuns agent -> UI
  const out = [];
  (entries || []).forEach(e => {
    if (!e || !e.name) return;
    out.push({ name: e.name, isDir: !!(e.type === "dir" || e.isDir) });
  });
  return out;
}
function remoteContext(serverName) {
  const srv = findServerByNameOrId(serverName);
  if (!srv) return { exists: false };
  const ref = serverNodeRef(srv);
  if (!ref) return { exists: true, remote: false, info: buildServerInfo(srv) };

  const node = findNodeByIdOrName(ref);
  if (!node) return { exists: true, remote: false, info: buildServerInfo(srv) };

  const baseDir = `${NODE_VOLUME_ROOT}/${sanitizeName(srv.name || serverName)}`;
  return {
    exists: true,
    remote: true,
    node,
    nodeId: node.uuid,
    baseDir,
    info: buildServerInfo(srv)
  };
}

// 1) INFO — spune UI-ului dacă serverul e pe nod extern
app.get("/api/nodes/server/:name/info", async (req, res) => {
  const ctx = remoteContext(req.params.name);
  if (!ctx.exists) return res.json({ ok: false, remote: false, info: null });

  // dacă e remote, verifică și starea nodului
  if (ctx.remote && ctx.node) {
    try { await activeCheckNode(ctx.node, { force: true }); } catch {}
    return res.json({
      ok: true,
      remote: true,
      nodeId: ctx.node.uuid,
      info: ctx.info || {},
      baseDir: ctx.baseDir
    });
  }
  return res.json({ ok: true, remote: false, nodeId: null, info: ctx.info || {} });
});

// 2) LISTARE fișiere (bridge către nod)
app.get("/api/nodes/server/:name/entries", async (req, res) => {
  const ctx = remoteContext(req.params.name);
  if (!ctx.exists) return res.status(404).json({ error: "server not found" });
  if (!ctx.remote || !ctx.node) return res.status(400).json({ error: "not_remote" });

  const rel = String(req.query.path || "");
  try {
    const full = safeJoinUnix(ctx.baseDir, rel);
    const { status, json } = await httpJson(
      nodeUrl(ctx.node, "/v1/fs/list"),
      { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, nodeHeaders(ctx.node)), body: { path: full, depth: 1 } }
    );
    if (status !== 200 || !json || !json.ok) return res.status(502).json({ error: "node_list_failed" });
    return res.json({ path: rel, entries: mapFsEntries(json.entries || []) });
  } catch (e) {
    return res.status(400).json({ error: e && e.message ? e.message : "bad_path" });
  }
});

// 3) READ FILE
app.get("/api/nodes/server/:name/file", async (req, res) => {
  const ctx = remoteContext(req.params.name);
  if (!ctx.exists) return res.status(404).json({ error: "server not found" });
  if (!ctx.remote || !ctx.node) return res.status(400).json({ error: "not_remote" });

  const rel = String(req.query.path || "");
  try {
    const full = safeJoinUnix(ctx.baseDir, rel);
    const { status, json } = await httpJson(
      nodeUrl(ctx.node, "/v1/fs/read"),
      { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, nodeHeaders(ctx.node)), body: { path: full, encoding: "utf8" } }
    );
    if (status !== 200 || !json || !json.ok) return res.status(502).json({ error: "node_read_failed" });
    return res.json({ path: rel, content: typeof json.content === "string" ? json.content : "" });
  } catch (e) {
    return res.status(400).json({ error: e && e.message ? e.message : "bad_path" });
  }
});

// 4) WRITE FILE
app.post("/api/nodes/server/:name/file", async (req, res) => {
  const ctx = remoteContext(req.params.name);
  if (!ctx.exists) return res.status(404).json({ error: "server not found" });
  if (!ctx.remote || !ctx.node) return res.status(400).json({ error: "not_remote" });

  const rel = String(req.body.path || "");
  const content = String((req.body && req.body.content) || "");
  try {
    const full = safeJoinUnix(ctx.baseDir, rel);
    const { status, json } = await httpJson(
      nodeUrl(ctx.node, "/v1/fs/write"),
      { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, nodeHeaders(ctx.node)), body: { path: full, content, encoding: "utf8" } }
    );
    if (status !== 200 || !json || !json.ok) return res.status(502).json({ error: "node_write_failed" });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(400).json({ error: e && e.message ? e.message : "bad_path" });
  }
});

// 5) DELETE (file/folder)
app.post("/api/nodes/server/:name/delete", async (req, res) => {
  const ctx = remoteContext(req.params.name);
  if (!ctx.exists) return res.status(404).json({ error: "server not found" });
  if (!ctx.remote || !ctx.node) return res.status(400).json({ error: "not_remote" });

  const rel = String(req.body.path || "");
  const isDir = !!req.body.isDir;
  try {
    const full = safeJoinUnix(ctx.baseDir, rel);
    const { status, json } = await httpJson(
      nodeUrl(ctx.node, "/v1/fs/delete"),
      { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, nodeHeaders(ctx.node)), body: { path: full, isDir } }
    );
    if (status !== 200 || !json || !json.ok) return res.status(502).json({ error: "node_delete_failed" });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(400).json({ error: e && e.message ? e.message : "bad_path" });
  }
});

// 6) RENAME
app.post("/api/nodes/server/:name/rename", async (req, res) => {
  const ctx = remoteContext(req.params.name);
  if (!ctx.exists) return res.status(404).json({ error: "server not found" });
  if (!ctx.remote || !ctx.node) return res.status(400).json({ error: "not_remote" });

  const rel = String(req.body.path || "");
  const newName = sanitizeName(req.body.newName || "");
  if (!newName) return res.status(400).json({ error: "invalid newName" });
  try {
    const full = safeJoinUnix(ctx.baseDir, rel);
    const { status, json } = await httpJson(
      nodeUrl(ctx.node, "/v1/fs/rename"),
      { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, nodeHeaders(ctx.node)), body: { path: full, newName } }
    );
    if (status !== 200 || !json || !json.ok) return res.status(502).json({ error: "node_rename_failed" });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(400).json({ error: e && e.message ? e.message : "bad_path" });
  }
});

// 7) EXTRACT (arhive)
app.post("/api/nodes/server/:name/extract", async (req, res) => {
  const ctx = remoteContext(req.params.name);
  if (!ctx.exists) return res.status(404).json({ error: "server not found" });
  if (!ctx.remote || !ctx.node) return res.status(400).json({ error: "not_remote" });

  const rel = String(req.body.path || "");
  try {
    const full = safeJoinUnix(ctx.baseDir, rel);
    const { status, json } = await httpJson(
      nodeUrl(ctx.node, "/v1/fs/extract"),
      { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, nodeHeaders(ctx.node)), body: { path: full } }
    );
    if (status !== 200 || !json || !json.ok) return res.status(502).json({ error: "node_extract_failed" });
    return res.json({ ok: true, msg: json.msg || "Extracted" });
  } catch (e) {
    return res.status(400).json({ error: e && e.message ? e.message : "bad_path" });
  }
});

// 8) UPLOAD (multipart -> base64 forward)
app.post("/api/nodes/server/:name/upload", upload.single("file"), async (req, res) => {
  const ctx = remoteContext(req.params.name);
  if (!ctx.exists) return res.status(404).json({ error: "server not found" });
  if (!ctx.remote || !ctx.node) return res.status(400).json({ error: "not_remote" });

  const rel = String(req.body.path || "");
  const file = req.file;
  if (!file) return res.status(400).json({ error: "no_file" });

  try {
    const full = safeJoinUnix(ctx.baseDir, rel ? rel : "");
    // Forward ca upload raw (base64) — agentul nodului va scrie fișierul
    const payload = {
      dir: full,
      filename: file.originalname,
      data_b64: file.buffer.toString("base64")
    };
    const { status, json } = await httpJson(
      nodeUrl(ctx.node, "/v1/fs/uploadRaw"),
      { method: "POST", headers: Object.assign({ "Content-Type": "application/json" }, nodeHeaders(ctx.node)), body: payload, timeoutMs: 120000 }
    );
    if (status !== 200 || !json || !json.ok) return res.status(502).json({ error: "node_upload_failed" });
    return res.json({ ok: true, msg: json.msg || "Uploaded" });
  } catch (e) {
    return res.status(400).json({ error: e && e.message ? e.message : "bad_path" });
  }
});

// 9) ACTION (run/stop/restart/status) – mapat pe /v1/servers/:name/*
app.post("/api/nodes/server/:name/action", async (req, res) => {
  try {
    const ctx = remoteContext(req.params.name);
    if (!ctx.exists) return res.status(404).json({ error: "server not found" });
    if (!ctx.remote || !ctx.node) return res.status(400).json({ error: "not_remote" });

    const cmdRaw = String((req.body && (req.body.cmd || req.body.action)) || "").toLowerCase();
    const cmd = (cmdRaw === "run") ? "start" : cmdRaw; // alias
    const hostPort = Number(req.body && req.body.hostPort);

    let path = null, method = "POST", payload = null;
    if (cmd === "start") {
      path = `/v1/servers/${encodeURIComponent(req.params.name)}/start`;
      if (Number.isFinite(hostPort)) payload = { hostPort };
    } else if (cmd === "stop") {
      path = `/v1/servers/${encodeURIComponent(req.params.name)}/stop`;
    } else if (cmd === "restart") {
      path = `/v1/servers/${encodeURIComponent(req.params.name)}/restart`;
    } else if (cmd === "status") {
      method = "GET";
      path = `/v1/servers/${encodeURIComponent(req.params.name)}`;
    } else {
      return res.status(400).json({ error: "invalid_cmd" });
    }

    const { status, json } = await callNodeApi(ctx.node, path, method, payload);
    if (status === 200 && json) return res.json(json);
    return res.status(502).json({ error: "node_action_failed", status, detail: json && json.error });
  } catch (e) {
    return res.status(500).json({ error: "bridge_failed", detail: e && e.message });
  }
});

// 10) CONSOLE COMMAND – mapat pe /v1/servers/:name/command
app.post("/api/nodes/server/:name/command", async (req, res) => {
  try {
    const ctx = remoteContext(req.params.name);
    if (!ctx.exists) return res.status(404).json({ error: "server not found" });
    if (!ctx.remote || !ctx.node) return res.status(400).json({ error: "not_remote" });

    const command = String((req.body && req.body.command) || "").trim();
    if (!command) return res.status(400).json({ error: "empty_command" });

    const { status, json } = await callNodeApi(
      ctx.node,
      `/v1/servers/${encodeURIComponent(req.params.name)}/command`,
      "POST",
      { command }
    );
    if (status === 200 && json && json.ok) return res.json(json);
    return res.status(502).json({ error: "node_command_failed", status, detail: json && json.error });
  } catch (e) {
    return res.status(500).json({ error: "bridge_failed", detail: e && e.message });
  }
});

app.post("/api/nodes/:id/server/action", async (req, res) => {
  try {
    const node = findNodeByIdOrName(req.params.id);
    if (!node) return res.status(404).json({ error: "not found" });

    const name = String((req.body && req.body.name) || "").trim();
    const finalCmd = (cmd === "run") ? "start" : cmd;
    const cmd = String((req.body && req.body.cmd) || "").trim().toLowerCase();
    const hostPort = req.body && req.body.hostPort ? Number(req.body.hostPort) : undefined;

    if (!name || !cmd) return res.status(400).json({ error: "missing name/cmd" });

    let path = null;
    let payload = null;

    if (cmd === "start") {
      path = `/v1/servers/${encodeURIComponent(name)}/start`;
      // payload e opțional; agentul ia portul și din adpanel.json, dar îl trimitem dacă l-ai setat
      if (Number.isFinite(hostPort)) payload = { hostPort };
    } else if (cmd === "stop") {
      path = `/v1/servers/${encodeURIComponent(name)}/stop`;
    } else if (cmd === "restart") {
      path = `/v1/servers/${encodeURIComponent(name)}/restart`;
    } else {
      return res.status(400).json({ error: "invalid cmd" });
    }

    const { status, json } = await callNodeApi(node, path, "POST", payload);
    if (status === 200 && json && (json.ok === true || json.ok === undefined)) {
      return res.json(json || { ok: true });
    }
    return res.status(502).json({ error: "node_action_failed", detail: `HTTP ${status}`, response: json });
  } catch (e) {
    return res.status(500).json({ error: "bridge_failed", detail: e && e.message });
  }
});

// -------- Bridge: command pe serverul de pe nod --------
app.post("/api/nodes/:id/server/command", async (req, res) => {
  try {
    const node = findNodeByIdOrName(req.params.id);
    if (!node) return res.status(404).json({ error: "not found" });

    const name = String((req.body && req.body.name) || "").trim();
    const command = String((req.body && req.body.command) || "").trim();
    if (!name || !command) return res.status(400).json({ error: "missing name/command" });

    const { status, json } = await callNodeApi(
      node,
      `/v1/servers/${encodeURIComponent(name)}/command`,
      "POST",
      { command }
    );

    if (status === 200 && json && json.ok) return res.json(json);
    return res.status(502).json({ error: "node_action_failed", detail: `HTTP ${status}`, response: json });
  } catch (e) {
    return res.status(500).json({ error: "bridge_failed", detail: e && e.message });
  }
});

app.get("/api/nodes/server/:name/info", (req, res) => {
  const { server, node } = resolveNodeForServer(req.params.name);
  if (!server || !node) return res.json({ remote: false, info: null });

  const ip = server.ip || node.address || null;
  const port = (server.port !== undefined && server.port !== null) ? server.port : null;

  return res.json({
    remote: true,
    nodeId: node.uuid,
    info: {
      ip, port,
      start: server.start || "server.jar",
      nodeName: node.name
    }
  });
});

// -------- Bridge: acțiuni (start/stop/restart) prin numele serverului --------
app.post("/api/nodes/server/:name/action", async (req, res) => {
  try {
    const { node } = resolveNodeForServer(req.params.name);
    if (!node) return res.status(404).json({ error: "server_or_node_not_found" });

    const cmd = String((req.body && req.body.cmd) || "").trim().toLowerCase();
    if (!cmd) return res.status(400).json({ error: "missing cmd" });

    let path = null;
    let payload = null;

    if (cmd === "start") {
      path = `/v1/servers/${encodeURIComponent(req.params.name)}/start`;
      const hostPort = req.body && Number(req.body.hostPort);
      if (Number.isFinite(hostPort)) payload = { hostPort };
    } else if (cmd === "stop") {
      path = `/v1/servers/${encodeURIComponent(req.params.name)}/stop`;
    } else if (cmd === "restart") {
      path = `/v1/servers/${encodeURIComponent(req.params.name)}/restart`;
    } else {
      return res.status(400).json({ error: "invalid cmd" });
    }

    const { status, json } = await callNodeApi(node, path, "POST", payload);
    if (status === 200 && json && (json.ok === true || json.ok === undefined)) {
      return res.json(json || { ok: true });
    }
    return res.status(502).json({ error: "node_action_failed", detail: `HTTP ${status}`, response: json });
  } catch (e) {
    return res.status(500).json({ error: "bridge_failed", detail: e && e.message });
  }
});

// -------- Bridge: command prin numele serverului --------
app.post("/api/nodes/server/:name/command", async (req, res) => {
  try {
    const { node } = resolveNodeForServer(req.params.name);
    if (!node) return res.status(404).json({ error: "server_or_node_not_found" });

    const command = String((req.body && req.body.command) || "").trim();
    if (!command) return res.status(400).json({ error: "missing command" });

    const { status, json } = await callNodeApi(
      node,
      `/v1/servers/${encodeURIComponent(req.params.name)}/command`,
      "POST",
      { command }
    );

    if (status === 200 && json && json.ok) return res.json(json);
    return res.status(502).json({ error: "node_action_failed", detail: `HTTP ${status}`, response: json });
  } catch (e) {
    return res.status(500).json({ error: "bridge_failed", detail: e && e.message });
  }
});

// -------- Bridge: LOGS (SSE proxy) prin numele serverului --------
app.get("/api/nodes/server/:name/logs", async (req, res) => {
  try {
    const { node } = resolveNodeForServer(req.params.name);
    if (!node) return res.status(404).json({ error: "server_or_node_not_found" });

    // pregătește SSE către client
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
    res.flushHeaders?.();

    // conectează-te la logs SSE al agentului
    const base = buildNodeBaseUrl(node.address, node.api_port);
    const fullUrl = `${base}/v1/servers/${encodeURIComponent(req.params.name)}/logs`;
    const isHttps = fullUrl.startsWith("https:");
    const lib = isHttps ? https : http;

    const nreq = lib.request(fullUrl, {
      method: "GET",
      headers: { "Authorization": `Bearer ${node.token}` }
    }, (nres) => {
      nres.on("data", (chunk) => { try { res.write(chunk); } catch {} });
      nres.on("end", () => { try { res.end(); } catch {} });
    });

    nreq.on("error", () => { try { res.end(); } catch {} });
    nreq.end();

    req.on("close", () => { try { nreq.destroy(); } catch {} });
  } catch {
    try { res.end(); } catch {}
  }
});

// ---------------- Start server (standalone) ----------------
if (require.main === module) {
  app.listen(PORT, () => console.log(`[nodes.js] Nodes API on :${PORT}`));
}

module.exports = app;
