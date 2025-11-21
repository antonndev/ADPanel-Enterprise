/* eslint-disable */
const express = require("express");
const path = require("path");
const fs = require("fs");
const fsp = require("fs/promises");
const net = require("net");
const dns = require("dns").promises;
const AdmZip = require("adm-zip");
const multer = require("multer");
const session = require("express-session");
const { spawn } = require("child_process");
const FileStore = require("session-file-store")(session);
const https = require("https");
const _startedOnce = new Set();
const nodesRouter = require("./nodes.js");
const httpMod = require("http");
const { URL } = require("url");
const lineBuffers  = {};            // name -> string (buffer pentru linii neterminate)
const logProcesses = {};            // name -> child process (docker logs -f)

let bcrypt;
try {
  bcrypt = require("bcrypt");
} catch (e) {
  console.log("Detected termux environment... Installing BcryptJS");
  bcrypt = require("bcryptjs");
}
let speakeasy;
try {
  speakeasy = require("speakeasy");
} catch (e) {
  console.log("Speakeasy is not installed correctly...");
  process.exit(1);
}
const tar = require("tar");
const crypto = require("crypto");

const app = express();
const http = require("http").createServer(app);
const io = require("socket.io")(http);

// --- DIRECTOARE / FISIERE ---
const BOTS_DIR = path.join(__dirname, "bots");
const UPLOADS_DIR = path.join(__dirname, "uploads");
const PUBLIC_DIR = path.join(__dirname, "public");
const DASHBOARD_CSS = path.join(PUBLIC_DIR, "dashboard.css");
const STYLE_CSS = path.join(PUBLIC_DIR, "style.css");
const CONFIG_FILE = path.join(__dirname, "config.json");
const NODE_AGENT_PORT = parseInt(process.env.NODE_AGENT_PORT || '8080', 10);
const LOCAL_NODE_TOKEN = process.env.NODE_AGENT_TOKEN || process.env.NODE_TOKEN || null;
const USER_ACCESS_FILE = path.join(__dirname, "user-access.json");
const USERS_FILE = path.join(__dirname, "user.json");
const remoteLogClients = {};
const SECURITY_FILE = path.join(__dirname, "security.json");
const SERVERS_FILE = path.join(__dirname, "servers.json"); // index cu start file
const versionsPath = path.join(__dirname, 'versions.json');
const NODES_FILE = path.join(__dirname, "nodes.json");     // lista de noduri

[BOTS_DIR, UPLOADS_DIR, PUBLIC_DIR].forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// --- RATE LIMIT CONFIG ---
let security = { rate_limiting: false, limit: 5, window_seconds: 120 };
try {
  if (!fs.existsSync(SECURITY_FILE)) {
    fs.writeFileSync(SECURITY_FILE, JSON.stringify(security, null, 2), "utf8");
    console.log("[rate-limiter] Created default security.json");
  } else {
    try {
      const raw = fs.readFileSync(SECURITY_FILE, "utf8");
      security = Object.assign(security, JSON.parse(raw) || {});
      console.log("[rate-limiter] Loaded security.json:", security);
    } catch (e) {
      console.warn("[rate-limiter] Failed to parse existing security.json, using defaults:", e && e.message);
    }
  }
} catch (err) {
  console.error("[rate-limiter] Error ensuring security.json:", err);
}
try {
  fs.watch(SECURITY_FILE, (evtType) => {
    if (evtType === "change" || evtType === "rename") {
      try {
        const raw = fs.readFileSync(SECURITY_FILE, "utf8");
        security = Object.assign(security, JSON.parse(raw) || {});
        console.log("[rate-limiter] security.json reloaded:", security);
      } catch (e) {
        console.warn("[rate-limiter] Failed to reload security.json:", e && e.message);
      }
    }
  });
} catch (e) {
  console.warn("[rate-limiter] fs.watch failed or not available:", e && e.message);
}

const SERVERS_ROOT = BOTS_DIR;

function botRoot(bot) {
  return path.join(SERVERS_ROOT, bot); // acum e același lucru cu path.join(BOTS_DIR, bot)
}
function safeResolve(bot, rel = '') {
  const base = botRoot(bot);
  const abs = path.resolve(base, String(rel || '').replace(/^\/+/, ''));
  if (!abs.startsWith(base)) throw new Error('Path escapes sandbox');
  return abs;
}
async function readText(abs) {
  const buf = await fsp.readFile(abs);
  if (buf.slice(0, 8192).includes(0)) throw new Error('Binary file; not opening as text');
  return buf.toString('utf8');
}

const rateRequests = new Map();
function rateLimiterMiddleware(req, res, next) {
  try {
    if (!security || security.rate_limiting !== true) return next();
    const forwarded = req.headers["x-forwarded-for"];
    const ip = forwarded ? forwarded.split(",")[0].trim() : (req.ip || req.connection.remoteAddress || "unknown");
    const now = Date.now();
    const windowMs = (security.window_seconds || 120) * 1000;
    const limit = security.limit || 5;
    let arr = rateRequests.get(ip) || [];
    arr = arr.filter(ts => (now - ts) <= windowMs);
    if (arr.length >= limit) {
      const oldest = arr[0] || now;
      const retryAfter = Math.ceil((oldest + windowMs - now) / 1000);
      res.setHeader("Retry-After", String(retryAfter));
      return res.status(429).send("429 Too Many Requests - Access temporarily blocked by rate limiter. If you're an admin, you can disable that setting false in security.json.");
    }
    arr.push(now);
    rateRequests.set(ip, arr);
    return next();
  } catch (e) {
    console.warn("[rate-limiter] middleware error:", e && e.message);
    return next();
  }
}
setInterval(() => {
  try {
    const now = Date.now();
    const windowMs = (security.window_seconds || 120) * 1000;
    for (const [ip, arr] of rateRequests.entries()) {
      const kept = arr.filter(ts => (now - ts) <= windowMs);
      if (kept.length > 0) rateRequests.set(ip, kept);
      else rateRequests.delete(ip);
    }
  } catch (e) {
    console.warn("[rate-limiter] cleanup error:", e && e.message);
  }
}, 30_000);

/* ==== NODES HELPERS (remote create) ==== */
function readJson(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const raw = fs.readFileSync(file, "utf8").trim();
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch { return fallback; }
}
function loadNodes() {
  const arr = readJson(NODES_FILE, []);
  return Array.isArray(arr) ? arr : [];
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
function clampApiPort(p) {
  const n = Number(p);
  if (!Number.isInteger(n)) return 8080;
  if (n < 1 || n > 65535) return 8080;
  return n;
}
function buildNodeBaseUrl(address, port) {
  let base = String(address || "").trim();
  if (!base) return null;
  if (/^https?:\/\//i.test(base)) {
    try {
      const u = new URL(base);
      if (!u.port) u.port = String(port || 8080);
      return u.toString().replace(/\/$/, "");
    } catch { /* fall back */ }
  }
  return `http://${base}:${clampApiPort(port || 8080)}`;
}

function httpRequestJson(fullUrl, method = "GET", headers = {}, body = null, timeoutMs = 15000) {
  return new Promise((resolve) => {
    try {
      const lib = fullUrl.startsWith("https:") ? https : httpMod;
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
      if (body != null) req.write(typeof body === "string" ? body : JSON.stringify(body));
      req.end();
    } catch {
      resolve({ status: 0, json: null });
    }
  });
}
async function createOnRemoteNode(node, payload) {
  const baseUrl = buildNodeBaseUrl(node.address, node.api_port || 8080);
  if (!baseUrl) throw new Error("invalid node address");
  // preflight: identitate
  const info = await httpRequestJson(`${baseUrl}/v1/info`, "GET", { "Authorization": `Bearer ${node.token}` }, null, 5000);
  if (info.status !== 200 || !(info.json && info.json.ok)) throw new Error("node not reachable");

  // create
  const res = await httpRequestJson(
    `${baseUrl}/v1/servers/create`,
    "POST",
    { "Authorization": `Bearer ${node.token}`, "Content-Type": "application/json" },
    payload,
    60_000
  );
  if (res.status !== 200 || !(res.json && res.json.ok)) {
    const msg = (res.json && res.json.error) ? res.json.error : `remote create failed (${res.status})`;
    throw new Error(msg);
  }
  return res.json;
}
/* ==== END NODES HELPERS ==== */

// --- USERS / ACCESS ---
function loadUsers() {
  try {
    if (!fs.existsSync(USERS_FILE)) return [];
    const raw = fs.readFileSync(USERS_FILE, "utf8").trim();
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed;
    if (typeof parsed === "object" && parsed !== null) return [parsed];
    return [];
  } catch (e) {
    console.warn("Failed to parse users file, returning empty array", e);
    return [];
  }
}
function saveUsers(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
    return true;
  } catch (e) {
    console.error("Failed to save users:", e);
    return false;
  }
}
function findUserByEmail(email) {
  if (!email) return null;
  const users = loadUsers();
  return users.find((u) => String(u.email).toLowerCase() === String(email).toLowerCase()) || null;
}
function updateUser(updatedUser) {
  const users = loadUsers();
  const idx = users.findIndex((u) => String(u.email).toLowerCase() === String(updatedUser.email).toLowerCase());
  if (idx === -1) {
    users.push(updatedUser);
  } else {
    users[idx] = updatedUser;
  }
  return saveUsers(users);
}

try {
  if (!fs.existsSync(USER_ACCESS_FILE)) {
    const defaultAccess = [];
    fs.writeFileSync(USER_ACCESS_FILE, JSON.stringify(defaultAccess, null, 2), "utf8");
    console.log("[user-access] Created default user-access.json");
  }
} catch (e) {
  console.warn("[user-access] Could not create default file:", e && e.message);
}
function loadUserAccess() {
  try {
    if (!fs.existsSync(USER_ACCESS_FILE)) return [];
    const raw = fs.readFileSync(USER_ACCESS_FILE, "utf8").trim();
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    console.warn("[user-access] failed to read/parse user-access.json:", e && e.message);
    return [];
  }
}
function saveUserAccess(arr) {
  try {
    fs.writeFileSync(USER_ACCESS_FILE, JSON.stringify(Array.isArray(arr) ? arr : [], null, 2), "utf8");
    return true;
  } catch (e) {
    console.error("[user-access] failed to write user-access.json:", e && e.message);
    return false;
  }
}
function getAccessListForEmail(email) {
  if (!email) return [];
  const arr = loadUserAccess();
  const record = arr.find(r => String(r.email).toLowerCase() === String(email).toLowerCase());
  if (!record) return [];
  return Array.isArray(record.servers) ? record.servers : [];
}
function setAccessListForEmail(email, servers) {
  if (!email) return false;
  const arr = loadUserAccess();
  const idx = arr.findIndex(r => String(r.email).toLowerCase() === String(email).toLowerCase());
  if (idx === -1) {
    arr.push({ email, servers: Array.isArray(servers) ? servers : [] });
  } else {
    arr[idx].servers = Array.isArray(servers) ? servers : [];
  }
  return saveUserAccess(arr);
}
function addAccessForEmail(email, server) {
  if (!email || !server) return false;
  const arr = loadUserAccess();
  let rec = arr.find(r => String(r.email).toLowerCase() === String(email).toLowerCase());
  if (!rec) {
    rec = { email, servers: [server] };
    arr.push(rec);
    return saveUserAccess(arr);
  }
  if (!Array.isArray(rec.servers)) rec.servers = [];
  if (!rec.servers.includes(server)) rec.servers.push(server);
  return saveUserAccess(arr);
}
function removeAccessForEmail(email, server) {
  if (!email || !server) return false;
  const arr = loadUserAccess();
  const rec = arr.find(r => String(r.email).toLowerCase() === String(email).toLowerCase());
  if (!rec) return saveUserAccess(arr);
  if (!Array.isArray(rec.servers)) rec.servers = [];
  rec.servers = rec.servers.filter(s => s !== server);
  return saveUserAccess(arr);
}
function userHasAccessToServer(email, botName) {
  if (!email) return false;
  const u = findUserByEmail(email);
  if (u && u.admin) return true;
  const access = getAccessListForEmail(email);
  if (!access || access.length === 0) return false;
  if (access.includes("all")) return true;
  return access.includes(botName);
}
function syncUserAccessWithUsers() {
  try {
    const users = loadUsers();
    if (!Array.isArray(users) || users.length === 0) {
      console.log("[user-access] No users found in user.json to sync.");
      return;
    }
    const access = loadUserAccess();
    const lowerSet = new Set(access.map(r => String(r.email).toLowerCase()));
    let added = 0;
    users.forEach(u => {
      const email = u && u.email ? String(u.email).trim() : null;
      if (!email) return;
      const lower = email.toLowerCase();
      if (!lowerSet.has(lower)) {
        access.push({ email, servers: [] });
        lowerSet.add(lower);
        added++;
      }
    });

    
    if (added > 0) {
      const ok = saveUserAccess(access);
      if (ok) console.log(`[user-access] Synced users -> user-access.json: added ${added} entries.`);
      else console.warn("[user-access] Failed to save user-access.json after sync.");
    } else {
      console.log("[user-access] user-access.json already contains all users from user.json.");
    }
  } catch (e) {
    console.error("[user-access] sync failed:", e && e.message);
  }
}
syncUserAccessWithUsers();

const _lineBuf = {};

function nodeAuthHeadersFor(node, isRemote) {
  const h = { 'Content-Type': 'application/json' };
  // nod remote: ia token din nodes.json
  const remoteToken = node && (node.token || node.secret || node.api_key);
  if (isRemote && remoteToken) {
    h['Authorization'] = `Bearer ${remoteToken}`;
    h['X-Node-Token']  = remoteToken; // fallback acceptat de agent
    return h;
  }
  // nod local: dacă ai definit un token local, îl trimitem
  if (!isRemote && LOCAL_NODE_TOKEN) {
    h['Authorization'] = `Bearer ${LOCAL_NODE_TOKEN}`;
    h['X-Node-Token']  = LOCAL_NODE_TOKEN;
  }
  return h;
}

// --- SERVERS INDEX (servers.json) ---
function ensureServersFile() {
  if (!fs.existsSync(SERVERS_FILE)) {
    try { fs.writeFileSync(SERVERS_FILE, "[]", "utf8"); } catch {}
  }
}
ensureServersFile();
function loadServersIndex() {
  try {
    if (!fs.existsSync(SERVERS_FILE)) return [];
    const raw = fs.readFileSync(SERVERS_FILE, "utf8").trim();
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch { return []; }
}
function saveServersIndex(list) {
  try {
    fs.writeFileSync(SERVERS_FILE, JSON.stringify(Array.isArray(list) ? list : [], null, 2), "utf8");
    return true;
  } catch { return false; }
}

function upsertServerIndexEntry(entry) {
  const list = loadServersIndex();
  const idx = list.findIndex(e => e && e.name === entry.name);
  if (idx >= 0) list[idx] = Object.assign({}, list[idx], entry);
  else list.push(entry);
  saveServersIndex(list);
}
function removeServerIndexEntry(name) {
  const list = loadServersIndex().filter(e => e && e.name !== name);
  saveServersIndex(list);
}

// --- APP SETUP ---
// --- SESSION (refactor ca să-l folosim și în socket.io)
const sessionStore = new FileStore({
  path: path.join(__dirname, ".sessions"),
  retries: 0,
  fileExtension: ".json"
});
const sessionMiddleware = session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || "adpanel",
  name: "adpanel.sid",
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: "lax",
    secure: false
  }
});
app.use(sessionMiddleware);
app.use(nodesRouter);
app.set("trust proxy", true);

app.get('/api/servers/:bot/permissions', (req, res) => {
  res.json({
    isAdmin: true,
    perms: {
      files_read:   true,
      files_delete: true,
      files_rename: true,
      console_write:true,
      server_stop:  true,
      server_start: true,
      files_upload: true,
      files_create: true
    }
  });
});

// --- VIEWS / BODY PARSERS / STATIC ---
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// --- AUTH HELPERS ---
function isAuthenticated(req) {
  if (!req.session || !req.session.user) return false;
  const u = findUserByEmail(req.session.user);
  return !!u;
}
function isAdmin(req) {
  const u = req.session && req.session.user ? findUserByEmail(req.session.user) : null;
  return !!(u && u.admin);
}

// --- DOCKER HELPERS ---
function run(cmd, args, opts = {}) {
  return spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"], ...opts });
}
function execCollect(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = run(cmd, args, opts);
    let out = "", err = "";
    p.stdout.on("data", d => out += d.toString());
    p.stderr.on("data", d => err += d.toString());
    p.on("close", code => {
      if (code === 0) resolve({ out, err, code });
      else reject(new Error(err || out || ("exit " + code)));
    });
    p.on("error", reject);
  });
}
function callDocker(args, opts = {}, onEmptyMsg = "[ADPanel] internal: empty docker args", room = null) {
  if (!Array.isArray(args) || args.length === 0) {
    if (room) _emitLine(room, onEmptyMsg);
    return null;
  }
  return docker(args, opts);
}

function docker(args, opts = {}) {
  if (!Array.isArray(args) || args.length === 0) return null; // safety
  return spawn("docker", args, { stdio: ["ignore", "pipe", "pipe"], ...opts });
}
function dockerCollect(args, opts = {}) { return execCollect("docker", args, opts); }
async function containerExists(name) { try { await dockerCollect(["inspect", name]); return true; } catch { return false; } }
async function ensureNoContainer(name) { try { await dockerCollect(["rm", "-f", name]); } catch {} }
async function pullImage(imageWithTag) {
  try { await dockerCollect(["pull", imageWithTag]); }
  catch (e) { console.warn("[docker] pull failed for", imageWithTag, e && e.message); }
}

// --- NET HELPERS (download jar / JSON) ---
function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
  return p;
}
function httpGetRaw(u) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(u);
    const lib = urlObj.protocol === "http:" ? httpMod : https;
    const req = lib.get(urlObj, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        const loc = res.headers.location.startsWith("http") ? res.headers.location : (urlObj.origin + res.headers.location);
        res.resume();
        resolve(httpGetRaw(loc));
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`HTTP ${res.statusCode} for ${u}`));
        return;
      }
      const chunks = [];
      res.on("data", d => chunks.push(d));
      res.on("end", () => resolve(Buffer.concat(chunks)));
    });
    req.on("error", reject);
  });
}
async function fetchJson(u) {
  const buf = await httpGetRaw(u);
  return JSON.parse(buf.toString("utf8"));
}
async function downloadToFile(u, destPath) {
  const buf = await httpGetRaw(u);
  ensureDir(path.dirname(destPath));
  fs.writeFileSync(destPath, buf);
  return destPath;
}

// --- SERVER INFO: Public IP din host-ul panoului (DNS "check host")
let _hostIpCache = { host: null, ip: null, ts: 0 };

function extractHostnameFromHeader(hostHeader) {
  if (!hostHeader) return null;
  const first = String(hostHeader).split(",")[0].trim();
  if (first.startsWith("[")) {
    const end = first.indexOf("]");
    if (end !== -1) return first.slice(1, end);
  }
  return first.split(":")[0];
}

async function resolvePublicIpFromHost(hostname) {
  if (!hostname) return null;
  if (net.isIP(hostname)) return hostname;
  try {
    const a = await dns.resolve4(hostname);
    if (Array.isArray(a) && a.length) return a[0];
  } catch {}
  try {
    const list = await dns.lookup(hostname, { all: true });
    const v4 = list.find(r => r && r.family === 4);
    if (v4) return v4.address;
    if (list[0] && list[0].address) return list[0].address;
  } catch {}
  try {
    const aaaa = await dns.resolve6(hostname);
    if (Array.isArray(aaaa) && aaaa.length) return aaaa[0];
  } catch {}
  return null;
}

app.get("/api/server-info", async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "not authenticated" });

  try {
    const rawHost =
      req.headers["x-forwarded-host"] ||
      req.headers["host"] ||
      "";
    const hostname = extractHostnameFromHeader(rawHost);

    const now = Date.now();
    if (
      _hostIpCache.host === hostname &&
      _hostIpCache.ip &&
      (now - _hostIpCache.ts) < 5 * 60 * 1000
    ) {
      return res.json({ publicIp: _hostIpCache.ip });
    }

    const ip = await resolvePublicIpFromHost(hostname);
    _hostIpCache = { host: hostname, ip, ts: now };

    return res.json({ publicIp: ip });
  } catch (e) {
    return res.status(500).json({ error: "failed to resolve host ip" });
  }
});

// INFO per server (din servers.json + IP din host-ul panoului)
app.get("/api/server-info/:name", async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "not authenticated" });

  const raw = String(req.params.name || "").trim();
  const resolved = resolveTemplateForBot(raw) || {};
  const entry = resolved.entry || {};
  const meta = resolved.meta || {};
  const template = resolved.template;
  const name = entry.name || raw;

  try {
    const rawHost = req.headers["x-forwarded-host"] || req.headers["host"] || "";
    const hostname = extractHostnameFromHeader(rawHost);

    const now = Date.now();
    let ip = entry.ip || null;
    if (!ip) {
      if (_hostIpCache.host === hostname && _hostIpCache.ip && (now - _hostIpCache.ts) < 5 * 60 * 1000) {
        ip = _hostIpCache.ip;
      } else {
        ip = await resolvePublicIpFromHost(hostname);
        _hostIpCache = { host: hostname, ip, ts: now };
      }
    }

    const port = (entry.port !== undefined && entry.port !== null)
      ? entry.port
      : (template === "minecraft" ? 25565 : null);

    return res.json({
      name,
      start: entry.start || null,
      ip: ip || null,
      port,
      template: template || null,         // <<–– IMPORTANT
      runtime: entry.runtime || meta.runtime || null,
      nodeId: entry.nodeId || entry.node || entry.node_id || null
    });
  } catch (e) {
    console.warn("[/api/server-info/:name] failed:", e && e.message);

    const port = (entry.port !== undefined && entry.port !== null)
      ? entry.port
      : (template === "minecraft" ? 25565 : null);

    return res.json({
      name,
      start: entry.start || null,
      ip: entry.ip || null,
      port,
      template: template || null,         // <<–– ȘI AICI
      runtime: entry.runtime || meta.runtime || null,
      nodeId: entry.nodeId || entry.node || entry.node_id || null
    });
  }
});

// --- TEMPLATES (pentru UI) ---
const DOCKER_TEMPLATES = [
  {
    id: "minecraft",
    name: "Minecraft",
    description: "itzg/minecraft-server + CUSTOM JAR; 25565/TCP; RCON off; console pipe on",
    docker: {
      image: "itzg/minecraft-server",
      tag: "latest",
      ports: [],
      env: {
        EULA: "TRUE",
        MEMORY: "2G",
        ENABLE_RCON: "false",
        CREATE_CONSOLE_IN_PIPE: "true"
      },
      volumes: ["{BOT_DIR}:/data"],
      command: "",
      restart: "unless-stopped"
    }
  },
  {
    id: "discord-bot",
    name: "Discord Bot",
    description: "Node 20 + mount /app, TOKEN env",
    docker: {
      image: "node",
      tag: "20-alpine",
      ports: [],
      env: { NODE_ENV: "production", DISCORD_TOKEN: "" },
      volumes: ["{BOT_DIR}:/app"],
      command: "node /app/index.js",
      restart: "unless-stopped"
    }
  },
  {
    id: "vanilla",
    name: "Empty (custom)",
    description: "Alpine + sleep 3600",
    docker: {
      image: "alpine",
      tag: "latest",
      ports: [],
      env: {},
      volumes: [],
      command: "sleep 3600",
      restart: "no"
    }
  }
];
app.get("/api/templates", (req, res) => res.json({ templates: DOCKER_TEMPLATES }));

// --- LOGIN / REGISTER ---
app.get("/login", (req, res) => { res.render("login", { error: null }); });
const SERVER_START = Date.now();
let USER_COUNT_CACHE = 0;
function loadUserCount() {
  try {
    if (!fs.existsSync(USERS_FILE)) return 0;
    const raw = fs.readFileSync(USERS_FILE, "utf8").trim();
    if (!raw) return 0;
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.length;
    if (typeof parsed === "object" && parsed !== null) return Object.keys(parsed).length;
    return 0;
  } catch (e) {
    console.warn("[user-count] loadUserCount failed:", e && e.message);
    return 0;
  }
}
USER_COUNT_CACHE = loadUserCount();
try {
  let lastSeen = Date.now();
  fs.watchFile(USERS_FILE, { interval: 1000 }, (curr, prev) => {
    const now = Date.now();
    if (now - lastSeen < 800) return;
    lastSeen = now;
    const newCount = loadUserCount();
    if (newCount !== USER_COUNT_CACHE) {
      USER_COUNT_CACHE = newCount;
      console.log("[user-count] updated to", USER_COUNT_CACHE);
    }
  });
} catch (e) {
  console.warn("[user-count] fs.watchFile failed:", e && e.message);
}
app.get("/api/usercount", (req, res) => res.json({ userCount: USER_COUNT_CACHE }));

app.get("/register", (req, res) => {
  const secret = speakeasy.generateSecret({ length: 20 });
  req.session.secret = secret.base32;
  res.render("register", { secret: req.session.secret });
});
app.get('/forgot-password', (req, res) => { res.render('forgot-password', { error: null, success: null }); });

app.post("/register", (req, res) => {
  const { email, password, code } = req.body;
  if (!email || !password || !code || !req.session.secret) return res.status(400).send("Complete all boxes.");
  const existing = findUserByEmail(email);
  if (existing) return res.redirect("/login");
  const verified = speakeasy.totp.verify({
    secret: req.session.secret,
    encoding: "base32",
    token: code,
    window: 2
  });
  if (!verified) return res.status(400).send("Invalid 2FA code.");
  const hashed = bcrypt.hashSync(password, 10);
  const newUser = { email, password: hashed, secret: req.session.secret, admin: true };
  const users = loadUsers();
  users.push(newUser);
  saveUsers(users);
  delete req.session.secret;
  return res.redirect("/login");
});

// === APPLY VERSION (no auth headers at all) ===
app.post('/api/servers/:name/apply-version', async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'not authenticated' });

  try {
    const serverName = String(req.params.name || '').trim();
    const { providerId, versionId } = req.body || {};
    if (!serverName || !providerId || !versionId) {
      return res.status(400).json({ error: 'missing fields' });
    }

    const list  = loadServersIndex();
    const entry = (list || []).find(e => e && e.name === serverName);
    if (!entry) return res.status(404).json({ error: 'server-not-found' });

    if (String(entry.template).toLowerCase() !== 'minecraft') {
      return res.status(400).json({ error: 'not-minecraft-template' });
    }

    // === găsim URL-ul din versions.json
    const url = findVersionUrl(providerId, versionId);
    if (!url) return res.status(400).json({ error: 'version-url-not-found' });

    console.log('[minecraft/apply] entry =', {
      name: entry.name,
      nodeId: entry.nodeId,
      ip: entry.ip,
    });

    // === dacă nodeId este null/falsy => LOCAL NODE -> descarcă în bots/<serverName> și gata
    if (!entry.nodeId) {
      try {
        console.log('[minecraft/apply] nodeId is null -> treating as local node, downloading to bots folder');
        const destPath = await downloadVersionToLocalBotsFolder(serverName, url);
        console.log('[minecraft/apply] local download ok:', destPath);
        return res.json({ ok: true, local: true, path: destPath });
      } catch (err) {
        console.error('[minecraft/apply] local download failed', err);
        return res.status(500).json({
          error: 'local-download-failed',
          detail: err && err.message ? err.message : String(err),
        });
      }
    }

    // === dacă avem nodeId -> comportamentul vechi (forward la node agent)
    const NODE_AGENT_PORT = process.env.NODE_AGENT_PORT || 8080;
    const baseUrl = (entry && entry.nodeId && entry.ip)
      ? `http://${entry.ip}:${NODE_AGENT_PORT}`
      : `http://127.0.0.1:${NODE_AGENT_PORT}`;

    const forwardUrl = `${baseUrl}/v1/servers/${encodeURIComponent(serverName)}/apply-version`;
    console.log('[minecraft/apply] forward -> node', {
      forwardUrl,
      nodeId: entry.nodeId,
    });

    const remote = await httpRequestJson(
      forwardUrl,
      'POST',
      { 'Content-Type': 'application/json' },   // FĂRĂ auth headers
      { providerId, versionId, url },
      60_000
    );

    if (remote.status !== 200 || !(remote.json && remote.json.ok)) {
      const msg = (remote.json && (remote.json.error || remote.json.detail)) || `remote status ${remote.status}`;
      console.warn('apply-version remote error:', {
        url: forwardUrl,
        status: remote.status,
        detail: msg,
      });
      return res.status(502).json({ error: 'server-error', detail: msg });
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error('apply-version error', e);
    return res.status(500).json({
      error: 'server-error',
      detail: e && e.message ? e.message : String(e),
    });
  }
});
app.post('/api/servers/:bot/apply-version', async (req, res) => {
  const bot = String(req.params.bot || '').trim();
  const { providerId, versionId } = req.body || {};

  if (!bot || !providerId || !versionId) {
    return res.status(400).json({ error: 'missing-fields' });
  }

  const url = findVersionUrl(providerId, versionId);
  if (!url) return res.status(400).json({ error: 'version-url-not-found' });

  const rec = getServerRecord(bot);
  if (!rec) return res.status(404).json({ error: 'server-not-found' });

  console.log('[apply] req', { bot, providerId, versionId, url });
  console.log('[apply] rec', { nodeId: rec.nodeId, ip: rec.ip });

  // === dacă nodeId este null/falsy => LOCAL NODE -> descarcă în bots/<bot> și gata
  if (!rec.nodeId) {
    try {
      console.log('[apply] nodeId is null -> treating as local node, downloading to bots folder');
      const destPath = await downloadVersionToLocalBotsFolder(bot, url);
      console.log('[apply] local download ok:', destPath);
      return res.json({ ok: true, local: true, path: destPath });
    } catch (err) {
      console.error('[apply] local download failed', err);
      return res.status(500).json({
        error: 'local-download-failed',
        detail: err && err.message ? err.message : String(err),
      });
    }
  }

  // === dacă avem nodeId -> comportamentul pe nod (forward)
  const nodeBase = resolveNodeBase(rec);
  if (!nodeBase) return res.status(400).json({ error: 'node-base-unresolved' });

  const pathOnly = `/v1/servers/${encodeURIComponent(bot)}/apply-version`;
  const forwardUrl = nodeBase + pathOnly;

  console.log('[apply] forward -> node', {
    forwardUrl,
    nodeId: rec.nodeId,
  });

  const body = { providerId, versionId, url, nodeId: rec.nodeId };

  try {
    const r = await fetch(forwardUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.error) {
      return res.status(r.status || 500).json({
        error: 'node-apply-failed',
        detail: j.error || j.detail || r.statusText,
      });
    }
    return res.json({ ok: true });
  } catch (e) {
    console.error('[apply] panel-apply-error', e);
    return res.status(500).json({
      error: 'panel-apply-error',
      detail: e && e.message ? e.message : String(e),
    });
  }
});
app.post("/login", (req, res) => {
  const { email, password, code } = req.body;
  const user = findUserByEmail(email);
  if (!user || !user.password || !bcrypt.compareSync(password, user.password)) return res.status(400).send("Email or password incorrect.");
  const verified = speakeasy.totp.verify({ secret: user.secret, encoding: "base32", token: code });
  if (!verified) return res.status(400).send("Invalid 2FA code.");
  req.session.user = user.email;
  res.redirect("/");
});
app.post("/forgot-password", (req, res) => {
  const { email, newPassword } = req.body;
  const user = findUserByEmail(email);
  if (!user) return res.status(400).send("Email not found.");
  if (!newPassword || newPassword.length < 4) return res.status(400).send("New password invalid or too short.");
  user.password = bcrypt.hashSync(newPassword, 10);
  updateUser(user);
  res.send("Password has been reset. Please log in with the new password.");
});
app.post('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Failed to logout' });
      }
      res.clearCookie('connect.sid');
      return res.json({ success: true });
    });
  } else {
    res.clearCookie('connect.sid');
    return res.json({ success: true });
  }
});

/* ===== AUTH GATE =====
   Permit fără sesiune rutele agentului de node + config.yml cu token */
const OPEN_NODE_ROUTES = [
  { method: "POST", path: "/api/nodes/auth" },
  { method: "POST", path: "/api/nodes/heartbeat" },
];
function isOpenNodeRoute(req) {
  if (req.method === "GET"  && /^\/api\/nodes\/[^/]+\/config\.yml$/.test(req.path)) return true;
  if (req.method === "POST" && /^\/api\/nodes\/[^/]+\/heartbeat$/.test(req.path)) return true;
  // dacă vei avea și /api/nodes/auth, îl poți lăsa aici:
  if (req.method === "POST" && req.path === "/api/nodes/auth") return true;
  return false;
}

function emitChunkLines(bot, chunk) {
  const s = chunk.toString().replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const parts = s.split("\n");
  for (let i = 0; i < parts.length; i++) {
    if (parts[i].trim() === "") continue;
    _emitLine(bot, parts[i]);
  }
}

app.use((req, res, next) => {
  if (
    req.path.startsWith("/login") ||
    req.path.startsWith("/register") ||
    req.path.startsWith("/forgot-password") ||
    isOpenNodeRoute(req)
  ) return next();
  if (!isAuthenticated(req)) return res.redirect("/login");
  next();
});

// --- DASHBOARD ---
app.get("/", (req, res) => {
  const allBotsLocal = fs.existsSync(BOTS_DIR) ? fs.readdirSync(BOTS_DIR) : [];
  const localFolders = allBotsLocal.filter(n => {
    try { return fs.statSync(path.join(BOTS_DIR, n)).isDirectory(); } catch { return false; }
  });

  // adaugă și cele indexate în servers.json (remote + local)
  const idx = loadServersIndex();
  const indexedNames = (Array.isArray(idx) ? idx : []).map(e => e && e.name).filter(Boolean);

  // unificare fără dubluri
  const set = new Set([...localFolders, ...indexedNames]);
  const unified = Array.from(set);

  const userObj = req.session && req.session.user ? findUserByEmail(req.session.user) : null;
  const safeUser = userObj ? { email: userObj.email, admin: !!userObj.admin } : null;

  let botsToShow = [];
  if (safeUser && safeUser.admin) {
    botsToShow = unified;
  } else {
    const access = getAccessListForEmail(req.session.user);
    if (access && access.includes("all")) {
      botsToShow = unified;
    } else {
      botsToShow = unified.filter(n => access && access.includes(n));
    }
  }
  res.render("index", { bots: botsToShow, isAdmin: safeUser ? safeUser.admin : false, user: safeUser, serverStartTime: SERVER_START });
});

app.get("/settings", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/");
  const user = findUserByEmail(req.session.user);
  res.render("settings", { user });
});

app.get("/settings/servers", (req, res) => {
  if (!isAdmin(req)) return res.redirect("/");
  res.render("server", { user: findUserByEmail(req.session.user) });
});

// --- BACKGROUND STYLE ---
function makeCssBackground(value, type) {
  if (!value) return null;
  if (type === "color") return `${value}`;
  const escaped = String(value).replace(/"/g, '\\"');
  return `url("${escaped}") center/cover no-repeat`;
}
function setBodyBackgroundInFile(filePath, cssBackgroundValue) {
  try {
    let content = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : "";
    const bodyBlockRe = /body\s*{[^}]*}/s;
    const hasBody = bodyBlockRe.test(content);
    const bgDeclaration = (cssBackgroundValue || "").trim();
    let newContent;
    if (hasBody) {
      newContent = content.replace(bodyBlockRe, (block) => {
        if (/background(-image)?\s*:/i.test(block)) {
          block = block.replace(/background(-image)?\s*:[^;}]*(;?)/ig, `background: ${bgDeclaration};`);
          return block;
        } else {
          return block.replace(/\{\s*/, `{ \n  background: ${bgDeclaration};\n  `);
        }
      });
    } else {
      newContent = `body { background: ${bgDeclaration}; }\n\n` + content;
    }
    fs.writeFileSync(filePath, newContent, "utf8");
    return true;
  } catch (err) {
    console.error("Failed to write CSS file", filePath, err);
    return false;
  }
}
function nodeAuthHeadersFor(node, isRemote) {
  const h = { 'Content-Type': 'application/json' };
  // nod remote: ia token din nodes.json
  const remoteToken = node && (node.token || node.secret || node.api_key);
  if (isRemote && remoteToken) {
    h['Authorization'] = `Bearer ${remoteToken}`;
    h['X-Node-Token']  = remoteToken; // fallback acceptat de agent
    return h;
  }
  // nod local: dacă ai definit un token local, îl trimitem
  if (!isRemote && LOCAL_NODE_TOKEN) {
    h['Authorization'] = `Bearer ${LOCAL_NODE_TOKEN}`;
    h['X-Node-Token']  = LOCAL_NODE_TOKEN;
  }
  return h;
}
app.post("/api/settings/background", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "not authenticated" });
  const { type, value } = req.body;
  if (!type || typeof value === "undefined") return res.status(400).json({ error: "missing type/value" });
  const cssVal = makeCssBackground(value, type);
  if (!cssVal) return res.status(400).json({ error: "invalid background value" });
  const ok1 = setBodyBackgroundInFile(DASHBOARD_CSS, cssVal);
  const ok2 = setBodyBackgroundInFile(STYLE_CSS, cssVal);
  if (ok1 && ok2) return res.json({ ok: true });
  return res.status(500).json({ error: "failed to update files" });
});

// --- SETTINGS: servers (DIRECTOARE) ---
app.get("/api/settings/servers", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "not authorized" });
  try {
    const local = fs.existsSync(BOTS_DIR)
      ? fs.readdirSync(BOTS_DIR, { withFileTypes: true }).filter(e => e.isDirectory()).map(d => d.name)
      : [];

    const index = loadServersIndex(); // servers.json
    const byName = new Map();

    // Locale (fallback: local)
    local.forEach(n => byName.set(n, { name: n, isLocal: true, nodeId: null }));

    // Index (poate să override-uiască “isLocal”)
    (index || []).forEach(e => {
      if (!e || !e.name) return;
      byName.set(e.name, {
        name: e.name,
        isLocal: !(e.nodeId && e.nodeId !== "local"),
        nodeId: e.nodeId || null
      });
    });

    const items = Array.from(byName.values()).sort((a,b) => a.name.localeCompare(b.name));
    return res.json({ items });
  } catch (e) {
    console.error("Failed to list servers:", e);
    return res.status(500).json({ error: "failed to read servers" });
  }
});
app.delete("/api/settings/servers/:name", async (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "not authorized" });

  let nameParam = req.params.name || "";
  try { nameParam = decodeURIComponent(nameParam); } catch {}
  const name = String(nameParam).trim();
  if (!name) return res.status(400).json({ error: "missing name" });
  if (name.includes("..") || /[\/\\]/.test(name)) return res.status(400).json({ error: "invalid name" });

  try {
    // vezi dacă e remote (servers.json)
    const idx = loadServersIndex();
    const entry = (idx || []).find(e => e && e.name === name) || null;
    const isRemote = !!(entry && entry.nodeId && entry.nodeId !== "local");

    // Scoatem din user-access.json (indiferent local/remote)
    try {
      const access = loadUserAccess();
      let changed = false;
      const normalized = String(name);
      const newAccess = (access || []).map(rec => {
        if (!rec || !rec.email) return rec;
        if (!Array.isArray(rec.servers)) return rec;
        const filtered = rec.servers.filter(s => s !== normalized);
        if (filtered.length !== rec.servers.length) {
          changed = true;
          return { ...rec, servers: filtered };
        }
        return rec;
      });
      if (changed) saveUserAccess(newAccess);
    } catch (e) {
      console.warn("[delete] Failed to update user-access.json:", e && e.message);
    }

    if (isRemote) {
      // —— REMOTE DELETE pe node
      const node = findNodeByIdOrName(entry.nodeId);
      if (!node) return res.status(400).json({ error: "node not found for server" });

      const baseUrl = buildNodeBaseUrl(node.address, node.api_port || 8080);
      if (!baseUrl) return res.status(400).json({ error: "invalid node address" });

      // DELETE la agentul de node
      const r = await httpRequestJson(
        `${baseUrl}/v1/servers/${encodeURIComponent(name)}`,
        "DELETE",
        { "Authorization": `Bearer ${node.token}` },
        null,
        60_000
      );
      if (r.status !== 200 || !(r.json && r.json.ok)) {
        const msg = (r.json && r.json.error) ? r.json.error : `remote delete failed (${r.status})`;
        return res.status(502).json({ error: msg });
      }

      // scoate intrarea din servers.json local (index)
      try { removeServerIndexEntry(name); } catch {}

      // gata, nu avem ce șterge pe disk local
      return res.json({ ok: true, remote: true });
    }

    // —— LOCAL DELETE (comportamentul tău vechi)
    const base = path.resolve(BOTS_DIR);
    const target = path.resolve(path.join(BOTS_DIR, name));
    if (!target.startsWith(base + path.sep) && target !== base) return res.status(400).json({ error: "invalid path" });

    if (!fs.existsSync(target)) {
      // Dacă nu mai e folderul local, tot scoatem index & docker
      try { removeServerIndexEntry(name); } catch {}
      try { await dockerCollect(["rm", "-f", name]); } catch {}
      return res.json({ ok: true, local: true });
    }

    const st = fs.statSync(target);
    if (!st.isDirectory()) return res.status(400).json({ error: "not a directory" });

    // Șterge folderul, containerul și scoate din index
    fs.rmSync(target, { recursive: true, force: true });
    try { removeServerIndexEntry(name); } catch {}
    try { await dockerCollect(["rm", "-f", name]); } catch {}

    return res.json({ ok: true, local: true });
  } catch (e) {
    console.error("[/api/settings/servers/:name DELETE] failed:", e && e.message);
    return res.status(500).json({ error: "failed to delete server" });
  }
});

// --- MY SERVERS ---
app.get("/api/my-servers", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "not authenticated" });
  try {
    const allLocal = fs.existsSync(BOTS_DIR) ? fs.readdirSync(BOTS_DIR, { withFileTypes: true }) : [];
    const dirNames = allLocal.filter(e => e.isDirectory()).map(d => d.name);

    const idx = loadServersIndex();
    const indexedNames = (Array.isArray(idx) ? idx : []).map(e => e && e.name).filter(Boolean);

    const set = new Set([...dirNames, ...indexedNames]);
    const unified = Array.from(set);

    const userEmail = req.session.user;
    const u = findUserByEmail(userEmail);
    if (u && u.admin) return res.json({ names: unified });

    const access = getAccessListForEmail(userEmail) || [];
    let names = [];
    if (access.includes("all")) names = unified;
    else names = unified.filter(n => access.includes(n));

    return res.json({ names });
  } catch (e) {
    console.error("Failed to list my-servers:", e);
    return res.status(500).json({ error: "failed to read servers" });
  }
});

// --- ACCOUNTS ---
app.get("/api/settings/accounts", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "not authorized" });
  try {
    const accountsRaw = loadUserAccess();
    const users = loadUsers();
    const adminEmails = users.filter(u => u && u.admin).map(u => String(u.email).toLowerCase());
    const accounts = Array.isArray(accountsRaw) ? accountsRaw.map(a => ({
      email: a.email,
      servers: Array.isArray(a.servers) ? a.servers : []
    })) : [];
    const filtered = accounts.filter(a => !adminEmails.includes(String(a.email).toLowerCase()));
    const allBots = fs.existsSync(BOTS_DIR) ? fs.readdirSync(BOTS_DIR, { withFileTypes: true }).filter(e => e.isDirectory()).map(d => d.name) : [];
    return res.json({ accounts: filtered, bots: allBots });
  } catch (e) {
    console.error("Failed to read accounts:", e);
    return res.status(500).json({ error: "failed to read accounts" });
  }
});

// === PUBLIC: apply-version (panel -> node sau local)
app.post('/api/servers/:bot/versions/apply', async (req, res) => {
  if (!isAuthenticated(req)) {
    return res.status(401).json({ ok: false, error: 'not-authenticated' });
  }

  try {
    const bot = String(req.params.bot || '').trim();
    const {
      providerId,
      versionId,
      url: bodyUrl,
      destPath: rawDestPath,   // poate veni din frontend, dar nu e obligatoriu
    } = req.body || {};

    if (!bot) {
      return res.status(400).json({ ok: false, error: 'missing-bot' });
    }

    // 1) determinăm URL-ul final
    let url = (bodyUrl && String(bodyUrl).trim()) || '';

    if (!url) {
      if (!providerId || !versionId) {
        return res.status(400).json({ ok: false, error: 'missing-params' });
      }

      // fallback pentru provideri clasici (Paper, Purpur etc) care folosesc versions.json
      url = getVersionUrlFromConfig(providerId, versionId);
      if (!url) {
        return res.status(404).json({ ok: false, error: 'version-url-not-found' });
      }
    }

    if (!/^https?:\/\//i.test(url)) {
      return res.status(400).json({ ok: false, error: 'invalid-url' });
    }

    // 2) decidem destinația relativă în folderul serverului
    let destRel = '';

    if (rawDestPath) {
      // frontend-ul a specificat explicit
      destRel = String(rawDestPath).trim();
    } else if (providerId === 'modrinth-plugin') {
      // automat: plugin Modrinth => plugins/<nume-jar-din-URL>
      let filename = '';
      try {
        const u = new URL(url);
        filename = require('path').basename(u.pathname);
      } catch (e) {
        // fallback dacă URL-ul e dubios
      }

      if (!filename || !filename.toLowerCase().endsWith('.jar')) {
        filename = (versionId ? `${versionId}.jar` : 'plugin.jar');
      }

      destRel = require('path').join('plugins', filename);
    } else {
      // default vechi: versiune de server => server.jar în root
      destRel = 'server.jar';
    }

    // sanitizare
    destRel = destRel.replace(/^\/+/, '');
    if (!destRel) destRel = 'server.jar';
    if (destRel.includes('..') || destRel.includes('\\')) {
      return res.status(400).json({ ok: false, error: 'invalid-destPath' });
    }

    console.log('[apply] req', {
      bot,
      providerId,
      versionId,
      url,
      destRel
    });

    // 3) determinăm dacă serverul e pe nod sau local
    const resolved = resolveTemplateForBot(bot) || {};
    const entry = resolved.entry || null;
    const meta = resolved.meta || {};

    const rawNodeId = entry && (entry.nodeId || entry.node || entry.id || entry.uuid || null);
    const ip        = entry && (entry.ip || entry.host || null);

    const serverTemplate = normalizeTemplateId(resolved.template || entry?.template);

    // === runtime selection pentru template-uri non-Minecraft (ex: Discord bot) ===
    if (serverTemplate && serverTemplate !== 'minecraft') {
      const providerCfg = findProviderConfig(providerId);
      if (!providerCfg || !providerSupportsTemplate(providerCfg, serverTemplate)) {
        return res.status(400).json({ ok: false, error: 'provider-not-supported' });
      }
      let versionCfg = findProviderVersionConfig(providerId, versionId);
      if (!versionCfg && providerId === 'python') {
        versionCfg = buildPythonVersionConfig(versionId, entry, meta);
      }
      if (!versionCfg) {
        return res.status(404).json({ ok: false, error: 'version-not-found' });
      }
      if (isRemoteEntry(entry)) {
        return res.status(400).json({ ok: false, error: 'runtime-change-remote-unsupported' });
      }
      const dockerCfg = versionCfg.docker || {};
      if (!dockerCfg.image || !dockerCfg.tag) {
        return res.status(400).json({ ok: false, error: 'missing-docker-config' });
      }

      const startFile = versionCfg.start || entry?.start || meta.start || 'index.js';

      const runtime = {
        providerId: providerCfg.id,
        versionId: versionCfg.id || versionId,
        image: dockerCfg.image,
        tag: dockerCfg.tag,
        command: dockerCfg.command || null,
        env: dockerCfg.env || {},
        volumes: dockerCfg.volumes || null
      };

      const updatedEntry = Object.assign({}, entry || {}, {
        name: bot,
        template: providerCfg.template || serverTemplate || 'discord-bot',
        start: startFile,
        runtime
      });

      upsertServerIndexEntry(updatedEntry);
      try {
        await dockerCollect(['pull', `${dockerCfg.image}:${dockerCfg.tag}`]);
      } catch (e) {
        console.warn('[apply] docker pull failed:', e && e.message);
      }

      return res.json({ ok: true, remote: false, msg: 'runtime-updated', runtime });
    }

    const isRemoteNode = !!(entry && rawNodeId && rawNodeId !== 'local' && ip);

    if (isRemoteNode) {
      // === PE NOD REMOTE ===
      const forwardUrl = `http://${ip}:${NODE_AGENT_PORT}/v1/servers/${encodeURIComponent(bot)}/apply-version`;
      console.log('[apply] forward -> node', { forwardUrl, nodeId: rawNodeId, destRel });

      const payload = { url, nodeId: rawNodeId, destPath: destRel };

      const r = await httpRequestJson(
        forwardUrl,
        'POST',
        { 'Content-Type': 'application/json' },
        payload,
        60_000
      );

      if (r.status !== 200 || !(r.json && r.json.ok)) {
        return res.status(502).json({
          ok: false,
          error:
            (r.json && (r.json.detail || r.json.error)) ||
            `node-forward-failed-${r.status}`
        });
      }

      return res.json({ ok: true, remote: true, msg: 'forwarded-to-node', destPath: destRel });
    }

    // === LOCAL NODE ===
    console.log('[apply] local node -> downloading into bots folder', {
      bot,
      url,
      destRel,
      hasEntry: !!entry,
      nodeId: rawNodeId || null,
      ip: ip || null
    });

    const botDir = path.join(BOTS_DIR, bot);
    try {
      fs.mkdirSync(botDir, { recursive: true });
    } catch {}

    const finalPath = path.join(botDir, destRel);
    try {
      fs.mkdirSync(path.dirname(finalPath), { recursive: true });
    } catch {}

    await downloadToFile(url, finalPath);

    return res.json({
      ok: true,
      remote: false,
      msg: 'downloaded',
      path: finalPath,
      destPath: destRel
    });
  } catch (e) {
    console.error('apply-version error', e);
    return res.status(500).json({ ok: false, error: 'server-error' });
  }
});

async function applyPythonRuntimeChange(bot, version){
  const resolved = resolveTemplateForBot(bot) || {};
  const entry = resolved.entry || {};
  const meta = resolved.meta || {};

  if (!entry && !fs.existsSync(botRoot(bot))) {
    return { status: 404, json: { error: 'server-not-found' } };
  }

  if (isRemoteEntry(entry)) {
    return { status: 400, json: { error: 'runtime-change-remote-unsupported' } };
  }

  const versionCfg = buildPythonVersionConfig(version, entry, meta);
  if (!versionCfg) return { status: 400, json: { error: 'invalid-python-version' } };

  await wipeBotDirectory(bot);

  const runtime = {
    providerId: 'python',
    versionId: version,
    image: versionCfg.docker.image,
    tag: versionCfg.docker.tag,
    command: versionCfg.docker.command,
    env: {},
    volumes: null
  };

  const updatedEntry = Object.assign({}, entry || {}, {
    name: bot,
    template: 'python',
    start: versionCfg.start,
    runtime
  });

  upsertServerIndexEntry(updatedEntry);

  try {
    await dockerCollect(['pull', `${runtime.image}:${runtime.tag}`]);
  } catch (e) {
    console.warn('[python-version] docker pull failed:', e && e.message);
  }

  return { status: 200, json: { ok: true, message: `Python version switched to ${versionCfg.name}. All existing files were removed.`, runtime } };
}

app.post('/api/servers/:bot/python-version', async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'not authenticated' });

  const bot = String(req.params?.bot || '').trim();
  const version = req.body?.version;

  if (!bot || !version) return res.status(400).json({ error: 'missing-params' });

  if (!isAdmin(req) && !userHasAccessToServer(req.session.user, bot)) {
    return res.status(403).json({ error: 'no access to server' });
  }

  try {
    const result = await applyPythonRuntimeChange(bot, version);
    return res.status(result.status).json(result.json);
  } catch (e) {
    console.error('[python-version] failed:', e && e.message);
    return res.status(500).json({ error: 'server-error' });
  }
});

app.post('/change-version', async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'not authenticated' });

  const bot = String(req.body?.bot || '').trim();
  const version = req.body?.version;

  if (!bot || !version) return res.status(400).json({ error: 'missing-params' });

  if (!isAdmin(req) && !userHasAccessToServer(req.session.user, bot)) {
    return res.status(403).json({ error: 'no access to server' });
  }

  try {
    const result = await applyPythonRuntimeChange(bot, version);
    return res.status(result.status).json(result.json);
  } catch (e) {
    console.error('[change-version] failed:', e && e.message);
    return res.status(500).json({ error: 'server-error' });
  }
});

app.post("/api/settings/accounts/:email/add", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "not authorized" });
  const encoded = req.params.email || "";
  let email;
  try { email = decodeURIComponent(encoded); } catch (e) { email = encoded; }
  const server = req.body && req.body.server ? String(req.body.server) : "";
  if (!email || !server) return res.status(400).json({ error: "missing email or server" });
  const allBots = fs.existsSync(BOTS_DIR) ? fs.readdirSync(BOTS_DIR, { withFileTypes: true }).filter(e => e.isDirectory()).map(d => d.name) : [];
  if (!allBots.includes(server) && server !== "all") return res.status(400).json({ error: "server not found" });

  try {
    const ok = addAccessForEmail(email, server);
    if (!ok) return res.status(500).json({ error: "failed to save access" });
    return res.json({ ok: true });
  } catch (e) {
    console.error("Failed to add access:", e);
    return res.status(500).json({ error: "failed to add access" });
  }
});
app.post("/api/settings/accounts/:email/remove", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "not authorized" });
  const encoded = req.params.email || "";
  let email;
  try { email = decodeURIComponent(encoded); } catch (e) { email = encoded; }
  const server = req.body && req.body.server ? String(req.body.server) : "";
  if (!email || !server) return res.status(400).json({ error: "missing email or server" });

  try {
    const ok = removeAccessForEmail(email, server);
    if (!ok) return res.status(500).json({ error: "failed to save access" });
    return res.json({ ok: true });
  } catch (e) {
    console.error("Failed to remove access:", e);
    return res.status(500).json({ error: "failed to remove access" });
  }
});

// --- FS helpers ---
function safeJoinAndCheck(dest, entryPath) {
  const target = path.join(dest, entryPath);
  const resolved = path.resolve(target);
  const baseResolved = path.resolve(dest);
  if (!resolved.startsWith(baseResolved + path.sep) && resolved !== baseResolved) return null;
  return resolved;
}

// --- LOCAL FS helpers pentru editor (acceptă și căi care încep cu "/")
function normalizeRelPath(rel) {
  let r = String(rel || "");
  if (path.isAbsolute(r)) r = r.replace(/^\/+/, "");
  return r;
}
function safeJoinLocal(base, rel) {
  return safeJoinAndCheck(base, normalizeRelPath(rel));
}

async function extractZipFile(filePath, dest) {
  return new Promise((resolve, reject) => {
    try {
      const zip = new AdmZip(filePath);
      const entries = zip.getEntries();
      for (const entry of entries) {
        const entryName = entry.entryName;
        if (!entryName || entryName.includes("..") || path.isAbsolute(entryName)) {
          console.warn("[extractZip] Skipping unsafe zip entry:", entryName);
          continue;
        }
        const outPath = safeJoinAndCheck(dest, entryName);
        if (!outPath) {
          console.warn("[extractZip] Skipping entry outside dest:", entryName);
          continue;
        }
        if (entry.isDirectory) {
          try { fs.mkdirSync(outPath, { recursive: true }); } catch (e) {}
        } else {
          try {
            fs.mkdirSync(path.dirname(outPath), { recursive: true });
            fs.writeFileSync(outPath, entry.getData());
          } catch (e) {
            console.error("[extractZip] Failed to write zip entry:", entryName, e);
            return reject(e);
          }
        }
      }
      return resolve();
    } catch (err) {
      return reject(err);
    }
  });
}
async function extractTarFile(filePath, dest) {
  return new Promise((resolve, reject) => {
    tar.x({
      file: filePath,
      cwd: dest,
      filter: (p, stat) => {
        if (!p) return false;
        if (p.includes("..")) {
          console.warn("[extractTar] Skipping tar entry with .. :", p);
          return false;
        }
        if (path.isAbsolute(p)) {
          console.warn("[extractTar] Skipping absolute tar entry:", p);
          return false;
        }
        return true;
      },
    }).then(() => resolve()).catch(err => reject(err));
  });
}
async function extractWith7zOrUnrar(filePath, dest) {
  return new Promise((resolve, reject) => {
    const tryCommands = [
      { cmd: "7z", args: ["x", filePath, `-o${dest}`, "-y"] },
      { cmd: "7za", args: ["x", filePath, `-o${dest}`, "-y"] },
      { cmd: "unrar", args: ["x", "-o+", filePath, dest] },
      { cmd: "unar", args: ["-o", dest, filePath] },
    ];
    let tried = 0;
    function attemptNext() {
      if (tried >= tryCommands.length) {
        return reject(new Error("No extractor found (7z/7za/unrar/unar)"));
      }
      const item = tryCommands[tried++];
      const cp = spawn(item.cmd, item.args, { stdio: "inherit" });

      cp.on("error", (err) => {
        console.warn(`[extract7z] extractor ${item.cmd} failed to start:`, err && err.message);
        attemptNext();
      });
      cp.on("close", (code) => {
        if (code === 0) return resolve();
        console.warn(`[extract7z] extractor ${item.cmd} exited with code ${code}, trying next...`);
        attemptNext();
      });
    }
    attemptNext();
  });
}

/**
 * Descarcă fișierul de la `url` în bots/<name>/ din același folder cu index.js.
 * Returnează calea finală.
 */
async function downloadVersionToLocalBotsFolder(name, url) {
  if (!name || !url) throw new Error('missing-name-or-url');

  const u = new URL(url);
  let fileName = path.basename(u.pathname);
  if (!fileName || fileName === '/' || fileName === '.') {
    fileName = 'downloaded-version.jar'; // fallback generic
  }

  const botsDir = path.join(__dirname, 'bots', name);
  await fs.promises.mkdir(botsDir, { recursive: true });

  const destPath = path.join(botsDir, fileName);
  const lib = u.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const req = lib.get(u, (res) => {
      // redirect simplu
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return downloadVersionToLocalBotsFolder(name, res.headers.location)
          .then(resolve)
          .catch(reject);
      }

      if (res.statusCode !== 200) {
        return reject(new Error(`download failed with status ${res.statusCode}`));
      }

      const fileStream = fs.createWriteStream(destPath);
      res.pipe(fileStream);

      fileStream.on('finish', () => fileStream.close(() => resolve(destPath)));
      fileStream.on('error', (err) => reject(err));
    });

    req.on('error', reject);
  });
}

// --- UPLOAD / EXTRACT ---
const upload = multer({ dest: UPLOADS_DIR });
app.post("/upload", upload.single("file"), async (req, res) => {
  if (!isAuthenticated(req)) {
    if (req.headers && req.headers.accept && req.headers.accept.includes("text/html")) return res.redirect("/login");
    return res.status(401).json({ error: "Not authenticated" });
  }
  if (!req.file) {
    if (req.headers && req.headers.accept && req.headers.accept.includes("text/html")) return res.redirect("/?upload=nofile");
    return res.status(400).json({ error: "No file uploaded" });
  }
  const uploadedPath = req.file.path;
  const originalName = req.file.originalname || "upload";
  const lower = originalName.toLowerCase();
  const bot = req.body && req.body.bot ? String(req.body.bot).trim() : "";
  const relPath = req.body && typeof req.body.path !== "undefined" ? String(req.body.path).trim() : "";

  if (bot) {
    if (bot.includes("..") || bot.includes("/") || bot.includes("\\")) {
      try { fs.unlinkSync(uploadedPath); } catch (e) {}
      return res.status(400).json({ error: "Invalid bot name" });
    }
    const base = path.resolve(BOTS_DIR);
    const targetDir = relPath ? path.join(BOTS_DIR, bot, relPath) : path.join(BOTS_DIR, bot);
    const resolvedTarget = path.resolve(targetDir);
    if (!resolvedTarget.startsWith(base + path.sep) && resolvedTarget !== base) {
      try { fs.unlinkSync(uploadedPath); } catch (e) {}
      return res.status(400).json({ error: "Invalid path" });
    }
    try {
      fs.mkdirSync(resolvedTarget, { recursive: true });
      const safeFilename = String(originalName).replace(/[\r\n]/g, "_");
      const destFile = path.join(resolvedTarget, safeFilename);
      fs.renameSync(uploadedPath, destFile);
      if (req.headers && req.headers.accept && req.headers.accept.includes("text/html")) return res.redirect("/");
      return res.json({ ok: true, msg: "Uploaded to bot folder", path: path.relative(BOTS_DIR, destFile) });
    } catch (e) {
      console.error("[upload->bot] Failed to move uploaded file:", e);
      try { fs.unlinkSync(uploadedPath); } catch (e2) {}
      return res.status(500).json({ error: "Failed to move uploaded file" });
    }
  }

  let baseName;
  if (lower.endsWith(".tar.gz")) baseName = originalName.slice(0, -7);
  else if (lower.endsWith(".tgz")) baseName = originalName.slice(0, -4);
  else baseName = originalName.replace(path.extname(originalName), "");

  let folderName = String(baseName).trim().replace(/\s+/g, "-").replace(/[^\w\-_.]/g, "").replace(/^-+|-+$/g, "");
  if (!folderName) folderName = "uploaded-" + Date.now();

  let finalFolder = folderName;
  let counter = 0;
  while (fs.existsSync(path.join(BOTS_DIR, finalFolder))) {
    counter++;
    finalFolder = `${folderName}-${counter}`;
    if (counter > 9999) break;
  }
  const destDir = path.join(BOTS_DIR, finalFolder);
  try {
    fs.mkdirSync(destDir, { recursive: true });
  } catch (e) {
    console.error("Failed to create dest folder for upload:", e);
    try { fs.unlinkSync(uploadedPath); } catch (e2) {}
    return res.status(500).json({ error: "Failed to create destination folder" });
  }

  let extractionError = null;
  try {
    if (lower.endsWith(".zip")) await extractZipFile(uploadedPath, destDir);
    else if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz") || lower.endsWith(".tar")) await extractTarFile(uploadedPath, destDir);
    else if (lower.endsWith(".7z") || lower.endsWith(".rar")) await extractWith7zOrUnrar(uploadedPath, destDir);
    else extractionError = "Unsupported archive type. Supported: .zip, .tar.gz, .tgz, .tar, .7z, .rar";
  } catch (err) {
    console.error("[upload] Extraction failed:", err && (err.message || err));
    extractionError = err && err.message ? err.message : String(err);
  }
  try { if (fs.existsSync(uploadedPath)) fs.unlinkSync(uploadedPath); } catch (e) {
    console.warn("[upload] Failed to remove uploaded temp file:", e && e.message);
  }

  if (extractionError) {
    try { fs.rmSync(destDir, { recursive: true, force: true }); } catch (e) {
      console.warn("[upload] Failed to cleanup dest dir after error:", e && e.message);
    }
    if (req.headers && req.headers.accept && req.headers.accept.includes("text/html")) return res.redirect("/?upload=failed");
    return res.status(400).json({ error: "Upload failed: " + extractionError });
  }

  if (req.headers && req.headers.accept && req.headers.accept.includes("text/html")) return res.redirect("/");
  return res.json({ ok: true, folder: finalFolder, msg: "Extracted to " + finalFolder });
});
app.post("/extract", async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "not authenticated" });
  const { bot, path: relPath } = req.body || {};
  if (!bot || !relPath) return res.status(400).json({ error: "missing bot or path" });
  if (bot.includes("..") || bot.includes("/") || bot.includes("\\")) return res.status(400).json({ error: "Invalid bot" });
  const base = path.resolve(BOTS_DIR);
  const fileFull = path.resolve(path.join(BOTS_DIR, bot, relPath));
  if (!fileFull.startsWith(base + path.sep) && fileFull !== base) return res.status(400).json({ error: "Invalid path" });
  if (!fs.existsSync(fileFull)) return res.status(404).json({ error: "File not found" });
  const stat = fs.statSync(fileFull);
  if (!stat.isFile()) return res.status(400).json({ error: "Not a file" });
  const fileLower = fileFull.toLowerCase();
  const destDir = path.dirname(fileFull);
  try {
    if (fileLower.endsWith(".zip")) await extractZipFile(fileFull, destDir);
    else if (fileLower.endsWith(".tar.gz") || fileLower.endsWith(".tgz") || fileLower.endsWith(".tar")) await extractTarFile(fileFull, destDir);
    else if (fileLower.endsWith(".7z") || fileLower.endsWith(".rar")) await extractWith7zOrUnrar(fileFull, destDir);
    else return res.status(400).json({ error: "Unsupported archive type" });
    return res.json({ ok: true, msg: "Extracted successfully" });
  } catch (e) {
    console.error("[extract] failed:", e && e.message);
    return res.status(500).json({ error: "Extraction failed: " + (e && e.message ? e.message : String(e)) });
  }
});

// --- BOT PAGE ---
const nodeVersions = ["14", "16", "18", "20"];
app.get("/bot/:bot", (req, res) => {
  // normalizează/canonizează numele ca să nu pice pe diferențe de caz/format
  const requested = req.params.bot;
  const botName = canonicalizeBotName(requested);

  // avem voie să intrăm dacă serverul e fie local (folder prezent),
  // fie înregistrat în servers.json (ex. creat pe un nod remote)
  const existsLocal = fs.existsSync(path.join(BOTS_DIR, botName));
  const isIndexed  = loadServersIndex().some(e => e && e.name === botName);

  if (!existsLocal && !isIndexed) {
    // nu există nici local, nici în index → întoarce la dashboard
    return res.redirect("/");
  }

  // verifică ACL: admin sau are acces explicit
  if (!isAdmin(req) && !userHasAccessToServer(req.session.user, botName)) {
    return res.redirect("/");
  }

  // randăm pagina chiar dacă e pe nod remote (fișierele/console se vor ocupa via API-urile tale)
  res.render("bot", {
    bot: botName,
    nodeVersions,
  });
});
app.get("/explore/:bot", (req, res) => {
  const bot = req.params.bot;
  const rel = req.query.path || "";
  const dir = path.join(BOTS_DIR, bot, rel);
  if (!fs.existsSync(dir)) return res.json({ error: "No such dir" });
  const entries = fs.readdirSync(dir).map((n) => {
    const full = path.join(dir, n);
    return { name: n, isDir: fs.statSync(full).isDirectory() };
  });
  res.json({ path: rel, entries });
});

// === FILES (LOCAL): list / read / write pentru editor ===
app.get("/api/servers/:name/files/list", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "not authenticated" });

  const name = String(req.params.name || "").trim();
  if (!isAdmin(req) && !userHasAccessToServer(req.session.user, name)) {
    return res.status(403).json({ error: "no access to server" });
  }

  const rel = String(req.query.path || "");
  const root = path.join(BOTS_DIR, name);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    return res.status(404).json({ error: "server not found" });
  }

  const dir = safeJoinLocal(root, rel);
  if (!dir) return res.status(400).json({ error: "invalid path" });
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    return res.status(400).json({ error: "not a directory" });
  }

  const entries = fs.readdirSync(dir, { withFileTypes: true }).map(d => {
    const fp = path.join(dir, d.name);
    const st = fs.statSync(fp);
    return { name: d.name, isDir: d.isDirectory(), size: d.isDirectory() ? 0 : st.size, mtime: st.mtimeMs };
  });

  return res.json({ ok: true, path: rel, entries });
});

app.get("/api/servers/:name/files/read", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "not authenticated" });

  const name = String(req.params.name || "").trim();
  if (!isAdmin(req) && !userHasAccessToServer(req.session.user, name)) {
    return res.status(403).json({ error: "no access to server" });
  }

  const rel = String(req.query.path || "");
  const root = path.join(BOTS_DIR, name);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    return res.status(404).json({ error: "server not found" });
  }

  const file = safeJoinLocal(root, rel);
  if (!file) return res.status(400).json({ error: "invalid path" });
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
    return res.status(404).json({ error: "file not found" });
  }

  const content = fs.readFileSync(file, "utf8");
  return res.json({ ok: true, path: rel, content });
});

app.put("/api/servers/:name/files/write", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "not authenticated" });

  const name = String(req.params.name || "").trim();
  if (!isAdmin(req) && !userHasAccessToServer(req.session.user, name)) {
    return res.status(403).json({ error: "no access to server" });
  }

  const rel = String(req.body && req.body.path || "");
  const content = String((req.body && req.body.content) || "");
  const root = path.join(BOTS_DIR, name);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    return res.status(404).json({ error: "server not found" });
  }

  const file = safeJoinLocal(root, rel);
  if (!file) return res.status(400).json({ error: "invalid path" });
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, "utf8");
  return res.json({ ok: true });
});

// --- LOG BUFFER ---
const LOG_BUFFER_SIZE = 500;
const buffers = {};
function initBuffer(bot) { if (!buffers[bot]) buffers[bot] = []; }
function pushBuffer(bot, line) {
  initBuffer(bot);
  const s = String(line)
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(/\s+$/g, ""); // taie TOT whitespace-ul de la final (inclusiv \n)
  if (!s) return;
  buffers[bot].push(s);
  if (buffers[bot].length > LOG_BUFFER_SIZE) buffers[bot].shift();
}

function safeLoadJSON(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return {}; }
}

function loadVersions() {
  if (!VERSIONS_JSON) VERSIONS_JSON = JSON.parse(fs.readFileSync(VERSIONS_JSON_PATH, 'utf8'));
  return VERSIONS_JSON;
}

let VERSIONS_JSON = null;

function findVersionUrl(providerId, versionId) {
  try {
    const providers = Array.isArray(versionsConfig)
      ? versionsConfig
      : (versionsConfig.providers || []);

    for (const p of providers) {
      const pid = p.id || p.provider;
      if (String(pid) !== String(providerId)) continue;

      const versions = p.versions || [];
      for (const v of versions) {
        const vid = v.id || v.name || v.version;
        if (String(vid) === String(versionId)) {
          return v.url || v.link || v.download || v.href || null;
        }
      }
    }
  } catch (e) {
    console.warn('[findVersionUrl] failed:', e && e.message);
  }
  return null;
}

function tailLogsRemote(name, baseUrl, headers) {
  if (remoteLogClients[name]) return;
  const url = `${baseUrl}/v1/servers/${encodeURIComponent(name)}/logs`;
  const lib = url.startsWith("https:") ? https : httpMod;
  const hdrs = { ...headers };
  delete hdrs["Content-Type"];
  const req = lib.request(url, { method: "GET", headers: hdrs });
  req.on("response", (res) => {
    res.setEncoding("utf8");
    res.on("data", (chunk) => {
      // parse SSE "data: { line: ... }"
      const lines = String(chunk).split("\n");
      for (const L of lines) {
        if (L.startsWith("data: ")) {
          try {
            const obj = JSON.parse(L.slice(6));
            if (obj && obj.line) _emitLine(name, obj.line);
          } catch {}
        }
      }
    });
    res.on("end", () => { delete remoteLogClients[name]; });
  });
  req.on("error", () => { delete remoteLogClients[name]; });
  req.end();
  remoteLogClients[name] = req;
}

function getServerRecord(name) {
  const list = loadServers();
  const n = String(name || '').trim();
  return list.find(s => (s.name === n) || (s.id === n)) || null;
}
function resolveNodeBase(serverRec) {
  // ia adresa nodului din server record (fără allowlist)
  const host = serverRec.nodeHost || serverRec.nodeIp || serverRec.ip;
  const port = Number(serverRec.nodeApiPort || 8080);
  if (!host) return null;
  return `http://${host}:${port}`;
}


// === [ADD route] ==========================================
// Primește { providerId, versionId } din frontend
// APPLY: descarcă/forward-ează versiunea selectată (frontend -> panel)

// ---- Helpers Minecraft detection + log cleaning ----
function findServer(botName) {
  const servers = loadServersIndex();
  const needle = String(botName || "").trim().toLowerCase();
  if (!Array.isArray(servers)) return null;
  return servers.find((s) => {
    if (!s) return false;
    if (s.name && String(s.name).toLowerCase() === needle) return true;
    if (s.id && String(s.id).toLowerCase() === needle) return true;
    if (s.bot && String(s.bot).toLowerCase() === needle) return true;
    return false;
  }) || null;
}

function isRemoteEntry(entry) {
  return !!(entry && entry.nodeId && entry.nodeId !== "local" && entry.ip);
}

async function forwardNodeKill(entry, bot) {
  // identifică nodul după entry.nodeId
  const node = findNodeByIdOrName(entry.nodeId);
  if (!node) {
    return { status: 400, json: { error: "node-not-found" } };
  }

  const baseUrl = buildNodeBaseUrl(node.address, node.api_port || 8080);
  const headers = nodeAuthHeadersFor(node, true); // -> pune Authorization/X-Node-Token

  return httpRequestJson(
    `${baseUrl}/v1/servers/${encodeURIComponent(bot)}/kill`,
    "POST",
    headers, // <— IMPORTANT: acum ai Bearer token
    null,
    20_000
  );
}

// Încarcă versions.json o singură dată (dacă vrei live-reload, poți citi în route)
let versionsConfig = { providers: [] };
try {
  const rawVersions = fs.readFileSync(versionsPath, 'utf8');
  versionsConfig = JSON.parse(rawVersions);
} catch (e) {
  console.error('Cannot read versions.json:', e.message);
}

function normalizeTemplateId(tpl){
  const raw = (tpl || '').toString().trim().toLowerCase();
  if (!raw) return '';
  if (["discord-bot", "discord", "discord bot", "bot", "node", "nodejs", "python"].includes(raw)) return "discord-bot";
  if (["mc", "minecraft"].includes(raw)) return "minecraft";
  return raw;
}

function providerTemplates(provider){
  if (!provider) return [];
  if (provider.templates && Array.isArray(provider.templates)) {
    return provider.templates.map(normalizeTemplateId);
  }
  if (provider.template) return [normalizeTemplateId(provider.template)];
  return ['minecraft'];
}

function providerSupportsTemplate(provider, tpl){
  const normalized = normalizeTemplateId(tpl);
  if (!normalized) return true;
  return providerTemplates(provider).includes(normalized);
}

function sanitizePythonVersionTag(version){
  const raw = (version || '').toString().trim();
  if (!raw) return null;
  const clean = raw.replace(/^v/, '');
  if (!/^[A-Za-z0-9._-]+$/.test(clean)) return null;
  return clean;
}

function inferPythonStart(entry, meta){
  const candidates = [entry?.start, meta?.start, 'main.py'];
  for (const c of candidates){
    if (!c) continue;
    const s = String(c).trim();
    if (!s) continue;
    if (s.toLowerCase().endsWith('.py')) return s;
  }
  return 'main.py';
}

function buildPythonVersionConfig(versionId, entry, meta){
  const clean = sanitizePythonVersionTag(versionId);
  if (!clean) return null;
  const startFile = inferPythonStart(entry, meta);
  return {
    id: versionId,
    name: clean,
    label: `Python ${clean}`,
    start: startFile,
    docker: {
      image: 'python',
      tag: `${clean}-slim`,
      command: `python /app/${startFile}`
    }
  };
}

async function wipeBotDirectory(bot){
  const dir = botRoot(bot);
  try {
    await fsp.rm(dir, { recursive: true, force: true });
  } catch (e) {
    console.warn('[python-runtime] failed to remove bot directory before recreate:', e && e.message);
  }
  try {
    await fsp.mkdir(dir, { recursive: true });
  } catch (e) {
    console.warn('[python-runtime] failed to recreate bot directory:', e && e.message);
    throw e;
  }
}

function readBotMeta(bot){
  try {
    const p = path.join(BOTS_DIR, bot, 'adpanel.json');
    if (!fs.existsSync(p)) return null;
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch { return null; }
}

function resolveTemplateForBot(bot){
  const entry = findServer(bot);
  const meta = readBotMeta(bot) || {};

  const explicit = normalizeTemplateId(entry?.template || meta.template || meta.type);
  if (explicit) return { entry, meta, template: explicit };

  const start = String(entry?.start || meta.start || '').toLowerCase();
  if (start.endsWith('.jar')) return { entry, meta, template: 'minecraft' };
  if (start.endsWith('.js') || start.endsWith('.ts') || start.endsWith('.py')) {
    return { entry, meta, template: 'discord-bot' };
  }

  return { entry, meta, template: '' };
}

function providersForTemplate(tpl){
  const providers = Array.isArray(versionsConfig)
    ? versionsConfig
    : (versionsConfig.providers || []);
  return providers.filter(p => providerSupportsTemplate(p, tpl));
}

async function fetchPythonTagsFromGitHub(){
  const url = 'https://api.github.com/repos/python/cpython/tags';
  return await fetchJson(url);
}

function mapPythonTagsToVersions(tags){
  const list = Array.isArray(tags) ? tags : [];
  return list.map(tag => {
    const raw = (tag && tag.name) ? String(tag.name) : '';
    const clean = sanitizePythonVersionTag(raw) || raw;
    return {
      id: raw,
      name: clean,
      label: `Python ${clean || raw || 'unknown'}`,
      releaseDate: '',
      tags: ['PYTHON']
    };
  });
}

function findProviderConfig(providerId){
  const providers = Array.isArray(versionsConfig)
    ? versionsConfig
    : (versionsConfig.providers || []);
  return providers.find(p => String(p.id) === String(providerId)) || null;
}

function findProviderVersionConfig(providerId, versionId){
  const provider = findProviderConfig(providerId);
  if (!provider) return null;
  const versions = Array.isArray(provider.versions) ? provider.versions : [];
  return versions.find(v => String(v.id || v.name || v.version) === String(versionId)) || null;
}

function stripMinecraftColors(s) {
  if (!s) return s;
  // culori RGB style §x§R§R§G§G§B§B
  s = s.replace(/§x(?:§[0-9A-Fa-f]){6}/g, "");
  // culori clasice §a, §b, §l, etc.
  s = s.replace(/§[0-9A-FK-ORa-fk-or]/g, "");
  return s;
}

/**
 * Detectează dacă serverul este Minecraft
 * 1) verifică servers.json (template === "minecraft")
 * 2) fallback: adpanel.json cu type: "minecraft"
 */
function isMinecraftBot(name) {
  // încearcă servers.json (index)
  const entry = findServer(name);
  if (entry && entry.template && String(entry.template).toLowerCase() === 'minecraft') {
    return true;
  }
  // fallback: citește adpanel.json din folderul local (dacă există)
  try {
    const metaPath = path.join(BOTS_DIR, name, 'adpanel.json');
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    if (String(meta.type || '').toLowerCase() === 'minecraft') return true;
    if (/server\.jar$/i.test(String(meta.start || ''))) return true;
  } catch {}
  return false;
}

const ANSI_RE = new RegExp(
  "[\\u001B\\u009B][[\\]()#;?]*(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\\u0007|(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-nq-uy=><~])",
  "g"
);
function stripMinecraftColors(s) {
  if (!s) return s;
  s = s.replace(/§x(?:§[0-9A-Fa-f]){6}/g, "");
  s = s.replace(/§[0-9A-FK-ORa-fk-or]/g, "");
  return s;
}

/**
 * Curăță logurile:
 *  - scoate ANSI
 *  - scoate culorile Minecraft
 *  - OPTIONAL: ascunde liniile de init ale imaginii itzg
 */
function cleanLog(bot, chunk) {
  if (!chunk) return "";
  let s = chunk.toString();

  // scoate escape ANSI
  s = s.replace(ANSI_RE, "");

  // normalize CRLF/CR -> LF
  s = s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

  // taie prefixele venite de la agenți remote (docker stream)
  s = s.replace(/^(?:stdout|stderr):\s?/gm, "");

  const out = [];
  for (let line of s.split("\n")) {
    // ascunde “waiting container …” emis de agentul remote
    if (/^\s*\[waiting\]\s+container\b/i.test(line)) continue;

    // filtrele tale existente
    if (
      line.includes("Usage:  docker") ||
      line.includes("Run 'docker COMMAND --help'") ||
      line.includes("For more help on how to use Docker")
    ) continue;
    if (/^\s*Container started\s*$/i.test(line)) continue;
    if (/^[0-9a-f]{64}(?:\s*Container started)?\s*$/i.test(line)) continue;
    if (/Error response from daemon:\s*No such container/i.test(line)) continue;
    if (/^\s*\[init\]\s/i.test(line)) continue;
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z,?version=.*$/i.test(line)) continue;

    line = line.replace(/\s+$/,"");
    if (typeof isMinecraftBot === "function" && isMinecraftBot(bot)) {
      line = stripMinecraftColors(line);
    }
    if (line.trim() === "") continue;
    out.push(line);
  }

  return out.join("\n").replace(/\n{2,}/g, "\n");
}

function buildArgsFromTemplate(name, tpl, botDir) {
  const d = tpl.docker || {};
  const args = ["run", "-d", "--name", name];
  if (d.restart) args.push("--restart", d.restart);
  (d.ports || []).forEach(p => { if (p) args.push("-p", p); });
  Object.entries(d.env || {}).forEach(([k, v]) => args.push("-e", `${k}=${v ?? ""}`));
  (d.volumes || []).forEach(v => {
    if (!v) return;
    const mapped = v.replaceAll("{BOT_DIR}", botDir);
    args.push("-v", mapped);
  });
  const image = `${d.image || "alpine"}:${d.tag || "latest"}`;
  const final = [...args, image];
  if (d.command && String(d.command).trim()) final.push("sh", "-lc", d.command);
  return final;
}
function guessArgsForLegacyRun(name, botDir, file, port) {
  if (file && file.endsWith(".js")) {
    const args = ["run", "-d", "--name", name, "--restart", "unless-stopped",
      "-v", `${botDir}:/app`];
    if (port) args.push("-p", `${port}:${port}`);
    const image = "node:20-alpine";
    const cmd = `node /app/${file}`;
    return [...args, image, "sh", "-lc", cmd];
  } else {
    const targetPort = port || 8080;
    const args = ["run", "-d", "--name", name, "--restart", "unless-stopped",
      "-v", `${botDir}:/usr/share/nginx/html:ro`,
      "-p", `${targetPort}:80`];
    const image = "nginx:alpine";
    return [...args, image];
  }
}

// Găsește URL-ul de download pentru (providerId, versionId) din versionsConfig
function getVersionUrlFromConfig(providerId, versionId) {
  try {
    const providers = Array.isArray(versionsConfig)
      ? versionsConfig
      : (versionsConfig.providers || []);
    for (const p of providers) {
      const pid = p.id || p.provider;
      if (String(pid) !== String(providerId)) continue;
      const versions = p.versions || [];
      for (const v of versions) {
        const vid = v.id || v.name || v.version;
        if (String(vid) === String(versionId)) {
          return v.url || v.link || v.download || v.href || null;
        }
      }
    }
  } catch (_) {}
  return null;
}

function _emitLine(name, text) {
  const cleaned = cleanLog(name, text);
  if (!cleaned) return;

  const noTrail = cleaned.replace(/\s+$/g, "");
  if (!noTrail) return;

  pushBuffer(name, noTrail);
  io.to(name).emit("output", noTrail);

  // Banner o singură dată când Paper zice că e "Done ..."
  if (
    !_startedOnce.has(name) &&
    /\bDone\s+\(.+?\)!\s+For help, type "help"/.test(noTrail)
  ) {
    _startedOnce.add(name);
    const banner = "[ADPanel] Server started";
    pushBuffer(name, banner);
    io.to(name).emit("output", banner);
  }
}

async function tailLogs(name) {
  if (logProcesses[name]) return;

  // pornește tail doar dacă există containerul
  try {
    await dockerCollect(["inspect", name]);
  } catch {
    setTimeout(() => tailLogs(name), 500);
    return;
  }

  const p = docker(["logs", "-f", name]);
  logProcesses[name] = p;
  _lineBuf[name] = "";

  function softSplit(buf) {
    buf = buf.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    // introduce NL înaintea markerelor cunoscute (dacă nu e deja un \n)
    buf = buf
      .replace(/(?<!\n)(?=20\d{2}-\d{2}-\d{2}T)/g, "\n") // ISO 8601
      .replace(/(?<!\n)(?=\[\d{2}:\d{2}:\d{2}\s(?:INFO|WARN|ERROR))/g, "\n")
      .replace(/(?<!\n)(?=Starting org\.bukkit\.craftbukkit\.Main)/g, "\n")
      .replace(/(?<!\n)(?=\*\*\* Warning)/g, "\n");
    return buf.replace(/\n{2,}/g, "\n");
  }

  function onData(d) {
    let buf = (_lineBuf[name] || "") + d.toString();
    buf = softSplit(buf);
    const parts = buf.split("\n");
    for (let i = 0; i < parts.length - 1; i++) _emitLine(name, parts[i]);
    _lineBuf[name] = parts[parts.length - 1]; // rest neterminat (fără \n)
  }

  p.stdout.on("data", onData);
  p.stderr.on("data", onData);

  p.on("close", () => {
    const rem = _lineBuf[name];
    if (rem) _emitLine(name, rem);
    delete _lineBuf[name];
    delete logProcesses[name];
    _emitLine(name, "[ADPanel] Server closed");
  });
}

// ---- CREATE API ----
function sanitizeServerName(raw) {
  let name = (raw || "").trim();
  if (!name) return "";
  if (name.includes("..") || /[\/\\]/.test(name) || name.length > 120) return "";
  name = name.replace(/\s+/g, "-").replace(/[^\w\-_.]/g, "").replace(/^-+|-+$/g, "");
  return name;
}

// pune asta imediat sub function sanitizeServerName(...) sau lângă loadServersIndex()
function canonicalizeBotName(raw) {
  const s = String(raw || '').trim();
  const list = loadServersIndex();
  const found = Array.isArray(list) ? list.find(e => e && typeof e.name === 'string' && e.name.toLowerCase() === s.toLowerCase()) : null;
  // dacă îl găsim în servers.json, întoarcem numele „canonic” din index; altfel păstrăm ce vine în URL
  return found ? found.name : s;
}

// NEW: helpers for port handling (minimal invasive)
function clampPort(p) {
  const n = Number(p);
  if (!Number.isInteger(n)) return 25565;
  if (n < 1 || n > 35650) return 25565;
  return n;
}
function setMinecraftServerPort(botDir, port) {
  const propsPath = path.join(botDir, "server.properties");
  let content = "";
  try { content = fs.existsSync(propsPath) ? fs.readFileSync(propsPath, "utf8") : ""; } catch {}
  if (!content) content = "";
  if (/^server-port\s*=/m.test(content)) {
    content = content.replace(/^server-port\s*=.*$/m, `server-port=${port}`);
  } else {
    if (content && !content.endsWith("\n")) content += "\n";
    content += `server-port=${port}\n`;
  }
  try { fs.writeFileSync(propsPath, content, "utf8"); } catch {}
}

function fixedJarUrlFor1218(fork) {
  const f = String(fork || "").toLowerCase();
  if (f === "paper") {
    return "https://fill-data.papermc.io/v1/objects/8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e/paper-1.21.8-60.jar";
  }
  if (f === "pufferfish") {
    return "https://ci.pufferfish.host/job/Pufferfish-1.21/33/artifact/pufferfish-server/build/libs/pufferfish-paperclip-1.21.8-R0.1-SNAPSHOT-mojmap.jar";
  }
  if (f === "vanilla") {
    return "https://piston-data.mojang.com/v1/objects/95495a7f485eedd84ce928cef5e223b757d2f764/server.jar";
  }
  return "https://api.purpurmc.org/v2/purpur/1.21.8/2497/download";
}
async function getMinecraftJarUrl(fork, version) {
  const v = String(version || "").trim();
  const f = String(fork || "").toLowerCase();
  if (v === "1.21.8") return fixedJarUrlFor1218(f);
  try {
    if (f === "purpur") {
      return `https://api.purpurmc.org/v2/purpur/${v}/latest/download`;
    }
    if (f === "paper") {
      const builds = await fetchJson(`https://api.papermc.io/v2/projects/paper/versions/${v}/builds`);
      const list = Array.isArray(builds && builds.builds) ? builds.builds : [];
      if (list.length > 0) {
        const last = list[list.length - 1];
        const build = last.build;
        const jarName = last.downloads?.application?.name || `paper-${v}-${build}.jar`;
        return `https://api.papermc.io/v2/projects/paper/versions/${v}/builds/${build}/downloads/${jarName}`;
      }
    }
    if (f === "vanilla") {
      const manifest = await fetchJson("https://piston-meta.mojang.com/mc/game/version_manifest_v2.json");
      const ver = (manifest.versions || []).find(x => x.id === v);
      if (ver?.url) {
        const det = await fetchJson(ver.url);
        if (det?.downloads?.server?.url) return det.downloads.server.url;
      }
    }
    if (f === "pufferfish") {
      const builds = await fetchJson(`https://api.papermc.io/v2/projects/paper/versions/${v}/builds`);
      const list = Array.isArray(builds && builds.builds) ? builds.builds : [];
      if (list.length > 0) {
        const last = list[list.length - 1];
        const build = last.build;
        const jarName = last.downloads?.application?.name || `paper-${v}-${build}.jar`;
        return `https://api.papermc.io/v2/projects/paper/versions/${v}/builds/${jarName ? jarName.replace(`paper-${v}-`, "") : last.build}/downloads/${jarName || `paper-${v}-${build}.jar`}`;
      }
    }
  } catch (e) {
    console.warn("[minecraft] jar url resolve failed:", e && e.message);
  }
  return `https://api.purpurmc.org/v2/purpur/${v}/latest/download`;
}
function writeMinecraftScaffold(botDir, name, fork, version) {
  const eulaPath = path.join(botDir, "eula.txt");
  try { fs.writeFileSync(eulaPath, "eula=true\n", "utf8"); } catch {}
  const props = `motd=${name}\nmax-players=20\nenforce-secure-profile=false\n`;
  try { fs.writeFileSync(path.join(botDir, "server.properties"), props, "utf8"); } catch {}
  const meta = { type: "minecraft", fork, version, start: "server.jar", createdAt: Date.now() };
  try { fs.writeFileSync(path.join(botDir, "adpanel.json"), JSON.stringify(meta, null, 2), "utf8"); } catch {}
}
function writeDiscordBotScaffold(botDir) {
  const idx = `console.log("ADPanel Discord Bot starter");\nconsole.log("TOKEN:", process.env.DISCORD_TOKEN ? "set" : "missing");\nsetInterval(()=>{}, 1<<30);\n`;
  try { fs.writeFileSync(path.join(botDir, "index.js"), idx, "utf8"); } catch {}
  const pkg = {
    name: path.basename(botDir),
    private: true,
    type: "module",
    version: "0.0.0",
    main: "index.js",
    scripts: { start: "node index.js" }
  };
  try { fs.writeFileSync(path.join(botDir, "package.json"), JSON.stringify(pkg, null, 2), "utf8"); } catch {}
}

function runTemplateContainerNow(name, templateId, botDir, moreEnv = {}, overrideDocker = null) {
  const tpl = DOCKER_TEMPLATES.find(t => t.id === templateId);
  if (!tpl) throw new Error("Unknown template");

  const copy = JSON.parse(JSON.stringify(tpl));
  copy.docker = copy.docker || {};
  if (overrideDocker && overrideDocker.env) {
    copy.docker.env = Object.assign({}, copy.docker.env || {}, overrideDocker.env || {});
  }
  copy.docker.env = Object.assign({}, copy.docker.env || {}, moreEnv || {});
  if (overrideDocker) {
    if (Array.isArray(overrideDocker.ports)) copy.docker.ports = overrideDocker.ports;
    if (Array.isArray(overrideDocker.volumes)) copy.docker.volumes = overrideDocker.volumes;
    if (typeof overrideDocker.command === "string") copy.docker.command = overrideDocker.command;
    if (typeof overrideDocker.restart === "string") copy.docker.restart = overrideDocker.restart;
  }

  const args = buildArgsFromTemplate(name, copy, botDir);
  const p = docker(args);

  // NU atașăm p.stdout (Docker ar scrie ID-ul containerului).
  // Dacă vrei erorile de la `docker run`, poți lăsa stderr:
p.stderr.on("data", d => _emitLine(name, d.toString()));

  p.on("close", (code) => {
if (code === 0) {
  _emitLine(name, "[ADPanel] Server started");
  tailLogs(name);
} else {
  _emitLine(name, "[ADPanel] Server failed to start");
}
  });
}

app.post("/api/servers/create", async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "not authenticated" });

  try {
    const { name: rawName, templateId } = req.body || {};
    const mcFork = req.body?.mcFork ? String(req.body.mcFork).toLowerCase() : "paper";
    const mcVersion = req.body?.mcVersion ? String(req.body.mcVersion).trim() : "1.21.8";
    const hostPortRaw = (req.body && (req.body.hostPort ?? req.body.port)) ?? null;
    const nodeId = req.body?.nodeId || "local";
    const isLocal = !nodeId || nodeId === "local";

    const name = sanitizeServerName(rawName);
    if (!name) return res.status(400).json({ error: "invalid name" });
    if (!templateId) return res.status(400).json({ error: "missing templateId" });

    // porțiuni comune pentru indexare + ACL
    function startFileFor(templateId) {
      if (templateId === "minecraft") return "server.jar";
      if (templateId === "discord-bot") return "index.js";
      return null;
    }

    if (!isLocal) {
      // ---- remote create on node ----
      const node = findNodeByIdOrName(nodeId);
      if (!node) return res.status(400).json({ error: "node not found" });

      const payload = {
        name,
        templateId,
        mcFork,
        mcVersion,
        hostPort: hostPortRaw
      };

      // va arunca eroare dacă nu reușește
      await createOnRemoteNode(node, payload);

      try {
        const me = req.session.user;
        const u = findUserByEmail(me);
        if (!(u && u.admin)) addAccessForEmail(me, name);
      } catch {}

      try {
        const savedPort = templateId === "minecraft" ? clampPort(hostPortRaw) : null;
        const entry = {
          name,
          template: templateId,
          start: startFileFor(templateId),
          ip: node.address || null,
          nodeId: node.uuid || node.id || node.name
        };
        if (savedPort != null) entry.port = savedPort;
        upsertServerIndexEntry(entry);
      } catch (e) {
        console.warn("[servers.json] upsert failed (remote):", e && e.message);
      }

      return res.json({ ok: true, name });
    }

    // ---- local create (comportamentul tău existent, neschimbat) ----
    const base = path.resolve(BOTS_DIR);
    const botDir = path.resolve(path.join(BOTS_DIR, name));
    if (!botDir.startsWith(base + path.sep) && botDir !== base) return res.status(400).json({ error: "invalid path" });
    if (fs.existsSync(botDir)) return res.status(400).json({ error: "server already exists" });

    fs.mkdirSync(botDir, { recursive: true });

    await ensureNoContainer(name);

    let startFileForIndex = null;
    let savedPort = null;

    if (templateId === "minecraft") {
      const fork = mcFork || "paper";
      const version = mcVersion || "1.21.8";
const hostPort = clampPort(hostPortRaw);
savedPort = hostPort;

// scrie fișierele de bază (eula, adpanel.json, server.properties simplu)
writeMinecraftScaffold(botDir, name, fork, version);

// setăm și portul în server.properties ca să nu fie 25565
setMinecraftServerPort(botDir, hostPort);

const jarUrl = await getMinecraftJarUrl(fork, version);
const jarPath = path.join(botDir, "server.jar");
      try { await downloadToFile(jarUrl, jarPath); } catch (e) {
        console.warn("[minecraft] download failed:", e && e.message);
      }

      await pullImage("itzg/minecraft-server:latest");

const uid = typeof process.getuid === "function" ? process.getuid() : 1000;
const gid = typeof process.getgid === "function" ? process.getgid() : 1000;

const extraEnv = {
  TYPE: "CUSTOM",
  CUSTOM_SERVER: "/data/server.jar",
  ENABLE_RCON: "false",
  CREATE_CONSOLE_IN_PIPE: "true",
  UID: String(uid),
  GID: String(gid),
  // dacă setezi și portul:
  SERVER_PORT: String(hostPort),
};

      const overrideDocker = { ports: [`${hostPort}:25565`] };
      runTemplateContainerNow(name, "minecraft", botDir, extraEnv, overrideDocker);

      startFileForIndex = "server.jar";
    } else if (templateId === "discord-bot") {
      writeDiscordBotScaffold(botDir);
      await pullImage("node:20-alpine");
      runTemplateContainerNow(name, "discord-bot", botDir, {});
      startFileForIndex = "index.js";
    } else if (templateId === "vanilla") {
      await pullImage("alpine:latest");
      runTemplateContainerNow(name, "vanilla", botDir, {});
      startFileForIndex = null;
    } else {
      console.warn("[create] unknown templateId", templateId);
    }

    try {
      const me = req.session.user;
      const u = findUserByEmail(me);
      if (!(u && u.admin)) addAccessForEmail(me, name);
    } catch {}

    try {
      let hostIp = null;
      try {
        const rawHost = req.headers["x-forwarded-host"] || req.headers["host"] || "";
        const hostname = extractHostnameFromHeader(rawHost);
        hostIp = await resolvePublicIpFromHost(hostname);
      } catch {}
      const entry = {
        name,
        template: templateId,
        start: startFileForIndex,
        ip: hostIp || null
      };
      if (savedPort != null) entry.port = savedPort;

      upsertServerIndexEntry(entry);
    } catch (e) {
      console.warn("[servers.json] upsert failed:", e && e.message);
    }

    return res.json({ ok: true, name });
  } catch (e) {
    console.error("[/api/servers/create] failed:", e && e.message);
    return res.status(500).json({ error: e && e.message ? e.message : "create failed" });
  }
});

app.post("/create", async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).send("Not authenticated");

  const { bot, type, name } = req.body || {};
  const relPath = (req.body && typeof req.body.path !== "undefined") ? String(req.body.path) : "";

  const normalizedType = String(type || "").trim().toLowerCase();
  if (!bot || !normalizedType || !name) return res.status(400).send("Missing fields");
  if (!isAdmin(req) && !userHasAccessToServer(req.session.user, bot)) {
    return res.status(403).send("Not authorized");
  }

  if (normalizedType !== "file" && normalizedType !== "folder") {
    return res.status(400).send("Invalid type");
  }

  const safeName = String(name).trim();
  if (!safeName || safeName.includes("..") || /[\\/]/.test(safeName)) {
    return res.status(400).send("Invalid name");
  }

  const root = path.join(BOTS_DIR, bot);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    return res.status(404).send("Server not found");
  }

  const target = safeJoinLocal(root, path.join(relPath || "", safeName));
  if (!target) return res.status(400).send("Invalid path");

  if (fs.existsSync(target)) return res.status(400).send("Already exists");

  try {
    if (normalizedType === "folder") {
      await fsp.mkdir(target, { recursive: true });
    } else {
      await fsp.mkdir(path.dirname(target), { recursive: true });
      await fsp.writeFile(target, "", "utf8");
    }
    return res.json({ ok: true, path: path.relative(root, target) });
  } catch (e) {
    console.error("[create] failed:", e && e.message ? e.message : e);
    return res.status(500).send("Create failed");
  }
});

app.post("/rename", (req, res) => {
  const { bot, oldPath, newName } = req.body || {};
  if (!bot || !oldPath || !newName) return res.status(400).send("Missing fields");
  const safeNewName = String(newName).trim();
  if (safeNewName === "" || safeNewName.includes("..") || safeNewName.includes("/") || safeNewName.includes("\\")) {
    return res.status(400).send("Invalid new name");
  }
  const base = path.resolve(BOTS_DIR);
  const oldFull = path.resolve(path.join(BOTS_DIR, bot, oldPath));
  if (!oldFull.startsWith(base + path.sep) && oldFull !== base) return res.status(400).send("Invalid path");
  if (!fs.existsSync(oldFull)) return res.status(404).send("Not found");

  const dir = path.dirname(oldFull);
  const newFull = path.resolve(path.join(dir, safeNewName));
  if (!newFull.startsWith(base + path.sep)) return res.status(400).send("Invalid new path");

  try {
    fs.renameSync(oldFull, newFull);
    return res.status(200).send("Renamed");
  } catch (e) {
    console.error("Rename failed:", e);
    return res.status(500).send("Rename failed");
  }
});

// --- ACCOUNTS: grant per-server permissions (servers.json -> acl[email] = perms)
app.post("/api/settings/accounts/:email/grant-perms", (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: "not authorized" });

  let emailParam = req.params.email || "";
  let email;
  try { email = decodeURIComponent(emailParam); } catch (e) { email = emailParam; }
  email = String(email).trim().toLowerCase();
  if (!email) return res.status(400).json({ error: "missing email" });

  const server = req.body && req.body.server ? String(req.body.server).trim() : "";
  const permsIn = (req.body && typeof req.body.permissions === "object") ? req.body.permissions : null;
  if (!server) return res.status(400).json({ error: "missing server" });

  const base = path.resolve(BOTS_DIR);
  const serverDir = path.resolve(path.join(BOTS_DIR, server));
  if (!serverDir.startsWith(base + path.sep) && serverDir !== base) {
    return res.status(400).json({ error: "invalid server path" });
  }
  if (!(fs.existsSync(serverDir) && fs.statSync(serverDir).isDirectory())) {
    return res.status(404).json({ error: "server not found" });
  }

  const ALLOWED_PERM_KEYS = [
    "files_read",
    "files_delete",
    "files_rename",
    "console_write",
    "server_stop",
    "server_start",
    "files_upload",
    "files_create"
  ];

  const cleanPerms = {};
  for (const k of ALLOWED_PERM_KEYS) {
    cleanPerms[k] = !!(permsIn && typeof permsIn[k] === "boolean" ? permsIn[k] : false);
  }

  try {
    const list = loadServersIndex();
    const idx = list.findIndex(e => e && e.name === server);
    if (idx === -1) {
      list.push({
        name: server,
        acl: { [email]: cleanPerms }
      });
    } else {
      const entry = list[idx] || {};
      const acl = (entry.acl && typeof entry.acl === "object") ? entry.acl : {};
      acl[email] = cleanPerms;
      entry.acl = acl;
      list[idx] = entry;
    }

    const ok = saveServersIndex(list);
    if (!ok) return res.status(500).json({ error: "failed to write servers.json" });

    try { addAccessForEmail(email, server); } catch (e) {
      console.warn("[grant-perms] addAccessForEmail failed:", e && e.message);
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error("[/api/settings/accounts/:email/grant-perms] failed:", e && e.message);
    return res.status(500).json({ error: "failed to grant permissions" });
  }
});

function getEffectivePermsForUserOnServer(email, serverName) {
  const permsTemplate = {
    files_read:false, files_delete:false, files_rename:false, console_write:false,
    server_stop:false, server_start:false, files_upload:false, files_create:false
  };
  if (!email || !serverName) return permsTemplate;

  const u = findUserByEmail(email);
  if (u && u.admin) {
    const allTrue = {};
    for (const k of Object.keys(permsTemplate)) allTrue[k] = true;
    return allTrue;
  }

  const list = loadServersIndex();
  const entry = list.find(e => e && e.name === serverName);
  const acl = entry && entry.acl && typeof entry.acl === 'object' ? entry.acl : null;
  const rec = acl ? acl[String(email).toLowerCase()] : null;

  if (rec && typeof rec === 'object') {
    const merged = { ...permsTemplate };
    for (const k of Object.keys(merged)) merged[k] = !!rec[k];
    return merged;
  }
  return permsTemplate;
}

// === API: permisiuni pentru serverul curent
app.get("/api/servers/:name/permissions", (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "not authenticated" });
  const serverName = String(req.params.name || "").trim();
  if (!isAdmin(req) && !userHasAccessToServer(req.session.user, serverName)) {
    return res.status(403).json({ error: "no access to server" });
  }
  const isAdm = isAdmin(req);
  const perms = getEffectivePermsForUserOnServer(req.session.user, serverName);
  return res.json({ isAdmin: isAdm, perms });
});

app.get('/api/servers/:bot/versions', (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "not authenticated" });

  const bot = req.params.bot;
  const { entry, template } = resolveTemplateForBot(bot);
  if (!entry && !fs.existsSync(botRoot(bot))) {
    return res.status(404).json({ error: 'server-not-found' });
  }

  const providers = providersForTemplate(template).map(p => ({
    id: p.id,
    name: p.name,
    description: p.description,
    logo: p.logo
  }));

  return res.json({ providers });
});

app.get('/api/servers/:bot/versions/:providerId', async (req, res) => {
  if (!isAuthenticated(req)) return res.status(401).json({ error: "not authenticated" });

  const bot = req.params.bot;
  const providerId = req.params.providerId;

  const resolved = resolveTemplateForBot(bot);
  const entry = resolved.entry;
  const template = resolved.template;

  if (!entry && !fs.existsSync(botRoot(bot))) {
    return res.status(404).json({ error: 'server-not-found' });
  }

  const provider = providersForTemplate(template).find(p => p.id === providerId);

  if (!provider) {
    return res.status(404).json({ error: 'provider-not-found' });
  }

  if (provider.id === 'python') {
    try {
      const tags = await fetchPythonTagsFromGitHub();
      const versions = mapPythonTagsToVersions(tags);
      return res.json({
        provider: provider.id,
        displayName: provider.name,
        description: provider.description,
        versions
      });
    } catch (e) {
      console.warn('[versions] failed to load python tags:', e && e.message);
      return res.status(502).json({ error: 'python-versions-unavailable' });
    }
  }

  return res.json({
    provider: provider.id,
    displayName: provider.name,
    description: provider.description,
    versions: provider.versions || []
  });
});

// --- SOCKET.IO
io.use((socket, next) => {
  sessionMiddleware(socket.request, socket.request.res || {}, next);
});

io.on("connection", (socket) => {
  socket.on("join", (botName) => {
    const name = (botName || "").toString().trim();
    if (!name) return;
    try { socket.join(name); } catch (_) {}
});
  // helpers vizibile DOAR pentru conexiunea curentă
  function deny(botName, msg = "Permission denied") {
    io.to(botName).emit("output", msg);
  }
  function hasPerm(botName, permKey) {
    const email = socket.request?.session?.user;
    const perms = getEffectivePermsForUserOnServer(email, botName);
    return !!(perms && perms[permKey]);
  }

socket.on('readFile', async ({ bot, path: rel }) => {
  try {
    const abs = safeResolve(bot, rel);
    const content = await readText(abs);
    io.to(bot).emit('fileData', { path: rel, content });
  } catch (err) {
    io.to(bot).emit('fileData', { path: rel, content: `/* ERROR: ${err.message} */` });
  }
});

socket.on('writeFile', async ({ bot, path: rel, content }) => {
  try {
    const abs = safeResolve(bot, rel);
    await fsp.mkdir(path.dirname(abs), { recursive: true });
    await fsp.writeFile(abs, content ?? '', 'utf8');
    io.to(bot).emit('toast', { type: 'success', msg: `Saved ${rel}` });
  } catch (err) {
    io.to(bot).emit('toast', { type: 'error', msg: `Save failed: ${err.message}` });
  }
});

socket.on('deleteFile', async ({ bot, path: rel }) => {
  try {
    const abs = safeResolve(bot, rel);
    await fsp.rm(abs, { recursive: true, force: true });
    io.to(bot).emit('toast', { type: 'success', msg: `Deleted ${rel}` });
  } catch (err) {
    io.to(bot).emit('toast', { type: 'error', msg: `Delete failed: ${err.message}` });
  }
});

  socket.on("action", async (data) => {
    const { bot, cmd, file, version, port, templateId, docker: overrideDocker } = data || {};
    const botDir = path.join(BOTS_DIR, bot);

    // asigură-te că socketul e în “camera” bot-ului ca să primească io.to(bot).emit(...)
    if (bot) { try { socket.join(bot); } catch {} }

    function logAndBroadcast(chunk) {
      const str = cleanLog(bot, chunk.toString());
      pushBuffer(bot, str);
      io.to(bot).emit("output", str);
    }

    // perm check
    if ((cmd === "stop" || cmd === "restart") && !hasPerm(bot, "server_stop")) return deny(bot);
    if (cmd === "run" && !hasPerm(bot, "server_start")) return deny(bot);
    if (cmd === "install" && !hasPerm(bot, "files_create")) return deny(bot);

    try {
      switch (cmd) {
        case "run": {
       const entry = findServer(bot);
       if (isRemoteEntry(entry)) {
        const node = findNodeByIdOrName(entry.nodeId);
        if (!node) { _emitLine(bot, "[ADPanel] node not found"); break; }
        const baseUrl = buildNodeBaseUrl(node.address, node.api_port || 8080);
        const headers = nodeAuthHeadersFor(node, true);
        const hostPort = entry && entry.port ? clampPort(entry.port) : clampPort(port || 25565);
        const r = await httpRequestJson(
          `${baseUrl}/v1/servers/${encodeURIComponent(bot)}/start`,
          "POST", headers, { hostPort }, 20000
    );
        if (r.status !== 200 || !(r.json && r.json.ok)) {
          const msg = (r.json && (r.json.error || r.json.detail)) || `node status ${r.status}`;
          _emitLine(bot, "[ADPanel] remote start failed: " + msg);
          break;
    }
        _emitLine(bot, "[ADPanel] Remote start OK");
        try { tailLogsRemote(bot, baseUrl, headers); } catch {}
        break;
}
        await ensureNoContainer(bot);

          let runArgs;
          if (templateId) {
            const tpl = DOCKER_TEMPLATES.find(t => t.id === templateId);
            if (!tpl) throw new Error("Unknown template");

            const tplCopy = JSON.parse(JSON.stringify(tpl));
            if (templateId === "minecraft") {
              const srv = findServer(bot);
              const hostPort = srv && srv.port ? clampPort(srv.port) : clampPort(port || 25565);

              setMinecraftServerPort(botDir, hostPort);
              tplCopy.docker.ports = [`${hostPort}:25565`];
              tplCopy.docker.env = Object.assign({}, tplCopy.docker.env || {}, {
                ENABLE_RCON: "false",
                CREATE_CONSOLE_IN_PIPE: "true",
                TYPE: "CUSTOM",
                CUSTOM_SERVER: "/data/server.jar",
                SERVER_PORT: String(hostPort)
              });
            } else if (overrideDocker && typeof overrideDocker === "object") {
              if (Array.isArray(overrideDocker.ports)) tplCopy.docker.ports = overrideDocker.ports;
              if (overrideDocker.env) {
                tplCopy.docker.env = Object.assign({}, tplCopy.docker.env || {}, overrideDocker.env || {});
              }
              if (Array.isArray(overrideDocker.volumes)) tplCopy.docker.volumes = overrideDocker.volumes;
              if (typeof overrideDocker.command === "string") tplCopy.docker.command = overrideDocker.command;
              if (typeof overrideDocker.restart === "string") tplCopy.docker.restart = overrideDocker.restart;
              if (overrideDocker.image) tplCopy.docker.image = overrideDocker.image;
              if (overrideDocker.tag) tplCopy.docker.tag = overrideDocker.tag;
            }

            runArgs = buildArgsFromTemplate(bot, tplCopy, botDir);
            const image = `${tplCopy.docker.image}:${tplCopy.docker.tag}`;
            try { await dockerCollect(["pull", image]); } catch (_) {}
          } else {
            runArgs = guessArgsForLegacyRun(bot, botDir, file, port);
          }

          const p = callDocker(runArgs);
          if (!p) {
            _emitLine(bot, "[ADPanel] cannot run: empty/invalid docker args");
            return;
          }

          p.stderr.on("data", d => _emitLine(bot, d.toString()));
          p.on("close", (code) => {
            if (code === 0) {
              _emitLine(bot, "[ADPanel] Server started");
              tailLogs(bot);
            } else {
              _emitLine(bot, "[ADPanel] Server failed to start");
            }
          });
          break;
        }

        case "stop": {
          try {
            const entry = findServer(bot);
            if (isRemoteEntry(entry)) {
              const node = findNodeByIdOrName(entry.nodeId);
              const baseUrl = buildNodeBaseUrl(node.address, node.api_port || 8080);
              const headers = nodeAuthHeadersFor(node, true);
              const r = await httpRequestJson(
                `${baseUrl}/v1/servers/${encodeURIComponent(bot)}/stop`,
                "POST", headers, null, 20000
  );
              if (r.status !== 200 || !(r.json && r.json.ok)) {
                const msg = (r.json && (r.json.error || r.json.detail)) || `node status ${r.status}`;
                throw new Error(msg);
              }
            _emitLine(bot, "Stop forwarded to node");
            } else {
              await dockerCollect(["kill", bot]);
              _emitLine(bot, "Container killed");
            }
          } catch (e) {
            _emitLine(bot, "Failed to kill container: " + (e?.message || String(e)));
          }
          break;
        }

      case "kill": {
      const entry = findServer(bot);
      if (isRemoteEntry(entry)) {
        const node = findNodeByIdOrName(entry.nodeId);
        const baseUrl = buildNodeBaseUrl(node.address, node.api_port || 8080);
        const headers = nodeAuthHeadersFor(node, true);
        await httpRequestJson(`${baseUrl}/v1/servers/${encodeURIComponent(bot)}/kill`, "POST", headers, null, 20000);
        _emitLine(bot, "Kill forwarded to node");
      } else {
        await dockerCollect(["rm", "-f", bot]);
        _emitLine(bot, "Container removed");
      }
      break;
    }

        case "restart": {
          try {
            const entry = findServer(bot);
            if (isRemoteEntry(entry)) {
            const node = findNodeByIdOrName(entry.nodeId);
            const baseUrl = buildNodeBaseUrl(node.address, node.api_port || 8080);
            const headers = nodeAuthHeadersFor(node, true);
            const r = await httpRequestJson(`${baseUrl}/v1/servers/${encodeURIComponent(bot)}/restart`, "POST", headers, null, 20000);
            if (!r.json || !r.json.ok) throw new Error("node restart failed");
            _emitLine(bot, "Node container restarted");
            tailLogsRemote(bot, baseUrl, headers);
            } else {
            await dockerCollect(["restart", bot]);
           _emitLine(bot, "Container restarted");
           tailLogs(bot);
    }
          } catch (e) {
            _emitLine(bot, "Failed to restart container");
          }
          break;
        }

        case "install": {
          const img = version ? `node:${version}-alpine` : "node:20-alpine";
          const inst = docker(["pull", img]);
          inst.stdout.on("data", d => logAndBroadcast(d));
          inst.stderr.on("data", d => logAndBroadcast(d));
          break;
        }

        default:
          io.to(bot).emit("output", "Unknown cmd");
          break;
      }
    } catch (e) {
      const msg = `[error] ${e?.message || String(e)}\n`;
      _emitLine(bot, msg);
    }
  });

  socket.on("command", ({ bot, command }) => {
    if (bot) { try { socket.join(bot); } catch {} }
    if (!hasPerm(bot, "console_write")) return deny(bot);
    if (!command || !command.trim()) return;

    if (isMinecraftBot(bot)) {
      const cp = docker(["exec", "--user", "1000", bot, "mc-send-to-console", command]);
      cp.stdout.on("data", d => emitChunkLines(bot, d));
      cp.stderr.on("data", d => emitChunkLines(bot, d));
    } else {
      const cp = docker(["exec", "-i", bot, "sh", "-lc", command]);
      cp.stdout.on("data", d => emitChunkLines(bot, d));
      cp.stderr.on("data", d => emitChunkLines(bot, d));
    }
  });
});

// --- START ---
http.listen(3000, () => {
  console.log("ADPanel running on http://localhost:3000");
});
