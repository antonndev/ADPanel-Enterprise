/* eslint-disable no-console */
/**
 * ADPanel Node Agent ("wings"-style)
 * ----------------------------------
 * - Exposes an authenticated HTTP API on port 8080 (configurable via config.yml)
 * - Opens TCP port 2022 (placeholder for future SFTP; currently a simple banner server)
 * - Manages per-server files under system.data/volumes/<serverName>
 * - Can create & run Minecraft servers (itzg/minecraft-server) with CUSTOM jar
 * - Streams logs over Server-Sent Events (SSE) and accepts console commands
 *
 * IMPORTANT:
 *  - This agent DOES NOT generate a config.yml.
 *  - If config is missing, it will refuse to start and tell you.
 *
 * Example config.yml (place it at /etc/adpanel/node/config.yml):
 *
 * debug: false
 * uuid: a435d2d2-b1c9-45c9-a34a-b1b74f1ccfc6
 * token_id: jkJnFhM6koiPRql9
 * token: LRlZ5721T0WesmMOrrIMTeZPsncRRB0I4J1KFevNQcyRH7YGJ52BuMBXBWmodRfN
 * api:
 *   host: 0.0.0.0
 *   port: 8080
 *   ssl:
 *     enabled: false
 *     cert: ""
 *     key: ""
 *   upload_limit: 1024
 * system:
 *   data: /var/lib/node
 *   sftp:
 *     bind_port: 2022
 * allowed_mounts: []
 */

const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const http = require("http");
const https = require("https");
const net = require("net");
const crypto = require("crypto");
const child_process = require("child_process");
const { spawn } = require("child_process");
const express = require("express");

// --- Auth: Bearer token din env sau din /etc/adnode/config.yml (fără js-yaml) ---
let NODE_TOKEN = process.env.NODE_TOKEN || null;
if (!NODE_TOKEN) {
  try {
    const cfg = fs.readFileSync("/var/lib/node/config.yml", "utf8");
    const m = cfg.match(/^\s*token:\s*["']?([A-Za-z0-9._-]+)["']?\s*$/m);
    if (m) NODE_TOKEN = m[1];
  } catch {
    /* no config yet */
  }
}

function getBearer(req) {
  const h = req.headers["authorization"] || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1] : null;
}

function requireBearer(req, res, next) {
  const t = getBearer(req);
  if (!t) return res.status(401).json({ error: "missing bearer" });
  if (!NODE_TOKEN) return res.status(500).json({ error: "node token not configured" });
  if (t !== NODE_TOKEN) return res.status(403).json({ error: "invalid token" });
  next();
}

// ---- Minimal YAML parser (subset)
function parseYAML(src) {
  const lines = String(src).replace(/\r\n/g, "\n").split("\n");
  const root = {};
  const stack = [{ indent: -1, obj: root }];
  let current = root;
  for (let raw of lines) {
    const line = raw.replace(/\t/g, "  ");
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const indent = line.match(/^ */)[0].length;
    const kv = line.trim();
    while (stack.length && indent <= stack[stack.length - 1].indent) stack.pop();
    current = stack[stack.length - 1].obj;
    const m = kv.match(/^([A-Za-z0-9_\-]+):\s*(.*)$/);
    if (!m) continue;
    const key = m[1];
    let val = m[2];
    if (val === "") {
      const obj = {};
      current[key] = obj;
      stack.push({ indent, obj });
    } else {
      if (/^(true|false)$/i.test(val)) val = /^true$/i.test(val);
      else if (/^-?\d+(\.\d+)?$/.test(val)) val = Number(val);
      else if (/^".*"$/.test(val) || /^'.*'$/.test(val)) val = val.slice(1, -1);
      current[key] = val;
    }
  }
  return root;
}

// ---- Load config.yml (do NOT generate if missing)
const DEFAULT_CONFIG_PATH = "/var/lib/node/config.yml";
const CONFIG_PATH = process.env.ADPANEL_NODE_CONFIG || DEFAULT_CONFIG_PATH;

if (!fs.existsSync(CONFIG_PATH)) {
  console.error("[config] Missing config.yml at:", CONFIG_PATH);
  console.error("[config] This agent does NOT generate a config file.");
  console.error("[config] Please create it on the node and restart the service.");
  process.exit(1);
}

let CONFIG_RAW = fs.readFileSync(CONFIG_PATH, "utf8");
let CONFIG;
try {
  CONFIG = parseYAML(CONFIG_RAW);
} catch (e) {
  console.error("[config] Failed to parse YAML:", e && e.message);
  process.exit(1);
}

const NODE_VERSION = "1.2.1";
const DEBUG = !!CONFIG.debug;
const TOKEN_ID = CONFIG.token_id || "";
const TOKEN = CONFIG.token || "";
const API_HOST = (CONFIG.api && CONFIG.api.host) || "0.0.0.0";
const API_PORT = Number((CONFIG.api && CONFIG.api.port) || 8080);
const UPLOAD_LIMIT_MB = (CONFIG.api && CONFIG.api.upload_limit) || 1024;

const DATA_ROOT = (CONFIG.system && CONFIG.system.data) || "/var/lib/node";
const VOLUMES_DIR = path.join(DATA_ROOT, "volumes");
const SFTP_PORT = (CONFIG.system && CONFIG.system.sftp && CONFIG.system.sftp.bind_port) || 2022;

fs.mkdirSync(VOLUMES_DIR, { recursive: true });

// ---- Helpers
function log(...args) {
  if (DEBUG) console.log(...args);
}
function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}
function sanitizeName(raw) {
  return String(raw || "")
    .trim()
    .replace(/\s+/g, "-")
    .replace(/[^\w\-_.]/g, "")
    .replace(/^-+|-+$/g, "")
    .slice(0, 120);
}
function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
  return p;
}

// Tolerant safeJoin: acceptă și căi care încep cu "/" și le tratează ca relative sub base.
function safeJoin(base, rel) {
  let r = String(rel || "");
  if (path.isAbsolute(r)) r = r.replace(/^\/+/, ""); // normalizează către relativ
  const target = path.join(base, r);
  const resolved = path.resolve(target);
  const baseResolved = path.resolve(base);
  if (!resolved.startsWith(baseResolved + path.sep) && resolved !== baseResolved) return null;
  return resolved;
}
// Validate absolute path under VOLUMES_DIR
function safeUnderVolumes(absPath) {
  const resolved = path.resolve(String(absPath || ""));
  const root = path.resolve(VOLUMES_DIR);
  if (!resolved.startsWith(root + path.sep) && resolved !== root) return null;
  return resolved;
}

const PANEL_HMAC_SECRET = process.env.PANEL_HMAC_SECRET || "";

function timingSafeEq(a, b) {
  try {
    const A = Buffer.from(String(a || ""), "utf8");
    const B = Buffer.from(String(b || ""), "utf8");
    if (A.length !== B.length) return false;
    return crypto.timingSafeEqual(A, B);
  } catch {
    return false;
  }
}

function checkSignature(req) {
  if (!PANEL_HMAC_SECRET) return { ok: true };
  try {
    const ts = String(req.headers["x-panel-ts"] || "");
    const sig = String(req.headers["x-panel-sign"] || "");
    if (!ts || !sig) return { ok: false, error: "missing-signature" };
    const now = Date.now();
    const drift = Math.abs(now - Number(ts));
    if (!Number.isFinite(Number(ts)) || drift > 5 * 60 * 1000) {
      return { ok: false, error: "expired" };
    }
    const name = String(req.params.name || "").trim();
    const { providerId, versionId, url } = req.body || {};
    const base = `${name}|${providerId}|${versionId}|${url}|${ts}`;
    const expect = crypto.createHmac("sha256", PANEL_HMAC_SECRET).update(base).digest("hex");
    if (!timingSafeEq(sig, expect)) return { ok: false, error: "bad-signature" };
    return { ok: true };
  } catch (e) {
    return { ok: false, error: "verify-failed" };
  }
}

function run(cmd, args, opts = {}) {
  return child_process.spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"], ...opts });
}
function execCollect(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const p = run(cmd, args, opts);
    let out = "",
      err = "";
    p.stdout.on("data", (d) => (out += d.toString()));
    p.stderr.on("data", (d) => (err += d.toString()));
    p.on("close", (code) => {
      if (code === 0) resolve({ out, err, code });
      else reject(new Error(err || out || "exit " + code));
    });
    p.on("error", reject);
  });
}
async function dockerCollect(args, opts = {}) {
  return execCollect("docker", args, opts);
}
function docker(args, opts = {}) {
  return run("docker", args, opts);
}
async function containerExists(name) {
  try {
    await dockerCollect(["inspect", name]);
    return true;
  } catch {
    return false;
  }
}
async function ensureNoContainer(name) {
  try {
    await dockerCollect(["rm", "-f", name]);
  } catch {}
}
async function pullImage(ref) {
  try {
    await dockerCollect(["pull", ref]);
  } catch (e) {
    log("[docker] pull failed:", e && e.message);
  }
}

/**
 * Try multiple variants to send a Minecraft console command.
 * - Tries mc-send-to-console (with/without path, with/without --user 1000)
 * - Falls back to rcon-cli
 * - Throws with code "failed-to-send" if all attempts fail
 */
async function sendMinecraftConsoleCommand(containerName, command) {
  const name = String(containerName || "").trim();
  const cmd = String(command || "");
  if (!name || !cmd) {
    const err = new Error("missing-params");
    err.code = "missing-params";
    throw err;
  }

  if (!(await containerExists(name))) {
    const err = new Error("container-not-running");
    err.code = "container-not-running";
    throw err;
  }

  const attempts = [
    { method: "pipe", args: ["exec", name, "mc-send-to-console", cmd] },
    { method: "pipe", args: ["exec", name, "/usr/local/bin/mc-send-to-console", cmd] },
    { method: "pipe", args: ["exec", "--user", "1000", name, "mc-send-to-console", cmd] },
    { method: "pipe", args: ["exec", "--user", "1000", name, "/usr/local/bin/mc-send-to-console", cmd] },
    { method: "rcon", args: ["exec", name, "rcon-cli", cmd] },
    { method: "rcon", args: ["exec", "--user", "1000", name, "rcon-cli", cmd] },
  ];

  let lastErr = null;
  for (const at of attempts) {
    try {
      await dockerCollect(at.args);
      return { ok: true, method: at.method, args: at.args };
    } catch (e) {
      lastErr = e;
    }
  }

  const err = new Error("failed-to-send");
  err.code = "failed-to-send";
  err.detail = lastErr && lastErr.message;
  throw err;
}

// HTTP helpers
async function httpGetBuffer(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith("https:") ? https : http;
    const req = lib.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        const loc = res.headers.location.startsWith("http")
          ? res.headers.location
          : new URL(res.headers.location, url).toString();
        return httpGetBuffer(loc).then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks = [];
      res.on("data", (d) => chunks.push(d));
      res.on("end", () => resolve(Buffer.concat(chunks)));
    });
    req.on("error", reject);
  });
}
async function httpGetJSON(url) {
  const buf = await httpGetBuffer(url);
  return JSON.parse(buf.toString("utf8"));
}
async function downloadToFile(url, destPath) {
  const buf = await httpGetBuffer(url);
  ensureDir(path.dirname(destPath));
  fs.writeFileSync(destPath, buf);
  return destPath;
}

// ---- Log clean (Minecraft colors)
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
function cleanLog(name, s) {
  return stripMinecraftColors(String(s || "").replace(ANSI_RE, ""));
}

// ---- Minecraft helpers
function writeMinecraftScaffold(serverDir, name, fork, version) {
  try {
    fs.writeFileSync(path.join(serverDir, "eula.txt"), "eula=true\n", "utf8");
  } catch {}
  const props = [
    `motd=${name}`,
    `max-players=20`,
    `enforce-secure-profile=false`,
    `server-port=25565`,
    `server-ip=`,
  ].join("\n") + "\n";
  try {
    fs.writeFileSync(path.join(serverDir, "server.properties"), props, "utf8");
  } catch {}
  const meta = {
    type: "minecraft",
    fork,
    version,
    start: "server.jar",
    createdAt: Date.now(),
  };
  try {
    fs.writeFileSync(path.join(serverDir, "adpanel.json"), JSON.stringify(meta, null, 2), "utf8");
  } catch {}
}

// Enforce server.properties to keep internal port 25565
function enforceServerProps(serverDir) {
  try {
    const p = path.join(serverDir, "server.properties");
    let txt = fs.existsSync(p) ? fs.readFileSync(p, "utf8") : "";
    if (!txt) {
      txt = "server-port=25565\nserver-ip=\n";
    } else {
      if (/^server-port=/m.test(txt)) txt = txt.replace(/^server-port=.*/m, "server-port=25565");
      else txt += "\nserver-port=25565\n";
      if (/^server-ip=/m.test(txt)) txt = txt.replace(/^server-ip=.*/m, "server-ip=");
      else txt += "server-ip=\n";
    }
    fs.writeFileSync(p, txt, "utf8");
  } catch {}
}

function fixedJarUrlFor1218(fork) {
  const f = String(fork || "").toLowerCase();
  if (f === "paper")
    return "https://fill-data.papermc.io/v1/objects/8de7c52c3b02403503d16fac58003f1efef7dd7a0256786843927fa92ee57f1e/paper-1.21.8-60.jar";
  if (f === "pufferfish")
    return "https://ci.pufferfish.host/job/Pufferfish-1.21/33/artifact/pufferfish-server/build/libs/pufferfish-paperclip-1.21.8-R0.1-SNAPSHOT-mojmap.jar";
  if (f === "vanilla")
    return "https://piston-data.mojang.com/v1/objects/95495a7f485eedd84ce928cef5e223b757d2f764/server.jar";
  return "https://api.purpurmc.org/v2/purpur/1.21.8/2497/download";
}
async function getMinecraftJarUrl(fork, version) {
  const v = String(version || "").trim();
  const f = String(fork || "").toLowerCase();
  if (v === "1.21.8") return fixedJarUrlFor1218(f);
  try {
    if (f === "purpur") return `https://api.purpurmc.org/v2/purpur/${v}/latest/download`;
    if (f === "paper" || f === "pufferfish") {
      const builds = await httpGetJSON(`https://api.papermc.io/v2/projects/paper/versions/${v}/builds`);
      const list = Array.isArray(builds && builds.builds) ? builds.builds : [];
      if (list.length > 0) {
        const last = list[list.length - 1];
        const build = last.build;
        const jarName = last.downloads?.application?.name || `paper-${v}-${build}.jar`;
        return `https://api.papermc.io/v2/projects/paper/versions/${v}/builds/${build}/downloads/${jarName}`;
      }
    }
    if (f === "vanilla") {
      const manifest = await httpGetJSON("https://piston-meta.mojang.com/mc/game/version_manifest_v2.json");
      const ver = (manifest.versions || []).find((x) => x.id === v);
      if (ver?.url) {
        const det = await httpGetJSON(ver.url);
        if (det?.downloads?.server?.url) return det.downloads.server.url;
      }
    }
  } catch (e) {
    log("[minecraft] jar url resolve failed:", e && e.message);
  }
  return `https://api.purpurmc.org/v2/purpur/${v}/latest/download`;
}

/* ========= RUNTIME HELPERS (Python / Node.js) ========= */

const PYTHON_MAIN_TEMPLATE = `def greet(name="World"):
    return f"Hello, {name}!"

if __name__ == "__main__":
    print("--- Starting main.py execution ---")

    user_name = "ADPanel"
    message_1 = greet(user_name)
    print(f"Message 1: {message_1}")

    message_2 = greet()
    print(f"Message 2: {message_2}")

    print("--- Execution finished ---")
`;

function clampAppPort(p, fallback = 3001) {
  const n = Number(p);
  if (!Number.isInteger(n)) return fallback;
  if (n < 1 || n > 65535) return fallback;
  return n;
}

function buildNodeIndexTemplate(port) {
  const p = clampAppPort(port, 3001);
  return `const express = require("express");
const app = express();

app.get("/", (req, res) => {
  res.send("Hello World from ADPanel!");
});

const PORT = ${p};

app.listen(PORT, () => {
  console.log(\`Server running on http://localhost:${p}\`);
});
`;
}

function defaultNodePackageJson(serverDir) {
  return {
    name: path.basename(serverDir),
    private: true,
    version: "1.0.0",
    main: "index.js",
    scripts: { start: "node index.js" },
    dependencies: { express: "^4.19.2" },
  };
}

function scaffoldPythonProject(serverDir, startFile) {
  try {
    const mainPath = path.join(serverDir, startFile || "main.py");
    fs.writeFileSync(mainPath, PYTHON_MAIN_TEMPLATE, "utf8");
  } catch (e) {
    log("[runtime/python] failed to scaffold main.py:", e && e.message);
  }
}

function scaffoldNodeProject(serverDir, startFile, port) {
  const idx = startFile && String(startFile).trim() ? startFile.trim() : "index.js";
  const idxPath = path.join(serverDir, idx);
  const pkgPath = path.join(serverDir, "package.json");
  try {
    fs.writeFileSync(idxPath, buildNodeIndexTemplate(port), "utf8");
  } catch (e) {
    log("[runtime/node] failed to scaffold index.js:", e && e.message);
  }
  try {
    if (!fs.existsSync(pkgPath)) {
      const pkg = defaultNodePackageJson(serverDir);
      fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2), "utf8");
    }
  } catch (e) {
    log("[runtime/node] failed to scaffold package.json:", e && e.message);
  }
}

/* ===================================================== */

// ---- Express app
const app = express();
app.set("trust proxy", true);
app.use(express.json({ limit: `${UPLOAD_LIMIT_MB}mb` }));

// Auth middleware (simple shared token)
function auth(req, res, next) {
  const header = req.headers["x-node-token"] || req.headers["authorization"];
  const token = header && String(header).startsWith("Bearer ") ? String(header).slice(7) : header;
  if (!TOKEN || !token || token !== TOKEN) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

// Basic health check (no auth)
app.head("/ping", (req, res) => res.status(204).end());
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    version: NODE_VERSION,
    uuid: CONFIG.uuid || null,
    token_id: TOKEN_ID || null,
    time: Date.now(),
    data_root: DATA_ROOT,
    volumes_dir: VOLUMES_DIR,
  });
});

// === PUBLIC: apply-version (panel -> node) ===
app.post("/v1/servers/:name/apply-version", async (req, res) => {
  try {
    const name = String(req.params.name || "").trim();
    const { url, nodeId, destPath: rawDestPath } = req.body || {};
    if (!name || !url) return res.status(400).json({ ok: false, error: "missing-fields" });
    if (!/^https?:\/\//i.test(url)) return res.status(400).json({ ok: false, error: "invalid-url" });

    const CFG_UUID = (CONFIG && CONFIG.uuid) ? String(CONFIG.uuid) : "";
    if (nodeId && CFG_UUID && nodeId !== CFG_UUID) {
      return res.status(401).json({ ok: false, error: "unauthorized" });
    }

    // destinația relativă în volumes/<name>
    let destRel = String(rawDestPath || "server.jar").trim();
    destRel = destRel.replace(/^\/+/, "");
    if (!destRel) destRel = "server.jar";
    if (destRel.includes("..") || destRel.includes("\\")) {
      return res.status(400).json({ ok: false, error: "invalid-destPath" });
    }

    const baseDir = path.join(VOLUMES_DIR, name);
    if (!fs.existsSync(baseDir) || !fs.statSync(baseDir).isDirectory()) {
      return res.status(404).json({ ok: false, error: "server-dir-not-found" });
    }

    const targetPath = path.join(baseDir, destRel);
    ensureDir(path.dirname(targetPath));

    // === cazul CLASIC: server.jar -> stop + replace + restart ===
    if (destRel === "server.jar") {
      try {
        await dockerCollect(["stop", name]);
      } catch {}

      await downloadToFile(url, targetPath);

      // citește hostPort din adpanel.json (dacă există)
      let hostPort = 25565;
      try {
        const meta = JSON.parse(fs.readFileSync(path.join(baseDir, "adpanel.json"), "utf8"));
        if (meta.hostPort) hostPort = Number(meta.hostPort) || hostPort;
      } catch {}

      // forțează server.properties
      enforceServerProps(baseDir);

      try {
        await dockerCollect(["rm", "-f", name]);
      } catch {}

      const args = [
        "run",
        "-d",
        "--name",
        name,
        "--restart",
        "unless-stopped",
        "-p",
        `${Number(hostPort)}:25565`,
        "-v",
        `${baseDir}:/data`,
        "-e",
        "EULA=TRUE",
        "-e",
        "TYPE=CUSTOM",
        "-e",
        "CUSTOM_SERVER=/data/server.jar",
        "-e",
        "ENABLE_RCON=false",
        "-e",
        "CREATE_CONSOLE_IN_PIPE=true",
        "itzg/minecraft-server:latest",
      ];
      await execCollect("docker", args);

      return res.json({
        ok: true,
        msg: "applied",
        server: name,
        hostPort: Number(hostPort),
        path: targetPath,
      });
    }

    // === PLUGIN / ALT FIȘIER: doar descarcă, fără restart ===
    await downloadToFile(url, targetPath);
    return res.json({
      ok: true,
      msg: "downloaded",
      server: name,
      path: targetPath,
      destPath: destRel,
    });
  } catch (e) {
    console.error("apply-version (node) failed:", e && e.message);
    return res.status(500).json({ ok: false, error: "server-error", detail: e && e.message });
  }
});

/* === PUBLIC: runtime switch (python / nodejs) ===
   - Called from panel when user changes runtime version
   - Body: { runtime, template, start, port, nodeId? }
   - Behavior:
       * wipe server dir
       * scaffold main.py or index.js + package.json
       * save adpanel.json with runtime metadata
       * docker pull image:tag
*/
app.post("/v1/servers/:name/runtime", async (req, res) => {
  try {
    const name = String(req.params.name || "").trim();
    if (!name) return res.status(400).json({ ok: false, error: "missing-name" });

    const body = req.body || {};
    const runtime = body.runtime || {};
    const template = String(body.template || runtime.providerId || "").toLowerCase();
    const startFileRaw = body.start;
    const portRaw = body.port;
    const nodeId = body.nodeId;

    if (!runtime || typeof runtime !== "object") {
      return res.status(400).json({ ok: false, error: "missing-runtime" });
    }

    // Optional safety: allow only if nodeId matches config.uuid (if provided)
    const CFG_UUID = (CONFIG && CONFIG.uuid) ? String(CONFIG.uuid) : "";
    if (nodeId && CFG_UUID && nodeId !== CFG_UUID) {
      return res.status(401).json({ ok: false, error: "unauthorized" });
    }

    const serverDir = path.join(VOLUMES_DIR, name);

    // wipe + recreate
    try {
      fs.rmSync(serverDir, { recursive: true, force: true });
    } catch {}
    ensureDir(serverDir);

    const kind = template || String(runtime.providerId || "").toLowerCase();
    let finalStart = (startFileRaw && String(startFileRaw).trim()) || "";
    if (!finalStart) {
      if (kind === "python") finalStart = "main.py";
      else if (kind === "nodejs" || kind === "discord-bot") finalStart = "index.js";
    }

    const hostPort = portRaw != null ? clampAppPort(portRaw, 3001) : 0;

    if (kind === "python") {
      scaffoldPythonProject(serverDir, finalStart);
    } else if (kind === "nodejs" || kind === "discord-bot") {
      scaffoldNodeProject(serverDir, finalStart, hostPort || 3001);
    } else {
      if (finalStart) {
        try {
          fs.writeFileSync(path.join(serverDir, finalStart), "", "utf8");
        } catch (e) {
          log("[runtime/generic] failed to create start file:", e && e.message);
        }
      }
    }

    const meta = {
      type: kind || "runtime",
      runtime,
      start: finalStart || null,
      hostPort: hostPort || undefined,
      updatedAt: Date.now(),
    };
    try {
      fs.writeFileSync(path.join(serverDir, "adpanel.json"), JSON.stringify(meta, null, 2), "utf8");
    } catch (e) {
      console.error("[runtime] failed to write adpanel.json:", e && e.message);
    }

    const img = String(runtime.image || (kind === "python" ? "python" : "node")).trim();
    const tag = String(runtime.tag || (kind === "python" ? "3.12-slim" : "20-alpine")).trim();
    const ref = img ? (tag ? `${img}:${tag}` : img) : null;

    if (ref) {
      try {
        await pullImage(ref);
      } catch (e) {
        log("[runtime] docker pull failed:", e && e.message);
      }
    }

    return res.json({ ok: true, type: meta.type, start: meta.start, hostPort: meta.hostPort || null });
  } catch (e) {
    console.error("[runtime] node error:", e && e.message);
    return res.status(500).json({ ok: false, error: "server-error", detail: e && e.message });
  }
});

// All remaining endpoints require auth
app.use(auth);

// Node info
app.get("/v1/info", (req, res) => {
  res.json({
    ok: true,
    node: {
      uuid: CONFIG.uuid || null,
      version: NODE_VERSION,
      dataRoot: DATA_ROOT,
      volumesDir: VOLUMES_DIR,
    },
  });
});

// Delete server
app.delete("/v1/servers/:name", async (req, res) => {
  const name = String(req.params.name || "").trim();
  if (!name) return res.status(400).json({ error: "missing name" });
  try {
    try {
      await dockerCollect(["rm", "-f", name]);
    } catch {}
    try {
      fs.rmSync(path.join(VOLUMES_DIR, name), { recursive: true, force: true });
    } catch {}
    return res.json({ ok: true });
  } catch (e) {
    console.error("[node] delete failed:", e && e.message);
    return res.status(500).json({ error: "delete failed" });
  }
});

// List servers
app.get("/v1/servers", async (req, res) => {
  try {
    const entries = fs
      .readdirSync(VOLUMES_DIR, { withFileTypes: true })
      .filter((e) => e.isDirectory())
      .map((d) => d.name);
    res.json({ ok: true, servers: entries });
  } catch (e) {
    res.status(500).json({ error: e.message || "failed" });
  }
});

// ---------- CREATE SERVER HANDLER ----------
async function createServerHandler(req, res) {
  try {
    const rawName = req.body && req.body.name;
    const templateId = req.body && req.body.templateId;
    const mcFork = (req.body && req.body.mcFork) || "paper";
    const mcVersion = (req.body && req.body.mcVersion) || "1.21.8";
    const hostPort = Number((req.body && req.body.hostPort) || 25565);
    const autoStart = !!(req.body && req.body.autoStart);

    const name = sanitizeName(rawName);
    if (!name) return res.status(400).json({ error: "invalid name" });
    if (!templateId) return res.status(400).json({ error: "missing templateId" });

    const serverDir = path.join(VOLUMES_DIR, name);
    if (fs.existsSync(serverDir)) return res.status(400).json({ error: "server already exists" });
    ensureDir(serverDir);

    let meta = {};
    if (templateId === "minecraft") {
      writeMinecraftScaffold(serverDir, name, mcFork, mcVersion);
      const jarUrl = await getMinecraftJarUrl(mcFork, mcVersion);
      await downloadToFile(jarUrl, path.join(serverDir, "server.jar"));
      meta = { type: "minecraft", fork: mcFork, version: mcVersion, start: "server.jar", hostPort };
      fs.writeFileSync(path.join(serverDir, "adpanel.json"), JSON.stringify(meta, null, 2), "utf8");

      // enforce properties (port intern 25565) înainte de start
      enforceServerProps(serverDir);

      if (autoStart) {
        try {
          await startMinecraftContainer(name, serverDir, hostPort);
        } catch (e) {
          return res.status(500).json({
            error: "created but failed to start container: " + (e && e.message),
          });
        }
      }
    } else {
      // for non-minecraft templates we just mark as "vanilla"; runtime endpoint can
      // later turn this into python/nodejs/etc.
      meta = { type: "vanilla", start: null, createdAt: Date.now() };
      fs.writeFileSync(path.join(serverDir, "adpanel.json"), JSON.stringify(meta, null, 2), "utf8");
    }

    res.json({ ok: true, name, meta });
  } catch (e) {
    res.status(500).json({ error: e.message || "failed" });
  }
}
app.post("/v1/servers", createServerHandler);
app.post("/v1/servers/create", createServerHandler);

// Server info & status
app.get("/v1/servers/:name", async (req, res) => {
  try {
    const name = sanitizeName(req.params.name);
    const serverDir = path.join(VOLUMES_DIR, name);
    if (!fs.existsSync(serverDir)) return res.status(404).json({ error: "not found" });
    const metaPath = path.join(serverDir, "adpanel.json");
    const meta = fs.existsSync(metaPath) ? JSON.parse(fs.readFileSync(metaPath, "utf8")) : {};
    let status = "stopped";
    if (await containerExists(name)) {
      try {
        const { out } = await dockerCollect(["inspect", "-f", "{{.State.Running}}", name]);
        status = out.trim() === "true" ? "running" : "stopped";
      } catch {
        status = "unknown";
      }
    }
    res.json({ ok: true, name, status, meta });
  } catch (e) {
    res.status(500).json({ error: e.message || "failed" });
  }
});

// Start / Stop / Restart
app.post("/v1/servers/:name/start", async (req, res) => {
  const name = sanitizeName(req.params.name);
  try {
    const serverDir = path.join(VOLUMES_DIR, name);
    if (!fs.existsSync(serverDir)) return res.status(404).json({ error: "not found" });
    const metaPath = path.join(serverDir, "adpanel.json");
    const meta = fs.existsSync(metaPath) ? JSON.parse(fs.readFileSync(metaPath, "utf8")) : {};

    if (meta.type === "minecraft") {
      const hostPort = Number(meta.hostPort) || Number((req.body && req.body.hostPort) || 25565);
      enforceServerProps(serverDir);
      await startMinecraftContainer(name, serverDir, hostPort);
      return res.json({ ok: true });
    }

    // New: start python/nodejs runtime containers based on adpanel.json
    if (
      meta.runtime &&
      (meta.type === "python" || meta.type === "nodejs" || meta.type === "discord-bot" || meta.type === "runtime")
    ) {
      const hostPort =
        Number(meta.hostPort) ||
        Number(meta.port) ||
        Number((req.body && req.body.hostPort) || 0) ||
        0;
      await startRuntimeContainer(name, serverDir, meta, hostPort);
      return res.json({ ok: true });
    }

    return res.status(400).json({ error: "unsupported template for start" });
  } catch (e) {
    res.status(500).json({ error: e.message || "failed" });
  }
});

// Stop: folosim kill endpoint logic (graceful + hard)
app.post("/v1/servers/:name/stop", async (req, res) => {
  const name = sanitizeName(req.params.name);
  try {
    if (!(await containerExists(name))) return res.json({ ok: true, note: "not running" });
    // Try graceful for Minecraft (pentru alte template-uri e no-op)
    try {
      await sendMinecraftConsoleCommand(name, "stop");
    } catch {}
    setTimeout(async () => {
      try {
        await dockerCollect(["stop", name]);
      } catch {}
    }, 20000);
    res.json({ ok: true, stopping: true });
  } catch (e) {
    res.status(500).json({ error: e.message || "failed" });
  }
});

app.post("/v1/servers/:name/restart", async (req, res) => {
  const name = sanitizeName(req.params.name);
  try {
    if (!(await containerExists(name))) return res.status(400).json({ error: "not running" });
    await dockerCollect(["restart", name]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message || "failed" });
  }
});

// Console command (panel-style)
app.post("/v1/servers/:name/command", async (req, res) => {
  const name = sanitizeName(req.params.name);
  const command = req.body && String(req.body.command || "");
  if (!command.trim()) return res.status(400).json({ error: "missing command" });
  try {
    const serverDir = path.join(VOLUMES_DIR, name);
    if (!fs.existsSync(serverDir)) return res.status(404).json({ error: "not found" });

    const metaPath = path.join(serverDir, "adpanel.json");
    let meta = {};
    if (fs.existsSync(metaPath)) {
      try {
        meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
      } catch {
        meta = {};
      }
    }

    // Pentru template-uri non-Minecraft nu avem pipe dedicat,
    // dar nu mai returnăm 500, doar confirmăm no-op.
    if (meta.type && meta.type !== "minecraft") {
      return res.json({
        ok: true,
        note: "console commands not supported for this template on node agent",
      });
    }

    try {
      const r = await sendMinecraftConsoleCommand(name, command);
      return res.json({ ok: true, method: r.method || "pipe" });
    } catch (e) {
      if (e && e.code === "container-not-running") {
        return res.status(400).json({ error: "container not running" });
      }
      // IMPORTANT: nu mai trimitem 500 ca să nu pice în `node_command_failed` pe panel
      return res.status(200).json({
        ok: false,
        error: "failed-to-send",
        detail: (e && e.detail) || (e && e.message) || "unknown",
      });
    }
  } catch (e) {
    res.status(500).json({ error: e.message || "failed" });
  }
});

// Logs via SSE (rezistent)
const logTails = new Map(); // name -> { proc, clients:Set(fn), retryTimer, closed }
app.get("/v1/servers/:name/logs", (req, res) => {
  const name = sanitizeName(req.params.name);
  const initialTail = Math.max(0, Number(req.query.tail || 200)) || 200;

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
  });

  const send = (payload) =>
    res.write(`data: ${JSON.stringify({ line: cleanLog(name, payload) })}\n\n`);
  const sendEvent = (event, data) =>
    res.write(`event: ${event}\ndata: ${JSON.stringify(data || {})}\n\n`);

  sendEvent("hello", { server: name, ts: Date.now(), tail: initialTail });
  const hb = setInterval(() => sendEvent("keepalive", { ts: Date.now() }), 15000);

  // 1) Istoric la conectare
  dockerCollect(["logs", "--tail", String(initialTail), name])
    .then(({ out }) => {
      if (out && out.trim())
        out.split(/\r?\n/).forEach((l) => {
          if (l) send(l);
        });
    })
    .catch(() => {
      /* ignore */
    });

  // 2) Follow
  let entry = logTails.get(name);
  if (!entry) {
    entry = { proc: null, clients: new Set(), retryTimer: null, closed: false };
    logTails.set(name, entry);

    const spawnFollow = () => {
      if (entry.closed) return;
      try {
        if (entry.proc) {
          try {
            entry.proc.kill("SIGTERM");
          } catch {}
          entry.proc = null;
        }
      } catch {}
      const p = docker(["logs", "--tail", "0", "-f", name]);
      entry.proc = p;
      p.stdout.on("data", (d) => {
        const s = d.toString();
        for (const c of entry.clients) c(`stdout:${s}`);
      });
      p.stderr.on("data", (d) => {
        const s = d.toString();
        if (/No such container/i.test(s)) return;
        if (/can not get logs from container which is dead or marked for removal/i.test(s)) return;
        for (const c of entry.clients) c(`stderr:${s}`);
      });
      p.on("close", () => {
        entry.proc = null;
        if (entry.closed) return;
        scheduleWaitAndRetry();
      });
    };

    const scheduleWaitAndRetry = () => {
      if (entry.closed || entry.retryTimer) return;
      let notified = false;
      entry.retryTimer = setInterval(() => {
        if (entry.closed) {
          try {
            clearInterval(entry.retryTimer);
          } catch {}
          entry.retryTimer = null;
          return;
        }
        dockerCollect(["inspect", "-f", "{{.State.Running}}", name])
          .then(({ out }) => {
            const running = (out || "").trim() === "true";
            if (running) {
              try {
                clearInterval(entry.retryTimer);
              } catch {}
              entry.retryTimer = null;
              spawnFollow();
            } else if (!notified) {
              for (const c of entry.clients) c(`[waiting] container "${name}" not found yet...\n`);
              notified = true;
            }
          })
          .catch(() => {
            /* retry */
          });
      }, 1000);
    };

    containerExists(name)
      .then((exists) => {
        exists ? spawnFollow() : scheduleWaitAndRetry();
      })
      .catch(() => scheduleWaitAndRetry());
  }

  const clientFn = (s) => send(s);
  entry.clients.add(clientFn);

  req.on("close", () => {
    clearInterval(hb);
    if (!entry) return;
    entry.clients.delete(clientFn);
    if (entry.clients.size === 0) {
      entry.closed = true;
      if (entry.retryTimer) {
        try {
          clearInterval(entry.retryTimer);
        } catch {}
        entry.retryTimer = null;
      }
      if (entry.proc) {
        try {
          entry.proc.kill("SIGTERM");
        } catch {}
        entry.proc = null;
      }
      logTails.delete(name);
    }
  });
});

// Kill (hard stop + clean tail)
app.post("/v1/servers/:name/kill", async (req, res) => {
  const name = req.params.name;
  try {
    const entry = logTails.get(name);
    if (entry) {
      entry.closed = true;
      if (entry.retryTimer) {
        try {
          clearInterval(entry.retryTimer);
        } catch {}
        entry.retryTimer = null;
      }
      if (entry.proc) {
        try {
          entry.proc.kill("SIGTERM");
        } catch {}
        entry.proc = null;
      }
      logTails.delete(name);
    }
    await execCollect("docker", ["update", "--restart=no", name]).catch(() => {});
    await execCollect("docker", ["rm", "-f", name]);
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message || String(e) });
  }
});

// ---- Start Minecraft container (NO SERVER_PORT env!)
async function startMinecraftContainer(name, serverDir, hostPort) {
  await ensureNoContainer(name);
  await pullImage("itzg/minecraft-server:latest");

  // detectează uid/gid din folderul de lucru
  let uid = 1000,
    gid = 1000;
  try {
    const st = fs.statSync(serverDir);
    if (typeof st.uid === "number") uid = st.uid;
    if (typeof st.gid === "number") gid = st.gid;
  } catch {}

  const args = [
    "run",
    "-d",
    "--name",
    name,
    "--restart",
    "unless-stopped",
    "-p",
    `${Number(hostPort)}:25565`,
    "-v",
    `${serverDir}:/data`,
    "-e",
    "EULA=TRUE",
    "-e",
    "TYPE=CUSTOM",
    "-e",
    "CUSTOM_SERVER=/data/server.jar",
    "-e",
    "ENABLE_RCON=false",
    "-e",
    "CREATE_CONSOLE_IN_PIPE=true",
    "-e",
    `UID=${uid}`,
    "-e",
    `GID=${gid}`,
    // IMPORTANT: fără SERVER_PORT – port intern rămâne 25565
    "itzg/minecraft-server:latest",
  ];

  const p = docker(args);
  return new Promise((resolve, reject) => {
    let err = "";
    p.stdout.on("data", (d) => log("[docker run]", d.toString().trim()));
    p.stderr.on("data", (d) => {
      err += d.toString();
      log("[docker run err]", d.toString().trim());
    });
    p.on("error", reject);
    p.on("close", (code) => {
      if (code === 0) resolve(true);
      else reject(new Error(err || "failed to start container"));
    });
  });
}

/* ---- Start generic runtime container (python/nodejs) ---- */
async function startRuntimeContainer(name, serverDir, meta, hostPort) {
  await ensureNoContainer(name);

  const runtime = meta.runtime || {};
  const tpl = String(meta.type || runtime.providerId || "").toLowerCase();
  const isPython = tpl === "python";
  const isNode = tpl === "nodejs" || tpl === "discord-bot";

  let image = String(runtime.image || (isPython ? "python" : "node")).trim();
  let tag = String(runtime.tag || (isPython ? "3.12-slim" : "20-alpine")).trim();
  if (!image) image = isPython ? "python" : "node";
  const imageRef = tag ? `${image}:${tag}` : image;

  const effectivePort = hostPort && Number(hostPort) > 0 ? Number(hostPort) : 0;

  let volumes = [];
  if (Array.isArray(runtime.volumes) && runtime.volumes.length) {
    volumes = runtime.volumes.map((v) => String(v));
  } else {
    volumes = [`${serverDir}:/app`];
  }

  const env = Object.assign({}, runtime.env || {});
  if (effectivePort && !env.PORT) env.PORT = String(effectivePort);

  let uid = 1000,
    gid = 1000;
  try {
    const st = fs.statSync(serverDir);
    if (typeof st.uid === "number") uid = st.uid;
    if (typeof st.gid === "number") gid = st.gid;
  } catch {}
  if (!env.UID) env.UID = String(uid);
  if (!env.GID) env.GID = String(gid);

  const args = ["run", "-d", "--name", name, "--restart", "unless-stopped"];

  if (effectivePort) args.push("-p", `${effectivePort}:${effectivePort}`);
  volumes.forEach((v) => {
    if (v) args.push("-v", v);
  });

  Object.entries(env).forEach(([k, v]) => {
    if (typeof v === "undefined" || v === null) return;
    args.push("-e", `${k}=${String(v)}`);
  });

  args.push(imageRef);

  const defaultCmd = isPython
    ? `python /app/${meta.start || "main.py"}`
    : `sh -c "cd /app && npm install && node /app/${meta.start || "index.js"}"`;

  const cmd = String(runtime.command || defaultCmd || "").trim();

  if (cmd) {
    args.push("sh", "-lc", cmd);
  }

  const p = docker(args);
  return new Promise((resolve, reject) => {
    let err = "";
    p.stdout.on("data", (d) => log("[docker runtime run]", d.toString().trim()));
    p.stderr.on("data", (d) => {
      err += d.toString();
      log("[docker runtime err]", d.toString().trim());
    });
    p.on("error", reject);
    p.on("close", (code) => {
      if (code === 0) resolve(true);
      else reject(new Error(err || "failed to start runtime container"));
    });
  });
}

/* =========================
 * === BRIDGE ENDPOINTS ====
 *  - /v1/fs/*   (absolute path under VOLUMES_DIR)
 *  - /v1/server/action
 *  - /v1/server/command
 * ========================= */

// FS: list — body: { path, depth }
app.post("/v1/fs/list", async (req, res) => {
  try {
    const p = String((req.body && req.body.path) || "");
    const depth = Number((req.body && req.body.depth) || 1);
    const abs = safeUnderVolumes(p);
    if (!abs) return res.status(400).json({ ok: false, error: "invalid path" });
    if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory())
      return res.status(400).json({ ok: false, error: "not a directory" });

    const entries = fs.readdirSync(abs, { withFileTypes: true }).map((d) => ({
      name: d.name,
      type: d.isDirectory() ? "dir" : "file",
    }));
    res.json({ ok: true, entries, depth });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "failed" });
  }
});

// FS: read — body: { path, encoding }
app.post("/v1/fs/read", async (req, res) => {
  try {
    const p = String((req.body && req.body.path) || "");
    const encoding = String((req.body && req.body.encoding) || "utf8").toLowerCase();
    const abs = safeUnderVolumes(p);
    if (!abs) return res.status(400).json({ ok: false, error: "invalid path" });
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile())
      return res.status(404).json({ ok: false, error: "file not found" });

    const buf = fs.readFileSync(abs);
    const content = encoding === "utf8" ? buf.toString("utf8") : buf.toString("base64");
    res.json({ ok: true, content, encoding });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "failed" });
  }
});

// FS: write — body: { path, content, encoding }
app.post("/v1/fs/write", async (req, res) => {
  try {
    const p = String((req.body && req.body.path) || "");
    const content = req.body && req.body.content;
    const encoding = String((req.body && req.body.encoding) || "utf8").toLowerCase();
    const abs = safeUnderVolumes(p);
    if (!abs) return res.status(400).json({ ok: false, error: "invalid path" });
    ensureDir(path.dirname(abs));
    const buf =
      encoding === "utf8"
        ? Buffer.from(String(content || ""), "utf8")
        : Buffer.from(String(content || ""), "base64");
    fs.writeFileSync(abs, buf);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "failed" });
  }
});

// FS: delete — body: { path, isDir }
app.post("/v1/fs/delete", async (req, res) => {
  try {
    const p = String((req.body && req.body.path) || "");
    const isDir = !!(req.body && req.body.isDir);
    const abs = safeUnderVolumes(p);
    if (!abs) return res.status(400).json({ ok: false, error: "invalid path" });
    if (!fs.existsSync(abs)) return res.json({ ok: true, note: "already missing" });
    if (isDir) fs.rmSync(abs, { recursive: true, force: true });
    else fs.rmSync(abs, { force: true });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "failed" });
  }
});

// FS: rename — body: { path, newName }
app.post("/v1/fs/rename", async (req, res) => {
  try {
    const p = String((req.body && req.body.path) || "");
    const newNameRaw = String((req.body && req.body.newName) || "");
    const newName = sanitizeName(newNameRaw);
    if (!newName) return res.status(400).json({ ok: false, error: "invalid newName" });
    const abs = safeUnderVolumes(p);
    if (!abs) return res.status(400).json({ ok: false, error: "invalid path" });
    const parent = path.dirname(abs);
    const target = safeUnderVolumes(path.join(parent, newName));
    if (!target) return res.status(400).json({ ok: false, error: "invalid target" });
    fs.renameSync(abs, target);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "failed" });
  }
});

// FS: extract — body: { path }
function detectArchiveType(p) {
  const lower = p.toLowerCase();
  if (lower.endsWith(".zip")) return "zip";
  if (lower.endsWith(".tar")) return "tar";
  if (lower.endsWith(".tar.gz") || lower.endsWith(".tgz")) return "targz";
  if (lower.endsWith(".tar.bz2") || lower.endsWith(".tbz2")) return "tarbz2";
  if (lower.endsWith(".7z")) return "7z";
  if (lower.endsWith(".rar")) return "rar";
  return null;
}
app.post("/v1/fs/extract", async (req, res) => {
  try {
    const p = String((req.body && req.body.path) || "");
    const abs = safeUnderVolumes(p);
    if (!abs) return res.status(400).json({ ok: false, error: "invalid path" });
    if (!fs.existsSync(abs) || !fs.statSync(abs).isFile())
      return res.status(404).json({ ok: false, error: "file not found" });

    const dir = path.dirname(abs);
    const type = detectArchiveType(abs);
    if (!type) return res.status(400).json({ ok: false, error: "unsupported archive type" });

    let args,
      cmd = null;
    if (type === "zip") {
      cmd = "unzip";
      args = ["-oq", abs, "-d", dir];
    } else if (type === "tar") {
      cmd = "tar";
      args = ["-xf", abs, "-C", dir];
    } else if (type === "targz") {
      cmd = "tar";
      args = ["-xzf", abs, "-C", dir];
    } else if (type === "tarbz2") {
      cmd = "tar";
      args = ["-xjf", abs, "-C", dir];
    } else if (type === "7z") {
      cmd = "7z";
      args = ["x", "-y", abs, `-o${dir}`];
    } else if (type === "rar") {
      cmd = "unrar";
      args = ["x", "-o+", abs, dir];
    }

    if (!cmd) return res.status(400).json({ ok: false, error: "no extractor" });

    try {
      const { out } = await execCollect(cmd, args);
      return res.json({ ok: true, msg: out.slice(0, 2000) });
    } catch (e) {
      return res.status(500).json({ ok: false, error: "extract failed: " + (e && e.message) });
    }
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "failed" });
  }
});

// FS: uploadRaw — body: { dir, filename, data_b64 }
app.post("/v1/fs/uploadRaw", async (req, res) => {
  try {
    const dir = String((req.body && req.body.dir) || "");
    const filename = String((req.body && req.body.filename) || "");
    const data_b64 = String((req.body && req.body.data_b64) || "");
    if (!filename) return res.status(400).json({ ok: false, error: "missing filename" });

    const absDir = safeUnderVolumes(dir);
    if (!absDir) return res.status(400).json({ ok: false, error: "invalid dir" });
    ensureDir(absDir);

    const dest = path.join(absDir, filename.replace(/[\r\n]/g, "_"));
    fs.writeFileSync(dest, Buffer.from(data_b64, "base64"));
    res.json({ ok: true, path: dest });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "failed" });
  }
});

// Bridge: /v1/server/action — { name, baseDir?, cmd, templateId?, docker? }
async function startMinecraftContainerWithOverrides(name, serverDir, hostPort, overrides = {}) {
  await ensureNoContainer(name);
  await pullImage("itzg/minecraft-server:latest");

  const args = ["run", "-d", "--name", name];

  const restart = overrides.restart || "unless-stopped";
  args.push("--restart", restart);

  const portList =
    Array.isArray(overrides.ports) && overrides.ports.length
      ? overrides.ports
      : [`${Number(hostPort)}:25565`];
  for (const p of portList) args.push("-p", String(p));

  args.push("-v", `${serverDir}:/data`);

  const env = Object.assign(
    {
      EULA: "TRUE",
      TYPE: "CUSTOM",
      CUSTOM_SERVER: "/data/server.jar",
      ENABLE_RCON: "false",
      CREATE_CONSOLE_IN_PIPE: "true",
    },
    overrides.env || {}
  );
  // NU setăm SERVER_PORT în env!
  for (const [k, v] of Object.entries(env)) args.push("-e", `${k}=${String(v)}`);

  args.push("itzg/minecraft-server:latest");

  const p = docker(args);
  return new Promise((resolve, reject) => {
    let err = "";
    p.stdout.on("data", (d) => log("[docker run]", d.toString().trim()));
    p.stderr.on("data", (d) => {
      err += d.toString();
      log("[docker run err]", d.toString().trim());
    });
    p.on("error", reject);
    p.on("close", (code) =>
      code === 0 ? resolve(true) : reject(new Error(err || "failed to start container"))
    );
  });
}

app.post("/v1/server/action", async (req, res) => {
  try {
    const body = req.body || {};
    const rawName = body.name || body.server || "";
    const name = sanitizeName(rawName);
    if (!name) return res.status(400).json({ ok: false, error: "missing name" });

    const cmd = String(body.cmd || body.action || "").toLowerCase();
    if (!cmd) return res.status(400).json({ ok: false, error: "missing cmd" });

    const baseDirFromBody = body.baseDir ? safeUnderVolumes(body.baseDir) : null;
    const serverDir = baseDirFromBody || path.join(VOLUMES_DIR, name);
    const hostPort = Number(body.hostPort || 25565);

    if (cmd === "run" || cmd === "start") {
      if ((body.templateId || "").toLowerCase() === "minecraft") {
        enforceServerProps(serverDir);
        await startMinecraftContainerWithOverrides(name, serverDir, hostPort, body.docker || {});
        return res.json({ ok: true, msg: "started" });
      }
      if (await containerExists(name)) {
        await dockerCollect(["start", name]);
        return res.json({ ok: true, msg: "started" });
      }
      return res.status(400).json({ ok: false, error: "unknown template and container missing" });
    }

    if (cmd === "stop") {
      if (!(await containerExists(name))) return res.json({ ok: true, note: "not running" });
      try {
        await sendMinecraftConsoleCommand(name, "stop");
      } catch {}
      setTimeout(async () => {
        try {
          await dockerCollect(["stop", name]);
        } catch {}
      }, 20000);
      return res.json({ ok: true, msg: "stopping" });
    }

    if (cmd === "remove" || cmd === "rm") {
      await ensureNoContainer(name);
      return res.json({ ok: true, msg: "removed" });
    }

    if (cmd === "status") {
      let running = false;
      if (await containerExists(name)) {
        try {
          const { out } = await dockerCollect(["inspect", "-f", "{{.State.Running}}", name]);
          running = out.trim() === "true";
        } catch {}
      }
      return res.json({ ok: true, running });
    }

    return res.status(400).json({ ok: false, error: "unsupported cmd" });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "failed" });
  }
});

// Bridge: /v1/server/command — { name, command }
app.post("/v1/server/command", async (req, res) => {
  try {
    const body = req.body || {};
    const name = sanitizeName(body.name || "");
    const command = String(body.command || "");
    if (!name || !command) return res.status(400).json({ ok: false, error: "missing params" });

    try {
      const r = await sendMinecraftConsoleCommand(name, command);
      return res.json({ ok: true, method: r.method || "pipe" });
    } catch (e) {
      if (e && e.code === "container-not-running") {
        return res.status(400).json({ ok: false, error: "container not running" });
      }
      // aici la fel: nu mai trimitem 500 ca să nu apară `node_command_failed`
      return res.status(200).json({
        ok: false,
        error: "failed-to-send",
        detail: (e && e.detail) || (e && e.message) || "unknown",
      });
    }
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "failed" });
  }
});

// ---- Files API (relative to server root)
app.get("/v1/servers/:name/files/list", async (req, res) => {
  try {
    const name = sanitizeName(req.params.name);
    const rel = String(req.query.path || "");
    const root = path.join(VOLUMES_DIR, name);
    if (!fs.existsSync(root)) return res.status(404).json({ error: "server not found" });
    const dir = safeJoin(root, rel);
    if (!dir) return res.status(400).json({ error: "invalid path" });
    if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory())
      return res.status(400).json({ error: "not a directory" });

    const entries = fs.readdirSync(dir, { withFileTypes: true }).map((d) => ({
      name: d.name,
      isDir: d.isDirectory(),
      size: d.isDirectory() ? 0 : fs.statSync(path.join(dir, d.name)).size || 0,
      mtime: fs.statSync(path.join(dir, d.name)).mtimeMs || 0,
    }));
    res.json({ ok: true, path: rel, entries });
  } catch (e) {
    res.status(500).json({ error: e.message || "failed" });
  }
});

app.get("/v1/servers/:name/files/read", async (req, res) => {
  try {
    const name = sanitizeName(req.params.name);
    const rel = String(req.query.path || "");
    const root = path.join(VOLUMES_DIR, name);
    if (!fs.existsSync(root)) return res.status(404).json({ error: "server not found" });
    const file = safeJoin(root, rel);
    if (!file) return res.status(400).json({ error: "invalid path" });
    if (!fs.existsSync(file) || !fs.statSync(file).isFile())
      return res.status(404).json({ error: "file not found" });

    const content = fs.readFileSync(file, "utf8");
    res.json({ ok: true, path: rel, content });
  } catch (e) {
    res.status(500).json({ error: e.message || "failed" });
  }
});

app.put("/v1/servers/:name/files/write", async (req, res) => {
  try {
    const name = sanitizeName(req.params.name);
    const rel = String((req.body && req.body.path) || "");
    const content = String(((req.body && req.body.content) || ""));
    const root = path.join(VOLUMES_DIR, name);
    if (!fs.existsSync(root)) return res.status(404).json({ error: "server not found" });
    const file = safeJoin(root, rel);
    if (!file) return res.status(400).json({ error: "invalid path" });
    ensureDir(path.dirname(file));
    fs.writeFileSync(file, content, "utf8");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message || "failed" });
  }
});

app.delete("/v1/servers/:name/files/delete", async (req, res) => {
  try {
    const name = sanitizeName(req.params.name);
    const rel = String((req.body && req.body.path) || "");
    const isDir = !!(req.body && req.body.isDir);
    const root = path.join(VOLUMES_DIR, name);
    if (!fs.existsSync(root)) return res.status(404).json({ error: "server not found" });
    const target = safeJoin(root, rel);
    if (!target) return res.status(400).json({ error: "invalid path" });
    if (!fs.existsSync(target)) return res.json({ ok: true, note: "already missing" });

    if (isDir) fs.rmSync(target, { recursive: true, force: true });
    else fs.rmSync(target, { force: true });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message || "failed" });
  }
});

app.post("/v1/servers/:name/files/mkdir", async (req, res) => {
  try {
    const name = sanitizeName(req.params.name);
    const rel = String((req.body && req.body.path) || "");
    const root = path.join(VOLUMES_DIR, name);
    if (!fs.existsSync(root)) return res.status(404).json({ error: "server not found" });
    const dir = safeJoin(root, rel);
    if (!dir) return res.status(400).json({ error: "invalid path" });
    ensureDir(dir);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message || "failed" });
  }
});

app.post("/v1/servers/:name/files/upload", async (req, res) => {
  try {
    const name = sanitizeName(req.params.name);
    const destDirRel = String((req.body && req.body.destDir) || "");
    const filename = String((req.body && req.body.filename) || "");
    const content = String((req.body && req.body.content) || "");
    if (!filename) return res.status(400).json({ error: "missing filename" });

    const root = path.join(VOLUMES_DIR, name);
    if (!fs.existsSync(root)) return res.status(404).json({ error: "server not found" });

    const destDir = safeJoin(root, destDirRel);
    if (!destDir) return res.status(400).json({ error: "invalid path" });
    ensureDir(destDir);

    const destFile = path.join(destDir, filename.replace(/[\r\n]/g, "_"));
    let data;
    if (content.startsWith("data:")) {
      const b64 = content.split(",")[1] || "";
      data = Buffer.from(b64, "base64");
    } else {
      data = Buffer.from(content, "base64");
    }
    fs.writeFileSync(destFile, data);
    res.json({ ok: true, path: path.relative(root, destFile) });
  } catch (e) {
    res.status(500).json({ error: e.message || "failed" });
  }
});

// ---- HTTP server
const httpServer = http.createServer(app);
httpServer.listen(API_PORT, API_HOST, () => {
  console.log(`[node] API listening on http://${API_HOST}:${API_PORT}`);
});

// ---- Placeholder TCP service on SFTP port (2022)
const banner = [
  "ADPanel Node Agent",
  `UUID: ${CONFIG.uuid || "n/a"}`,
  `Version: ${NODE_VERSION}`,
  "SFTP functionality is not implemented yet on this preview build.",
  "Use HTTP API on port 8080.",
  "",
].join("\n");

const sftpServer = net.createServer((socket) => {
  socket.write(banner + "\n");
  socket.end();
});
sftpServer.on("error", (e) => console.error("[sftp-port] error:", e && e.message));
sftpServer.listen(SFTP_PORT, API_HOST, () => {
  console.log(`[node] SFTP placeholder listening on ${API_HOST}:${SFTP_PORT}`);
});

// ---- Graceful shutdown
function shutdown() {
  console.log("[node] shutting down...");
  try {
    httpServer.close(() => console.log("[node] http closed"));
  } catch {}
  try {
    sftpServer.close(() => console.log("[node] sftp closed"));
  } catch {}
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
