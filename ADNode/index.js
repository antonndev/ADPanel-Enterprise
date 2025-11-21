/* eslint-disable */
const express = require("express");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const crypto = require("crypto");
const http = require("http");
const https = require("https");
const { spawn } = require("child_process");

const PORT = Number(process.env.NODE_AGENT_PORT || 8080);
const AUTH_TOKEN = process.env.NODE_TOKEN || "changeme";
const VOLUME_ROOT = process.env.NODE_VOLUME_ROOT || "/var/lib/node/volumes/volumes";
const LOG_TAIL = 400;

const app = express();
app.use(express.json({ limit: "50mb" }));

function sanitizeName(raw) {
  let s = String(raw || "").trim();
  if (!s) return "";
  s = s.replace(/[^\w\-. ]+/g, " ").replace(/\s+/g, " ").trim();
  s = s.replace(/\s/g, "-");
  if (s.length > 100) s = s.slice(0, 100);
  return s;
}

function clampPort(p, def = 3001) {
  const n = Number(p);
  if (!Number.isFinite(n)) return def;
  const rounded = Math.round(n);
  if (rounded < 1 || rounded > 65535) return def;
  return rounded;
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

async function wipeDir(dir) {
  try {
    await fsp.rm(dir, { recursive: true, force: true });
  } catch (_) {}
  ensureDir(dir);
}

function isPathInside(base, target) {
  const rel = path.relative(base, target);
  return rel && !rel.startsWith("..") && !path.isAbsolute(rel);
}

function resolveServerPaths(name) {
  const safe = sanitizeName(name);
  if (!safe) return null;
  const volumeDir = path.join(VOLUME_ROOT, safe);
  const dataDir = path.join(volumeDir, "_data");
  return { safe, volumeDir, dataDir, metaPath: path.join(volumeDir, "meta.json") };
}

async function writeFileSafe(targetPath, content, encoding = "utf8") {
  await fsp.mkdir(path.dirname(targetPath), { recursive: true });
  await fsp.writeFile(targetPath, content, encoding);
}

function runDocker(args, name) {
  return new Promise((resolve, reject) => {
    const p = spawn("docker", args);
    const stderr = [];
    p.stderr.on("data", (d) => stderr.push(d.toString()));
    p.on("close", (code) => {
      if (code === 0) return resolve();
      reject(new Error(`docker ${name || "cmd"} failed: ${stderr.join("") || code}`));
    });
    p.on("error", reject);
  });
}

async function dockerCollect(args, name) {
  try { await runDocker(args, name); } catch (e) { return e; }
  return null;
}

function downloadToFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const client = url.startsWith("https") ? https : http;
    const req = client.get(url, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return downloadToFile(res.headers.location, destPath).then(resolve).catch(reject);
      }
      if (res.statusCode !== 200) return reject(new Error(`download status ${res.statusCode}`));
      const ws = fs.createWriteStream(destPath);
      res.pipe(ws);
      ws.on("finish", () => ws.close(() => resolve(destPath)));
      ws.on("error", reject);
    });
    req.on("error", reject);
  });
}

function authMiddleware(req, res, next) {
  const header = req.headers["authorization"] || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : header;
  if (AUTH_TOKEN && token !== AUTH_TOKEN) return res.status(401).json({ ok: false, error: "unauthorized" });
  next();
}

function nodeScaffoldContent(port) {
  const safePort = clampPort(port, 3001);
  const idx = [
    "const express = require(\"express\");",
    "const app = express();",
    "",
    "app.get(\"/\", (req, res) => {",
    "  res.send(\"Hello World from ADPanel!\");",
    "});",
    "",
    "const PORT = process.env.PORT || " + safePort + ";",
    "app.listen(PORT, () => {",
    "  console.log(\`Server running on http://localhost:${PORT}\`);",
    "});",
    ""
  ].join("\n");

  const pkg = {
    name: "adpanel-node-app",
    version: "1.0.0",
    private: true,
    type: "module",
    main: "index.js",
    scripts: {
      start: "node index.js"
    },
    dependencies: {
      express: "^4.19.2"
    }
  };

  return { idx, pkg: JSON.stringify(pkg, null, 2) };
}

function pythonScaffoldContent() {
  return [
    "def greet(name=\"World\"):",
    "    return f\"Hello, {name}!\"",
    "",
    "if __name__ == \"__main__\":",
    "    print(\"--- Starting main.py execution ---\")",
    "",
    "    user_name = \"ADPanel\"",
    "    message_1 = greet(user_name)",
    "    print(f\"Message 1: {message_1}\")",
    "",
    "    message_2 = greet()",
    "    print(f\"Message 2: {message_2}\")",
    "",
    "    print(\"--- Execution finished ---\")",
    ""
  ].join("\n");
}

async function ensureScaffold(templateId, paths, hostPort) {
  ensureDir(paths.dataDir);
  const meta = { template: templateId, port: hostPort ? clampPort(hostPort) : undefined };

  if (templateId === "nodejs" || templateId === "discord-bot") {
    const { idx, pkg } = nodeScaffoldContent(hostPort || 3001);
    await writeFileSafe(path.join(paths.dataDir, "index.js"), idx);
    await writeFileSafe(path.join(paths.dataDir, "package.json"), pkg);
  } else if (templateId === "python") {
    await writeFileSafe(path.join(paths.dataDir, "main.py"), pythonScaffoldContent());
  }

  await writeFileSafe(paths.metaPath, JSON.stringify(meta, null, 2));
}

function loadMeta(paths) {
  try {
    const raw = fs.readFileSync(paths.metaPath, "utf8");
    return JSON.parse(raw);
  } catch (_) {
    return {};
  }
}

app.get("/v1/info", authMiddleware, (_req, res) => {
  res.json({ ok: true, agent: "adnode", version: "1.0.0", time: Date.now() });
});

app.post("/v1/servers/create", authMiddleware, async (req, res) => {
  try {
    const { name, templateId, hostPort } = req.body || {};
    const paths = resolveServerPaths(name);
    if (!paths) return res.status(400).json({ ok: false, error: "invalid-name" });
    await ensureScaffold(templateId || "nodejs", paths, hostPort);
    return res.json({ ok: true, name: paths.safe });
  } catch (e) {
    console.error("[node] create failed", e);
    return res.status(500).json({ ok: false, error: "create-failed" });
  }
});

app.delete("/v1/servers/:name", authMiddleware, async (req, res) => {
  try {
    const paths = resolveServerPaths(req.params.name);
    if (!paths) return res.status(404).json({ ok: false, error: "not-found" });
    fs.rmSync(paths.volumeDir, { recursive: true, force: true });
    await dockerCollect(["rm", "-f", paths.safe], "rm");
    res.json({ ok: true });
  } catch (e) {
    console.error("[node] delete failed", e);
    res.status(500).json({ ok: false, error: "delete-failed" });
  }
});

app.get("/v1/servers/:name", authMiddleware, async (req, res) => {
  const paths = resolveServerPaths(req.params.name);
  if (!paths) return res.status(404).json({ ok: false, error: "not-found" });
  const meta = loadMeta(paths);
  res.json({ ok: true, name: paths.safe, meta });
});

app.post("/v1/servers/:name/apply-version", authMiddleware, async (req, res) => {
  try {
    const { url, destPath } = req.body || {};
    if (!url) return res.status(400).json({ ok: false, error: "missing-url" });
    const paths = resolveServerPaths(req.params.name);
    if (!paths) return res.status(404).json({ ok: false, error: "not-found" });

    const target = destPath ? path.resolve(destPath) : path.join(paths.dataDir, "server.jar");
    if (!isPathInside(VOLUME_ROOT, target)) return res.status(400).json({ ok: false, error: "invalid-path" });

    ensureDir(path.dirname(target));
    await downloadToFile(url, target);

    res.json({ ok: true, dest: target });
  } catch (e) {
    console.error("[node] apply-version failed", e);
    res.status(500).json({ ok: false, error: "apply-failed" });
  }
});

app.post("/v1/servers/:name/runtime", authMiddleware, async (req, res) => {
  try {
    const { runtime, template, start, port } = req.body || {};
    const paths = resolveServerPaths(req.params.name);
    if (!paths) return res.status(404).json({ ok: false, error: "not-found" });

    if (!runtime || !runtime.image || !runtime.tag) {
      return res.status(400).json({ ok: false, error: "missing-runtime" });
    }

    const templateId = template || runtime.template || "nodejs";
    const hostPort = clampPort(port ?? runtime.port ?? 3001, 3001);
    await wipeDir(paths.dataDir);

    if (templateId === "nodejs" || templateId === "discord-bot") {
      const { idx, pkg } = nodeScaffoldContent(hostPort || 3001);
      await writeFileSafe(path.join(paths.dataDir, "index.js"), idx);
      await writeFileSafe(path.join(paths.dataDir, "package.json"), pkg);
    } else if (templateId === "python") {
      await writeFileSafe(path.join(paths.dataDir, "main.py"), pythonScaffoldContent());
    }

    const meta = loadMeta(paths);
    const nextMeta = Object.assign({}, meta, {
      template: templateId,
      port: hostPort,
      start: start || meta.start,
      runtime: Object.assign({}, runtime, { template: templateId })
    });

    if (!nextMeta.start) {
      nextMeta.start = templateId === "python" ? "main.py" : "index.js";
    }

    await writeFileSafe(paths.metaPath, JSON.stringify(nextMeta, null, 2));

    const imageRef = `${runtime.image}:${runtime.tag}`;
    const pullErr = await dockerCollect(["pull", imageRef], "pull-runtime");
    if (pullErr) console.warn("[node] runtime pull failed", pullErr.message || pullErr);

    res.json({ ok: true, runtime: nextMeta.runtime, meta: nextMeta });
  } catch (e) {
    console.error("[node] runtime change failed", e);
    res.status(500).json({ ok: false, error: "runtime-change-failed" });
  }
});

app.get("/v1/servers/:name/logs", authMiddleware, async (req, res) => {
  try {
    const name = sanitizeName(req.params.name);
    if (!name) return res.status(400).json({ ok: false, error: "invalid-name" });
    const p = spawn("docker", ["logs", "--tail", String(LOG_TAIL), name]);
    const chunks = [];
    p.stdout.on("data", (d) => chunks.push(d.toString()));
    p.stderr.on("data", (d) => chunks.push(d.toString()));
    p.on("close", () => res.json({ ok: true, logs: chunks.join("") }));
    p.on("error", (err) => res.status(500).json({ ok: false, error: err.message }));
  } catch (e) {
    res.status(500).json({ ok: false, error: "logs-failed" });
  }
});

app.post("/v1/servers/:name/start", authMiddleware, async (req, res) => {
  try {
    const paths = resolveServerPaths(req.params.name);
    if (!paths) return res.status(404).json({ ok: false, error: "not-found" });

    const meta = loadMeta(paths);
    const runtime = meta.runtime || {};
    const templateId = meta.template || runtime.template || "nodejs";
    const hostPort = clampPort(req.body?.hostPort ?? meta.port ?? 3001, 3001);
    const startFile = meta.start || (templateId === "python" ? "main.py" : "index.js");
    meta.port = hostPort;
    await writeFileSafe(paths.metaPath, JSON.stringify(meta, null, 2));

    await dockerCollect(["rm", "-f", paths.safe], "rm-old");

    if (templateId === "minecraft") {
      const args = [
        "run", "-d", "--name", paths.safe,
        "-p", `${hostPort}:25565`,
        "-v", `${paths.dataDir}:/data`,
        "--restart", "unless-stopped",
        "itzg/minecraft-server:latest"
      ];
      await runDocker(args, "mc-start");
    } else if (templateId === "python") {
      const imageRef = `${runtime.image || "python"}:${runtime.tag || "3.12-alpine"}`;
      const args = [
        "run", "-d", "--name", paths.safe,
        "-v", `${paths.dataDir}:/app`,
        "-w", "/app",
        "--restart", "unless-stopped",
        imageRef
      ];
      const envEntries = Object.entries(runtime.env || {});
      envEntries.forEach(([k, v]) => {
        args.splice(args.length - 1, 0, "-e", `${k}=${v}`);
      });
      const cmd = runtime.command || `python /app/${startFile}`;
      args.push("sh", "-c", cmd);
      await runDocker(args, "py-start");
    } else {
      const imageRef = `${runtime.image || "node"}:${runtime.tag || "20-alpine"}`;
      const args = [
        "run", "-d", "--name", paths.safe,
        "-p", `${hostPort}:${hostPort}`,
        "-e", `PORT=${hostPort}`,
        "-v", `${paths.dataDir}:/app`,
        "-w", "/app",
        "--restart", "unless-stopped",
        imageRef
      ];
      const envEntries = Object.entries(runtime.env || {});
      envEntries.forEach(([k, v]) => {
        args.splice(args.length - 1, 0, "-e", `${k}=${v}`);
      });
      const cmd = runtime.command || `npm install && node ${startFile}`;
      args.push("sh", "-c", cmd);
      await runDocker(args, "node-start");
    }

    res.json({ ok: true, port: hostPort });
  } catch (e) {
    console.error("[node] start failed", e);
    res.status(500).json({ ok: false, error: "start-failed" });
  }
});

app.post("/v1/servers/:name/stop", authMiddleware, async (req, res) => {
  try {
    const name = sanitizeName(req.params.name);
    if (!name) return res.status(400).json({ ok: false, error: "invalid-name" });
    await runDocker(["kill", name], "stop");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: "stop-failed" });
  }
});

app.post("/v1/servers/:name/kill", authMiddleware, async (req, res) => {
  try {
    const name = sanitizeName(req.params.name);
    if (!name) return res.status(400).json({ ok: false, error: "invalid-name" });
    await dockerCollect(["rm", "-f", name], "rm");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: "kill-failed" });
  }
});

app.post("/v1/servers/:name/restart", authMiddleware, async (req, res) => {
  try {
    const name = sanitizeName(req.params.name);
    if (!name) return res.status(400).json({ ok: false, error: "invalid-name" });
    await runDocker(["restart", name], "restart");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: "restart-failed" });
  }
});

function assertSafePath(target) {
  const resolved = path.resolve(target);
  const base = path.resolve(VOLUME_ROOT);
  if (!resolved.startsWith(base + path.sep) && resolved !== base) {
    throw new Error("invalid-path");
  }
  return resolved;
}

app.post("/v1/fs/read", authMiddleware, async (req, res) => {
  try {
    const target = assertSafePath(req.body?.path || "");
    const encoding = req.body?.encoding || "utf8";
    const content = await fsp.readFile(target, encoding);
    res.json({ ok: true, content });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || "read-failed" });
  }
});

app.post("/v1/fs/write", authMiddleware, async (req, res) => {
  try {
    const target = assertSafePath(req.body?.path || "");
    const encoding = req.body?.encoding || "utf8";
    await writeFileSafe(target, req.body?.content ?? "", encoding);
    res.json({ ok: true, path: target });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || "write-failed" });
  }
});

app.post("/v1/fs/delete", authMiddleware, async (req, res) => {
  try {
    const target = assertSafePath(req.body?.path || "");
    const isDir = !!req.body?.isDir;
    if (isDir) await fsp.rm(target, { recursive: true, force: true });
    else await fsp.rm(target, { force: true });
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || "delete-failed" });
  }
});

app.post("/v1/fs/rename", authMiddleware, async (req, res) => {
  try {
    const src = assertSafePath(req.body?.src || "");
    const dest = assertSafePath(req.body?.dest || "");
    await fsp.mkdir(path.dirname(dest), { recursive: true });
    await fsp.rename(src, dest);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || "rename-failed" });
  }
});

app.post("/v1/fs/uploadRaw", authMiddleware, async (req, res) => {
  try {
    const dir = assertSafePath(req.body?.dir || "");
    const filename = String(req.body?.filename || "upload").replace(/[\r\n]/g, "_");
    const dataB64 = req.body?.data_b64 || "";
    const buffer = Buffer.from(dataB64, "base64");

    await fsp.mkdir(dir, { recursive: true });
    const dest = path.join(dir, filename);
    await fsp.writeFile(dest, buffer);
    res.json({ ok: true, path: dest });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || "upload-failed" });
  }
});

app.listen(PORT, () => {
  console.log(`[ADNode] agent listening on ${PORT}`);
});
