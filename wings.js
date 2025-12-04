/* eslint-disable */
const express = require('express');
const { spawn } = require('child_process');

const app = express();
const PORT = Number(process.env.NODE_AGENT_PORT || process.env.NODE_PORT || 8080);
const TOKEN = process.env.NODE_AGENT_TOKEN || process.env.NODE_TOKEN || process.env.NODE_SECRET || null;

app.use(express.json());

function dockerCollect(args) {
  return new Promise((resolve, reject) => {
    const p = spawn('docker', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', (d) => out += d.toString());
    p.stderr.on('data', (d) => err += d.toString());
    p.on('close', (code) => {
      if (code === 0) return resolve(out);
      reject(new Error(err || out || String(code)));
    });
    p.on('error', reject);
  });
}

function authorized(req) {
  if (!TOKEN) return true;
  const bearer = (req.headers['authorization'] || '').replace(/bearer\s+/i, '').trim();
  const headerToken = (req.headers['x-node-token'] || '').trim();
  return bearer === TOKEN || headerToken === TOKEN;
}

app.use((req, res, next) => {
  if (!authorized(req)) return res.status(401).json({ error: 'unauthorized' });
  next();
});

async function inspectStatus(name) {
  try {
    const raw = await dockerCollect(['inspect', '-f', '{{.State.Status}}|{{.State.Running}}|{{.State.Health.Status}}', name]);
    const parts = String(raw || '').trim().split('|');
    const state = parts[0] || null;
    const running = (parts[1] || '').toLowerCase() === 'true';
    const health = parts[2] || null;
    return { name, running, status: state, state, health };
  } catch (e) {
    return { name, running: false, status: 'not_found', state: 'not_found', health: null };
  }
}

app.get('/v1/servers/:name', async (req, res) => {
  const info = await inspectStatus(req.params.name);
  const payload = Object.assign({}, info, {
    online: !!info.running,
    docker: {
      running: !!info.running,
      status: info.status,
      state: info.state,
      health: info.health
    }
  });
  res.json(payload);
});

app.listen(PORT, () => {
  console.log(`[wings] status bridge listening on ${PORT}`);
});
