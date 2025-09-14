// const express = require('express');
import express from 'express'
// const crypto = require('crypto');
import crypto from 'crypto';
import { execFile } from 'child_process';

const app = express();
app.use(express.json());

const SECRET = process.env.SIDECAR_SECRET || 'dev_secret';
const IFACE = process.env.WG_IFACE || 'wg0';

function authOk(req) {
  const sig = req.header('x-signature') || '';
  const body = JSON.stringify(req.body || {});
  const h = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
  try { return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(h)); } catch { return false; }
}

const run = (cmd, args, options = {}) =>
  new Promise((res, rej) => {
    const child = execFile(cmd, args, options, (err, out, errout) => {
      if (err) return rej(errout || err);
      res(out.trim());
    });

    // If we pass input, write it to stdin
    if (options.input) {
      child.stdin.write(options.input);
      child.stdin.end();
    }
});

app.get('/keys/new', async (req, res) => {
  if (!authOk(req)) return res.status(401).json({ error: 'bad signature' });

  try {
    const privateKey = (await run('wg', ['genkey'])).trim();
    const publicKey = (await run('wg', ['pubkey'], { input: privateKey })).trim();
    res.json({ privateKey, publicKey });
  } catch (err) {
    console.error('Key generation failed:', err);
    res.status(500).json({ error: String(err) });
  }
});


app.post('/peers/add', async (req, res) => {
  if (!authOk(req)) return res.status(401).json({ error: 'bad signature' });
  const { peerPublicKey, peerIp } = req.body;
  console.log({ peerPublicKey, peerIp });
  try {
    await run('wg', ['set', IFACE, 'peer', peerPublicKey, 'allowed-ips', `${peerIp}/32`]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

// remove peer
app.post('/peers/remove', async (req, res) => {
  if (!authOk(req)) return res.status(401).json({ error: 'bad signature' });
  const { peerPublicKey } = req.body;
  try {
    await run('wg', ['set', IFACE, 'peer', peerPublicKey, 'remove']);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e) }); }
});

app.listen(8443, "0.0.0.0", () => console.log("Sidecar listening on :8443"));