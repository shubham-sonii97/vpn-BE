import 'dotenv/config';
import express from 'express';
import dayjs from 'dayjs';
import axios from 'axios';
import { db } from '../../db/db.js';
import { signHmac } from './sign.js';

const app = express();
app.use(express.json());

// --- helpers ---
async function ensureUserAndDevice(googlePlayId, deviceId) {
  let [rows] = await db.query('SELECT id FROM users WHERE google_play_id=?', [googlePlayId]);
  let userId;
  if (rows.length === 0) {
    const [r] = await db.query('INSERT INTO users (google_play_id) VALUES (?)', [googlePlayId]);
    userId = r.insertId;
  } else userId = rows[0].id;

  await db.query(
    'INSERT IGNORE INTO devices (user_id, device_id, last_seen) VALUES (?,?,NOW())',
    [userId, deviceId]
  );
  await db.query('UPDATE devices SET last_seen=NOW() WHERE user_id=? AND device_id=?', [userId, deviceId]);
  return userId;
}

async function ensureServerRow() {
  // Insert or upsert one server row for 'sg'
  const [[region]] = await db.query('SELECT id FROM regions WHERE code=?', [process.env.REGION_CODE || 'sg']);
  console.log(region);
  debugger;
  if (!region.id) throw new Error('Region sg missing. Seed regions first.');

  const sidecarUrl = process.env.SIDECAR_BASE_URL;
  const publicIp = process.env.SERVER_PUBLIC_IP;
  const wgInterface = process.env.WG_INTERFACE || 'wg0';

  // Read server public key from file (in WSL)
  const fs = await import('fs/promises');
  const keyFile = process.env.SERVER_PUBLIC_KEY_FILE || '/etc/wireguard/server_public.key';
  const serverPublicKey = (await fs.readFile(keyFile, 'utf8')).trim();

  const [rows] = await db.query('SELECT id FROM servers WHERE region_id=? LIMIT 1', [region.id]);
  if (rows.length === 0) {
    await db.query(
      `INSERT INTO servers (region_id, public_ip, server_public_key, wg_interface, sidecar_base_url, sidecar_secret, next_ip_last_octet, is_active)
       VALUES (?,?,?,?,?,?,?,1)`,
      [region.id, publicIp, serverPublicKey, wgInterface, sidecarUrl, process.env.SIDECAR_SECRET, 10]
    );
  } else {
    await db.query(
      `UPDATE servers SET public_ip=?, server_public_key=?, wg_interface=?, sidecar_base_url=?, sidecar_secret=? WHERE id=?`,
      [publicIp, serverPublicKey, wgInterface, sidecarUrl, process.env.SIDECAR_SECRET, rows[0].id]
    );
  }
}

async function allocateIp(serverId) {
  // simple allocator: 10.7.1.X, X increments using servers.next_ip_last_octet
  const [[srv]] = await db.query('SELECT next_ip_last_octet FROM servers WHERE id=? FOR UPDATE', [serverId]);
  let next = srv.next_ip_last_octet || 10;
  if (next >= 250) next = 10; // wrap
  const ip = `10.7.1.${next}`;
  // advance pointer
  await db.query('UPDATE servers SET next_ip_last_octet=? WHERE id=?', [next + 1, serverId]);
  return ip;
}

// --- middleware: "auth" by Google Play ID (no JWT) ---
app.use(async (req, res, next) => {
  if (req.path.startsWith('/healthz') || req.path.startsWith('/setup')) return next();

  let googlePlayId = req.header('x-google-play-id');
  let deviceId = req.header('x-device-id');
  googlePlayId= parseInt(googlePlayId);
  deviceId = parseInt(deviceId);
  if (!googlePlayId || !deviceId) {
    console.log('Missing headers:', { googlePlayId, deviceId });
    return res.status(400).json({ error: 'Missing x-google-play-id or x-device-id' });
  }
  try {
    console.log(googlePlayId);
    req.userId = await ensureUserAndDevice(googlePlayId, deviceId);
    req.deviceId = deviceId;
    return next();
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'auth failed' });
  }
});

// --- routes ---
app.get('/healthz', async (_req, res) => {
  try { await db.query('SELECT 1'); res.json({ ok: true }); }
  catch { res.status(500).json({ ok: false }); }
});

app.post('/setup/ensure-server', async (_req, res) => {
  try { await ensureServerRow(); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: String(e) }); }
});

// list region(s) — single region 'sg'
app.get('/v1/regions', async (_req, res) => {
  const [rows] = await db.query('SELECT code,name FROM regions WHERE code=?', [process.env.REGION_CODE || 'sg']);
  res.json(rows);
});

// start session: create keys via sidecar, add peer, persist, return client config
app.post('/v1/sessions/start', async (req, res) => {
  const userId = req.userId;
  const deviceId = req.deviceId;
  console.log({ userId, deviceId });
  try {
    const [[server]] = await db.query(
      `SELECT * FROM servers WHERE is_active=1 ORDER BY id LIMIT 1`
    );
    console.log('server:', server);
    if (!server) return res.status(400).json({ error: 'No server available' });

    // Generate keypair via sidecar
    const sig1 = signHmac({}, process.env.SIDECAR_SECRET);
    console.log('sig1:', sig1);
    const { data: keys } = await axios.get(`${server.sidecar_base_url}/keys/new`, {
      headers: { 'x-signature': sig1 }
    });
    console.log('keys:', keys);
    const clientPrivateKey = keys.privateKey;
    const clientPublicKey  = keys.publicKey;

    // IP allocate
    await db.query('START TRANSACTION');
    const peerIp = await allocateIp(server.id);
    await db.query('COMMIT');

    // Tell sidecar to add peer
    const body = { peerPublicKey: clientPublicKey, peerIp };
    const sig2 = signHmac(body, server.sidecar_secret);
    await axios.post(`${server.sidecar_base_url}/peers/add`, body, { headers: { 'x-signature': sig2 } });

    // Save peer + session
    const [r1] = await db.query(
      `INSERT INTO wg_peers (server_id,user_id,device_id,peer_private_key,peer_public_key,peer_ip)
       VALUES (?,?,?,?,?,?)`,
      [server.id, userId, deviceId, clientPrivateKey, clientPublicKey, peerIp]
    );
    const peerId = r1.insertId;
    const start = dayjs();
    const expires = start.add(Number(process.env.SESSION_MINUTES || 60), 'minute');

    const [r2] = await db.query(
      `INSERT INTO sessions (user_id,device_id,server_id,peer_id,start_at,expires_at)
       VALUES (?,?,?,?,?,?)`,
      [userId, deviceId, server.id, peerId, start.toDate(), expires.toDate()]
    );

    // Build client config (import this in WireGuard for Windows)
    const config = [
      '[Interface]',
      `PrivateKey = ${clientPrivateKey}`,
      `Address = ${peerIp}/32`,
      'DNS = 1.1.1.1, 8.8.8.8',
      '',
      '[Peer]',
      `PublicKey = ${server.server_public_key}`,
      'AllowedIPs = 0.0.0.0/0, ::/0',
      `Endpoint = ${server.public_ip}:51820`,
      'PersistentKeepalive = 25'
    ].join('\n');

    res.json({ sessionId: r2.insertId, expiresAt: expires.toISOString(), wireguardConfig: config });
  } catch (e) {
    console.error(e);
    // try rollback
    try { await db.query('ROLLBACK'); } catch {}
    res.status(500).json({ error: String(e) });
  }
});

// stop session: remove peer
app.post('/v1/sessions/stop', async (req, res) => {
  const userId = req.userId;
  const deviceId = req.deviceId;
  const { sessionId } = req.body || {};
  if (!sessionId) return res.status(400).json({ error: 'sessionId required' });

  const [[row]] = await db.query(
    `SELECT s.id, s.server_id, s.peer_id, p.peer_public_key
       FROM sessions s JOIN wg_peers p ON p.id = s.peer_id
      WHERE s.id=? AND s.user_id=? AND s.device_id=? AND s.ended_at IS NULL`,
    [sessionId, userId, deviceId]
  );
  if (!row) return res.json({ ok: true }); // already ended

  const [[server]] = await db.query(`SELECT * FROM servers WHERE id=?`, [row.server_id]);
  const body = { peerPublicKey: row.peer_public_key };
  const sig = signHmac(body, server.sidecar_secret);

  try {
    await axios.post(`${server.sidecar_base_url}/peers/remove`, body, { headers: { 'x-signature': sig } });
  } catch (e) { console.warn('remove peer warning:', e?.message || e); }

  await db.query(`UPDATE sessions SET ended_at=NOW(), reason='user_stop' WHERE id=?`, [sessionId]);
  res.json({ ok: true });
});

app.use((err, req, res, next) => {
  console.error("❌ API Error:", err);
  res.status(500).json({ error: "Internal Server Error" });
});
const PORT = process.env.PORT || 4000;
// Bind to 0.0.0.0 so Postman/Windows can access WSL server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 API running on http://0.0.0.0:${PORT}`);
});
