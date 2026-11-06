require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const db = require('./src/db');
const market = require('./src/market');
const engine = require('./src/engine');
const { err, SYMBOL } = engine;

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 16) {
  console.error('Set JWT_SECRET (16+ characters) in .env first. See README.');
  process.exit(1);
}
const app = express();
app.use(express.json({ limit: '10kb' }), cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);
const auth = (req, res, next) => {
  try { req.uid = jwt.verify(req.cookies.token, process.env.JWT_SECRET).uid; next(); }
  catch { res.status(401).json({ error: 'Please log in' }); }
};
const session = (res, uid) => res.cookie('token', jwt.sign({ uid }, process.env.JWT_SECRET, { expiresIn: '7d' }),
  { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 864e5 });
const sym = (s) => { s = String(s || '').toUpperCase(); if (!SYMBOL.test(s)) throw err('Invalid symbol'); return s; };

// Basic brute-force guard: 20 login/register attempts per IP per 15 minutes.
const tries = new Map();
const limited = (req) => {
  const now = Date.now(), a = (tries.get(req.ip) || []).filter((t) => now - t < 9e5);
  a.push(now); tries.set(req.ip, a); return a.length > 20;
};

app.post('/api/register', wrap(async (req, res) => {
  if (limited(req)) throw err('Too many attempts. Wait a few minutes.', 429);
  const { username, password } = req.body || {};
  if (!/^[A-Za-z0-9_]{3,20}$/.test(username || '')) throw err('Username must be 3 to 20 letters, numbers or underscores');
  if (typeof password !== 'string' || password.length < 8 || password.length > 72) throw err('Password must be 8 to 72 characters');
  if (db.prepare('SELECT 1 FROM users WHERE username=? COLLATE NOCASE').get(username)) throw err('That username is taken', 409);
  const id = db.prepare('INSERT INTO users(username,hash,created_at) VALUES(?,?,?)').run(username, await bcrypt.hash(password, 12), Date.now()).lastInsertRowid;
  db.prepare('INSERT INTO snapshots VALUES(?,?,?)').run(id, Date.now(), 100000);
  session(res, id);
  res.json({ ok: true });
}));

app.post('/api/login', wrap(async (req, res) => {
  if (limited(req)) throw err('Too many attempts. Wait a few minutes.', 429);
  const { username, password } = req.body || {};
  const u = db.prepare('SELECT id, hash FROM users WHERE username=? COLLATE NOCASE').get(String(username || ''));
  if (!u || !(await bcrypt.compare(String(password || ''), u.hash))) throw err('Invalid username or password', 401);
  session(res, u.id);
  res.json({ ok: true });
}));

app.post('/api/logout', (req, res) => res.clearCookie('token').json({ ok: true }));

app.get('/api/portfolio', auth, wrap(async (req, res) => res.json(await engine.portfolio(req.uid))));
app.get('/api/portfolio/history', auth, (req, res) => res.json(engine.history(req.uid, String(req.query.range))));

app.post('/api/orders', auth, wrap(async (req, res) => res.json(await engine.place(req.uid, req.body || {}))));
app.get('/api/orders', auth, (req, res) => res.json(db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 100').all(req.uid)));
app.delete('/api/orders/:id', auth, (req, res) => {
  const r = db.prepare("UPDATE orders SET status='canceled' WHERE id=? AND user_id=? AND status='pending'").run(+req.params.id, req.uid);
  if (!r.changes) throw err('No pending order found', 404);
  res.json({ ok: true });
});
app.get('/api/transactions', auth, (req, res) => res.json(db.prepare('SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 200').all(req.uid)));

app.get('/api/market/search', auth, wrap(async (req, res) => res.json(await market.search(String(req.query.q || '').slice(0, 40)))));
app.get('/api/market/indices', auth, wrap(async (req, res) => res.json(await market.indices())));
app.get('/api/market/details/:s', auth, wrap(async (req, res) => res.json(await market.details(sym(req.params.s)))));
app.get('/api/market/history/:s', auth, wrap(async (req, res) => res.json(await market.history(sym(req.params.s), String(req.query.range)))));
app.get('/api/market/news', auth, wrap(async (req, res) => res.json(await market.news(req.query.symbol ? sym(req.query.symbol) : null))));

app.use((e, req, res, next) => {
  if (!e.status) console.error(e);
  res.status(e.status || 500).json({ error: e.status ? e.message : 'Something went wrong on the server' });
});

setInterval(() => engine.processPending().catch((e) => console.error('Order check failed:', e.message)), 20000);
app.listen(process.env.PORT || 3000, () => console.log(`E's PaperIO running on http://localhost:${process.env.PORT || 3000}`));
