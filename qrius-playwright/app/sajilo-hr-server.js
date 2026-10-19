// Sajilo HR practice server (Qrius Bootcamp, Module 6)
// v2 for Session 2: richer login validation, a locked account, and a lockout rule.
// One file, no npm installs. Start it with:  node app/sajilo-hr-server.js
// It serves app/sajilo-hr.html and a small JSON API protected by real JWTs.
// PRACTICE ONLY: the secret below is public, and data lives in memory.

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT) || 5050;
const SECRET = 'qrius-practice-secret';      // never hard-code a real secret
const TOKEN_LIFETIME_SECONDS = 60 * 60;      // tokens expire after 1 hour
const LOGIN_DELAY_MS = 600;                  // a real server is never instant
const PAGE = path.join(__dirname, 'sajilo-hr.html');

// ---------- seeded users (all share one practice password) ----------
const PASSWORD = 'Sajilo@123';
const USERS = {
  'admin.anil': { name: 'Anil Shrestha', role: 'ADMIN' },
  'hr.sita':    { name: 'Sita Gurung',   role: 'HR' },
  'emp.ram':    { name: 'Ram Thapa',     role: 'EMPLOYEE' },
  // v2: test accounts
  'emp.hari':   { name: 'Hari Karki',    role: 'EMPLOYEE', locked: true },  // locked by HR, stays locked
  'emp.sunita': { name: 'Sunita Tamang', role: 'EMPLOYEE' },                // for wrong-password tests
  'emp.bikash': { name: 'Bikash Rai',    role: 'EMPLOYEE' },                // for lockout tests
};

// ---------- v2: lockout rule ----------
// 3 failed logins within 15 minutes lock the account for 15 minutes.
// A successful login does NOT clear earlier failures; they expire after 15 minutes.
const MAX_FAILED_LOGINS = 3;
const LOCK_WINDOW_MS = 15 * 60 * 1000;
const failedLogins = {};   // username -> [timestamps]
const lockedUntil = {};    // username -> timestamp

const MSG = {
  BOTH_EMPTY: 'Enter your username and password.',
  NO_USERNAME: 'Enter your username.',
  NO_PASSWORD: 'Enter your password.',
  INVALID: 'Invalid username or password.',
  LOCKED: 'Your account is locked. Contact HR, then try again.',
};

function isLocked(username) {
  if (USERS[username].locked) return true;
  if (lockedUntil[username] && lockedUntil[username] > Date.now()) return true;
  delete lockedUntil[username];
  return false;
}

function recordFailure(username) {
  const now = Date.now();
  const recent = (failedLogins[username] || []).filter((t) => now - t < LOCK_WINDOW_MS);
  recent.push(now);
  failedLogins[username] = recent;
  if (recent.length >= MAX_FAILED_LOGINS) lockedUntil[username] = now + LOCK_WINDOW_MS;
}

const STAFF = [
  { id: 1, name: 'Anil Shrestha',  department: 'Management',  branch: 'Kathmandu' },
  { id: 2, name: 'Sita Gurung',    department: 'HR',          branch: 'Kathmandu' },
  { id: 3, name: 'Ram Thapa',      department: 'QA',          branch: 'Lalitpur' },
  { id: 4, name: 'Gita Adhikari',  department: 'Engineering', branch: 'Pokhara' },
  { id: 5, name: 'Bikash Rai',     department: 'Engineering', branch: 'Kathmandu' },
  { id: 6, name: 'Sunita Tamang',  department: 'Finance',     branch: 'Butwal' },
];

// monthly basic salary in rupees
const PAYROLL = [
  { name: 'Anil Shrestha', salary: 185000 },
  { name: 'Sita Gurung',   salary: 95000 },
  { name: 'Ram Thapa',     salary: 72000 },
  { name: 'Gita Adhikari', salary: 110000 },
  { name: 'Bikash Rai',    salary: 88000 },
  { name: 'Sunita Tamang', salary: 80000 },
];

const LEAVE_TYPES = ['Dashain-Tihar leave', 'Sick leave', 'Home leave'];
let leaves = [];       // { id, username, type, days, reason, status }
let nextLeaveId = 1;

// ---------- JWT (HS256) using only node:crypto ----------
const b64url = (input) => Buffer.from(input).toString('base64url');

function signToken(payload) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const signature = crypto.createHmac('sha256', SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

// returns { user } when valid, or { error } explaining why not
function verifyToken(token) {
  const parts = (token || '').split('.');
  if (parts.length !== 3) return { error: 'Missing or invalid token' };
  const [header, body, signature] = parts;
  const expected = crypto.createHmac('sha256', SECRET).update(`${header}.${body}`).digest('base64url');
  if (signature.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return { error: 'Missing or invalid token' };
  }
  let payload;
  try { payload = JSON.parse(Buffer.from(body, 'base64url').toString()); }
  catch { return { error: 'Missing or invalid token' }; }
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return { error: 'Token expired' };
  return { user: { username: payload.sub, name: payload.name, role: payload.role } };
}

// ---------- helpers ----------
function send(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(data === undefined ? '' : JSON.stringify(data));
}

function readJson(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); } catch { resolve(null); }
    });
  });
}

// 401 = we don't know who you are. 403 = we know, and the answer is no.
function authorise(req, res, allowedRoles) {
  const header = req.headers['authorization'] || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const { user, error } = verifyToken(token);
  if (!user) { send(res, 401, { message: error }); return null; }
  if (allowedRoles && !allowedRoles.includes(user.role)) {
    send(res, 403, { message: `Forbidden: requires role ${allowedRoles.join(' or ')}` });
    return null;
  }
  return user;
}

// ---------- routes ----------
async function handleApi(req, res, url) {
  const route = `${req.method} ${url.pathname}`;

  if (route === 'GET /api/health') return send(res, 200, { status: 'ok' });

  if (route === 'POST /api/login') {
    const body = (await readJson(req)) || {};
    await new Promise((r) => setTimeout(r, LOGIN_DELAY_MS));
    const username = String(body.username ?? '').trim();
    const password = String(body.password ?? '');

    // 400: something is missing
    if (!username && !password) return send(res, 400, { message: MSG.BOTH_EMPTY });
    if (!username) return send(res, 400, { message: MSG.NO_USERNAME });
    if (!password) return send(res, 400, { message: MSG.NO_PASSWORD });

    const found = Object.hasOwn(USERS, username) ? USERS[username] : null;
    // 423: the account exists but is locked (checked before the password)
    if (found && isLocked(username)) return send(res, 423, { message: MSG.LOCKED });
    // 401: unknown user or wrong password. Usernames and passwords are case-sensitive.
    if (!found || password !== PASSWORD) {
      if (found) recordFailure(username);
      return send(res, 401, { message: MSG.INVALID });
    }
    const now = Math.floor(Date.now() / 1000);
    const token = signToken({ sub: username, name: found.name, role: found.role, iat: now, exp: now + TOKEN_LIFETIME_SECONDS });
    return send(res, 200, { token, user: { username, name: found.name, role: found.role } });
  }

  // v2: TEST-ONLY hook. Clears the failed logins and any lockout for one user.
  // It never unlocks an account that HR locked (emp.hari). Real apps offer hooks
  // like this only in test environments, never in production.
  if (route === 'POST /api/test/reset-login') {
    const body = (await readJson(req)) || {};
    const username = String(body.username ?? '').trim();
    delete failedLogins[username];
    delete lockedUntil[username];
    return send(res, 204);
  }

  if (route === 'GET /api/me') {
    const user = authorise(req, res);
    if (user) send(res, 200, user);
    return;
  }

  if (route === 'GET /api/staff') {
    if (authorise(req, res, ['ADMIN', 'HR'])) send(res, 200, STAFF);
    return;
  }

  if (route === 'GET /api/payroll') {
    if (authorise(req, res, ['ADMIN'])) send(res, 200, PAYROLL);
    return;
  }

  if (route === 'GET /api/leave') {
    const user = authorise(req, res);
    if (user) send(res, 200, leaves.filter((l) => l.username === user.username));
    return;
  }

  if (route === 'POST /api/leave') {
    const user = authorise(req, res);
    if (!user) return;
    const body = await readJson(req);
    const days = Number(body && body.days);
    if (!body || !LEAVE_TYPES.includes(body.type) || !Number.isInteger(days) || days < 1 || days > 15 || !body.reason) {
      return send(res, 400, { message: 'Choose a leave type, 1 to 15 days, and a reason' });
    }
    const leave = { id: nextLeaveId++, username: user.username, type: body.type, days, reason: String(body.reason), status: 'Pending' };
    leaves.push(leave);
    return send(res, 201, leave);
  }

  const del = url.pathname.match(/^\/api\/leave\/(\d+)$/);
  if (req.method === 'DELETE' && del) {
    const user = authorise(req, res);
    if (!user) return;
    const id = Number(del[1]);
    const index = leaves.findIndex((l) => l.id === id && l.username === user.username);
    if (index === -1) return send(res, 404, { message: 'Leave request not found' });
    leaves.splice(index, 1);
    return send(res, 204);
  }

  send(res, 404, { message: 'Not found' });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname.startsWith('/api/')) {
    handleApi(req, res, url).catch(() => send(res, 500, { message: 'Server error' }));
    return;
  }
  // every other path returns the single page app; it reads the path itself
  fs.readFile(PAGE, (err, html) => {
    if (err) { res.writeHead(500); res.end('sajilo-hr.html is missing next to this server file'); return; }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  });
});

server.listen(PORT, () => {
  console.log(`Sajilo HR v2 running at http://localhost:${PORT}`);
  console.log('Users: admin.anil, hr.sita, emp.ram   Password: Sajilo@123');
  console.log('Test accounts: emp.hari (locked), emp.sunita, emp.bikash');
});
