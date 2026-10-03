// backend/auth.js
// Authentication middleware untuk SPPG Finance.
// Menggunakan express-session + PostgreSQL session store.

const bcrypt = require('bcryptjs');
const session = require('express-session');
const connectPgSimple = require('connect-pg-simple');
const crypto = require('crypto');
const pool = require('./db');

const PgSession = connectPgSimple(session);

function createSessionMiddleware() {
  return session({
    store: new PgSession({
      pool,
      tableName: 'user_sessions',
      createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: process.env.NODE_ENV === 'production' ? 'lax' : 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 8
    }
  });
}

function requireAuth(req, res, next) {
  if (!req.session?.user) {
    return res.status(401).json({ error: 'Silakan login terlebih dahulu.' });
  }
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.session?.user) {
      return res.status(401).json({ error: 'Silakan login terlebih dahulu.' });
    }
    if (!roles.includes(req.session.user.role)) {
      return res.status(403).json({ error: 'Anda tidak memiliki hak akses.' });
    }
    next();
  };
}

async function writeAudit(req, action, module, description, recordId = null) {
  const u = req.session?.user;
  await pool.query(
    `INSERT INTO audit_logs
      (user_id, username, action, module, record_id, description, ip_address, user_agent)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      u?.id || null,
      u?.username || '',
      action,
      module,
      recordId,
      description,
      req.ip || null,
      req.get('user-agent') || null
    ]
  );
}

async function loginUser(username, password) {
  const normalizedUsername = String(username || '').trim().toLowerCase();

  if (!normalizedUsername || !password) {
    return null;
  }

  const result = await pool.query(
    `
    SELECT
      id,
      username,
      name,
      full_name,
      password_hash,
      role,
      is_active
    FROM users
    WHERE LOWER(username) = LOWER($1)
    LIMIT 1
    `,
    [normalizedUsername]
  );

  if (!result.rowCount) {
    return null;
  }

  const user = result.rows[0];

  if (!user.is_active) {
    return null;
  }

  const valid = await bcrypt.compare(
    String(password),
    user.password_hash
  );

  if (!valid) {
    return null;
  }

  // Catat waktu login.
  await pool.query(
    `
    UPDATE users
    SET last_login_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
    WHERE id = $1
    `,
    [user.id]
  );

  return {
    id: user.id,
    username: user.username,
    name: user.name,
    full_name: user.full_name,
    role: user.role
  };
}

async function createUser({ username, full_name, password, role = 'staff' }) {
  if (!username || !password) {
    throw new Error('Username dan password wajib diisi.');
  }

  if (password.length < 8) {
    throw new Error('Password minimal 8 karakter.');
  }

  const allowedRoles = ['admin', 'staff', 'auditor'];

  if (!allowedRoles.includes(role)) {
    throw new Error('Role tidak valid.');
  }

  const normalizedUsername = username.trim().toLowerCase();
  const normalizedName = (full_name || normalizedUsername).trim();

  const existing = await pool.query(
    `SELECT id FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1`,
    [normalizedUsername]
  );

  if (existing.rows.length > 0) {
    throw new Error(`Username "${normalizedUsername}" sudah digunakan.`);
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const result = await pool.query(
    `
    INSERT INTO users
      (username, name, full_name, password_hash, role, is_active)
    VALUES
      ($1, $2, $2, $3, $4, TRUE)
    RETURNING
      id,
      username,
      name,
      full_name,
      role,
      is_active,
      created_at
    `,
    [
      normalizedUsername,
      normalizedName,
      passwordHash,
      role
    ]
  );

  return result.rows[0];
}

module.exports = {
  createSessionMiddleware,
  requireAuth,
  requireRole,
  writeAudit,
  loginUser,
  createUser
};
