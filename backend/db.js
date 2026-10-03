const { Pool } = require('pg');

// Prioritas:
// 1. NEON_DATABASE_URL → digunakan di Vercel
// 2. DATABASE_URL      → digunakan untuk lokal
const databaseUrl =
  process.env.NEON_DATABASE_URL ||
  process.env.DATABASE_URL;

if (!databaseUrl) {
  throw new Error(
    'Database URL belum diatur. Pastikan NEON_DATABASE_URL atau DATABASE_URL tersedia.'
  );
}

const pool = new Pool({
  connectionString: databaseUrl,

  max: Number(process.env.DB_POOL_MAX || 10),

  idleTimeoutMillis: 30000,

  connectionTimeoutMillis: 10000,

  ssl:
    process.env.DATABASE_SSL === 'false'
      ? false
      : { rejectUnauthorized: false }
});

pool.on('error', (err) => {
  console.error('Unexpected PostgreSQL pool error:', err);
});

module.exports = pool;