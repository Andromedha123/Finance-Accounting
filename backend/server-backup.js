require('dotenv').config();

const express = require('express');
const path = require('path');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const pool = require('./db');
const {
  createSessionMiddleware,
  requireAuth,
  requireRole,
  writeAudit,
  loginUser,
  createUser
} = require('./auth');

const app = express();

const PORT = process.env.PORT || 3000;

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(compression());

app.use(
  express.json({
    limit: '2mb'
  })
);

app.use(
  express.urlencoded({
    extended: true
  })
);

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api', apiLimiter);

app.use(createSessionMiddleware());


/* =========================================================
   HELPER
========================================================= */

function clean(value) {
  if (value === undefined || value === null) {
    return '';
  }

  return String(value).trim();
}

function num(value) {
  const n = Number(value);

  return Number.isFinite(n) ? n : 0;
}

function generateId() {
  return (
    Date.now().toString(36) +
    Math.random().toString(36).slice(2, 8)
  );
}

function normalizeDate(value) {
  if (!value) {
    return null;
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString().slice(0, 10);
}

function normalizeInvoiceItems(items) {
  if (!Array.isArray(items)) {
    return [];
  }

  return items.map((item) => ({
    id: clean(item.id) || generateId(),
    name: clean(item.name),
    qty: num(item.qty),
    unit: clean(item.unit),
    price: num(item.price),
    masterType: clean(
      item.masterType || item.master_type
    ),
    masterId: clean(
      item.masterId || item.master_id
    )
  }));
}


/* =========================================================
   DATABASE COMPATIBILITY
========================================================= */

async function ensureCompatibility() {
  /*
    Kolom payment_method digunakan untuk menyimpan:
    Transfer Bank / Tunai / QRIS / Lainnya
  */

  await pool.query(`
    ALTER TABLE invoices
    ADD COLUMN IF NOT EXISTS payment_method
    TEXT NOT NULL DEFAULT ''
  `);

  await pool.query(`
    ALTER TABLE invoices
    ADD COLUMN IF NOT EXISTS updated_at
    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  `);

  await pool.query(`
    ALTER TABLE invoice_items
    ADD COLUMN IF NOT EXISTS updated_at
    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
  `);
}


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        NOW() AS server_time
    `);

    res.json({
      ok: true,
      database: 'connected',
      serverTime: result.rows[0].server_time
    });

  } catch (error) {

    console.error('Health check error:', error);

    res.status(500).json({
      ok: false,
      database: 'disconnected',
      message: error.message
    });
  }
});


/* =========================================================
   AUTHENTICATION / USERS / AUDIT
========================================================= */

app.post('/api/auth/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');

    if (!username || !password) {
      return res.status(400).json({
        error: 'Username dan password wajib diisi.'
      });
    }

    const user = await loginUser(username, password);

    if (!user) {
      return res.status(401).json({
        error: 'Username atau password salah.'
      });
    }

    // Buat session ID baru setiap login.
    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => {
        if (err) return reject(err);
        resolve();
      });
    });

    req.session.user = {
      id: user.id,
      username: user.username,
      name: user.name || user.full_name || user.username,
      full_name: user.full_name || user.name || user.username,
      role: user.role
    };

    // Pastikan session tersimpan sebelum response login dikirim.
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) return reject(err);
        resolve();
      });
    });

    // Audit tidak boleh membuat login gagal.
    try {
      await writeAudit(
        req,
        'LOGIN',
        'AUTH',
        `User ${user.username} berhasil login.`
      );
    } catch (auditError) {
      console.error('Login audit error:', auditError);
    }

    return res.json({
      ok: true,
      user: req.session.user
    });

  } catch (err) {
    console.error('LOGIN ERROR:', err);

    return res.status(500).json({
      error: 'Login gagal.',
      detail:
        process.env.NODE_ENV === 'production'
          ? undefined
          : err.message
    });
  }
});


app.post('/api/auth/logout', requireAuth, async (req, res) => {
  const user = req.session.user;

  try {
    await writeAudit(
      req,
      'LOGOUT',
      'AUTH',
      `User ${user.username} logout.`
    );
  } catch (auditError) {
    console.error('Logout audit error:', auditError);
  }

  req.session.destroy((err) => {
    if (err) {
      console.error('Session destroy error:', err);

      return res.status(500).json({
        error: 'Logout gagal.'
      });
    }

    res.clearCookie('connect.sid', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      path: '/'
    });

    return res.json({
      ok: true
    });
  });
});


app.get('/api/auth/me', (req, res) => {
  if (!req.session?.user) {
    return res.status(401).json({
      authenticated: false
    });
  }

  return res.json({
    authenticated: true,
    user: req.session.user
  });
});


app.get('/api/users', requireRole('admin'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        id,
        username,
        name,
        full_name,
        role,
        is_active,
        last_login_at,
        created_at,
        updated_at
      FROM users
      ORDER BY username
    `);

    return res.json(result.rows);
  } catch (err) {
    console.error('GET /api/users:', err);

    return res.status(500).json({
      error: 'Gagal mengambil user.'
    });
  }
});


app.post('/api/users', requireRole('admin'), async (req, res) => {
  try {
    const user = await createUser(req.body || {});

    await writeAudit(
      req,
      'CREATE',
      'USER',
      `Membuat user ${user.username} dengan role ${user.role}.`,
      user.id
    );

    return res.status(201).json(user);
  } catch (err) {
    console.error('POST /api/users:', err);

    if (err.code === '23505') {
      return res.status(409).json({
        error: 'Username sudah digunakan.'
      });
    }

    return res.status(400).json({
      error: err.message
    });
  }
});


app.patch('/api/users/:id/status', requireRole('admin'), async (req, res) => {
  try {
    if (
      req.params.id === req.session.user.id &&
      req.body?.enabled === false
    ) {
      return res.status(400).json({
        error: 'Admin yang sedang login tidak dapat menonaktifkan dirinya sendiri.'
      });
    }

    const result = await pool.query(
      `
      UPDATE users
      SET
        is_active = $1,
        updated_at = NOW()
      WHERE id = $2
      RETURNING
        id,
        username,
        name,
        full_name,
        role,
        is_active
      `,
      [
        Boolean(req.body?.enabled),
        req.params.id
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'User tidak ditemukan.'
      });
    }

    const u = result.rows[0];

    await writeAudit(
      req,
      req.body?.enabled
        ? 'ACTIVATE_USER'
        : 'DEACTIVATE_USER',
      'USER',
      `${
        req.body?.enabled
          ? 'Mengaktifkan'
          : 'Menonaktifkan'
      } user ${u.username}.`,
      u.id
    );

    return res.json(u);
  } catch (err) {
    console.error('PATCH /api/users/:id/status:', err);

    return res.status(500).json({
      error: 'Gagal mengubah status user.'
    });
  }
});


app.get(
  '/api/audit-logs',
  requireRole('admin', 'auditor'),
  async (req, res) => {
    try {
      const limit = Math.min(
        Math.max(Number(req.query.limit) || 100, 1),
        500
      );

      const result = await pool.query(
        `
        SELECT
          id,
          user_id,
          username,
          action,
          module,
          record_id,
          description,
          ip_address,
          user_agent,
          created_at
        FROM audit_logs
        ORDER BY created_at DESC
        LIMIT $1
        `,
        [limit]
      );

      return res.json(result.rows);
    } catch (err) {
      console.error('GET /api/audit-logs:', err);

      return res.status(500).json({
        error: 'Gagal mengambil audit trail.'
      });
    }
  }
);


/* =========================================================
   SETTINGS
========================================================= */

async function readSettings() {

  const result = await pool.query(`
    SELECT
      id,
      name,
      location,
      prepared,
      approved
    FROM settings
    ORDER BY id
    LIMIT 1
  `);

  if (!result.rows.length) {

    return {
      name: 'SPPG Magelang Muntilan Gunungpring 01',
      location: '',
      prepared: '',
      approved: ''
    };
  }

  const row = result.rows[0];

  return {
    name: row.name || '',
    location: row.location || '',
    prepared: row.prepared || '',
    approved: row.approved || ''
  };
}


app.get('/api/settings', requireRole('admin','staff','auditor'), async (req, res) => {

  try {

    const settings = await readSettings();

    res.json(settings);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal mengambil pengaturan.'
    });
  }
});


app.put('/api/settings', requireRole('admin'), async (req, res) => {

  try {

    const data = req.body || {};

    await pool.query(
      `
      INSERT INTO settings (
        id,
        name,
        location,
        prepared,
        approved,
        updated_at
      )
      VALUES (
        'main',
        $1,
        $2,
        $3,
        $4,
        CURRENT_TIMESTAMP
      )
      ON CONFLICT (id)
      DO UPDATE SET
        name = EXCLUDED.name,
        location = EXCLUDED.location,
        prepared = EXCLUDED.prepared,
        approved = EXCLUDED.approved,
        updated_at = CURRENT_TIMESTAMP
      `,
      [
        clean(data.name),
        clean(data.location),
        clean(data.prepared),
        clean(data.approved)
      ]
    );

    res.json({
      success: true
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal menyimpan pengaturan.'
    });
  }
});


/* =========================================================
   SUPPLIERS
========================================================= */

async function readSuppliers() {

  const result = await pool.query(`
    SELECT
      id,
      name,
      phone,
      address
    FROM suppliers
    ORDER BY name ASC
  `);

  return result.rows.map((row) => ({
    id: row.id,
    name: row.name || '',
    phone: row.phone || '',
    address: row.address || ''
  }));
}


app.get('/api/suppliers', requireRole('admin','staff','auditor'), async (req, res) => {

  try {

    res.json(await readSuppliers());

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal mengambil supplier.'
    });
  }
});


app.post('/api/suppliers', requireRole('admin','staff'), async (req, res) => {

  try {

    const data = req.body || {};

    const id = clean(data.id) || generateId();
    const name = clean(data.name);

    if (!name) {
      return res.status(400).json({
        message: 'Nama supplier wajib diisi.'
      });
    }

    await pool.query(
      `
      INSERT INTO suppliers (
        id,
        name,
        phone,
        address
      )
      VALUES ($1, $2, $3, $4)
      `,
      [
        id,
        name,
        clean(data.phone),
        clean(data.address)
      ]
    );

    res.status(201).json({
      success: true,
      id
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal menyimpan supplier.'
    });
  }
});


app.put('/api/suppliers/:id', requireRole('admin','staff'), async (req, res) => {

  try {

    const id = clean(req.params.id);
    const data = req.body || {};

    await pool.query(
      `
      UPDATE suppliers
      SET
        name = $1,
        phone = $2,
        address = $3,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $4
      `,
      [
        clean(data.name),
        clean(data.phone),
        clean(data.address),
        id
      ]
    );

    res.json({
      success: true
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal memperbarui supplier.'
    });
  }
});


app.delete('/api/suppliers/:id', requireRole('admin'), async (req, res) => {

  try {

    const id = clean(req.params.id);

    const used = await pool.query(
      `
      SELECT COUNT(*)::int AS total
      FROM invoices
      WHERE supplier_id = $1
      `,
      [id]
    );

    if (used.rows[0].total > 0) {

      return res.status(409).json({
        message:
          'Supplier tidak dapat dihapus karena sudah digunakan pada invoice.'
      });
    }

    await pool.query(
      `
      DELETE FROM suppliers
      WHERE id = $1
      `,
      [id]
    );

    res.json({
      success: true
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal menghapus supplier.'
    });
  }
});


/* =========================================================
   CATEGORIES
========================================================= */

async function readCategories() {

  const result = await pool.query(`
    SELECT
      id,
      name
    FROM categories
    ORDER BY name ASC
  `);

  return result.rows.map((row) => row.name);
}


app.get('/api/categories', requireRole('admin','staff','auditor'), async (req, res) => {

  try {

    res.json(await readCategories());

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal mengambil kategori.'
    });
  }
});


app.post('/api/categories', requireRole('admin','staff'), async (req, res) => {

  try {

    const name = clean(req.body?.name);

    if (!name) {

      return res.status(400).json({
        message: 'Nama kategori wajib diisi.'
      });
    }

    const id = clean(req.body?.id) || generateId();

    await pool.query(
      `
      INSERT INTO categories (
        id,
        name
      )
      VALUES ($1, $2)
      `,
      [id, name]
    );

    res.status(201).json({
      success: true,
      id
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal menyimpan kategori.'
    });
  }
});


app.delete('/api/categories/:id', requireRole('admin'), async (req, res) => {

  try {

    const id = clean(req.params.id);

    await pool.query(
      `
      DELETE FROM categories
      WHERE id = $1
      `,
      [id]
    );

    res.json({
      success: true
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal menghapus kategori.'
    });
  }
});


/* =========================================================
   RAW MATERIALS
========================================================= */

async function readRawMaterials() {

  const result = await pool.query(`
    SELECT
      id,
      name,
      subcategory,
      unit,
      price,
      supplier_id
    FROM raw_materials
    ORDER BY name ASC
  `);

  return result.rows.map((row) => ({
    id: row.id,
    name: row.name || '',
    subcategory: row.subcategory || '',
    unit: row.unit || '',
    price: num(row.price),
    supplierId: row.supplier_id || ''
  }));
}


app.get('/api/raw-materials', requireRole('admin','staff','auditor'), async (req, res) => {

  try {

    res.json(await readRawMaterials());

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal mengambil bahan baku.'
    });
  }
});


app.post('/api/raw-materials', requireRole('admin','staff'), async (req, res) => {

  try {

    const data = req.body || {};

    const id = clean(data.id) || generateId();

    await pool.query(
      `
      INSERT INTO raw_materials (
        id,
        name,
        subcategory,
        unit,
        price,
        supplier_id
      )
      VALUES ($1, $2, $3, $4, $5, $6)
      `,
      [
        id,
        clean(data.name),
        clean(data.subcategory),
        clean(data.unit),
        num(data.price),
        clean(data.supplierId) || null
      ]
    );

    res.status(201).json({
      success: true,
      id
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal menyimpan bahan baku.'
    });
  }
});


app.put('/api/raw-materials/:id', requireRole('admin','staff'), async (req, res) => {

  try {

    const id = clean(req.params.id);
    const data = req.body || {};

    await pool.query(
      `
      UPDATE raw_materials
      SET
        name = $1,
        subcategory = $2,
        unit = $3,
        price = $4,
        supplier_id = $5,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $6
      `,
      [
        clean(data.name),
        clean(data.subcategory),
        clean(data.unit),
        num(data.price),
        clean(data.supplierId) || null,
        id
      ]
    );

    res.json({
      success: true
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal memperbarui bahan baku.'
    });
  }
});


app.delete('/api/raw-materials/:id', requireRole('admin'), async (req, res) => {

  try {

    const id = clean(req.params.id);

    const used = await pool.query(
      `
      SELECT COUNT(*)::int AS total
      FROM invoice_items
      WHERE master_id = $1
      `,
      [id]
    );

    if (used.rows[0].total > 0) {

      return res.status(409).json({
        message:
          'Bahan baku tidak dapat dihapus karena sudah digunakan pada invoice.'
      });
    }

    await pool.query(
      `
      DELETE FROM raw_materials
      WHERE id = $1
      `,
      [id]
    );

    res.json({
      success: true
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal menghapus bahan baku.'
    });
  }
});


/* =========================================================
   OPERATIONAL ITEMS
========================================================= */

async function readOperationalItems() {

  const result = await pool.query(`
    SELECT
      id,
      name,
      subcategory,
      unit,
      price,
      supplier_id
    FROM operational_items
    ORDER BY name ASC
  `);

  return result.rows.map((row) => ({
    id: row.id,
    name: row.name || '',
    subcategory: row.subcategory || '',
    unit: row.unit || '',
    price: num(row.price),
    supplierId: row.supplier_id || ''
  }));
}


app.get('/api/operational-items', requireRole('admin','staff','auditor'), async (req, res) => {

  try {

    res.json(await readOperationalItems());

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal mengambil barang operasional.'
    });
  }
});


app.post('/api/operational-items', requireRole('admin','staff'), async (req, res) => {

  try {

    const data = req.body || {};

    const id = clean(data.id) || generateId();

    await pool.query(
      `
      INSERT INTO operational_items (
        id,
        name,
        subcategory,
        unit,
        price,
        supplier_id
      )
      VALUES ($1, $2, $3, $4, $5, $6)
      `,
      [
        id,
        clean(data.name),
        clean(data.subcategory),
        clean(data.unit),
        num(data.price),
        clean(data.supplierId) || null
      ]
    );

    res.status(201).json({
      success: true,
      id
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal menyimpan barang operasional.'
    });
  }
});


app.put('/api/operational-items/:id', requireRole('admin','staff'), async (req, res) => {

  try {

    const id = clean(req.params.id);
    const data = req.body || {};

    await pool.query(
      `
      UPDATE operational_items
      SET
        name = $1,
        subcategory = $2,
        unit = $3,
        price = $4,
        supplier_id = $5,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $6
      `,
      [
        clean(data.name),
        clean(data.subcategory),
        clean(data.unit),
        num(data.price),
        clean(data.supplierId) || null,
        id
      ]
    );

    res.json({
      success: true
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal memperbarui barang operasional.'
    });
  }
});


app.delete('/api/operational-items/:id', requireRole('admin'), async (req, res) => {

  try {

    const id = clean(req.params.id);

    const used = await pool.query(
      `
      SELECT COUNT(*)::int AS total
      FROM invoice_items
      WHERE master_id = $1
      `,
      [id]
    );

    if (used.rows[0].total > 0) {

      return res.status(409).json({
        message:
          'Barang operasional tidak dapat dihapus karena sudah digunakan pada invoice.'
      });
    }

    await pool.query(
      `
      DELETE FROM operational_items
      WHERE id = $1
      `,
      [id]
    );

    res.json({
      success: true
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal menghapus barang operasional.'
    });
  }
});


/* =========================================================
   INVOICE
========================================================= */

async function readInvoices() {

  const invoiceResult = await pool.query(`
    SELECT
      i.id,
      i.number,
      i.date,
      i.supplier_id,
      i.category,
      i.subtotal,
      i.tax,
      i.total,
      i.payment_method,
      i.status,
      i.notes
    FROM invoices i
    ORDER BY i.date DESC, i.created_at DESC
  `);

  const itemResult = await pool.query(`
    SELECT
      id,
      invoice_id,
      name,
      qty,
      unit,
      price,
      subtotal,
      master_type,
      master_id
    FROM invoice_items
    ORDER BY created_at ASC
  `);

  const itemsByInvoice = {};

  for (const row of itemResult.rows) {

    if (!itemsByInvoice[row.invoice_id]) {
      itemsByInvoice[row.invoice_id] = [];
    }

    itemsByInvoice[row.invoice_id].push({
      id: row.id,
      name: row.name || '',
      qty: num(row.qty),
      unit: row.unit || '',
      price: num(row.price),
      masterType: row.master_type || '',
      masterId: row.master_id || ''
    });
  }

  return invoiceResult.rows.map((row) => ({
    id: row.id,
    number: row.number || '',
    date: normalizeDate(row.date),
    supplierId: row.supplier_id || '',
    category: row.category || '',
    items: itemsByInvoice[row.id] || [],
    tax: num(row.tax),

    /*
      Total berasal dari database.
      Jangan dihitung ulang dari browser.
    */
    subtotal: num(row.subtotal),
    total: num(row.total),

    status: row.status || 'Menunggu Pembayaran',

    /*
      Frontend lama menggunakan field "payment"
      sebagai metode pembayaran.
    */
    payment: row.payment_method || '',

    notes: row.notes || ''
  }));
}


app.get('/api/invoices', requireRole('admin','staff','auditor'), async (req, res) => {

  try {

    res.json(await readInvoices());

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal mengambil invoice.'
    });
  }
});


app.get('/api/invoices/:id', requireRole('admin','staff','auditor'), async (req, res) => {

  try {

    const id = clean(req.params.id);

    const invoices = await readInvoices();

    const invoice = invoices.find(
      (item) => item.id === id
    );

    if (!invoice) {

      return res.status(404).json({
        message: 'Invoice tidak ditemukan.'
      });
    }

    res.json(invoice);

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal mengambil detail invoice.'
    });
  }
});


/* =========================================================
   CREATE / UPDATE INVOICE
========================================================= */

async function saveInvoice(data, req = null) {

  const client = await pool.connect();

  try {

    await client.query('BEGIN');

    const invoiceId =
      clean(data.id) || generateId();

    const number =
      clean(data.number);

    const date =
      normalizeDate(data.date);

    const supplierId =
      clean(data.supplierId) || null;

    const category =
      clean(data.category);

    const tax =
      num(data.tax);

    const status =
      clean(data.status) ||
      'Menunggu Pembayaran';

    const paymentMethod =
      clean(
        data.payment ||
        data.paymentMethod
      );

    const notes =
      clean(data.notes);

    const items =
      normalizeInvoiceItems(data.items);

    if (!number) {

      throw new Error(
        'Nomor invoice wajib diisi.'
      );
    }

    if (!date) {

      throw new Error(
        'Tanggal invoice tidak valid.'
      );
    }

    if (!items.length) {

      throw new Error(
        'Invoice harus memiliki minimal satu item.'
      );
    }

    for (const item of items) {

      if (!item.name) {

        throw new Error(
          'Nama item invoice wajib diisi.'
        );
      }

      if (item.qty <= 0) {

        throw new Error(
          `Qty item "${item.name}" harus lebih dari 0.`
        );
      }

      if (item.price < 0) {

        throw new Error(
          `Harga item "${item.name}" tidak valid.`
        );
      }
    }

    /*
      Hitung subtotal DI SERVER.
      Browser tidak menjadi sumber kebenaran.
    */

    const subtotal = items.reduce(
      (total, item) => {
        return total +
          item.qty *
          item.price;
      },
      0
    );

    /*
      INSERT / UPDATE invoice
    */

    await client.query(
      `
      INSERT INTO invoices (
        id,
        number,
        date,
        supplier_id,
        category,
        subtotal,
        tax,
        payment_method,
        status,
        notes,
        updated_at
      )
      VALUES (
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        $7,
        $8,
        $9,
        $10,
        CURRENT_TIMESTAMP
      )
      ON CONFLICT (id)
      DO UPDATE SET
        number = EXCLUDED.number,
        date = EXCLUDED.date,
        supplier_id = EXCLUDED.supplier_id,
        category = EXCLUDED.category,
        subtotal = EXCLUDED.subtotal,
        tax = EXCLUDED.tax,
        payment_method = EXCLUDED.payment_method,
        status = EXCLUDED.status,
        notes = EXCLUDED.notes,
        updated_at = CURRENT_TIMESTAMP
      `,
      [
        invoiceId,
        number,
        date,
        supplierId,
        category,
        subtotal,
        tax,
        paymentMethod,
        status,
        notes
      ]
    );

    /*
      Hapus item lama jika update.
    */

    await client.query(
      `
      DELETE FROM invoice_items
      WHERE invoice_id = $1
      `,
      [invoiceId]
    );

    /*
      Masukkan item baru.
    */

    for (const item of items) {

      await client.query(
        `
        INSERT INTO invoice_items (
          id,
          invoice_id,
          name,
          qty,
          unit,
          price,
          master_type,
          master_id,
          updated_at
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          $8,
          CURRENT_TIMESTAMP
        )
        `,
        [
          item.id,
          invoiceId,
          item.name,
          item.qty,
          item.unit,
          item.price,
          item.masterType,
          item.masterId || null
        ]
      );
    }

    /*
      Audit log
    */

    await client.query(
      `
      INSERT INTO audit_logs (
        user_id, username, action, module, record_id, description, new_data
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)
      `,
      [
        req?.session?.user?.id || null,
        req?.session?.user?.username || '',
        data.id ? 'UPDATE' : 'CREATE',
        'invoices',
        invoiceId,
        data.id
          ? `Invoice ${number} diperbarui`
          : `Invoice ${number} dibuat`,
        JSON.stringify({
          number,
          date,
          supplierId,
          category,
          subtotal,
          tax,
          paymentMethod,
          status,
          notes,
          items
        })
      ]
    );

    await client.query('COMMIT');

    return invoiceId;

  } catch (error) {

    await client.query('ROLLBACK');

    throw error;

  } finally {

    client.release();
  }
}


app.post('/api/invoices', requireRole('admin','staff'), async (req, res) => {

  try {

    const id = await saveInvoice(req.body || {}, req);

    res.status(201).json({
      success: true,
      id
    });

  } catch (error) {

    console.error('Create invoice:', error);

    res.status(400).json({
      message: error.message
    });
  }
});


app.put('/api/invoices/:id', requireRole('admin','staff'), async (req, res) => {

  try {

    const data = {
      ...(req.body || {}),
      id: req.params.id
    };

    const id = await saveInvoice(data, req);

    res.json({
      success: true,
      id
    });

  } catch (error) {

    console.error('Update invoice:', error);

    res.status(400).json({
      message: error.message
    });
  }
});


app.delete('/api/invoices/:id', requireRole('admin'), async (req, res) => {

  const client = await pool.connect();

  try {

    const id = clean(req.params.id);

    await client.query('BEGIN');

    const invoice = await client.query(
      `
      SELECT
        number
      FROM invoices
      WHERE id = $1
      `,
      [id]
    );

    if (!invoice.rows.length) {

      await client.query('ROLLBACK');

      return res.status(404).json({
        message: 'Invoice tidak ditemukan.'
      });
    }

    await client.query(
      `
      DELETE FROM invoices
      WHERE id = $1
      `,
      [id]
    );

    await client.query(
      `
      INSERT INTO audit_logs (
        user_id, username, action, module, record_id, description, old_data
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)
      `,
      [
        req.session?.user?.id || null,
        req.session?.user?.username || '',
        'DELETE',
        'invoices',
        id,
        `Invoice ${invoice.rows[0].number} dihapus`,
        JSON.stringify({
          number: invoice.rows[0].number
        })
      ]
    );

    await client.query('COMMIT');

    res.json({
      success: true
    });

  } catch (error) {

    await client.query('ROLLBACK');

    console.error('Delete invoice:', error);

    res.status(500).json({
      message: 'Gagal menghapus invoice.'
    });

  } finally {

    client.release();
  }
});


/* =========================================================
   READ ALL DATA
   COMPATIBLE DENGAN FRONTEND LAMA
========================================================= */

async function readAllData() {

  const [
    settings,
    suppliers,
    categories,
    bahan,
    operasional,
    invoices
  ] = await Promise.all([
    readSettings(),
    readSuppliers(),
    readCategories(),
    readRawMaterials(),
    readOperationalItems(),
    readInvoices()
  ]);

  return {
    settings,
    suppliers,
    categories,
    bahan,
    operasional,
    invoices
  };
}


app.get('/api/data', requireRole('admin','staff','auditor'), async (req, res) => {

  try {

    const data = await readAllData();

    res.json(data);

  } catch (error) {

    console.error('GET /api/data:', error);

    res.status(500).json({
      message: 'Gagal mengambil data aplikasi.',
      error: error.message
    });
  }
});


/* =========================================================
   PUT /api/data
   KOMPATIBILITAS DENGAN FRONTEND LAMA
========================================================= */

async function replaceAllData(data) {

  const client = await pool.connect();

  try {

    await client.query('BEGIN');

    /*
      Hapus data transaksi terlebih dahulu
      karena mempunyai foreign key.
    */

    await client.query(`
      DELETE FROM invoice_items
    `);

    await client.query(`
      DELETE FROM invoices
    `);

    await client.query(`
      DELETE FROM raw_materials
    `);

    await client.query(`
      DELETE FROM operational_items
    `);

    await client.query(`
      DELETE FROM categories
    `);

    await client.query(`
      DELETE FROM suppliers
    `);


    /* SETTINGS */

    const settings =
      data.settings || {};

    await client.query(
      `
      INSERT INTO settings (
        id,
        name,
        location,
        prepared,
        approved,
        updated_at
      )
      VALUES (
        'main',
        $1,
        $2,
        $3,
        $4,
        CURRENT_TIMESTAMP
      )
      ON CONFLICT (id)
      DO UPDATE SET
        name = EXCLUDED.name,
        location = EXCLUDED.location,
        prepared = EXCLUDED.prepared,
        approved = EXCLUDED.approved,
        updated_at = CURRENT_TIMESTAMP
      `,
      [
        clean(settings.name),
        clean(settings.location),
        clean(settings.prepared),
        clean(settings.approved)
      ]
    );


    /* SUPPLIERS */

    for (const supplier of data.suppliers || []) {

      await client.query(
        `
        INSERT INTO suppliers (
          id,
          name,
          phone,
          address
        )
        VALUES ($1, $2, $3, $4)
        `,
        [
          clean(supplier.id) || generateId(),
          clean(supplier.name),
          clean(supplier.phone),
          clean(supplier.address)
        ]
      );
    }


    /* CATEGORIES */

    for (const category of data.categories || []) {

      const name =
        typeof category === 'string'
          ? category
          : clean(category.name);

      if (!name) {
        continue;
      }

      await client.query(
        `
        INSERT INTO categories (
          id,
          name
        )
        VALUES ($1, $2)
        `,
        [
          generateId(),
          name
        ]
      );
    }


    /* RAW MATERIALS */

    for (const item of data.bahan || []) {

      await client.query(
        `
        INSERT INTO raw_materials (
          id,
          name,
          subcategory,
          unit,
          price,
          supplier_id
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        `,
        [
          clean(item.id) || generateId(),
          clean(item.name),
          clean(item.subcategory),
          clean(item.unit),
          num(item.price),
          clean(item.supplierId) || null
        ]
      );
    }


    /* OPERATIONAL */

    for (const item of data.operasional || []) {

      await client.query(
        `
        INSERT INTO operational_items (
          id,
          name,
          subcategory,
          unit,
          price,
          supplier_id
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        `,
        [
          clean(item.id) || generateId(),
          clean(item.name),
          clean(item.subcategory),
          clean(item.unit),
          num(item.price),
          clean(item.supplierId) || null
        ]
      );
    }


    /* INVOICES */

    for (const invoice of data.invoices || []) {

      const invoiceId =
        clean(invoice.id) || generateId();

      const items =
        normalizeInvoiceItems(
          invoice.items
        );

      const subtotal =
        items.reduce(
          (sum, item) =>
            sum +
            item.qty *
            item.price,
          0
        );

      const tax =
        num(invoice.tax);

      await client.query(
        `
        INSERT INTO invoices (
          id,
          number,
          date,
          supplier_id,
          category,
          subtotal,
          tax,
          payment_method,
          status,
          notes
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          $8,
          $9,
          $10
        )
        `,
        [
          invoiceId,
          clean(invoice.number),
          normalizeDate(invoice.date),
          clean(invoice.supplierId) || null,
          clean(invoice.category),
          subtotal,
          tax,
          clean(invoice.payment),
          clean(invoice.status) ||
            'Menunggu Pembayaran',
          clean(invoice.notes)
        ]
      );


      for (const item of items) {

        await client.query(
          `
          INSERT INTO invoice_items (
            id,
            invoice_id,
            name,
            qty,
            unit,
            price,
            master_type,
            master_id
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8
          )
          `,
          [
            item.id,
            invoiceId,
            item.name,
            item.qty,
            item.unit,
            item.price,
            item.masterType,
            item.masterId || null
          ]
        );
      }
    }


    await client.query('COMMIT');

  } catch (error) {

    await client.query('ROLLBACK');

    throw error;

  } finally {

    client.release();
  }
}


app.put('/api/data', requireRole('admin'), async (req, res) => {

  try {

    await replaceAllData(
      req.body || {}
    );

    res.json({
      success: true
    });

  } catch (error) {

    console.error('PUT /api/data:', error);

    res.status(500).json({
      message: 'Gagal menyimpan data.',
      error: error.message
    });
  }
});


/* =========================================================
   REPORTS
========================================================= */

app.get('/api/reports/summary', requireRole('admin','staff','auditor'), async (req, res) => {

  try {

    const from =
      normalizeDate(req.query.from);

    const to =
      normalizeDate(req.query.to);

    const result = await pool.query(
      `
      SELECT
        COUNT(*)::int AS invoice_count,
        COALESCE(
          SUM(subtotal),
          0
        ) AS subtotal,
        COALESCE(
          SUM(tax),
          0
        ) AS tax,
        COALESCE(
          SUM(total),
          0
        ) AS total
      FROM invoices
      WHERE
        ($1::date IS NULL OR date >= $1)
        AND
        ($2::date IS NULL OR date <= $2)
      `,
      [
        from,
        to
      ]
    );

    const row =
      result.rows[0];

    res.json({
      invoiceCount:
        Number(row.invoice_count || 0),

      subtotal:
        num(row.subtotal),

      tax:
        num(row.tax),

      total:
        num(row.total)
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: 'Gagal mengambil laporan.'
    });
  }
});


/* =========================================================
   STATIC FRONTEND
========================================================= */

const frontendPath =
  path.join(
    __dirname,
    '..',
    'frontend'
  );

// Halaman login bersifat publik. Aplikasi utama wajib login.
app.get(['/','/index.html'], (req, res, next) => {
  if (!req.session?.user) return res.redirect('/login.html');
  next();
});

app.use(express.static(frontendPath));

app.get('/{*splat}', (req, res) => {
  if (!req.session?.user) return res.redirect('/login.html');
  res.sendFile(path.join(frontendPath, 'index.html'));
});


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {

    console.error(
      'Unhandled error:',
      error
    );

    res.status(500).json({
      message:
        'Terjadi kesalahan pada server.'
    });
  }
);


/* =========================================================
   START SERVER
========================================================= */

async function startServer() {

  try {

    await ensureCompatibility();

    /*
      Tes koneksi database
    */

    await pool.query(
      'SELECT NOW()'
    );

    app.listen(
      PORT,
      () => {

        console.log(
          `SPPG Finance berjalan di http://localhost:${PORT}`
        );

        console.log(
          'PostgreSQL terhubung.'
        );
      }
    );

  } catch (error) {

    console.error(
      'Gagal menjalankan server:'
    );

    console.error(
      error.message
    );

    process.exit(1);
  }
}


startServer();