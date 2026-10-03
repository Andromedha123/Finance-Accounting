CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS settings (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    name TEXT NOT NULL DEFAULT 'SPPG Magelang Muntilan Gunungpring 01',
    location TEXT NOT NULL DEFAULT '',
    prepared TEXT NOT NULL DEFAULT '',
    approved TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS suppliers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_suppliers_name_lower
ON suppliers (LOWER(name));

CREATE TABLE IF NOT EXISTS categories (
    name TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS raw_materials (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    subcategory TEXT NOT NULL DEFAULT '',
    unit TEXT NOT NULL,
    default_price NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (default_price >= 0),
    supplier_id TEXT REFERENCES suppliers(id) ON UPDATE CASCADE ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_raw_materials_name_lower
ON raw_materials (LOWER(name));

CREATE TABLE IF NOT EXISTS operational_items (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    subcategory TEXT NOT NULL DEFAULT '',
    unit TEXT NOT NULL,
    default_price NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (default_price >= 0),
    supplier_id TEXT REFERENCES suppliers(id) ON UPDATE CASCADE ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_operational_items_name_lower
ON operational_items (LOWER(name));

CREATE TABLE IF NOT EXISTS invoices (
    id TEXT PRIMARY KEY,
    invoice_number TEXT NOT NULL,
    invoice_date DATE NOT NULL,
    supplier_id TEXT REFERENCES suppliers(id) ON UPDATE CASCADE ON DELETE RESTRICT,
    category TEXT NOT NULL,
    tax NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (tax >= 0),
    status TEXT NOT NULL DEFAULT 'Lunas',
    payment_method TEXT NOT NULL DEFAULT 'Transfer Bank',
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_invoice_number
ON invoices (invoice_number);

CREATE INDEX IF NOT EXISTS idx_invoices_date ON invoices(invoice_date);
CREATE INDEX IF NOT EXISTS idx_invoices_supplier ON invoices(supplier_id);
CREATE INDEX IF NOT EXISTS idx_invoices_category ON invoices(category);

CREATE TABLE IF NOT EXISTS invoice_items (
    id TEXT PRIMARY KEY,
    invoice_id TEXT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    master_type TEXT NOT NULL DEFAULT '',
    master_id TEXT NOT NULL DEFAULT '',
    item_name TEXT NOT NULL,
    qty NUMERIC(18,3) NOT NULL DEFAULT 0 CHECK (qty >= 0),
    unit TEXT NOT NULL DEFAULT '',
    price NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (price >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invoice_items_invoice
ON invoice_items(invoice_id);

INSERT INTO settings (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;

INSERT INTO categories (name) VALUES
('Bahan Makanan'), ('Bahan Pendukung'), ('Operasional'),
('Transportasi'), ('Peralatan'), ('Gas'), ('Listrik'),
('Air'), ('ATK'), ('Lainnya')
ON CONFLICT (name) DO NOTHING;

INSERT INTO suppliers (id, name, phone, address)
VALUES ('s1', 'Koperasi Gunungpring Terpadu Sejahtera', '', '')
ON CONFLICT (id) DO NOTHING;
