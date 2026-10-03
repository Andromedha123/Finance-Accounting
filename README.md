# SPPG Finance - PostgreSQL + Authentication

Versi terintegrasi dari project SPPG Finance yang sudah menggunakan PostgreSQL, ditambah:
- Login session berbasis PostgreSQL
- Role Admin / Staff / Auditor
- Manajemen user
- Audit trail
- Proteksi API berdasarkan role
- Backup/restore dibatasi Admin
- Halaman utama otomatis mengarahkan user yang belum login ke login.html

## 1. Copy file ke project lama
Backup folder `D:\Finance-Accounting` terlebih dahulu. Jangan hapus database.

File utama yang perlu diganti/ditambahkan:
- backend/server.js
- backend/auth.js
- backend/auth-routes.js
- backend/create-admin.js
- frontend/login.html
- frontend/auth-helper.js
- frontend/index.html
- database/auth-migration.sql

## 2. Install dependency
PowerShell di `D:\Finance-Accounting`:

```powershell
npm install bcryptjs express-session connect-pg-simple
```

## 3. Tambahkan SESSION_SECRET ke .env
Contoh:

```env
NODE_ENV=development
SESSION_SECRET=ganti_dengan_string_acak_minimal_32_karakter
```

Jangan bagikan `.env` atau password database.

## 4. Jalankan migration audit
Di pgAdmin Query Tool, pilih database `sppg_finance`, lalu jalankan seluruh isi:

`database/auth-migration.sql`

Migration ini menambahkan `old_data` dan `new_data` ke `audit_logs`, karena server invoice memakai kedua kolom tersebut.

## 5. Buat admin pertama
Di PowerShell:

```powershell
node backend/create-admin.js
```

Isi username, nama lengkap, dan password minimal 8 karakter.

## 6. Jalankan server
```powershell
npm start
```

Buka:

http://localhost:3000

User yang belum login akan diarahkan ke `/login.html`.

## 7. Role
- Admin: semua fitur dan manajemen user
- Staff: input/edit transaksi dan master data, tanpa delete/restore/user management
- Auditor: read-only untuk data dan laporan + audit trail

Proteksi dilakukan di backend; menyembunyikan tombol di frontend bukan satu-satunya pengaman.
