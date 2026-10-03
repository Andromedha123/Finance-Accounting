UPDATE FRONTEND - PostgreSQL CRUD

Ganti frontend/index.html lama dengan index.html dari folder ini.

Frontend sekarang menggunakan API untuk:
- Supplier
- Kategori
- Bahan Baku
- Barang Operasional
- Invoice
- Pengaturan SPPG

Endpoint yang digunakan:
GET /api/data
POST/PUT/DELETE /api/suppliers
POST/PUT/DELETE /api/categories
POST/PUT/DELETE /api/raw-materials
POST/PUT/DELETE /api/operational-items
POST/PUT/DELETE /api/invoices
PUT /api/settings

Catatan:
Frontend mengharapkan backend memiliki PUT /api/categories/:name untuk edit kategori.
Jika route tersebut belum ada, tambahkan route sesuai instruksi di chat.
