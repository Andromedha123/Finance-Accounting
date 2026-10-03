// backend/create-admin.js
// Jalankan sekali:
// node backend/create-admin.js
//
// Setelah admin berhasil dibuat, Anda dapat menghapus file ini
// atau menyimpan hanya di lingkungan development.

require('dotenv').config();

const readline = require('readline');
const pool = require('./db');
const { createUser } = require('./auth');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function ask(question) {
  return new Promise(resolve => rl.question(question, resolve));
}

(async () => {
  try {
    const username = await ask('Username admin [admin]: ') || 'admin';
    const fullName = await ask('Nama lengkap [Administrator]: ') || 'Administrator';
    const password = await ask('Password admin: ');

    if (!password || password.length < 8) {
      throw new Error('Password minimal 8 karakter.');
    }

    const user = await createUser({
      username,
      full_name: fullName,
      password,
      role: 'admin'
    });

    console.log('\nAdmin berhasil dibuat:');
    console.log({
      id: user.id,
      username: user.username,
      role: user.role
    });
  } catch (err) {
    console.error('\nGagal membuat admin:', err.message);
    process.exitCode = 1;
  } finally {
    rl.close();
    await pool.end();
  }
})();
