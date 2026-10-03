// backend/auth-routes.js
//
// Authentication routes untuk SPPG Finance.
// File ini harus di-load dari server.js menggunakan:
// const registerAuthRoutes = require('./auth-routes');
// registerAuthRoutes(app, pool);

const {
  createSessionMiddleware,
  requireAuth,
  requireRole,
  writeAudit,
  loginUser,
  createUser
} = require('./auth');

function registerAuthRoutes(app, pool) {

  // =========================================================
  // SESSION
  // =========================================================

  // WAJIB dipasang sebelum route yang membutuhkan session.
  app.use(createSessionMiddleware());


  // =========================================================
  // LOGIN
  // =========================================================

  app.post('/api/auth/login', async (req, res) => {
    try {

      const username = String(
        req.body?.username || ''
      ).trim();

      const password = String(
        req.body?.password || ''
      );

      if (!username || !password) {
        return res.status(400).json({
          error: 'Username dan password wajib diisi.'
        });
      }

      const user = await loginUser(
        username,
        password
      );

      if (!user) {
        return res.status(401).json({
          error: 'Username atau password salah.'
        });
      }

      /*
       * Selalu buat session baru ketika login.
       *
       * Ini penting setelah user logout kemudian
       * melakukan login kembali.
       */
      req.session.regenerate(async (sessionError) => {

        if (sessionError) {

          console.error(
            'Session regenerate error:',
            sessionError
          );

          return res.status(500).json({
            error: 'Gagal membuat session login.'
          });
        }

        /*
         * Simpan user ke session.
         */
        req.session.user = {
          id: user.id,
          username: user.username,
          name: user.name || user.full_name || user.username,
          full_name: user.full_name || user.name || user.username,
          role: user.role
        };

        try {

          /*
           * Audit LOGIN
           */
          await writeAudit(
            req,
            'LOGIN',
            'AUTH',
            `User ${user.username} berhasil login.`
          );

          /*
           * Pastikan session tersimpan di PostgreSQL
           * sebelum response dikirim ke browser.
           */
          req.session.save((saveError) => {

            if (saveError) {

              console.error(
                'Session save error:',
                saveError
              );

              return res.status(500).json({
                error: 'Gagal menyimpan session login.'
              });
            }

            return res.json({
              ok: true,
              user: req.session.user
            });

          });

        } catch (auditError) {

          console.error(
            'Login audit error:',
            auditError
          );

          return res.status(500).json({
            error: 'Login gagal menyimpan audit.'
          });
        }

      });

    } catch (err) {

      console.error(
        'LOGIN ERROR:',
        err
      );

      return res.status(500).json({
        error: 'Login gagal.',
        detail:
          process.env.NODE_ENV === 'production'
            ? undefined
            : err.message
      });
    }
  });


  // =========================================================
  // CURRENT USER / SESSION
  // =========================================================

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


  // =========================================================
  // LOGOUT
  // =========================================================

  app.post(
    '/api/auth/logout',
    requireAuth,
    async (req, res) => {

      const user = req.session.user;

      /*
       * Audit dilakukan sebelum session dihancurkan,
       * karena writeAudit membutuhkan req.session.user.
       */
      try {

        await writeAudit(
          req,
          'LOGOUT',
          'AUTH',
          `User ${user.username} logout.`
        );

      } catch (auditError) {

        console.error(
          'Logout audit error:',
          auditError
        );

        /*
         * Logout tetap dilanjutkan meskipun audit gagal.
         */
      }


      /*
       * Hancurkan session di PostgreSQL.
       */
      req.session.destroy((err) => {

        if (err) {

          console.error(
            'Session destroy error:',
            err
          );

          return res.status(500).json({
            error: 'Logout gagal.'
          });
        }


        /*
         * Hapus cookie session dari browser.
         */
        res.clearCookie(
          'connect.sid',
          {
            httpOnly: true,
            sameSite: 'lax',
            secure:
              process.env.NODE_ENV === 'production',
            path: '/'
          }
        );


        return res.json({
          ok: true
        });

      });

    }
  );


  // =========================================================
  // USER MANAGEMENT
  // ADMIN ONLY
  // =========================================================

  app.get(
    '/api/users',
    requireRole('admin'),
    async (req, res) => {

      try {

        const result = await pool.query(
          `
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
          `
        );

        return res.json(
          result.rows
        );

      } catch (err) {

        console.error(
          'GET /api/users:',
          err
        );

        return res.status(500).json({
          error: 'Gagal mengambil data user.'
        });
      }

    }
  );


  // =========================================================
  // CREATE USER
  // ADMIN ONLY
  // =========================================================

  app.post(
    '/api/users',
    requireRole('admin'),
    async (req, res) => {

      try {

        const user = await createUser(
          req.body
        );

        await writeAudit(
          req,
          'CREATE',
          'USER',
          `Membuat user ${user.username} dengan role ${user.role}.`,
          user.id
        );

        return res.status(201).json(
          user
        );

      } catch (err) {

        console.error(
          'POST /api/users:',
          err
        );

        if (err.code === '23505') {

          return res.status(409).json({
            error: 'Username sudah digunakan.'
          });

        }

        return res.status(400).json({
          error: err.message
        });
      }

    }
  );


  // =========================================================
  // ACTIVATE / DEACTIVATE USER
  // ADMIN ONLY
  // =========================================================

  app.patch(
    '/api/users/:id/status',
    requireRole('admin'),
    async (req, res) => {

      try {

        const enabled =
          Boolean(req.body?.enabled);

        const result = await pool.query(
          `
          UPDATE users
          SET
            is_active = $1,
            updated_at = CURRENT_TIMESTAMP
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
            enabled,
            req.params.id
          ]
        );


        if (!result.rowCount) {

          return res.status(404).json({
            error: 'User tidak ditemukan.'
          });
        }


        const updatedUser =
          result.rows[0];


        await writeAudit(
          req,
          enabled
            ? 'ACTIVATE_USER'
            : 'DEACTIVATE_USER',
          'USER',
          `${
            enabled
              ? 'Mengaktifkan'
              : 'Menonaktifkan'
          } user ${updatedUser.username}.`,
          req.params.id
        );


        return res.json(
          updatedUser
        );

      } catch (err) {

        console.error(
          'PATCH /api/users/:id/status:',
          err
        );

        return res.status(500).json({
          error: 'Gagal mengubah status user.'
        });
      }

    }
  );


  // =========================================================
  // AUDIT LOG
  // ADMIN + AUDITOR
  // =========================================================

  app.get(
    '/api/audit-logs',
    requireRole('admin', 'auditor'),
    async (req, res) => {

      try {

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
          LIMIT 500
          `
        );

        return res.json(
          result.rows
        );

      } catch (err) {

        console.error(
          'GET /api/audit-logs:',
          err
        );

        return res.status(500).json({
          error: 'Gagal mengambil audit trail.'
        });
      }

    }
  );


  console.log(
    'Authentication routes aktif.'
  );

}


module.exports = registerAuthRoutes;