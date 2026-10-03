const app = require('./backend/server');

if (require.main === module) {
  app.startServer();
}

module.exports = app;
