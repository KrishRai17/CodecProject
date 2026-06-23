require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth.routes');
const noteRoutes = require('./routes/note.routes');

const app = express();
const PORT = process.env.PORT || 5000;

// Security headers and basic hardening
app.use(helmet());
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.use(express.static('public'));

app.get('/health', (_req, res) => {
  res.status(200).json({ ok: true, message: 'Secure Vault API is running.' });
});

app.get('/', (_req, res) => {
  res.sendFile(require('path').join(__dirname, '../public/index.html'));
});

app.use('/api/auth', authRoutes);
app.use('/api/notes', noteRoutes);

app.use((err, _req, res, _next) => {
  console.error(err.stack || err);
  const status = err.statusCode || 500;
  res.status(status).json({
    ok: false,
    message: err.message || 'Internal server error',
  });
});

connectDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Secure Vault API listening on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('Failed to start server:', error);
    process.exit(1);
  });
