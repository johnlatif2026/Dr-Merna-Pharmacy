const express = require('express');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Initialize Firestore from FIREBASE_CONFIG JSON string in .env
if (!process.env.FIREBASE_CONFIG) {
  console.error('FIREBASE_CONFIG is not set in .env (put service account JSON).');
  process.exit(1);
}
let serviceAccount;
try {
  serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
} catch (err) {
  console.error('Failed to parse FIREBASE_CONFIG JSON:', err.message);
  process.exit(1);
}
const db = admin.firestore();

// Ensure uploads dir
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// Multer storage (save to uploads)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '';
    const name = `${Date.now()}-${Math.random().toString(36).slice(2,8)}${ext}`;
    cb(null, name);
  }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// JWT & CSRF settings
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '8h';
const csrfProtection = csurf({ cookie: true });

// Simple admin credential check (from .env)
// Note: currently compares plain text; recommended: use bcrypt + stored hash
function checkAdminCredentials(name, pass) {
  const ADMIN_NAME = process.env.ADMIN_NAME;
  const ADMIN_PASS = process.env.ADMIN_PASS;
  if (!ADMIN_NAME || !ADMIN_PASS) return false;
  return name === ADMIN_NAME && pass === ADMIN_PASS;
}

// Verify JWT middleware
function verifyJWT(req, res, next) {
  const token = req.cookies && req.cookies.token;
  if (!token) return res.redirect('/login'); // redirect for browser attempts
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.admin = payload;
    return next();
  } catch (e) {
    return res.clearCookie('token').redirect('/login');
  }
}

// Nodemailer setup (optional)
let transporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: (process.env.SMTP_SECURE === 'true') || false,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}

// Serve uploads (product images)
app.use('/uploads', express.static(uploadsDir));

// Serve root pages (not from public folder)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login', (req, res) => {
  // if already logged in, redirect to dashboard
  const token = req.cookies && req.cookies.token;
  if (token) {
    try { jwt.verify(token, JWT_SECRET); return res.redirect('/dashboard'); } catch(e) { /* invalid */ }
  }
  return res.sendFile(path.join(__dirname, 'login.html'));
});
// Protect dashboard route with JWT (server-side)
app.get('/dashboard', verifyJWT, (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));

// CSRF token endpoint (sets cookie and returns token for SPA)
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// LOGIN (admin) -> expects CSRF token header 'x-csrf-token'
app.post('/api/login', csrfProtection, (req, res) => {
  const { name, password } = req.body;
  if (!checkAdminCredentials(name, password)) return res.status(401).json({ error: 'Invalid credentials' });
  const payload = { name };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax' }); // Secure flag should be set when using HTTPS
  res.json({ ok: true });
});

// LOGOUT
app.post('/api/logout', verifyJWT, (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

/* -----------------------
   PUBLIC: submit order
   - POST /api/orders  => accepts customer order (public)
     saves to Firestore 'orders' collection and notifies Telegram + SMTP
   - GET /api/orders (list) IS NOT PROVIDED - can't read all orders publicly
------------------------*/
app.post('/api/orders', async (req, res) => {
  try {
    const { name, phone, note } = req.body;
    if (!name || !phone) return res.status(400).json({ error: 'name and phone required' });
    const docRef = await db.collection('orders').add({
      name, phone, note: note || '', status: 'new', createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Telegram notification
    if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID) {
      const text = `🆕 طلب جديد\nالاسم: ${name}\nالهاتف: ${phone}\nالطلب: ${note || '-'}\nID: ${docRef.id}`;
      const tgUrl = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`;
      try {
        await axios.post(tgUrl, { chat_id: process.env.TELEGRAM_CHAT_ID, text });
      } catch (e) {
        console.warn('Telegram notify failed:', e.message);
      }
    }

    // SMTP notify if configured
    if (transporter && process.env.NOTIFY_EMAIL_TO) {
      try {
        await transporter.sendMail({
          from: process.env.SMTP_FROM || process.env.SMTP_USER,
          to: process.env.NOTIFY_EMAIL_TO,
          subject: `طلب جديد - ${process.env.SITE_NAME || 'صيدلية'}`,
          text: `طلب جديد\nالاسم: ${name}\nالهاتف: ${phone}\nالطلب: ${note || '-'}\nID: ${docRef.id}`
        });
      } catch (e) {
        console.warn('SMTP notify failed:', e.message);
      }
    }

    return res.json({ ok: true, id: docRef.id });
  } catch (err) {
    console.error('Order save error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

/* -----------------------
   ADMIN PROTECTED APIs (JWT + CSRF)
   - /api/admin/orders [GET]  -> list orders for admin
   - /api/products [GET public] -> list products (public)
   - /api/products [POST] -> add product (admin)
   - /api/products/:id [PUT, DELETE] -> modify/delete (admin)
   - /api/admin/send-email [POST] -> send via SMTP (admin)
------------------------*/

// Admin: list orders (protected)
app.get('/api/admin/orders', verifyJWT, csrfProtection, async (req, res) => {
  try {
    const snap = await db.collection('orders').orderBy('createdAt', 'desc').get();
    const items = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    return res.json({ items });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// Public: list products
app.get('/api/products', async (req, res) => {
  try {
    const snap = await db.collection('products').orderBy('createdAt','desc').get();
    const items = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    return res.json({ items });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// Admin: add product (with image upload) - protected
app.post('/api/products', verifyJWT, csrfProtection, upload.single('image'), async (req, res) => {
  try {
    const { name, price } = req.body;
    if (!name || !price) return res.status(400).json({ error: 'name & price required' });
    let imageUrl = null;
    if (req.file) imageUrl = `/uploads/${req.file.filename}`;
    const docRef = await db.collection('products').add({
      name, price, imageUrl, outOfStock: false, createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    return res.json({ ok: true, id: docRef.id });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// Admin: update product
app.put('/api/products/:id', verifyJWT, csrfProtection, upload.single('image'), async (req, res) => {
  try {
    const id = req.params.id;
    const { name, price } = req.body;
    const updateData = {};
    if (name) updateData.name = name;
    if (price) updateData.price = price;
    if (req.file) updateData.imageUrl = `/uploads/${req.file.filename}`;
    await db.collection('products').doc(id).update(updateData);
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// Admin: delete product
app.delete('/api/products/:id', verifyJWT, csrfProtection, async (req, res) => {
  try {
    const id = req.params.id;
    await db.collection('products').doc(id).delete();
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// Admin: mark out of stock
app.post('/api/products/:id/out-of-stock', verifyJWT, csrfProtection, async (req, res) => {
  try {
    const id = req.params.id;
    await db.collection('products').doc(id).update({ outOfStock: true });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// Admin: send email via SMTP
app.post('/api/admin/send-email', verifyJWT, csrfProtection, async (req, res) => {
  if (!transporter) return res.status(500).json({ error: 'SMTP not configured' });
  const { to, subject, text } = req.body;
  try {
    await transporter.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to, subject, text });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// Fallback 404
app.use((req, res) => res.status(404).send('Not found'));

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
