// index.js

// Load environment variables from .env file
require('dotenv').config();
// Initialize database connection and create tables
const db = require('./database.js');
db.initializeDB();

const { encrypt, decrypt } = require('./encryption.js');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
// Serve static files from the "public" directory
app.use(express.static('public'));
// Middleware to parse incoming JSON requests
app.use(express.json());

// Middleware to authenticate JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

const PORT = process.env.PORT || 3000;

// --- API ROUTES ---

// POST /api/register - Register a new user
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required.' });
    }
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const sql = `INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id`;
    const { rows } = await db.query(sql, [username, passwordHash]);
    
    res.status(201).json({ message: 'User created successfully', userId: rows[0].id });
  } catch (err) {
    // Check for unique constraint violation (Postgres error code '23505')
    if (err.code === '23505') {
      return res.status(409).json({ message: 'Username already taken.' });
    }
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// POST /api/login - Authenticate a user and return a JWT
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required.' });
    }
    const sql = `SELECT * FROM users WHERE username = $1`;
    const { rows } = await db.query(sql, [username]);
    const user = rows[0];

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const payload = { userId: user.id, username: user.username };
    const secret = process.env.JWT_SECRET;
    const token = jwt.sign(payload, secret, { expiresIn: '1h' });

    res.json({ message: 'Logged in successfully', token: token });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// A protected route - only accessible with a valid JWT
app.get('/api/profile', authenticateToken, (req, res) => {
  res.json({ message: `Welcome, ${req.user.username}!`, userId: req.user.userId });
});

// CREATE a new entry
app.post('/api/entries', authenticateToken, async (req, res) => {
  try {
    const { entryText } = req.body;
    const userId = req.user.userId;
    if (!entryText) {
      return res.status(400).json({ message: 'Entry text is required.' });
    }

    const userResult = await db.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
        return res.status(404).json({ message: 'User not found.' });
    }
    const user = userResult.rows[0];
    
    const encryptedText = encrypt(entryText, user.password_hash);
    const createdAt = new Date();

    const sql = `INSERT INTO entries (user_id, encrypted_text, created_at) VALUES ($1, $2, $3) RETURNING id`;
    const result = await db.query(sql, [userId, encryptedText, createdAt]);
    
    res.status(201).json({ id: result.rows[0].id, created_at: createdAt });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// READ all entries for a user
app.get('/api/entries', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userResult = await db.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
        return res.status(404).json({ message: 'User not found.' });
    }
    const user = userResult.rows[0];

    const sql = `SELECT * FROM entries WHERE user_id = $1 ORDER BY created_at DESC`;
    const { rows } = await db.query(sql, [userId]);
    
    const decryptedEntries = rows.map(entry => {
      try {
        return { ...entry, encrypted_text: decrypt(entry.encrypted_text, user.password_hash) };
      } catch (e) {
        return { ...entry, encrypted_text: '[Decryption Failed]' };
      }
    });
    res.json(decryptedEntries);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// UPDATE an entry
app.put('/api/entries/:id', authenticateToken, async (req, res) => {
  try {
    const entryId = req.params.id;
    const { entryText } = req.body;
    const userId = req.user.userId;

    if (!entryText) {
      return res.status(400).json({ message: 'Entry text is required.' });
    }
    
    const userResult = await db.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
        return res.status(404).json({ message: 'User not found.' });
    }
    const user = userResult.rows[0];

    const encryptedText = encrypt(entryText, user.password_hash);
    const sql = `UPDATE entries SET encrypted_text = $1 WHERE id = $2 AND user_id = $3`;
    const result = await db.query(sql, [encryptedText, entryId, userId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Entry not found or user not authorized.' });
    }
    res.json({ message: 'Entry updated successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// DELETE an entry
app.delete('/api/entries/:id', authenticateToken, async (req, res) => {
  try {
    const entryId = req.params.id;
    const userId = req.user.userId;
    
    const sql = `DELETE FROM entries WHERE id = $1 AND user_id = $2`;
    const result = await db.query(sql, [entryId, userId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Entry not found or user not authorized.' });
    }
    res.json({ message: 'Entry deleted successfully.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is listening on http://localhost:${PORT}`);
});