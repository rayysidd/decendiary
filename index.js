// index.js

// Load environment variables from .env file
require('dotenv').config(); 
// Initialize database connection and create tables
const db = require('./database.js'); 
const { encrypt, decrypt } = require('./encryption.js');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.static('public')); 

function getUser(userId, callback) {
  const sql = `SELECT * FROM users WHERE id = ?`;
  db.get(sql, [userId], (err, user) => {
    callback(err, user);
  });
}
// Middleware to parse incoming JSON requests
app.use(express.json()); 
// Middleware to authenticate JWT
function authenticateToken(req, res, next) {
  // Get the token from the Authorization header
  // The header format is "Bearer TOKEN"
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    // No token provided
    return res.sendStatus(401); // Unauthorized
  }

  // Verify the token
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      // Token is invalid or expired
      return res.sendStatus(403); // Forbidden
    }

    // Token is valid, attach the user payload to the request object
    req.user = user;
    next(); // Proceed to the next middleware or route handler
  });
}

const PORT = process.env.PORT || 3000;

// API ROUTES 

// POST /api/register - Register a new user
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Basic validation
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required.' });
    }

    // Hash the password using bcrypt
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Insert the new user into the database
    // Using a parameterized query to prevent SQL injection
    const sql = `INSERT INTO users (username, password_hash) VALUES (?, ?)`;
    db.run(sql, [username, passwordHash], function(err) {
      if (err) {
        // Check for unique constraint error (username already exists)
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(409).json({ message: 'Username already taken.' });
        }
        return res.status(500).json({ message: 'Database error', error: err.message });
      }
      res.status(201).json({ message: 'User created successfully', userId: this.lastID });
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// POST /api/login - Authenticate a user and return a JWT
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  const sql = `SELECT * FROM users WHERE username = ?`;
  db.get(sql, [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Database error', error: err.message });
    }
    // Check if user exists
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Compare provided password with the stored hash
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Passwords match, create a JWT
    const payload = { userId: user.id, username: user.username };
    const secret = process.env.JWT_SECRET;
    const options = { expiresIn: '1h' }; // Token expires in 1 hour

    const token = jwt.sign(payload, secret, options);

    res.json({ message: 'Logged in successfully', token: token });
  });
});

// A protected route - only accessible with a valid JWT
app.get('/api/profile', authenticateToken, (req, res) => {
  // Thanks to the middleware, req.user is available here
  res.json({ 
    message: `Welcome, ${req.user.username}!`, 
    userId: req.user.userId 
  });
});


// CREATE a new entry
app.post('/api/entries', authenticateToken, (req, res) => {
  const { entryText } = req.body;
  const userId = req.user.userId;

  if (!entryText) {
    return res.status(400).json({ message: 'Entry text is required.' });
  }

  getUser(userId, (err, user) => {
    if (err || !user) {
      return res.status(500).json({ message: 'Error retrieving user data.' });
    }
    const encryptedText = encrypt(entryText, user.password_hash);
    const createdAt = new Date().toISOString();
    const sql = `INSERT INTO entries (user_id, encrypted_text, created_at) VALUES (?, ?, ?)`;
    db.run(sql, [userId, encryptedText, createdAt], function (err) {
      if (err) return res.status(500).json({ message: 'Database error', error: err.message });
      res.status(201).json({ id: this.lastID, created_at: createdAt });
    });
  });
});

// READ all entries for a user
app.get('/api/entries', authenticateToken, (req, res) => {
  const userId = req.user.userId;
  getUser(userId, (err, user) => {
    if (err || !user) {
      return res.status(500).json({ message: 'Error retrieving user data.' });
    }
    const sql = `SELECT * FROM entries WHERE user_id = ? ORDER BY created_at DESC`;
    db.all(sql, [userId], (err, rows) => {
      if (err) return res.status(500).json({ message: 'Database error', error: err.message });
      const decryptedEntries = rows.map(entry => {
        try {
          return { ...entry, encrypted_text: decrypt(entry.encrypted_text, user.password_hash) };
        } catch (e) {
          return { ...entry, encrypted_text: '[Decryption Failed]' };
        }
      });
      res.json(decryptedEntries);
    });
  });
});

// UPDATE an entry
app.put('/api/entries/:id', authenticateToken, (req, res) => {
  const entryId = req.params.id;
  const { entryText } = req.body;
  const userId = req.user.userId;

  if (!entryText) {
    return res.status(400).json({ message: 'Entry text is required.' });
  }
  
  getUser(userId, (err, user) => {
    if (err || !user) {
      return res.status(500).json({ message: 'Error retrieving user data.' });
    }
    const encryptedText = encrypt(entryText, user.password_hash);
    // The "AND user_id = ?" is a crucial security check
    const sql = `UPDATE entries SET encrypted_text = ? WHERE id = ? AND user_id = ?`;
    db.run(sql, [encryptedText, entryId, userId], function (err) {
      if (err) return res.status(500).json({ message: 'Database error', error: err.message });
      if (this.changes === 0) return res.status(404).json({ message: 'Entry not found or user not authorized.' });
      res.json({ message: 'Entry updated successfully.' });
    });
  });
});

// DELETE an entry
app.delete('/api/entries/:id', authenticateToken, (req, res) => {
  const entryId = req.params.id;
  const userId = req.user.userId;
  
  // The "AND user_id = ?" is a crucial security check
  const sql = `DELETE FROM entries WHERE id = ? AND user_id = ?`;
  db.run(sql, [entryId, userId], function (err) {
    if (err) return res.status(500).json({ message: 'Database error', error: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'Entry not found or user not authorized.' });
    res.json({ message: 'Entry deleted successfully.' });
  });
});

app.listen(PORT, () => {
  console.log(`Server is listening on http://localhost:${PORT}`);
});