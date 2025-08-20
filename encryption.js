// encryption.js

const crypto = require('crypto');

// We'll use AES-256-GCM for authenticated encryption
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // GCM standard
const SALT_LENGTH = 64; // PBKDF2 standard
const KEY_LENGTH = 32; // AES-256 key length
const TAG_LENGTH = 16; // GCM standard
const ITERATIONS = 100000; // PBKDF2 standard

// This is the "master key" for deriving user-specific keys.
// It should be the same as your JWT_SECRET for consistency.
const MASTER_KEY = process.env.JWT_SECRET;

/**
 * Derives a cryptographic key from the user's password hash.
 * @param {string} passwordHash - The user's stored password hash.
 * @param {Buffer} salt - A cryptographic salt.
 * @returns {Buffer} The derived key.
 */
function getKey(passwordHash, salt) {
  return crypto.pbkdf2Sync(MASTER_KEY, salt + passwordHash, ITERATIONS, KEY_LENGTH, 'sha512');
}

/**
 * Encrypts plain text.
 * @param {string} text - The text to encrypt.
 * @param {string} passwordHash - The user's password hash, used for key derivation.
 * @returns {string} The encrypted text, formatted for storage.
 */
function encrypt(text, passwordHash) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = getKey(passwordHash, salt);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Combine salt, iv, tag, and encrypted data into a single string
  return Buffer.concat([salt, iv, tag, encrypted]).toString('hex');
}

/**
 * Decrypts text.
 * @param {string} encryptedText - The encrypted text to decrypt.
 * @param {string} passwordHash - The user's password hash, used for key derivation.
 * @returns {string} The decrypted plain text.
 */
function decrypt(encryptedText, passwordHash) {
  const data = Buffer.from(encryptedText, 'hex');
  const salt = data.slice(0, SALT_LENGTH);
  const iv = data.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const tag = data.slice(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
  const encrypted = data.slice(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);

  const key = getKey(passwordHash, salt);
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  
  return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
}

module.exports = { encrypt, decrypt };