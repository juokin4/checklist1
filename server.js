const path = require("path");
const fs = require("fs");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

const dataDir = path.join(__dirname, "data");
const dbPath = path.join(dataDir, "app.db");

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
const db = new Database(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    status TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )
`);

app.use(express.json());
app.use(express.static(__dirname));

function issueToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: "7d"
  });
}

function isValidEmail(email) {
  return typeof email === "string" && email.includes("@") && email.length <= 320;
}

function isValidPassword(password) {
  return typeof password === "string" && password.length >= 8;
}

app.post("/api/register", (req, res) => {
  const { email, password } = req.body || {};

  if (!isValidEmail(email) || !isValidPassword(password)) {
    return res.status(400).json({ error: "Geçerli e-posta ve en az 8 karakter şifre gerekli." });
  }

  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) {
    return res.status(409).json({ error: "Bu e-posta zaten kayıtlı." });
  }

  const passwordHash = bcrypt.hashSync(password, 12);
  const stmt = db.prepare("INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)");
  const result = stmt.run(email, passwordHash, new Date().toISOString());
  db.prepare("INSERT INTO subscriptions (user_id, status, updated_at) VALUES (?, ?, ?)")
    .run(result.lastInsertRowid, "trial", new Date().toISOString());
  const token = issueToken({ id: result.lastInsertRowid, email });

  return res.json({ token, email });
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body || {};

  if (!isValidEmail(email) || typeof password !== "string") {
    return res.status(400).json({ error: "Geçersiz giriş bilgisi." });
  }

  const user = db.prepare("SELECT id, email, password_hash FROM users WHERE email = ?").get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "E-posta veya şifre hatalı." });
  }

  const token = issueToken(user);
  return res.json({ token, email: user.email });
});

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ error: "Oturum bulunamadı." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch (error) {
    return res.status(401).json({ error: "Oturum geçersiz." });
  }
}

app.get("/api/session", requireAuth, (req, res) => {
  return res.json({ email: req.user.email });
});

app.get("/api/subscription", requireAuth, (req, res) => {
  const subscription = db
    .prepare("SELECT status, updated_at FROM subscriptions WHERE user_id = ?")
    .get(req.user.id);

  if (!subscription) {
    return res.status(404).json({ error: "Abonelik bilgisi bulunamadı." });
  }

  return res.json(subscription);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
