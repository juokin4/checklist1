const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const slowDown = require("express-slow-down");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

const db = new sqlite3.Database(path.join(__dirname, "data.db"));

db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email_verified INTEGER DEFAULT 0,
      email_verification_token TEXT,
      password_reset_token TEXT,
      password_reset_expires INTEGER,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    )`
  );
});

const runQuery = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });

const getQuery = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "10kb" }));
app.use(express.static(__dirname));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Çok fazla giriş denemesi. Lütfen sonra tekrar deneyin." }
});

const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Çok fazla istek. Lütfen sonra tekrar deneyin." }
});

const loginSlowdown = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 3,
  delayMs: (hits) => hits * 500
});

app.use("/api/auth", authLimiter);

const isValidEmail = (email) => /.+@.+\..+/.test(email);

const sendEmail = (type, email, token) => {
  const baseUrl = process.env.APP_BASE_URL || "http://localhost:3000";
  const linkMap = {
    verify: `${baseUrl}/?verifyToken=${token}`,
    reset: `${baseUrl}/?resetToken=${token}`
  };

  console.log(`\n[EMAIL:${type}] ${email}`);
  console.log(`Token: ${token}`);
  console.log(`Link: ${linkMap[type]}\n`);
};

app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "E-posta ve şifre zorunludur." });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: "Geçerli bir e-posta girin." });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Şifre en az 8 karakter olmalıdır." });
    }

    const existing = await getQuery("SELECT id FROM users WHERE email = ?", [email]);
    if (existing) {
      return res.status(409).json({ error: "Bu e-posta ile kayıt mevcut." });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const verificationToken = crypto.randomBytes(32).toString("hex");

    await runQuery(
      "INSERT INTO users (email, password_hash, email_verification_token) VALUES (?, ?, ?)",
      [email, passwordHash, verificationToken]
    );

    sendEmail("verify", email, verificationToken);

    return res.status(201).json({
      message: "Kayıt başarılı. E-posta doğrulaması gönderildi.",
      notice:
        process.env.NODE_ENV === "production"
          ? "E-posta doğrulama mailini kontrol edin."
          : `Doğrulama tokenı: ${verificationToken}`
    });
  } catch (error) {
    return res.status(500).json({ error: "Kayıt sırasında hata oluştu." });
  }
});

app.post("/api/auth/verify-email", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: "Token zorunludur." });
    }

    const user = await getQuery(
      "SELECT id FROM users WHERE email_verification_token = ?",
      [token]
    );
    if (!user) {
      return res.status(400).json({ error: "Token geçersiz." });
    }

    await runQuery(
      "UPDATE users SET email_verified = 1, email_verification_token = NULL WHERE id = ?",
      [user.id]
    );

    return res.json({ message: "E-posta doğrulandı." });
  } catch (error) {
    return res.status(500).json({ error: "Doğrulama sırasında hata oluştu." });
  }
});

app.post("/api/auth/login", loginLimiter, loginSlowdown, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "E-posta ve şifre zorunludur." });
    }

    const user = await getQuery(
      "SELECT id, email, password_hash, email_verified FROM users WHERE email = ?",
      [email]
    );

    if (!user) {
      return res.status(401).json({ error: "E-posta veya şifre hatalı." });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: "E-posta veya şifre hatalı." });
    }

    if (!user.email_verified) {
      return res
        .status(403)
        .json({ error: "E-posta doğrulanmadı. Lütfen e-postanı doğrula." });
    }

    const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "1h"
    });

    return res.json({ token, email: user.email });
  } catch (error) {
    return res.status(500).json({ error: "Giriş sırasında hata oluştu." });
  }
});

app.post("/api/auth/request-password-reset", resetLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: "E-posta zorunludur." });
    }

    const user = await getQuery("SELECT id FROM users WHERE email = ?", [email]);
    if (!user) {
      return res.json({ notice: "Eğer hesap varsa sıfırlama bilgisi gönderildi." });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;

    await runQuery(
      "UPDATE users SET password_reset_token = ?, password_reset_expires = ? WHERE id = ?",
      [resetToken, expiresAt, user.id]
    );

    sendEmail("reset", email, resetToken);

    return res.json({
      notice:
        process.env.NODE_ENV === "production"
          ? "E-posta gelen kutunu kontrol et."
          : `Sıfırlama tokenı: ${resetToken}`
    });
  } catch (error) {
    return res.status(500).json({ error: "İstek sırasında hata oluştu." });
  }
});

app.post("/api/auth/reset-password", resetLimiter, async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) {
      return res.status(400).json({ error: "Token ve yeni şifre zorunludur." });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Şifre en az 8 karakter olmalıdır." });
    }

    const user = await getQuery(
      "SELECT id, password_reset_expires FROM users WHERE password_reset_token = ?",
      [token]
    );
    if (!user) {
      return res.status(400).json({ error: "Token geçersiz." });
    }

    const now = Math.floor(Date.now() / 1000);
    if (user.password_reset_expires && user.password_reset_expires < now) {
      return res.status(400).json({ error: "Token süresi dolmuş." });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    await runQuery(
      "UPDATE users SET password_hash = ?, password_reset_token = NULL, password_reset_expires = NULL WHERE id = ?",
      [passwordHash, user.id]
    );

    return res.json({ message: "Şifre güncellendi." });
  } catch (error) {
    return res.status(500).json({ error: "Şifre güncellemede hata oluştu." });
  }
});

app.get("/api/auth/me", (req, res) => {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.replace("Bearer ", "");
  if (!token) {
    return res.status(401).json({ error: "Yetkisiz." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return res.json({ id: payload.sub, email: payload.email });
  } catch (error) {
    return res.status(401).json({ error: "Token geçersiz." });
  }
});

app.listen(PORT, () => {
  if (JWT_SECRET === "dev-secret-change-me") {
    console.warn("JWT_SECRET değişkenini üretimde güncelleyin.");
  }
  console.log(`Auth API çalışıyor: http://localhost:${PORT}`);
});
