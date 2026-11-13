
require("dotenv").config();

const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const db = new Database("shahdol.db");

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:false}));

if (!process.env.SESSION_SECRET ||
    !process.env.ADMIN_PASSWORD ||
    process.env.SESSION_SECRET === "change-this-to-a-long-random-secret") {
  throw new Error("Set secure SESSION_SECRET and ADMIN_PASSWORD in .env");
}

if (process.env.ADMIN_PASSWORD.length < 12) {
  throw new Error("Admin password must be at least 12 characters");
}

// Database setup
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  address TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  image TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);
`);

const admin = db.prepare(
  "SELECT id FROM admins WHERE username=?"
).get(process.env.ADMIN_USERNAME || "admin");

if (!admin) {
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  db.prepare(
    "INSERT INTO admins(username,password) VALUES(?,?)"
  ).run(process.env.ADMIN_USERNAME || "admin", hash);
}

// Session
app.use(session({
  name: "apna_shahdol_session",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 2 * 60 * 60 * 1000
  }
}));

app.use(express.static(path.join(__dirname, "public")));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const categories = [
  "शिक्षा", "स्कूल", "कॉलेज", "गाँव",
  "ग्राम पंचायत", "तहसील", "सड़क",
  "मंदिर", "पर्यटन", "कृषि", "अस्पताल",
  "सरकारी कार्यालय", "पुलिस", "व्यापार",
  "रोजगार", "अन्य"
];

function requireAdmin(req,res,next) {
  if (!req.session.adminId) {
    return res.status(401).json({error:"पहले एडमिन लॉगिन करें"});
  }
  next();
}

function clean(value, max=2000) {
  return typeof value === "string"
    ? value.trim().slice(0,max) : "";
}

function validImage(value) {
  if (!value) return true;
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol);
  } catch {
    return false;
  }
}

// Public: all entries
app.get("/api/entries", (req,res) => {
  const search = clean(req.query.search,100);
  const category = clean(req.query.category,100);

  let sql = "SELECT * FROM entries WHERE 1=1";
  const params = [];

  if (category) {
    sql += " AND category=?";
    params.push(category);
  }

  if (search) {
    sql += " AND (title LIKE ? OR description LIKE ? OR address LIKE ?)";
    const term = "%" + search + "%";
    params.push(term,term,term);
  }

  sql += " ORDER BY id DESC";

  res.json(db.prepare(sql).all(...params));
});

// Public: categories
app.get("/api/categories", (req,res) => {
  res.json(categories);
});

// Admin login
app.post("/api/login", loginLimiter, (req,res) => {
  const username = clean(req.body.username,100);
  const password = typeof req.body.password === "string"
    ? req.body.password : "";

  const user = db.prepare(
    "SELECT * FROM admins WHERE username=?"
  ).get(username);

  if (!user || !bcrypt.compareSync(password,user.password)) {
    return res.status(401).json({error:"गलत यूजरनेम या पासवर्ड"});
  }

  req.session.regenerate(err => {
    if (err) return res.status(500).json({error:"Login error"});

    req.session.adminId = user.id;
    res.json({success:true,message:"लॉगिन सफल"});
  });
});

// Check login
app.get("/api/me", requireAdmin, (req,res) => {
  res.json({loggedIn:true});
});

// Add information
app.post("/api/entries", requireAdmin, (req,res) => {
  const title = clean(req.body.title,150);
  const category = clean(req.body.category,100);
  const description = clean(req.body.description,2000);
  const address = clean(req.body.address,300);
  const phone = clean(req.body.phone,30);
  const image = clean(req.body.image,1000);

  if (!title || !description || !categories.includes(category)) {
    return res.status(400).json({error:"सभी जरूरी जानकारी सही भरें"});
  }

  if (!validImage(image)) {
    return res.status(400).json({error:"फोटो URL सही नहीं है"});
  }

  const result = db.prepare(`
    INSERT INTO entries(title,category,description,address,phone,image)
    VALUES(?,?,?,?,?,?)
  `).run(title,category,description,address,phone,image);

  res.json({success:true,id:result.lastInsertRowid});
});

// Edit information
app.put("/api/entries/:id", requireAdmin, (req,res) => {
  const id = Number(req.params.id);
  const title = clean(req.body.title,150);
  const category = clean(req.body.category,100);
  const description = clean(req.body.description,2000);
  const address = clean(req.body.address,300);
  const phone = clean(req.body.phone,30);
  const image = clean(req.body.image,1000);

  if (!Number.isInteger(id) || id < 1 ||
      !title || !description || !categories.includes(category)) {
    return res.status(400).json({error:"जानकारी सही भरें"});
  }

  if (!validImage(image)) {
    return res.status(400).json({error:"फोटो URL सही नहीं है"});
  }

  const result = db.prepare(`
    UPDATE entries SET
    title=?,category=?,description=?,address=?,phone=?,image=?
    WHERE id=?
  `).run(title,category,description,address,phone,image,id);

  if (!result.changes) {
    return res.status(404).json({error:"जानकारी नहीं मिली"});
  }

  res.json({success:true});
});

// Delete information
app.delete("/api/entries/:id", requireAdmin, (req,res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({error:"गलत ID"});
  }

  const result = db.prepare(
    "DELETE FROM entries WHERE id=?"
  ).run(id);

  if (!result.changes) {
    return res.status(404).json({error:"जानकारी नहीं मिली"});
  }

  res.json({success:true});
});

// Logout
app.post("/api/logout", requireAdmin, (req,res) => {
  req.session.destroy(() => {
    res.clearCookie("apna_shahdol_session");
    res.json({success:true});
  });
});

app.get("/api/stats", requireAdmin, (req,res) => {
  const total = db.prepare(
    "SELECT COUNT(*) AS total FROM entries"
  ).get().total;

  const result = db.prepare(`
    SELECT category, COUNT(*) AS total
    FROM entries GROUP BY category
  `).all();

  res.json({total, categories:result});
});

app.get("/admin", (req,res) => {
  res.sendFile(path.join(__dirname,"public","admin.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Apna Shahdol running on port " + PORT);
});
