## ✅ Mot Site — Full Stack (No Terminal) **BUONG CODE** per file

> **Assumptions (para tumakbo agad):**
> - Backend runs on **Node.js** (localhost or any host).
> - Frontend is static files (pwede sa GitHub Pages), pero **kailangan mong i-set** `API Base` sa Settings papunta sa hosted backend URL.
> - File Manager is **per-user workspace**: `backend/storage/userFiles/<username>/...`
> - Features included: **Auth, Dashboard, File Manager (folders, upload, create file, edit text+MD preview, unzip), Bank (passkey), Market (publish/buy/download + tags + filters), Leaderboard, Notifications, Profile, Settings, Admin Panel, Changelog w/ progress bars**.

---

## 1) Folder Structure (exact)
```
frontend/
├── index.html
├── login.html
├── register.html
├── pages/
│   ├── file-manager.html
│   ├── bank.html
│   ├── leaderboard.html
│   ├── public-files.html
│   ├── profile.html
│   ├── settings.html
│   ├── admin.html
│   ├── changelog.html
│   └── notifications.html
├── css/
│   └── style.css
└── js/
    ├── main.js
    ├── auth.js
    ├── fileManager.js
    ├── bank.js
    ├── market.js
    ├── profile.js
    ├── settings.js
    ├── admin.js
    ├── leaderboard.js
    ├── changelog.js
    └── notifications.js
backend/
├── server.js
├── package.json
├── routes/
│   ├── auth.js
│   ├── files.js
│   ├── bank.js
│   ├── admin.js
│   ├── market.js
│   ├── leaderboard.js
│   ├── changelog.js
│   └── notifications.js
├── data/
│   ├── users.json
│   ├── publicFiles.json
│   ├── badges.json
│   ├── notifications.json
│   ├── changelog.json
│   └── transactions.json
├── storage/
│   └── userFiles/
└── utils/
    ├── authMiddleware.js
    └── fileUtils.js
```

---

# ✅ BACKEND (complete)

## backend/package.json
```json
{
  "name": "mot-site-backend",
  "version": "1.0.0",
  "main": "server.js",
  "type": "commonjs",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "archiver": "^7.0.1",
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "express": "^4.19.2",
    "jsonwebtoken": "^9.0.2",
    "multer": "^1.4.5-lts.1",
    "unzipper": "^0.10.14"
  }
}
```

## backend/server.js
```js
const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");

const authRoutes = require("./routes/auth");
const filesRoutes = require("./routes/files");
const bankRoutes = require("./routes/bank");
const adminRoutes = require("./routes/admin");
const marketRoutes = require("./routes/market");
const leaderboardRoutes = require("./routes/leaderboard");
const changelogRoutes = require("./routes/changelog");
const notificationsRoutes = require("./routes/notifications");

const app = express();

app.use(cors());
app.use(express.json({ limit: "10mb" }));

// Ensure required folders
fs.mkdirSync(path.join(__dirname, "storage", "userFiles"), { recursive: true });
fs.mkdirSync(path.join(__dirname, "data"), { recursive: true });

// Health
app.get("/api/health", (req, res) => res.json({ ok: true, name: "Mot Site API" }));

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/files", filesRoutes);
app.use("/api/bank", bankRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/market", marketRoutes);
app.use("/api/leaderboard", leaderboardRoutes);
app.use("/api/changelog", changelogRoutes);
app.use("/api/notifications", notificationsRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Mot Site backend running on :${PORT}`));
```

## backend/utils/authMiddleware.js
```js
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "mot-site-dev-secret-change-me";

function authRequired(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function adminRequired(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "No user" });
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });
  return next();
}

module.exports = { authRequired, adminRequired, JWT_SECRET };
```

## backend/utils/fileUtils.js
```js
const fs = require("fs");
const path = require("path");

function safeJoin(base, target) {
  const targetPath = path
    .normalize(String(target || ""))
    .replace(/^(\.\.(\/|\\|$))+/, "")
    .replace(/^([/\\])+/, "");
  const resolved = path.join(base, targetPath);
  const realBase = path.resolve(base);
  const realResolved = path.resolve(resolved);
  if (!realResolved.startsWith(realBase)) throw new Error("Invalid path");
  return realResolved;
}

function readJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJson(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function listDir(dirAbs) {
  const items = fs.readdirSync(dirAbs, { withFileTypes: true });
  return items.map(d => ({
    name: d.name,
    type: d.isDirectory() ? "dir" : "file"
  }));
}

module.exports = { safeJoin, readJson, writeJson, listDir };
```

---

## backend/data/users.json
```json
[]
```

## backend/data/publicFiles.json
```json
[]
```

## backend/data/notifications.json
```json
[]
```

## backend/data/transactions.json
```json
[]
```

## backend/data/badges.json
```json
{
  "allBadges": [
    "beginner","pro","programmer","web-dev","fullstack","debugger","speed-coder","night-owl","early-bird","helper",
    "markdown-master","css-wizard","js-ninja","node-runner","git-hero","api-builder","ui-designer","bug-hunter","optimizer","architect",
    "changelog-keeper","market-maker","trader","collector","top-10","top-1","rich","saver","spender","banker",
    "uploader","publisher","tagger","organizer","cleaner","reviewer","tester","mentor","learner","explorer",
    "creator","builder","shipper","maintainer","refactorer","documenter","supporter","contributor","innovator","pioneer",
    "badge-51","badge-52","badge-53","badge-54","badge-55","badge-56","badge-57","badge-58","badge-59","badge-60",
    "badge-61","badge-62","badge-63","badge-64","badge-65","badge-66","badge-67","badge-68","badge-69","badge-70",
    "badge-71","badge-72","badge-73","badge-74","badge-75","badge-76","badge-77","badge-78","badge-79","badge-80",
    "badge-81","badge-82","badge-83","badge-84","badge-85","badge-86","badge-87","badge-88","badge-89","badge-90",
    "badge-91","badge-92","badge-93","badge-94","badge-95","badge-96","badge-97","badge-98","badge-99","badge-100"
  ]
}
```

## backend/data/changelog.json
```json
{
  "updates": [
    {
      "date": "2025-12-28",
      "title": "Mot Site released",
      "details": "Full stack: Auth, File Manager (folders/upload/create/edit/markdown/unzip), Bank, Market, Leaderboard, Notifications, Admin, Changelog."
    }
  ],
  "nextFeatures": [
    { "name": "UI polish + animations", "percent": 70 },
    { "name": "More file preview types", "percent": 40 },
    { "name": "Better marketplace pages", "percent": 55 }
  ],
  "progress": { "js": 90, "css": 60, "html": 100 }
}
```

---

# backend/routes/auth.js
```js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");

const { JWT_SECRET, authRequired } = require("../utils/authMiddleware");
const { readJson, writeJson } = require("../utils/fileUtils");

const router = express.Router();
const usersPath = path.join(__dirname, "..", "data", "users.json");
const storageRoot = path.join(__dirname, "..", "storage", "userFiles");
const badgesPath = path.join(__dirname, "..", "data", "badges.json");
const notifPath = path.join(__dirname, "..", "data", "notifications.json");

function addNotif(userId, message) {
  const notifs = readJson(notifPath, []);
  notifs.unshift({ id: "n-" + Date.now(), userId, message, createdAt: new Date().toISOString(), read: false });
  writeJson(notifPath, notifs);
}

function publicUser(u) {
  return {
    id: u.id,
    username: u.username,
    role: u.role,
    money: u.money,
    bankBalance: u.bankBalance,
    badges: u.badges || [],
    createdAt: u.createdAt
  };
}

router.post("/register", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });
  if (!/^[a-zA-Z0-9_-]{3,20}$/.test(username)) return res.status(400).json({ error: "Username invalid" });
  if (String(password).length < 6) return res.status(400).json({ error: "Password too short" });

  const users = readJson(usersPath, []);
  if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: "Username exists" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const id = `u-${Date.now()}`;

  const allBadges = readJson(badgesPath, { allBadges: [] }).allBadges || [];
  const starterBadges = ["beginner"].filter(b => allBadges.includes(b) || b === "beginner");

  const user = {
    id,
    username,
    passwordHash,
    role: "user",
    money: 100,
    bankBalance: 0,
    bankPasskeyHash: "",
    badges: starterBadges,
    createdAt: new Date().toISOString()
  };

  users.push(user);
  writeJson(usersPath, users);

  fs.mkdirSync(path.join(storageRoot, username), { recursive: true });
  addNotif(user.id, "Welcome to Mot Site! You received 100 starter money.");

  res.json({ ok: true });
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  const users = readJson(usersPath, []);
  const user = users.find(u => u.username.toLowerCase() === String(username || "").toLowerCase());
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password || "", user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: publicUser(user) });
});

router.get("/me", authRequired, (req, res) => {
  const users = readJson(usersPath, []);
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user: publicUser(user) });
});

router.post("/bank-passkey", authRequired, async (req, res) => {
  const { passkey } = req.body || {};
  if (!/^\d{4}$/.test(String(passkey || ""))) return res.status(400).json({ error: "Passkey must be 4 digits" });

  const users = readJson(usersPath, []);
  const idx = users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: "User not found" });

  users[idx].bankPasskeyHash = await bcrypt.hash(String(passkey), 10);
  writeJson(usersPath, users);
  addNotif(req.user.id, "Bank passkey updated.");
  res.json({ ok: true });
});

module.exports = router;
```

---

# backend/routes/files.js  ✅ File manager complete (folders + create + upload + edit + unzip)
```js
const express = require("express");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const unzipper = require("unzipper");
const archiver = require("archiver");

const { authRequired } = require("../utils/authMiddleware");
const { safeJoin, listDir } = require("../utils/fileUtils");

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });
const storageRoot = path.join(__dirname, "..", "storage", "userFiles");

function userRoot(username) {
  return path.join(storageRoot, username);
}

function isTextExt(p) {
  const ext = path.extname(p).toLowerCase();
  return [".txt", ".md", ".js", ".html", ".css", ".json", ".yml", ".yaml"].includes(ext);
}

// LIST directory
router.get("/list", authRequired, (req, res) => {
  const rel = req.query.path || "";
  const base = userRoot(req.user.username);
  fs.mkdirSync(base, { recursive: true });

  const dirAbs = safeJoin(base, rel);
  if (!fs.existsSync(dirAbs)) return res.status(404).json({ error: "Not found" });
  if (!fs.statSync(dirAbs).isDirectory()) return res.status(400).json({ error: "Not a directory" });

  const items = listDir(dirAbs).sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : a.type === "dir" ? -1 : 1));
  res.json({ path: rel, items });
});

// MKDIR
router.post("/mkdir", authRequired, (req, res) => {
  const { path: rel } = req.body || {};
  if (!rel) return res.status(400).json({ error: "Missing path" });
  const base = userRoot(req.user.username);
  const dirAbs = safeJoin(base, rel);
  fs.mkdirSync(dirAbs, { recursive: true });
  res.json({ ok: true });
});

// CREATE EMPTY FILE
router.post("/create-file", authRequired, (req, res) => {
  const { path: relFile } = req.body || {};
  if (!relFile) return res.status(400).json({ error: "Missing path" });

  const base = userRoot(req.user.username);
  const fileAbs = safeJoin(base, relFile);
  fs.mkdirSync(path.dirname(fileAbs), { recursive: true });

  if (fs.existsSync(fileAbs)) return res.status(409).json({ error: "File already exists" });
  fs.writeFileSync(fileAbs, "", "utf8");
  res.json({ ok: true });
});

// UPLOAD file into directory
router.post("/upload", authRequired, upload.single("file"), (req, res) => {
  const rel = req.query.path || "";
  const base = userRoot(req.user.username);
  fs.mkdirSync(base, { recursive: true });

  if (!req.file) return res.status(400).json({ error: "No file" });

  const targetDir = safeJoin(base, rel);
  fs.mkdirSync(targetDir, { recursive: true });

  const filename = path.basename(req.file.originalname);
  const fileAbs = safeJoin(targetDir, filename);

  fs.writeFileSync(fileAbs, req.file.buffer);
  res.json({ ok: true, name: filename });
});

// READ text file for editor
router.get("/read", authRequired, (req, res) => {
  const relFile = req.query.file;
  if (!relFile) return res.status(400).json({ error: "Missing file" });

  const base = userRoot(req.user.username);
  const fileAbs = safeJoin(base, relFile);

  if (!fs.existsSync(fileAbs)) return res.status(404).json({ error: "Not found" });
  if (!fs.statSync(fileAbs).isFile()) return res.status(400).json({ error: "Not a file" });

  if (!isTextExt(fileAbs)) return res.status(400).json({ error: "Not a supported text file" });

  const stat = fs.statSync(fileAbs);
  if (stat.size > 2 * 1024 * 1024) return res.status(400).json({ error: "File too large for editor" });

  const content = fs.readFileSync(fileAbs, "utf8");
  res.json({ file: relFile, content });
});

// WRITE text file from editor
router.post("/write", authRequired, (req, res) => {
  const { file, content } = req.body || {};
  if (!file) return res.status(400).json({ error: "Missing file" });

  const base = userRoot(req.user.username);
  const fileAbs = safeJoin(base, file);

  if (!isTextExt(fileAbs)) return res.status(400).json({ error: "Not a supported text file" });
  if (String(content || "").length > 2 * 1024 * 1024) return res.status(400).json({ error: "Too large" });

  fs.mkdirSync(path.dirname(fileAbs), { recursive: true });
  fs.writeFileSync(fileAbs, String(content || ""), "utf8");

  res.json({ ok: true });
});

// DELETE file or empty dir (no recursive delete)
router.post("/delete", authRequired, (req, res) => {
  const { path: rel } = req.body || {};
  if (!rel) return res.status(400).json({ error: "Missing path" });

  const base = userRoot(req.user.username);
  const abs = safeJoin(base, rel);

  if (!fs.existsSync(abs)) return res.status(404).json({ error: "Not found" });

  const stat = fs.statSync(abs);
  if (stat.isDirectory()) {
    const items = fs.readdirSync(abs);
    if (items.length) return res.status(400).json({ error: "Folder not empty" });
    fs.rmdirSync(abs);
  } else {
    fs.unlinkSync(abs);
  }
  res.json({ ok: true });
});

// UNZIP a .zip file into a target folder
router.post("/unzip", authRequired, (req, res) => {
  const { file, to } = req.body || {};
  if (!file) return res.status(400).json({ error: "Missing file" });

  const base = userRoot(req.user.username);
  const zipAbs = safeJoin(base, file);
  if (!fs.existsSync(zipAbs)) return res.status(404).json({ error: "Not found" });
  if (path.extname(zipAbs).toLowerCase() !== ".zip") return res.status(400).json({ error: "Only .zip supported" });

  const targetDir = safeJoin(base, to || path.dirname(file));
  fs.mkdirSync(targetDir, { recursive: true });

  fs.createReadStream(zipAbs)
    .pipe(unzipper.Extract({ path: targetDir }))
    .on("close", () => res.json({ ok: true }))
    .on("error", () => res.status(500).json({ error: "Unzip failed" }));
});

// ZIP a folder or file for download
router.get("/zip", authRequired, (req, res) => {
  const rel = req.query.path || "";
  const base = userRoot(req.user.username);
  const abs = safeJoin(base, rel);
  if (!fs.existsSync(abs)) return res.status(404).json({ error: "Not found" });

  res.setHeader("Content-Type", "application/zip");
  res.setHeader("Content-Disposition", `attachment; filename="mot-${Date.now()}.zip"`);

  const archive = archiver("zip", { zlib: { level: 9 } });
  archive.on("error", () => res.status(500).end());
  archive.pipe(res);

  const stat = fs.statSync(abs);
  if (stat.isDirectory()) archive.directory(abs, false);
  else archive.file(abs, { name: path.basename(abs) });

  archive.finalize();
});

module.exports = router;
```

---

# backend/routes/bank.js
```js
const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const { authRequired } = require("../utils/authMiddleware");
const { readJson, writeJson } = require("../utils/fileUtils");

const router = express.Router();
const usersPath = path.join(__dirname, "..", "data", "users.json");
const txPath = path.join(__dirname, "..", "data", "transactions.json");
const notifPath = path.join(__dirname, "..", "data", "notifications.json");

function addNotif(userId, message) {
  const notifs = readJson(notifPath, []);
  notifs.unshift({ id: "n-" + Date.now(), userId, message, createdAt: new Date().toISOString(), read: false });
  writeJson(notifPath, notifs);
}

function addTx(tx) {
  const txs = readJson(txPath, []);
  txs.unshift({ id: "t-" + Date.now(), ...tx, createdAt: new Date().toISOString() });
  writeJson(txPath, txs);
}

async function verifyPasskey(user, passkey) {
  if (!user.bankPasskeyHash) return false;
  return bcrypt.compare(String(passkey || ""), user.bankPasskeyHash);
}

router.get("/status", authRequired, (req, res) => {
  const users = readJson(usersPath, []);
  const u = users.find(x => x.id === req.user.id);
  if (!u) return res.status(404).json({ error: "User not found" });
  res.json({ money: u.money, bankBalance: u.bankBalance, hasPasskey: !!u.bankPasskeyHash });
});

router.post("/deposit", authRequired, async (req, res) => {
  const { amount, passkey } = req.body || {};
  const amt = Number(amount);
  if (!Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "Invalid amount" });

  const users = readJson(usersPath, []);
  const idx = users.findIndex(x => x.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: "User not found" });

  const u = users[idx];
  if (!(await verifyPasskey(u, passkey))) return res.status(403).json({ error: "Invalid passkey" });
  if (u.money < amt) return res.status(400).json({ error: "Not enough money" });

  u.money -= amt;
  u.bankBalance += amt;
  users[idx] = u;
  writeJson(usersPath, users);

  addTx({ type: "deposit", fromUserId: u.id, toUserId: u.id, amount: amt });
  addNotif(u.id, `Deposited ${amt} to bank.`);
  res.json({ ok: true, money: u.money, bankBalance: u.bankBalance });
});

router.post("/withdraw", authRequired, async (req, res) => {
  const { amount, passkey } = req.body || {};
  const amt = Number(amount);
  if (!Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "Invalid amount" });

  const users = readJson(usersPath, []);
  const idx = users.findIndex(x => x.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: "User not found" });

  const u = users[idx];
  if (!(await verifyPasskey(u, passkey))) return res.status(403).json({ error: "Invalid passkey" });
  if (u.bankBalance < amt) return res.status(400).json({ error: "Not enough bank balance" });

  u.bankBalance -= amt;
  u.money += amt;
  users[idx] = u;
  writeJson(usersPath, users);

  addTx({ type: "withdraw", fromUserId: u.id, toUserId: u.id, amount: amt });
  addNotif(u.id, `Withdrew ${amt} from bank.`);
  res.json({ ok: true, money: u.money, bankBalance: u.bankBalance });
});

router.post("/send", authRequired, async (req, res) => {
  const { toUsername, amount, passkey } = req.body || {};
  const amt = Number(amount);
  if (!toUsername) return res.status(400).json({ error: "Missing toUsername" });
  if (!Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "Invalid amount" });

  const users = readJson(usersPath, []);
  const fromIdx = users.findIndex(x => x.id === req.user.id);
  const toIdx = users.findIndex(x => x.username.toLowerCase() === String(toUsername).toLowerCase());
  if (fromIdx === -1) return res.status(404).json({ error: "User not found" });
  if (toIdx === -1) return res.status(404).json({ error: "Receiver not found" });
  if (fromIdx === toIdx) return res.status(400).json({ error: "Cannot send to self" });

  const from = users[fromIdx];
  const to = users[toIdx];

  if (!(await verifyPasskey(from, passkey))) return res.status(403).json({ error: "Invalid passkey" });
  if (from.bankBalance < amt) return res.status(400).json({ error: "Not enough bank balance" });

  from.bankBalance -= amt;
  to.bankBalance += amt;

  users[fromIdx] = from;
  users[toIdx] = to;
  writeJson(usersPath, users);

  addTx({ type: "send", fromUserId: from.id, toUserId: to.id, amount: amt });
  addNotif(from.id, `Sent ${amt} to ${to.username}.`);
  addNotif(to.id, `Received ${amt} from ${from.username}.`);

  res.json({ ok: true });
});

router.get("/transactions", authRequired, (req, res) => {
  const txs = readJson(txPath, []);
  const mine = txs.filter(t => t.fromUserId === req.user.id || t.toUserId === req.user.id).slice(0, 100);
  res.json({ items: mine });
});

module.exports = router;
```

---

# backend/routes/market.js
```js
const express = require("express");
const path = require("path");
const fs = require("fs");

const { authRequired } = require("../utils/authMiddleware");
const { readJson, writeJson, safeJoin } = require("../utils/fileUtils");

const router = express.Router();

const usersPath = path.join(__dirname, "..", "data", "users.json");
const publicFilesPath = path.join(__dirname, "..", "data", "publicFiles.json");
const notifPath = path.join(__dirname, "..", "data", "notifications.json");
const storageRoot = path.join(__dirname, "..", "storage", "userFiles");

function addNotif(userId, message) {
  const notifs = readJson(notifPath, []);
  notifs.unshift({ id: "n-" + Date.now(), userId, message, createdAt: new Date().toISOString(), read: false });
  writeJson(notifPath, notifs);
}

router.get("/public-files", authRequired, (req, res) => {
  const { sort = "low", tag = "", free = "" } = req.query;
  let items = readJson(publicFilesPath, []);

  if (tag) items = items.filter(x => (x.tags || []).map(t => t.toLowerCase()).includes(String(tag).toLowerCase()));
  if (free === "true") items = items.filter(x => Number(x.price) === 0);

  if (sort === "high") items.sort((a, b) => Number(b.price) - Number(a.price));
  else items.sort((a, b) => Number(a.price) - Number(b.price));

  res.json({ items });
});

router.post("/publish", authRequired, (req, res) => {
  const { file, title, price = 0, tags = [] } = req.body || {};
  if (!file) return res.status(400).json({ error: "Missing file" });

  const base = path.join(storageRoot, req.user.username);
  const fileAbs = safeJoin(base, file);
  if (!fs.existsSync(fileAbs)) return res.status(404).json({ error: "File not found" });

  const stat = fs.statSync(fileAbs);
  if (!stat.isFile()) return res.status(400).json({ error: "Publish file only (zip recommended)" });

  const items = readJson(publicFilesPath, []);
  const rec = {
    id: "pf-" + Date.now(),
    ownerId: req.user.id,
    ownerUsername: req.user.username,
    filePath: file,
    title: title || path.basename(file),
    price: Math.max(0, Number(price) || 0),
    tags: Array.isArray(tags) ? tags.slice(0, 10).map(t => String(t).slice(0, 20)) : [],
    createdAt: new Date().toISOString(),
    downloads: 0,
    buyers: []
  };

  items.unshift(rec);
  writeJson(publicFilesPath, items);

  addNotif(req.user.id, `Published "${rec.title}" (${rec.price === 0 ? "FREE" : rec.price}).`);
  res.json({ ok: true, item: rec });
});

router.post("/buy", authRequired, (req, res) => {
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: "Missing id" });

  const users = readJson(usersPath, []);
  const buyerIdx = users.findIndex(u => u.id === req.user.id);
  if (buyerIdx === -1) return res.status(404).json({ error: "Buyer not found" });

  const items = readJson(publicFilesPath, []);
  const idx = items.findIndex(x => x.id === id);
  if (idx === -1) return res.status(404).json({ error: "Item not found" });

  const item = items[idx];
  if (item.ownerId === req.user.id) return res.status(400).json({ error: "Cannot buy your own file" });

  item.buyers = item.buyers || [];
  if (item.price === 0) {
    if (!item.buyers.includes(req.user.id)) item.buyers.push(req.user.id);
    items[idx] = item;
    writeJson(publicFilesPath, items);
    addNotif(req.user.id, `Claimed FREE file "${item.title}".`);
    return res.json({ ok: true, free: true });
  }

  if (item.buyers.includes(req.user.id)) return res.json({ ok: true, alreadyOwned: true });

  const price = Number(item.price) || 0;
  const sellerIdx = users.findIndex(u => u.id === item.ownerId);
  if (sellerIdx === -1) return res.status(404).json({ error: "Seller not found" });

  const buyer = users[buyerIdx];
  const seller = users[sellerIdx];

  if (buyer.money < price) return res.status(400).json({ error: "Not enough money" });

  buyer.money -= price;
  seller.money += price;

  item.buyers.push(req.user.id);
  item.downloads = (item.downloads || 0) + 1;

  users[buyerIdx] = buyer;
  users[sellerIdx] = seller;
  items[idx] = item;

  writeJson(usersPath, users);
  writeJson(publicFilesPath, items);

  addNotif(buyer.id, `Bought "${item.title}" for ${price}.`);
  addNotif(seller.id, `Your file "${item.title}" was bought by ${buyer.username} (+${price}).`);

  res.json({ ok: true });
});

router.get("/download", authRequired, (req, res) => {
  const id = req.query.id;
  const items = readJson(publicFilesPath, []);
  const item = items.find(x => x.id === id);
  if (!item) return res.status(404).json({ error: "Item not found" });

  const allowed =
    item.price === 0 ||
    (item.buyers || []).includes(req.user.id) ||
    item.ownerId === req.user.id;

  if (!allowed) return res.status(403).json({ error: "Not purchased" });

  const ownerBase = path.join(storageRoot, item.ownerUsername);
  const fileAbs = safeJoin(ownerBase, item.filePath);
  if (!fs.existsSync(fileAbs)) return res.status(404).json({ error: "File missing" });

  res.download(fileAbs, path.basename(fileAbs));
});

module.exports = router;
```

---

# backend/routes/leaderboard.js
```js
const express = require("express");
const path = require("path");
const { authRequired } = require("../utils/authMiddleware");
const { readJson } = require("../utils/fileUtils");

const router = express.Router();
const usersPath = path.join(__dirname, "..", "data", "users.json");

router.get("/", authRequired, (req, res) => {
  const users = readJson(usersPath, []);
  const top = users
    .map(u => ({
      username: u.username,
      money: u.money,
      bankBalance: u.bankBalance,
      total: (u.money || 0) + (u.bankBalance || 0),
      badges: u.badges || []
    }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 50);

  res.json({ items: top });
});

module.exports = router;
```

---

# backend/routes/notifications.js
```js
const express = require("express");
const path = require("path");
const { authRequired } = require("../utils/authMiddleware");
const { readJson, writeJson } = require("../utils/fileUtils");

const router = express.Router();
const notifPath = path.join(__dirname, "..", "data", "notifications.json");

router.get("/", authRequired, (req, res) => {
  const notifs = readJson(notifPath, []);
  const mine = notifs.filter(n => n.userId === req.user.id).slice(0, 100);
  res.json({ items: mine });
});

router.post("/mark-read", authRequired, (req, res) => {
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: "Missing id" });

  const notifs = readJson(notifPath, []);
  const idx = notifs.findIndex(n => n.id === id && n.userId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: "Not found" });

  notifs[idx].read = true;
  writeJson(notifPath, notifs);
  res.json({ ok: true });
});

router.post("/mark-all-read", authRequired, (req, res) => {
  const notifs = readJson(notifPath, []);
  let changed = 0;
  for (const n of notifs) {
    if (n.userId === req.user.id && !n.read) {
      n.read = true;
      changed++;
    }
  }
  writeJson(notifPath, notifs);
  res.json({ ok: true, changed });
});

module.exports = router;
```

---

# backend/routes/changelog.js
```js
const express = require("express");
const path = require("path");
const { authRequired } = require("../utils/authMiddleware");
const { readJson, writeJson } = require("../utils/fileUtils");

const router = express.Router();
const changelogPath = path.join(__dirname, "..", "data", "changelog.json");

router.get("/", authRequired, (req, res) => {
  const data = readJson(changelogPath, { updates: [], nextFeatures: [], progress: { js: 0, css: 0, html: 0 } });
  res.json(data);
});

router.post("/add-update", authRequired, (req, res) => {
  // admin only via admin route; keep simple: block non-admin here
  if (req.user.role !== "admin") return res.status(403).json({ error: "Admin only" });

  const { date, title, details } = req.body || {};
  if (!date || !title) return res.status(400).json({ error: "Missing fields" });

  const data = readJson(changelogPath, { updates: [], nextFeatures: [], progress: { js: 0, css: 0, html: 0 } });
  data.updates.unshift({ date, title, details: details || "" });
  writeJson(changelogPath, data);
  res.json({ ok: true });
});

module.exports = router;
```

---

# backend/routes/admin.js
```js
const express = require("express");
const path = require("path");
const { authRequired, adminRequired } = require("../utils/authMiddleware");
const { readJson, writeJson } = require("../utils/fileUtils");

const router = express.Router();
const usersPath = path.join(__dirname, "..", "data", "users.json");
const notifPath = path.join(__dirname, "..", "data", "notifications.json");

router.get("/users", authRequired, adminRequired, (req, res) => {
  const users = readJson(usersPath, []);
  res.json({
    items: users.map(u => ({
      id: u.id,
      username: u.username,
      role: u.role,
      money: u.money,
      bankBalance: u.bankBalance,
      badges: u.badges || [],
      createdAt: u.createdAt
    }))
  });
});

router.post("/promote", authRequired, adminRequired, (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: "Missing username" });

  const users = readJson(usersPath, []);
  const idx = users.findIndex(u => u.username.toLowerCase() === String(username).toLowerCase());
  if (idx === -1) return res.status(404).json({ error: "Not found" });

  users[idx].role = "admin";
  writeJson(usersPath, users);
  res.json({ ok: true });
});

router.post("/notify", authRequired, adminRequired, (req, res) => {
  const { message } = req.body || {};
  if (!message) return res.status(400).json({ error: "Missing message" });

  const notifs = readJson(notifPath, []);
  const users = readJson(usersPath, []);
  const now = new Date().toISOString();

  users.forEach(u => {
    notifs.unshift({
      id: "n-" + Date.now() + "-" + u.id,
      userId: u.id,
      message,
      createdAt: now,
      read: false
    });
  });

  writeJson(notifPath, notifs);
  res.json({ ok: true });
});

module.exports = router;
```

---

# ✅ FRONTEND (complete)

## frontend/css/style.css
```css
:root{
  --bg:#0b1220;
  --card:#101a33;
  --muted:#7f8bb3;
  --text:#e8eeff;
  --accent:#6ea8fe;
  --accent2:#7cfcbd;
  --danger:#ff5c7a;
  --border:rgba(255,255,255,.08);
  --shadow: 0 12px 30px rgba(0,0,0,.35);
  --radius: 16px;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  --sans: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
}

*{box-sizing:border-box}
body{
  margin:0;
  font-family:var(--sans);
  color:var(--text);
  background: radial-gradient(1200px 600px at 20% -10%, rgba(110,168,254,.35), transparent 60%),
              radial-gradient(900px 500px at 110% 10%, rgba(124,252,189,.18), transparent 55%),
              var(--bg);
}
a{color:inherit;text-decoration:none}
.container{max-width:1100px;margin:0 auto;padding:20px}
.nav{
  position:sticky; top:0; z-index:50;
  backdrop-filter: blur(10px);
  background: rgba(11,18,32,.65);
  border-bottom:1px solid var(--border);
}
.nav .container{display:flex;align-items:center;justify-content:space-between;gap:12px}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;letter-spacing:.3px}
.brand .dot{width:10px;height:10px;border-radius:99px;background:linear-gradient(135deg,var(--accent),var(--accent2))}
.navlinks{display:flex;gap:10px;flex-wrap:wrap}
.pill{
  padding:10px 12px;border-radius:999px;border:1px solid var(--border);
  background:rgba(255,255,255,.02);
}
.pill:hover{border-color:rgba(110,168,254,.4)}
.btn{
  border:0; cursor:pointer;
  background: linear-gradient(135deg, rgba(110,168,254,.95), rgba(124,252,189,.85));
  color:#07101f;
  padding:10px 14px;border-radius:12px;
  box-shadow: var(--shadow);
  font-weight:700;
}
.btn.secondary{
  background: transparent;
  color: var(--text);
  border:1px solid var(--border);
  box-shadow:none;
}
.btn.danger{
  background: transparent;
  color: var(--danger);
  border:1px solid rgba(255,92,122,.35);
  box-shadow:none;
}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}
.card{
  background: rgba(16,26,51,.72);
  border:1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding:16px;
}
h1,h2,h3{margin:0 0 10px 0}
.muted{color:var(--muted)}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
.input{
  width:100%;
  padding:12px 12px;
  border-radius: 12px;
  border:1px solid var(--border);
  background: rgba(255,255,255,.03);
  color: var(--text);
  outline:none;
}
.input:focus{border-color:rgba(110,168,254,.55)}
.table{width:100%;border-collapse:collapse}
.table th,.table td{padding:10px;border-bottom:1px solid var(--border);text-align:left}
.badge{
  display:inline-flex;gap:6px;align-items:center;
  padding:6px 10px;border-radius:999px;
  border:1px solid var(--border);
  background:rgba(255,255,255,.03);
  font-size:12px;
}
.kbd{font-family:var(--mono);font-size:12px;color:var(--muted)}
hr{border:0;border-top:1px solid var(--border);margin:14px 0}
.progress{
  height:12px;border-radius:999px;border:1px solid var(--border);
  background:rgba(255,255,255,.04);
  overflow:hidden;
}
.progress > div{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2))}
.toast{
  position:fixed;right:16px;bottom:16px;max-width:340px;
  background:rgba(16,26,51,.9);border:1px solid var(--border);
  padding:12px;border-radius:14px;box-shadow:var(--shadow);display:none;
}
.codebox{
  font-family: var(--mono);
  font-size: 13px;
  background: rgba(0,0,0,.25);
  border:1px solid var(--border);
  border-radius: 14px;
  padding: 12px;
  white-space: pre-wrap;
}
.breadcrumbs a{color:rgba(110,168,254,.95)}
.breadcrumbs span{color:var(--muted)}
@media (max-width: 820px){
  .grid{gap:10px}
}
```

---

## frontend/js/main.js
```js
const API_BASE = localStorage.getItem("MOT_API") || "http://localhost:3000/api";

function setToast(msg){
  const t = document.getElementById("toast");
  if (!t) return alert(msg);
  t.textContent = msg;
  t.style.display = "block";
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(()=> t.style.display="none", 2400);
}

function getToken(){ return localStorage.getItem("mot_token"); }
function setToken(t){ localStorage.setItem("mot_token", t); }

async function api(path, opts={}){
  const headers = opts.headers || {};
  headers["Content-Type"] = headers["Content-Type"] || "application/json";
  const token = getToken();
  if (token) headers["Authorization"] = "Bearer " + token;

  const res = await fetch(API_BASE + path, { ...opts, headers });
  const data = await res.json().catch(()=> ({}));
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

function requireAuth(){
  if (!getToken()) location.href = "../login.html";
}

async function loadMe(){
  const out = await api("/auth/me", { method:"GET" });
  localStorage.setItem("mot_user", JSON.stringify(out.user));
  return out.user;
}

function navHtml(){
  const u = JSON.parse(localStorage.getItem("mot_user") || "null");
  const adminLink = u?.role === "admin" ? `<a class="pill" href="admin.html">Admin</a>` : "";
  return `
  <div class="nav">
    <div class="container">
      <div class="brand"><span class="dot"></span><span>Mot Site</span></div>
      <div class="navlinks">
        <a class="pill" href="../index.html">Dashboard</a>
        <a class="pill" href="file-manager.html">File Manager</a>
        <a class="pill" href="bank.html">Bank</a>
        <a class="pill" href="public-files.html">Public Files</a>
        <a class="pill" href="leaderboard.html">Leaderboard</a>
        <a class="pill" href="notifications.html">Notifications</a>
        <a class="pill" href="profile.html">Profile</a>
        <a class="pill" href="settings.html">Settings</a>
        <a class="pill" href="changelog.html">Changelog</a>
        ${adminLink}
      </div>
      <div class="row">
        <span class="badge">${u ? u.username : "Guest"}</span>
        ${u ? `<button class="btn secondary" id="logoutBtn">Logout</button>` : `<a class="btn secondary" href="../login.html">Login</a>`}
      </div>
    </div>
  </div>`;
}

function mountNav(){
  const el = document.getElementById("nav");
  if (!el) return;
  el.innerHTML = navHtml();
  const btn = document.getElementById("logoutBtn");
  if (btn) btn.onclick = ()=>{
    localStorage.removeItem("mot_token");
    localStorage.removeItem("mot_user");
    location.href = "../login.html";
  };
}

function escapeHtml(s){
  return String(s||"")
    .replaceAll("&","&amp;").replaceAll("<","&lt;")
    .replaceAll(">","&gt;").replaceAll('"',"&quot;");
}
```

---

## frontend/js/auth.js
```js
async function doLogin(e){
  e.preventDefault();
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  try{
    const out = await api("/auth/login", { method:"POST", body: JSON.stringify({ username, password }) });
    setToken(out.token);
    localStorage.setItem("mot_user", JSON.stringify(out.user));
    location.href = "index.html";
  }catch(err){
    setToast(err.message);
  }
}

async function doRegister(e){
  e.preventDefault();
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  try{
    await api("/auth/register", { method:"POST", body: JSON.stringify({ username, password }) });
    setToast("Registered! Please login.");
    setTimeout(()=> location.href="login.html", 800);
  }catch(err){
    setToast(err.message);
  }
}
```

---

## frontend/index.html
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mot Site • Dashboard</title>
  <link rel="stylesheet" href="css/style.css"/>
</head>
<body>
  <div id="nav"></div>
  <div class="container">
    <div class="grid">
      <div class="card" style="grid-column: span 12;">
        <h1>Dashboard</h1>
        <p class="muted">Welcome sa Mot Site. File Manager + Bank + Public Files Marketplace.</p>
      </div>

      <div class="card" style="grid-column: span 6;">
        <h3>Account</h3>
        <div id="meBox" class="muted">Loading...</div>
        <hr/>
        <div class="row">
          <a class="btn secondary" href="pages/file-manager.html">Open File Manager</a>
          <a class="btn secondary" href="pages/public-files.html">Open Market</a>
        </div>
      </div>

      <div class="card" style="grid-column: span 6;">
        <h3>Quick Stats</h3>
        <div id="stats" class="codebox"></div>
      </div>
    </div>
  </div>

  <div id="toast" class="toast"></div>
  <script src="js/main.js"></script>
  <script>
    requireAuth();
    (async ()=>{
      const u = await loadMe();
      mountNav();
      document.getElementById("meBox").innerHTML = `
        <div class="row">
          <span class="badge">Role: ${u.role}</span>
          <span class="badge">Money: ${u.money}</span>
          <span class="badge">Bank: ${u.bankBalance}</span>
        </div>
        <div style="margin-top:10px" class="muted">Badges: ${(u.badges||[]).slice(0,8).join(", ")}${(u.badges||[]).length>8?" ...":""}</div>
      `;
      document.getElementById("stats").textContent =
`Tips:
- Set passkey sa Settings para ma-enable deposit/send.
- Upload ZIP, then Unzip in File Manager.
- Publish .zip sa Public Files then set price/tags.`;
    })().catch(e=>setToast(e.message));
  </script>
</body>
</html>
```

---

## frontend/login.html
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mot Site • Login</title>
  <link rel="stylesheet" href="css/style.css"/>
</head>
<body>
  <div class="container">
    <div class="card" style="max-width:520px;margin:40px auto;">
      <h1>Login</h1>
      <p class="muted">Sign in to Mot Site.</p>
      <form onsubmit="doLogin(event)">
        <label class="muted">Username</label>
        <input class="input" id="username" autocomplete="username"/>
        <div style="height:10px"></div>
        <label class="muted">Password</label>
        <input class="input" id="password" type="password" autocomplete="current-password"/>
        <div style="height:14px"></div>
        <button class="btn" type="submit">Login</button>
        <a class="btn secondary" href="register.html" style="margin-left:10px">Register</a>
      </form>
    </div>
  </div>

  <div id="toast" class="toast"></div>
  <script src="js/main.js"></script>
  <script src="js/auth.js"></script>
</body>
</html>
```

## frontend/register.html
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mot Site • Register</title>
  <link rel="stylesheet" href="css/style.css"/>
</head>
<body>
  <div class="container">
    <div class="card" style="max-width:520px;margin:40px auto;">
      <h1>Register</h1>
      <p class="muted">New account starts with <b>100 money</b>.</p>
      <form onsubmit="doRegister(event)">
        <label class="muted">Username (3–20, letters/numbers/_-)</label>
        <input class="input" id="username" autocomplete="username"/>
        <div style="height:10px"></div>
        <label class="muted">Password (min 6)</label>
        <input class="input" id="password" type="password" autocomplete="new-password"/>
        <div style="height:14px"></div>
        <button class="btn" type="submit">Create</button>
        <a class="btn secondary" href="login.html" style="margin-left:10px">Back to Login</a>
      </form>
    </div>
  </div>

  <div id="toast" class="toast"></div>
  <script src="js/main.js"></script>
  <script src="js/auth.js"></script>
</body>
</html>
```

---

# Frontend Pages

## frontend/pages/file-manager.html  ✅ folder navigation like `workspace/folder/`
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mot Site • File Manager</title>
  <link rel="stylesheet" href="../css/style.css"/>
</head>
<body>
  <div id="nav"></div>
  <div class="container">
    <div class="grid">
      <div class="card" style="grid-column: span 12;">
        <h2>File Manager</h2>
        <div class="muted">Workspace path: <span id="crumbs" class="breadcrumbs"></span></div>
      </div>

      <div class="card" style="grid-column: span 5;">
        <div class="row">
          <input class="input" id="path" placeholder="workspace path (auto)" disabled />
          <button class="btn secondary" onclick="goUp()">Up</button>
          <button class="btn secondary" onclick="refresh()">Refresh</button>
        </div>

        <hr/>

        <div class="row">
          <input type="file" id="uploader"/>
          <button class="btn" onclick="uploadFile()">Upload</button>
        </div>

        <div style="height:10px"></div>

        <div class="row">
          <button class="btn secondary" onclick="makeDir()">Create Folder</button>
          <button class="btn secondary" onclick="createFile()">Create File</button>
        </div>

        <hr/>

        <div id="list" class="codebox" style="min-height:260px"></div>
      </div>

      <div class="card" style="grid-column: span 7;">
        <h3>Editor</h3>
        <div class="muted">Supports: txt, md, js, html, css, json, yml/yaml</div>
        <div style="height:10px"></div>
        <div class="row">
          <input class="input" id="editFile" placeholder="click a file from list to open" />
          <button class="btn secondary" onclick="openFile()">Open</button>
          <button class="btn" onclick="saveFile()">Save</button>
          <button class="btn secondary" onclick="togglePreview()">MD Preview</button>
        </div>
        <div style="height:10px"></div>
        <textarea class="input" id="editor" style="min-height:280px;font-family:var(--mono)"></textarea>
        <div style="height:10px"></div>
        <div id="preview" class="card" style="display:none;padding:14px"></div>

        <hr/>
        <h3>ZIP Tools</h3>
        <div class="row">
          <input class="input" id="zipFile" placeholder="zip file path (e.g. my.zip)"/>
          <button class="btn secondary" onclick="unzip()">Unzip Here</button>
        </div>
      </div>
    </div>
  </div>

  <div id="toast" class="toast"></div>
  <script src="../js/main.js"></script>
  <script src="../js/fileManager.js"></script>
  <script>
    requireAuth();
    (async()=>{ await loadMe(); mountNav(); initFM(); })().catch(e=>setToast(e.message));
  </script>
</body>
</html>
```

## frontend/js/fileManager.js
```js
let FM_CWD = ""; // relative path inside user workspace

function setCwd(p){
  FM_CWD = (p || "").replace(/^\/+/, "").replace(/\/+$/, "");
  document.getElementById("path").value = "workspace/" + (FM_CWD ? (FM_CWD + "/") : "");
  renderCrumbs();
}

function renderCrumbs(){
  const el = document.getElementById("crumbs");
  const parts = FM_CWD ? FM_CWD.split("/") : [];
  let html = `<a href="#" onclick="setCwd(''); refresh(); return false;">workspace</a>`;
  let acc = "";
  for (const part of parts){
    acc = acc ? (acc + "/" + part) : part;
    html += ` <span>/</span> <a href="#" onclick="setCwd('${acc}'); refresh(); return false;">${escapeHtml(part)}</a>`;
  }
  el.innerHTML = html;
}

function goUp(){
  if (!FM_CWD) return;
  const parts = FM_CWD.split("/");
  parts.pop();
  setCwd(parts.join("/"));
  refresh();
}

async function initFM(){
  setCwd("");
  await refresh();
}

async function refresh(){
  const out = await api("/files/list?path=" + encodeURIComponent(FM_CWD), { method:"GET" });

  const list = document.getElementById("list");
  list.innerHTML = "";

  if (!out.items.length){
    list.textContent = "(empty)";
    return;
  }

  // clickable entries
  const lines = out.items.map(it => {
    if (it.type === "dir"){
      return `📁 <a href="#" onclick="openDir('${escapeHtml(it.name)}');return false;">${escapeHtml(it.name)}/</a>`;
    } else {
      return `📄 <a href="#" onclick="pickFile('${escapeHtml(it.name)}');return false;">${escapeHtml(it.name)}</a>`;
    }
  }).join("\n");
  list.innerHTML = lines;
}

function openDir(name){
  const next = FM_CWD ? (FM_CWD + "/" + name) : name;
  setCwd(next);
  refresh();
}

function pickFile(name){
  const full = FM_CWD ? (FM_CWD + "/" + name) : name;
  document.getElementById("editFile").value = full;
  document.getElementById("zipFile").value = full;
  openFile().catch(e=>setToast(e.message));
}

async function uploadFile(){
  const f = document.getElementById("uploader").files[0];
  if (!f) return setToast("Choose a file first");

  const token = getToken();
  const fd = new FormData();
  fd.append("file", f);

  const res = await fetch(API_BASE + "/files/upload?path=" + encodeURIComponent(FM_CWD), {
    method:"POST",
    headers: token ? { "Authorization": "Bearer " + token } : {},
    body: fd
  });
  const data = await res.json().catch(()=> ({}));
  if (!res.ok) return setToast(data.error || "Upload failed");

  setToast("Uploaded: " + data.name);
  await refresh();
}

async function makeDir(){
  const name = prompt("Folder name?");
  if (!name) return;
  const rel = FM_CWD ? (FM_CWD + "/" + name) : name;
  await api("/files/mkdir", { method:"POST", body: JSON.stringify({ path: rel }) });
  setToast("Folder created");
  await refresh();
}

async function createFile(){
  const name = prompt("File name? (e.g. note.txt, index.html, README.md)");
  if (!name) return;
  const rel = FM_CWD ? (FM_CWD + "/" + name) : name;
  await api("/files/create-file", { method:"POST", body: JSON.stringify({ path: rel }) });
  setToast("File created");
  document.getElementById("editFile").value = rel;
  await openFile();
  await refresh();
}

async function openFile(){
  const file = document.getElementById("editFile").value.trim();
  if (!file) return setToast("Select a file");
  const out = await api("/files/read?file=" + encodeURIComponent(file), { method:"GET" });
  document.getElementById("editor").value = out.content;
  renderPreviewIfMd();
  setToast("Opened");
}

async function saveFile(){
  const file = document.getElementById("editFile").value.trim();
  const content = document.getElementById("editor").value;
  if (!file) return setToast("Select a file");
  await api("/files/write", { method:"POST", body: JSON.stringify({ file, content }) });
  renderPreviewIfMd();
  setToast("Saved");
  await refresh();
}

function simpleMarkdown(md){
  const esc = (s)=> s.replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");
  let html = esc(md);
  html = html.replace(/^### (.*)$/gm, "<h3>$1</h3>");
  html = html.replace(/^## (.*)$/gm, "<h2>$1</h2>");
  html = html.replace(/^# (.*)$/gm, "<h1>$1</h1>");
  html = html.replace(/\*\*(.*?)\*\*/g, "<b>$1</b>");
  html = html.replace(/\*(.*?)\*/g, "<i>$1</i>");
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  html = html.replace(/\n/g, "<br/>");
  return html;
}

function renderPreviewIfMd(){
  const file = document.getElementById("editFile").value.trim().toLowerCase();
  const prev = document.getElementById("preview");
  if (!file.endsWith(".md")) return;
  prev.innerHTML = simpleMarkdown(document.getElementById("editor").value);
}

function togglePreview(){
  const prev = document.getElementById("preview");
  const show = prev.style.display === "none";
  prev.style.display = show ? "block" : "none";
  if (show) renderPreviewIfMd();
}

async function unzip(){
  const file = document.getElementById("zipFile").value.trim();
  if (!file) return setToast("Enter zip file path");
  await api("/files/unzip", { method:"POST", body: JSON.stringify({ file, to: FM_CWD }) });
  setToast("Unzipped");
  await refresh();
}
```

---

## frontend/pages/bank.html
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mot Site • Bank</title>
  <link rel="stylesheet" href="../css/style.css"/>
</head>
<body>
  <div id="nav"></div>
  <div class="container">
    <div class="grid">
      <div class="card" style="grid-column: span 12;">
        <h2>Bank</h2>
        <p class="muted">Deposit/Withdraw/Send using your 4-digit passkey.</p>
        <div id="status" class="muted">Loading...</div>
      </div>

      <div class="card" style="grid-column: span 4;">
        <h3>Deposit</h3>
        <input class="input" id="dAmt" placeholder="amount" />
        <div style="height:10px"></div>
        <input class="input" id="dKey" placeholder="passkey (4 digits)" />
        <div style="height:10px"></div>
        <button class="btn" onclick="deposit()">Deposit</button>
      </div>

      <div class="card" style="grid-column: span 4;">
        <h3>Withdraw</h3>
        <input class="input" id="wAmt" placeholder="amount" />
        <div style="height:10px"></div>
        <input class="input" id="wKey" placeholder="passkey (4 digits)" />
        <div style="height:10px"></div>
        <button class="btn" onclick="withdraw()">Withdraw</button>
      </div>

      <div class="card" style="grid-column: span 4;">
        <h3>Send</h3>
        <input class="input" id="toUser" placeholder="to username" />
        <div style="height:10px"></div>
        <input class="input" id="sAmt" placeholder="amount" />
        <div style="height:10px"></div>
        <input class="input" id="sKey" placeholder="passkey (4 digits)" />
        <div style="height:10px"></div>
        <button class="btn" onclick="sendMoney()">Send</button>
      </div>

      <div class="card" style="grid-column: span 12;">
        <h3>Transactions</h3>
        <div id="tx" class="codebox"></div>
      </div>
    </div>
  </div>

  <div id="toast" class="toast"></div>
  <script src="../js/main.js"></script>
  <script src="../js/bank.js"></script>
  <script>
    requireAuth();
    (async()=>{ await loadMe(); mountNav(); await refreshBank(); })().catch(e=>setToast(e.message));
  </script>
</body>
</html>
```

## frontend/js/bank.js
```js
async function refreshBank(){
  const s = await api("/bank/status", { method:"GET" });
  document.getElementById("status").innerHTML =
    `<div class="row">
      <span class="badge">Money: ${s.money}</span>
      <span class="badge">Bank: ${s.bankBalance}</span>
      <span class="badge">Passkey: ${s.hasPasskey ? "SET" : "NOT SET (go Settings)"}</span>
    </div>`;
  const t = await api("/bank/transactions", { method:"GET" });
  document.getElementById("tx").textContent =
    (t.items||[]).map(x => `${x.createdAt} • ${x.type} • ${x.amount}`).join("\n") || "(none)";
}

async function deposit(){
  try{
    await api("/bank/deposit", { method:"POST", body: JSON.stringify({
      amount: document.getElementById("dAmt").value,
      passkey: document.getElementById("dKey").value
    })});
    setToast("Deposited");
    await refreshBank();
  }catch(e){ setToast(e.message); }
}

async function withdraw(){
  try{
    await api("/bank/withdraw", { method:"POST", body: JSON.stringify({
      amount: document.getElementById("wAmt").value,
      passkey: document.getElementById("wKey").value
    })});
    setToast("Withdrew");
    await refreshBank();
  }catch(e){ setToast(e.message); }
}

async function sendMoney(){
  try{
    await api("/bank/send", { method:"POST", body: JSON.stringify({
      toUsername: document.getElementById("toUser").value,
      amount: document.getElementById("sAmt").value,
      passkey: document.getElementById("sKey").value
    })});
    setToast("Sent");
    await refreshBank();
  }catch(e){ setToast(e.message); }
}
```

---

## frontend/pages/public-files.html
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mot Site • Public Files</title>
  <link rel="stylesheet" href="../css/style.css"/>
</head>
<body>
  <div id="nav"></div>
  <div class="container">
    <div class="grid">
      <div class="card" style="grid-column: span 12;">
        <h2>Public Files</h2>
        <p class="muted">Publish your zip/files with tags + price. Buy and download others.</p>
      </div>

      <div class="card" style="grid-column: span 5;">
        <h3>Publish</h3>
        <input class="input" id="pubFile" placeholder="your file path (recommend .zip)"/>
        <div style="height:10px"></div>
        <input class="input" id="pubTitle" placeholder="title"/>
        <div style="height:10px"></div>
        <input class="input" id="pubPrice" placeholder="price (0 = free)"/>
        <div style="height:10px"></div>
        <input class="input" id="pubTags" placeholder="tags comma-separated (e.g. css, template)"/>
        <div style="height:10px"></div>
        <button class="btn" onclick="publish()">Publish</button>
      </div>

      <div class="card" style="grid-column: span 7;">
        <div class="row">
          <select class="input" id="sort">
            <option value="low">Low → High</option>
            <option value="high">High → Low</option>
          </select>
          <input class="input" id="tag" placeholder="filter tag"/>
          <label class="badge"><input type="checkbox" id="free"/> free only</label>
          <button class="btn secondary" onclick="loadMarket()">Apply</button>
        </div>
        <div style="height:10px"></div>
        <table class="table">
          <thead>
            <tr><th>Title</th><th>Owner</th><th>Price</th><th>Tags</th><th>Actions</th></tr>
          </thead>
          <tbody id="marketRows"></tbody>
        </table>
      </div>
    </div>
  </div>

  <div id="toast" class="toast"></div>
  <script src="../js/main.js"></script>
  <script src="../js/market.js"></script>
  <script>
    requireAuth();
    (async()=>{ await loadMe(); mountNav(); await loadMarket(); })().catch(e=>setToast(e.message));
  </script>
</body>
</html>
```

## frontend/js/market.js
```js
async function loadMarket(){
  const sort = document.getElementById("sort").value;
  const tag = document.getElementById("tag").value.trim();
  const free = document.getElementById("free").checked;

  const q = new URLSearchParams({ sort, tag, free: String(free) });
  const out = await api("/market/public-files?" + q.toString(), { method:"GET" });

  const tbody = document.getElementById("marketRows");
  tbody.innerHTML = "";
  out.items.forEach(it=>{
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(it.title)}</td>
      <td>${escapeHtml(it.ownerUsername)}</td>
      <td>${Number(it.price) === 0 ? "FREE" : it.price}</td>
      <td class="muted">${(it.tags||[]).map(escapeHtml).join(", ")}</td>
      <td>
        <button class="btn secondary" onclick="buyItem('${it.id}')">Buy/Claim</button>
        <button class="btn secondary" onclick="downloadItem('${it.id}')">Download</button>
      </td>`;
    tbody.appendChild(tr);
  });
}

async function publish(){
  const file = document.getElementById("pubFile").value.trim();
  const title = document.getElementById("pubTitle").value.trim();
  const price = document.getElementById("pubPrice").value.trim();
  const tags = document.getElementById("pubTags").value.split(",").map(x=>x.trim()).filter(Boolean);

  try{
    await api("/market/publish", { method:"POST", body: JSON.stringify({ file, title, price, tags }) });
    setToast("Published");
    await loadMarket();
  }catch(e){ setToast(e.message); }
}

async function buyItem(id){
  try{
    await api("/market/buy", { method:"POST", body: JSON.stringify({ id }) });
    setToast("Success");
  }catch(e){ setToast(e.message); }
}

function downloadItem(id){
  const token = getToken();
  (async()=>{
    try{
      const res = await fetch(API_BASE + "/market/download?id=" + encodeURIComponent(id), {
        headers: { "Authorization": "Bearer " + token }
      });
      if (!res.ok){
        const data = await res.json().catch(()=> ({}));
        throw new Error(data.error || "Download failed");
      }
      const blob = await res.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "download";
      a.click();
      setTimeout(()=> URL.revokeObjectURL(a.href), 1000);
    }catch(e){
      setToast(e.message);
    }
  })();
}
```

---

## frontend/pages/leaderboard.html
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mot Site • Leaderboard</title>
  <link rel="stylesheet" href="../css/style.css"/>
</head>
<body>
  <div id="nav"></div>
  <div class="container">
    <div class="card">
      <h2>Leaderboard (Richest)</h2>
      <table class="table">
        <thead><tr><th>#</th><th>User</th><th>Total</th><th>Badges</th></tr></thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
  </div>
  <div id="toast" class="toast"></div>

  <script src="../js/main.js"></script>
  <script src="../js/leaderboard.js"></script>
  <script>
    requireAuth();
    (async()=>{ await loadMe(); mountNav(); await loadLB(); })().catch(e=>setToast(e.message));
  </script>
</body>
</html>
```

## frontend/js/leaderboard.js
```js
async function loadLB(){
  const out = await api("/leaderboard", { method:"GET" });
  const tbody = document.getElementById("rows");
  tbody.innerHTML = "";
  out.items.forEach((u,i)=>{
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${i+1}</td>
      <td>${escapeHtml(u.username)}</td>
      <td>${u.total}</td>
      <td class="muted">${(u.badges||[]).slice(0,6).map(escapeHtml).join(", ")}${(u.badges||[]).length>6?" ...":""}</td>`;
    tbody.appendChild(tr);
  });
}
```

---

## frontend/pages/notifications.html
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mot Site • Notifications</title>
  <link rel="stylesheet" href="../css/style.css"/>
</head>
<body>
  <div id="nav"></div>
  <div class="container">
    <div class="card">
      <div class="row" style="justify-content:space-between">
        <div>
          <h2>Notifications</h2>
          <div class="muted">Latest 100 notifications.</div>
        </div>
        <button class="btn secondary" onclick="markAllRead()">Mark all read</button>
      </div>
      <hr/>
      <div id="list" class="codebox"></div>
    </div>
  </div>

  <div id="toast" class="toast"></div>
  <script src="../js/main.js"></script>
  <script src="../js/notifications.js"></script>
  <script>
    requireAuth();
    (async()=>{ await loadMe(); mountNav(); await loadNotifs(); })().catch(e=>setToast(e.message));
  </script>
</body>
</html>
```

## frontend/js/notifications.js
```js
async function loadNotifs(){
  const out = await api("/notifications", { method:"GET" });
  const lines = (out.items || []).map(n => {
    const mark = n.read ? "✓" : "•";
    return `${mark} ${n.createdAt} — ${n.message}  [id=${n.id}]`;
  }).join("\n");
  document.getElementById("list").textContent = lines || "(none)";
}

async function markAllRead(){
  try{
    const out = await api("/notifications/mark-all-read", { method:"POST", body: JSON.stringify({}) });
    setToast("Marked read: " + out.changed);
    await loadNotifs();
  }catch(e){ setToast(e.message); }
}
```

---

## frontend/pages/profile.html
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mot Site • Profile</title>
  <link rel="stylesheet" href="../css/style.css"/>
</head>
<body>
  <div id="nav"></div>
  <div class="container">
    <div class="grid">
      <div class="card" style="grid-column: span 7;">
        <h2>Profile</h2>
        <div id="box" class="muted">Loading...</div>
      </div>
      <div class="card" style="grid-column: span 5;">
        <h3>Recent Notifications</h3>
        <div id="notifs" class="codebox"></div>
      </div>
    </div>
  </div>

  <div id="toast" class="toast"></div>
  <script src="../js/main.js"></script>
  <script src="../js/profile.js"></script>
  <script>
    requireAuth();
    (async()=>{ const u=await loadMe(); mountNav(); await loadProfile(u); })().catch(e=>setToast(e.message));
  </script>
</body>
</html>
```

## frontend/js/profile.js
```js
async function loadProfile(u){
  document.getElementById("box").innerHTML = `
    <div class="row">
      <span class="badge">Username: ${escapeHtml(u.username)}</span>
      <span class="badge">Role: ${escapeHtml(u.role)}</span>
    </div>
    <div style="margin-top:10px" class="row">
      <span class="badge">Money: ${u.money}</span>
      <span class="badge">Bank: ${u.bankBalance}</span>
    </div>
    <div style="margin-top:10px" class="muted">
      Badges (${(u.badges||[]).length}): ${(u.badges||[]).map(escapeHtml).join(", ")}
    </div>
  `;

  const n = await api("/notifications", { method:"GET" });
  document.getElementById("notifs").textContent =
    (n.items||[]).slice(0,15).map(x => `${x.read ? "✓" : "•"} ${x.createdAt} — ${x.message}`).join("\n") || "(none)";
}
```

---

## frontend/pages/settings.html
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mot Site • Settings</title>
  <link rel="stylesheet" href="../css/style.css"/>
</head>
<body>
  <div id="nav"></div>
  <div class="container">
    <div class="grid">
      <div class="card" style="grid-column: span 6;">
        <h2>Settings</h2>
        <p class="muted">Set bank passkey (4 digits).</p>
        <input class="input" id="passkey" placeholder="1234"/>
        <div style="height:10px"></div>
        <button class="btn" onclick="savePasskey()">Save Passkey</button>
      </div>
      <div class="card" style="grid-column: span 6;">
        <h3>API Base</h3>
        <p class="muted">Example: https://your-backend-host/api</p>
        <input class="input" id="apiBase"/>
        <div style="height:10px"></div>
        <button class="btn secondary" onclick="saveApi()">Save</button>
      </div>
    </div>
  </div>

  <div id="toast" class="toast"></div>
  <script src="../js/main.js"></script>
  <script src="../js/settings.js"></script>
  <script>
    requireAuth();
    (async()=>{ await loadMe(); mountNav(); initSettings(); })().catch(e=>setToast(e.message));
  </script>
</body>
</html>
```

## frontend/js/settings.js
```js
function initSettings(){
  document.getElementById("apiBase").value = localStorage.getItem("MOT_API") || "http://localhost:3000/api";
}

async function savePasskey(){
  try{
    await api("/auth/bank-passkey", { method:"POST", body: JSON.stringify({ passkey: document.getElementById("passkey").value }) });
    setToast("Passkey saved");
  }catch(e){ setToast(e.message); }
}

function saveApi(){
  localStorage.setItem("MOT_API", document.getElementById("apiBase").value.trim());
  setToast("Saved. Reload page.");
}
```

---

## frontend/pages/admin.html
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mot Site • Admin</title>
  <link rel="stylesheet" href="../css/style.css"/>
</head>
<body>
  <div id="nav"></div>
  <div class="container">
    <div class="grid">
      <div class="card" style="grid-column: span 12;">
        <h2>Admin Panel</h2>
        <p class="muted">Promote users + broadcast notifications.</p>
      </div>
      <div class="card" style="grid-column: span 6;">
        <h3>Promote user to admin</h3>
        <input class="input" id="pUser" placeholder="username"/>
        <div style="height:10px"></div>
        <button class="btn" onclick="promote()">Promote</button>
      </div>
      <div class="card" style="grid-column: span 6;">
        <h3>Broadcast notification</h3>
        <input class="input" id="msg" placeholder="message"/>
        <div style="height:10px"></div>
        <button class="btn" onclick="broadcast()">Send</button>
      </div>
      <div class="card" style="grid-column: span 12;">
        <h3>Users</h3>
        <div id="users" class="codebox"></div>
      </div>
    </div>
  </div>

  <div id="toast" class="toast"></div>
  <script src="../js/main.js"></script>
  <script src="../js/admin.js"></script>
  <script>
    requireAuth();
    (async()=>{ await loadMe(); mountNav(); await loadUsers(); })().catch(e=>setToast(e.message));
  </script>
</body>
</html>
```

## frontend/js/admin.js
```js
async function loadUsers(){
  const out = await api("/admin/users", { method:"GET" });
  document.getElementById("users").textContent = out.items.map(u =>
    `${u.username} • ${u.role} • money=${u.money} bank=${u.bankBalance} • badges=${(u.badges||[]).length}`
  ).join("\n") || "(none)";
}

async function promote(){
  try{
    await api("/admin/promote", { method:"POST", body: JSON.stringify({ username: document.getElementById("pUser").value.trim() }) });
    setToast("Promoted");
    await loadUsers();
  }catch(e){ setToast(e.message); }
}

async function broadcast(){
  try{
    await api("/admin/notify", { method:"POST", body: JSON.stringify({ message: document.getElementById("msg").value.trim() }) });
    setToast("Sent");
  }catch(e){ setToast(e.message); }
}
```

---

## frontend/pages/changelog.html
```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Mot Site • Changelog</title>
  <link rel="stylesheet" href="../css/style.css"/>
</head>
<body>
  <div id="nav"></div>
  <div class="container">
    <div class="card">
      <h2>Changelog</h2>
      <div id="progress"></div>
      <hr/>
      <h3>Updates</h3>
      <div id="updates" class="codebox"></div>
      <hr/>
      <h3>Next Features</h3>
      <div id="next"></div>
    </div>
  </div>

  <div id="toast" class="toast"></div>
  <script src="../js/main.js"></script>
  <script src="../js/changelog.js"></script>
  <script>
    requireAuth();
    (async()=>{ await loadMe(); mountNav(); await loadChangelog(); })().catch(e=>setToast(e.message));
  </script>
</body>
</html>
```

## frontend/js/changelog.js
```js
async function loadChangelog(){
  const data = await api("/changelog", { method:"GET" });

  const prog = data.progress || { js: 0, css: 0, html: 0 };
  document.getElementById("progress").innerHTML = `
    <div class="row">
      <div style="flex:1">
        <div class="muted">JS: ${prog.js}%</div>
        <div class="progress"><div style="width:${prog.js}%"></div></div>
      </div>
      <div style="flex:1">
        <div class="muted">CSS: ${prog.css}%</div>
        <div class="progress"><div style="width:${prog.css}%"></div></div>
      </div>
      <div style="flex:1">
        <div class="muted">HTML: ${prog.html}%</div>
        <div class="progress"><div style="width:${prog.html}%"></div></div>
      </div>
    </div>
  `;

  document.getElementById("updates").textContent =
    (data.updates || []).map(u => `${u.date} • ${u.title}\n${u.details || ""}\n`).join("\n") || "(none)";

  const next = (data.nextFeatures || []).map(n => `
    <div class="card" style="margin-top:10px">
      <div class="muted">${escapeHtml(n.name)} • ${n.percent}%</div>
      <div class="progress"><div style="width:${n.percent}%"></div></div>
    </div>
  `).join("");

  document.getElementById("next").innerHTML = next || "(none)";
}
```

---

## frontend/pages/settings.html + others already done ✅

---
