
/* ============================ server.js ============================ */
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import crypto from "crypto";
import fs from "fs";
import path from "path";

dotenv.config();
fs.mkdirSync("uploads", { recursive: true });

/* ------------------------------- Config ------------------------------ */

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("JWT_SECRET is not set. Add it to server/.env and restart.");
  process.exit(1);
}

const MONGO_URI =
  process.env.MONGODB_URI ||
  process.env.MONGO_URI ||
  "mongodb://127.0.0.1:27017/traceguard";

const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";
const PORT = process.env.PORT || 5000;
const UPLOAD_DIR = path.resolve("uploads");
const MAX_FILE_BYTES = 10 * 1024 * 1024; // 10 MB (matches README)

const app = express();
app.use(cors({ origin: CLIENT_URL, credentials: false }));
app.use(express.json({ limit: "1mb" }));

/* ------------------------- Status normalization ---------------------- */

// Canonical stored values: "Pending" | "Under Investigation" | "Resolved" | "Closed"
const STATUS_CANON = {
  pending: "Pending",
  "under investigation": "Under Investigation",
  under_investigation: "Under Investigation",
  resolved: "Resolved",
  closed: "Closed",
  open: "Pending",        // legacy snake_case → canonical
  archived: "Closed",     // legacy snake_case → canonical
};

function normalizeStatus(value) {
  if (value === undefined || value === null) return undefined;
  const key = String(value).trim().toLowerCase();
  return STATUS_CANON[key] || undefined;
}

const SEVERITY_CANON = {
  low: "Low", medium: "Medium", high: "High", critical: "Critical",
};
function normalizeSeverity(value) {
  if (value === undefined || value === null) return undefined;
  return SEVERITY_CANON[String(value).trim().toLowerCase()];
}

/* ------------------------------- Models ------------------------------ */

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    passwordHash: { type: String, required: true, select: false },
    role: {
      type: String,
      enum: ["admin", "investigator", "reporter"],
      default: "reporter",
      index: true,
    },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

const evidenceSchema = new mongoose.Schema(
  {
    filename: { type: String, required: true },     // stored on-disk name
    originalName: { type: String, default: "" },
    mimetype: { type: String, default: "" },
    size: { type: Number, default: 0 },
    sha256: { type: String, default: "" },
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    uploadedAt: { type: Date, default: Date.now },
  },
  { _id: true }
);

const noteSchema = new mongoose.Schema(
  {
    body: { type: String, required: true, trim: true },   // canonical storage key
    text: { type: String, default: "" },                  // mirror for frontend
    author: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    createdAt: { type: Date, default: Date.now },
  },
  { _id: true }
);

const caseSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    category: { type: String, default: "Other" },
    severity: { type: String, enum: ["Low", "Medium", "High", "Critical"], default: "Medium" },
    priority: { type: String, enum: ["low", "medium", "high", "critical"], default: "medium" },
    status: {
      type: String,
      enum: ["Pending", "Under Investigation", "Resolved", "Closed"],
      default: "Pending",
      index: true,
    },
    caseNumber: { type: String, unique: true, index: true, sparse: true },
    reporter: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },
    assignedTo: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
      index: true,
    },
    evidence: [evidenceSchema],
    notes: [noteSchema],
  },
  { timestamps: true }
);

caseSchema.pre("validate", function (next) {
  if (!this.caseNumber) {
    const year = new Date().getFullYear();
    this.caseNumber = `CASE-${year}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
  }
  next();
});

const Case = mongoose.model("Case", caseSchema);

/* ----------------------------- Serializers --------------------------- */

const publicUser = (u) => ({
  id: String(u._id),
  _id: String(u._id),
  name: u.name,
  email: u.email,
  role: u.role,
});

function publicCase(doc) {
  const obj = typeof doc.toObject === "function" ? doc.toObject() : { ...doc };
  return {
    ...obj,
    _id: String(obj._id),
    status: obj.status,
    reporter: obj.reporter && typeof obj.reporter === "object"
      ? { _id: String(obj.reporter._id), name: obj.reporter.name, email: obj.reporter.email }
      : obj.reporter,
    assignedTo: obj.assignedTo && typeof obj.assignedTo === "object"
      ? { _id: String(obj.assignedTo._id), name: obj.assignedTo.name, email: obj.assignedTo.email }
      : obj.assignedTo,
    notes: (obj.notes || []).map((n) => ({
      ...n,
      _id: String(n._id),
      text: n.text || n.body,
      body: n.body || n.text,
      author: n.author && typeof n.author === "object"
        ? { _id: String(n.author._id), name: n.author.name, role: n.author.role }
        : n.author,
    })),
    evidence: (obj.evidence || []).map((e) => ({ ...e, _id: String(e._id) })),
  };
}

/* ----------------------------- Middleware ---------------------------- */

const auth = async (req, res, next) => {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing bearer token" });
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ error: "User no longer exists" });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
};

const requireRole = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ error: "Insufficient permissions" });
  }
  next();
};

// admin: all; investigator: only assigned; reporter: only own
const canAccess = (user, doc) => {
  if (user.role === "admin") return true;
  if (user.role === "investigator") return String(doc.assignedTo) === String(user._id);
  return String(doc.reporter) === String(user._id);
};

const signToken = (user) =>
  jwt.sign({ sub: String(user._id), role: user.role }, JWT_SECRET, { expiresIn: "7d" });

/* ------------------------------- Uploads ----------------------------- */

const ALLOWED_MIME = new Set([
  "image/png", "image/jpeg", "image/webp", "image/gif",
  "application/pdf",
  "video/mp4", "video/quicktime",
  "audio/mpeg", "audio/wav",
  "text/plain", "text/csv",
]);

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, "");
      cb(null, `${Date.now()}-${crypto.randomBytes(12).toString("hex")}${ext}`);
    },
  }),
  limits: { fileSize: MAX_FILE_BYTES, files: 10 },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_MIME.has(file.mimetype)) {
      return cb(Object.assign(new Error("Unsupported file type"), { status: 415 }));
    }
    cb(null, true);
  },
});

// Accept "file" (single) or "files" (array) to match either frontend variant.
const uploadAny = upload.any();

function normalizeUploads(req) {
  const files = req.files || [];
  if (files.length === 0) return [];
  // If a single file was sent under "file", it is already in the array.
  return files;
}

async function hashFile(absPath) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash("sha256");
    const stream = fs.createReadStream(absPath);
    stream.on("error", reject);
    stream.on("data", (chunk) => h.update(chunk));
    stream.on("end", () => resolve(h.digest("hex")));
  });
}

/* -------------------------------- Auth ------------------------------- */

app.post("/api/auth/register", async (req, res, next) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: "name, email and password are required" });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }
    const normalizedEmail = String(email).toLowerCase().trim();
    if (await User.exists({ email: normalizedEmail })) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const isFirst = (await User.estimatedDocumentCount()) === 0;
    const user = await User.create({
      name,
      email: normalizedEmail,
      passwordHash: await bcrypt.hash(password, 12),
      role: isFirst ? "admin" : "reporter",
    });

    res.status(201).json({ token: signToken(user), user: publicUser(user) });
  } catch (err) {
    next(err);
  }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }
    const user = await User.findOne({
      email: String(email).toLowerCase().trim(),
    }).select("+passwordHash");

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    res.json({ token: signToken(user), user: publicUser(user) });
  } catch (err) {
    next(err);
  }
});

app.get("/api/auth/me", auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

/* -------------------------------- Users ------------------------------ */

// All users (admin only)
app.get("/api/users", auth, requireRole("admin"), async (req, res, next) => {
  try {
    const { role } = req.query;
    const filter = {};
    if (role) filter.role = role;
    const users = await User.find(filter).sort({ createdAt: -1 });
    res.json({ users: users.map(publicUser) });
  } catch (err) {
    next(err);
  }
});

// Investigators + admins — the route the admin dropdown calls.
app.get("/api/users/investigators", auth, requireRole("admin"), async (req, res, next) => {
  try {
    const users = await User.find({ role: { $in: ["investigator", "admin"] } }).sort({ name: 1 });
    const list = users.map(publicUser);
    res.json({ users: list, investigators: list });
  } catch (err) {
    next(err);
  }
});

// Create a user (admin only). This is the endpoint to seed investigators from the UI.
app.post("/api/users", auth, requireRole("admin"), async (req, res, next) => {
  try {
    const { name, email, password, role } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ error: "name, email and password are required" });
    }
    if (!["admin", "investigator", "reporter"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }
    const normalizedEmail = String(email).toLowerCase().trim();
    if (await User.exists({ email: normalizedEmail })) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const user = await User.create({
      name,
      email: normalizedEmail,
      passwordHash: await bcrypt.hash(password, 12),
      role,
    });
    res.status(201).json({ user: publicUser(user) });
  } catch (err) {
    next(err);
  }
});

// Change a user's role (admin only)
app.patch("/api/users/:id/role", auth, requireRole("admin"), async (req, res, next) => {
  try {
    const { role } = req.body || {};
    if (!["admin", "investigator", "reporter"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }
    if (String(req.params.id) === String(req.user._id) && role !== "admin") {
      return res.status(400).json({ error: "You cannot demote yourself" });
    }
    const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ user: publicUser(user) });
  } catch (err) {
    next(err);
  }
});

/* ------------------------------ Dashboard ---------------------------- */

app.get("/api/dashboard/stats", auth, async (req, res, next) => {
  try {
    const filter = {};
    if (req.user.role === "investigator") filter.assignedTo = req.user._id;
    if (req.user.role === "reporter") filter.reporter = req.user._id;

    const [total, pending, active, resolved, closed] = await Promise.all([
      Case.countDocuments(filter),
      Case.countDocuments({ ...filter, status: "Pending" }),
      Case.countDocuments({ ...filter, status: "Under Investigation" }),
      Case.countDocuments({ ...filter, status: "Resolved" }),
      Case.countDocuments({ ...filter, status: "Closed" }),
    ]);

    res.json({ total, pending, active, resolved: resolved + closed, closed });
  } catch (err) {
    next(err);
  }
});

/* -------------------------------- Cases ------------------------------ */

app.get("/api/cases", auth, async (req, res, next) => {
  try {
    const filter = {};
    if (req.user.role === "investigator") filter.assignedTo = req.user._id;
    if (req.user.role === "reporter") filter.reporter = req.user._id;

    if (req.query.status) {
      const s = normalizeStatus(req.query.status);
      if (s) filter.status = s;
    }
    if (req.query.severity) {
      const s = normalizeSeverity(req.query.severity);
      if (s) filter.severity = s;
    }

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 50));

    const [cases, total] = await Promise.all([
      Case.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .populate("reporter", "name email")
        .populate("assignedTo", "name email"),
      Case.countDocuments(filter),
    ]);

    res.json({
      cases: cases.map(publicCase),
      page,
      limit,
      total,
      pages: Math.ceil(total / limit),
    });
  } catch (err) {
    next(err);
  }
});

app.post("/api/cases", auth, async (req, res, next) => {
  try {
    const { title, description, category, severity, priority } = req.body || {};
    if (!title) return res.status(400).json({ error: "title is required" });

    const doc = await Case.create({
      title,
      description: description || "",
      category: category || "Other",
      severity: normalizeSeverity(severity) || "Medium",
      priority: priority || "medium",
      status: "Pending",
      reporter: req.user._id,
    });

    res.status(201).json({ case: publicCase(doc) });
  } catch (err) {
    next(err);
  }
});

app.get("/api/cases/:id", auth, async (req, res, next) => {
  try {
    const doc = await Case.findById(req.params.id)
      .populate("reporter", "name email")
      .populate("assignedTo", "name email")
      .populate("notes.author", "name role");
    if (!doc) return res.status(404).json({ error: "Case not found" });
    if (!canAccess(req.user, doc)) return res.status(404).json({ error: "Case not found" });
    res.json({ case: publicCase(doc) });
  } catch (err) {
    next(err);
  }
});

// General patch: title/description/category/severity/priority/status/assignedTo
app.patch("/api/cases/:id", auth, async (req, res, next) => {
  try {
    const doc = await Case.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: "Case not found" });
    if (!canAccess(req.user, doc)) return res.status(404).json({ error: "Case not found" });

    const { title, description, category, severity, priority, status, assignedTo } = req.body || {};

    if (req.user.role === "reporter") {
      if (assignedTo !== undefined || status !== undefined) {
        return res.status(403).json({ error: "Reporters cannot change status or assignment" });
      }
      if (doc.status !== "Pending") {
        return res.status(403).json({ error: "Case is no longer editable" });
      }
    }

    if (title !== undefined) doc.title = title;
    if (description !== undefined) doc.description = description;
    if (category !== undefined) doc.category = category;
    if (severity !== undefined) {
      const s = normalizeSeverity(severity);
      if (s) doc.severity = s;
    }
    if (priority !== undefined && ["low", "medium", "high", "critical"].includes(priority)) {
      doc.priority = priority;
    }
    if (status !== undefined) {
      const s = normalizeStatus(status);
      if (!s) return res.status(400).json({ error: "Invalid status" });
      if (req.user.role === "reporter") {
        return res.status(403).json({ error: "Reporters cannot change status" });
      }
      doc.status = s;
    }
    if (assignedTo !== undefined) {
      if (req.user.role !== "admin") {
        return res.status(403).json({ error: "Only admins can assign cases" });
      }
      if (assignedTo === null || assignedTo === "") {
        doc.assignedTo = null;
      } else {
        const target = await User.findById(assignedTo);
        if (!target) return res.status(400).json({ error: "Assignee not found" });
        if (!["investigator", "admin"].includes(target.role)) {
          return res.status(400).json({ error: "Assignee must be an investigator or admin" });
        }
        doc.assignedTo = target._id;
      }
    }

    await doc.save();
    const populated = await Case.findById(doc._id)
      .populate("reporter", "name email")
      .populate("assignedTo", "name email");
    res.json({ case: publicCase(populated) });
  } catch (err) {
    next(err);
  }
});

// Convenience: assign
app.patch("/api/cases/:id/assign", auth, requireRole("admin"), async (req, res, next) => {
  try {
    const { investigatorId, assignedTo } = req.body || {};
    const targetId = investigatorId ?? assignedTo;
    if (!targetId) return res.status(400).json({ error: "investigatorId is required" });

    const doc = await Case.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: "Case not found" });

    const target = await User.findById(targetId);
    if (!target) return res.status(400).json({ error: "Assignee not found" });
    if (!["investigator", "admin"].includes(target.role)) {
      return res.status(400).json({ error: "Assignee must be an investigator or admin" });
    }
    doc.assignedTo = target._id;
    if (doc.status === "Pending") doc.status = "Under Investigation";
    await doc.save();

    const populated = await Case.findById(doc._id)
      .populate("reporter", "name email")
      .populate("assignedTo", "name email");
    res.json({ case: publicCase(populated) });
  } catch (err) {
    next(err);
  }
});

// Convenience: status
app.patch("/api/cases/:id/status", auth, requireRole("admin", "investigator"), async (req, res, next) => {
  try {
    const { status } = req.body || {};
    const s = normalizeStatus(status);
    if (!s) return res.status(400).json({ error: "Invalid status" });

    const doc = await Case.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: "Case not found" });
    if (!canAccess(req.user, doc)) return res.status(404).json({ error: "Case not found" });

    doc.status = s;
    await doc.save();

    const populated = await Case.findById(doc._id)
      .populate("reporter", "name email")
      .populate("assignedTo", "name email");
    res.json({ case: publicCase(populated) });
  } catch (err) {
    next(err);
  }
});

/* ------------------------------- Evidence ---------------------------- */

app.post("/api/cases/:id/evidence", auth, uploadAny, async (req, res, next) => {
  try {
    const files = normalizeUploads(req);
    if (!files.length) return res.status(400).json({ error: "No files uploaded" });

    const doc = await Case.findById(req.params.id);
    if (!doc) {
      // clean up uploaded temp files on error
      for (const f of files) fs.promises.unlink(f.path).catch(() => {});
      return res.status(404).json({ error: "Case not found" });
    }
    if (!canAccess(req.user, doc)) {
      for (const f of files) fs.promises.unlink(f.path).catch(() => {});
      return res.status(404).json({ error: "Case not found" });
    }

    const added = [];
    for (const f of files) {
      const sha256 = await hashFile(f.path);
      doc.evidence.push({
        filename: f.filename,
        originalName: f.originalname,
        mimetype: f.mimetype,
        size: f.size,
        sha256,
        uploadedBy: req.user._id,
      });
      added.push({ originalName: f.originalname, sha256 });
    }
    await doc.save();

    res.status(201).json({
      evidence: doc.evidence.slice(-files.length),
      sha256: added[0]?.sha256, // convenience for single-file uploads
    });
  } catch (err) {
    next(err);
  }
});

app.get("/api/cases/:id/evidence/:evidenceId", auth, async (req, res, next) => {
  try {
    const doc = await Case.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: "Case not found" });
    if (!canAccess(req.user, doc)) return res.status(404).json({ error: "Case not found" });

    const item = doc.evidence.id(req.params.evidenceId);
    if (!item) return res.status(404).json({ error: "Evidence not found" });

    const abs = path.join(UPLOAD_DIR, path.basename(item.filename));
    if (!fs.existsSync(abs)) return res.status(410).json({ error: "File missing on disk" });

    res.download(abs, item.originalName || item.filename);
  } catch (err) {
    next(err);
  }
});

app.delete("/api/cases/:id/evidence/:evidenceId", auth, async (req, res, next) => {
  try {
    const doc = await Case.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: "Case not found" });
    if (!canAccess(req.user, doc)) return res.status(404).json({ error: "Case not found" });

    const item = doc.evidence.id(req.params.evidenceId);
    if (!item) return res.status(404).json({ error: "Evidence not found" });
    if (req.user.role === "reporter" && String(item.uploadedBy) !== String(req.user._id)) {
      return res.status(403).json({ error: "You can only delete your own uploads" });
    }

    const abs = path.join(UPLOAD_DIR, path.basename(item.filename));
    item.deleteOne();
    await doc.save();
    fs.promises.unlink(abs).catch(() => {});

    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

/* --------------------------------- Notes ----------------------------- */

app.post("/api/cases/:id/notes", auth, async (req, res, next) => {
  try {
    const { body, text } = req.body || {};
    const content = String(body ?? text ?? "").trim();
    if (!content) return res.status(400).json({ error: "body is required" });

    const doc = await Case.findById(req.params.id);
    if (!doc) return res.status(404).json({ error: "Case not found" });
    if (!canAccess(req.user, doc)) return res.status(404).json({ error: "Case not found" });

    doc.notes.push({
      body: content,
      text: content,
      author: req.user._id,
    });
    await doc.save();

    const populated = await Case.findById(doc._id).populate("notes.author", "name role");
    const last = populated.notes[populated.notes.length - 1];
    res.status(201).json({
      note: {
        ...last.toObject(),
        _id: String(last._id),
        text: last.text || last.body,
        body: last.body || last.text,
        author: last.author && typeof last.author === "object"
          ? { _id: String(last.author._id), name: last.author.name, role: last.author.role }
          : last.author,
      },
    });
  } catch (err) {
    next(err);
  }
});

/* ------------------------------ Fallbacks ---------------------------- */

app.get("/api/health", (req, res) => res.json({ ok: true, uptime: process.uptime() }));

app.use((req, res) => res.status(404).json({ error: "Not found" }));

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    const msg = err.code === "LIMIT_FILE_SIZE" ? "File too large (max 10 MB)" : err.message;
    return res.status(400).json({ error: msg });
  }
  if (err.status) return res.status(err.status).json({ error: err.message });

  console.error(err);
  if (err.name === "ValidationError") {
    return res.status(400).json({ error: Object.values(err.errors).map((e) => e.message).join("; ") });
  }
  if (err.code === 11000) {
    return res.status(409).json({ error: `Duplicate value for ${Object.keys(err.keyPattern).join(", ")}` });
  }
  res.status(500).json({ error: "Internal server error" });
});

/* -------------------------------- Boot ------------------------------- */

const start = async () => {
  await mongoose.connect(MONGO_URI);
  console.log("MongoDB connected");
  app.listen(PORT, () => {
    console.log(`API listening on http://localhost:${PORT}`);
    console.log(`CORS origin: ${CLIENT_URL}`);
  });
};

start().catch((err) => {
  console.error("Failed to start:", err);
  process.exit(1);
});