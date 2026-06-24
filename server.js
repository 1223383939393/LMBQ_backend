// server.js
const express = require("express");
const http = require("http");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const os = require("os");
const fs = require("fs");
const multer = require("multer");

const JWT_SECRET = process.env.JWT_SECRET || "SUPER_SECRET_KEY_CHANGE_ME";
const BASE_URL =
  process.env.BASE_URL || "http://localhost:3000";

const app = express();

// ===== CORS =====
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());

// ===== Multer: uploads dir =====
const uploadsDir =
  process.env.UPLOADS_DIR || path.join(os.tmpdir(), "uploads");

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname || "");
    cb(null, unique + ext);
  },
});

const upload = multer({ storage });

app.use("/uploads", express.static(uploadsDir));

// ===== In-memory users (demo) =====
const users = [];
let nextUserId = 1;

// ===== In-memory posts (demo) =====
const posts = [];
let nextPostId = 1;

// ===== JWT helpers =====
function createToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, email: user.email },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "No token" });

  const [type, token] = auth.split(" ");
  if (type !== "Bearer" || !token) {
    return res.status(401).json({ error: "Invalid auth header" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ===== Auth endpoints =====
app.post("/api/auth/register", async (req, res) => {
  const { username, email, password, fullName, avatarUrl, bio } = req.body;
  if (!username || !email || !password) {
    return res
      .status(400)
      .json({ error: "username, email, password are required" });
  }

  const exists = users.find(
    (u) => u.email === email || u.username === username
  );
  if (exists) {
    return res
      .status(400)
      .json({ error: "User with this email/username already exists" });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const user = {
      id: String(nextUserId++),
      username,
      email,
      fullName: fullName || username,
      avatarUrl: avatarUrl || null,
      bio: bio || null,
      passwordHash,
    };
    users.push(user);

    const token = createToken(user);
    return res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        avatarUrl: user.avatarUrl,
        bio: user.bio,
      },
    });
  } catch (e) {
    console.error("Register error:", e);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { emailOrUsername, password } = req.body;
  if (!emailOrUsername || !password) {
    return res
      .status(400)
      .json({ error: "emailOrUsername, password are required" });
  }

  const user = users.find(
    (u) => u.email === emailOrUsername || u.username === emailOrUsername
  );
  if (!user) {
    return res.status(400).json({ error: "User not found" });
  }

  try {
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(400).json({ error: "Invalid password" });
    }

    const token = createToken(user);
    return res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        fullName: user.fullName,
        avatarUrl: user.avatarUrl,
        bio: user.bio,
      },
    });
  } catch (e) {
    console.error("Login error:", e);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ===== Upload media (images + audio) =====
// поля: files[] - картинки, audios[] - аудио
app.post(
  "/api/upload-media",
  authMiddleware,
  upload.fields([
    { name: "files", maxCount: 20 },
    { name: "audios", maxCount: 10 },
  ]),
  (req, res) => {
    const filesField = (req.files && req.files.files) || [];
    const audiosField = (req.files && req.files.audios) || [];

    const images = filesField.map((f) => {
      return `${BASE_URL}/uploads/${encodeURIComponent(f.filename)}`;
    });

    const audios = audiosField.map((f) => {
      return `${BASE_URL}/uploads/${encodeURIComponent(f.filename)}`;
    });

    res.json({ images, audios });
  }
);

// ===== Users endpoints =====
app.get("/api/users", authMiddleware, (req, res) => {
  const minimized = users.map((u) => ({
    id: u.id,
    username: u.username,
    email: u.email,
    fullName: u.fullName,
    avatarUrl: u.avatarUrl,
    bio: u.bio,
  }));
  res.json(minimized);
});

app.get("/api/users/me", authMiddleware, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    fullName: user.fullName,
    avatarUrl: user.avatarUrl,
    bio: user.bio,
  });
});

app.put("/api/users/me", authMiddleware, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: "User not found" });

  const { username, fullName, avatarUrl, bio } = req.body;

  if (username) user.username = username;
  if (fullName) user.fullName = fullName;
  if (avatarUrl !== undefined) user.avatarUrl = avatarUrl;
  if (bio !== undefined) user.bio = bio;

  res.json({
    id: user.id,
    username: user.username,
    email: user.email,
    fullName: user.fullName,
    avatarUrl: user.avatarUrl,
    bio: user.bio,
  });
});

// ===== Posts endpoints =====
app.get("/api/posts", authMiddleware, (req, res) => {
  res.json(posts);
});

app.post("/api/posts", authMiddleware, (req, res) => {
  const { caption, imageUrl, audioUrl, tags } = req.body;
  if (!caption) {
    return res.status(400).json({ error: "caption is required" });
  }

  const post = {
    id: String(nextPostId++),
    authorId: req.user.id,
    caption,
    imageUrl: imageUrl || null,   // "img1|||img2"
    audioUrl: audioUrl || null,   // "audio1|||audio2"
    tags: Array.isArray(tags) ? tags : [],
    likes: 0,
    likedByUserIds: [],
    createdAt: new Date().toISOString(),
    comments: [],
  };

  posts.unshift(post);
  res.status(201).json(post);
});

app.post("/api/posts/:postId/like", authMiddleware, (req, res) => {
  const post = posts.find((p) => p.id === req.params.postId);
  if (!post) return res.status(404).json({ error: "Post not found" });

  const uid = req.user.id;
  const alreadyLiked = post.likedByUserIds.includes(uid);

  if (alreadyLiked) {
    post.likedByUserIds = post.likedByUserIds.filter((id) => id !== uid);
    post.likes = Math.max(0, post.likes - 1);
  } else {
    post.likedByUserIds.push(uid);
    post.likes += 1;
  }

  res.json(post);
});

app.post("/api/posts/:postId/comments", authMiddleware, (req, res) => {
  const post = posts.find((p) => p.id === req.params.postId);
  if (!post) return res.status(404).json({ error: "Post not found" });

  const { text } = req.body;
  if (!text) {
    return res.status(400).json({ error: "text is required" });
  }

  const comment = {
    id: String(Date.now()),
    authorId: req.user.id,
    text,
    createdAt: new Date().toISOString(),
  };

  post.comments.push(comment);
  res.status(201).json(comment);
});

app.get("/api/posts/:postId/comments", authMiddleware, (req, res) => {
  const post = posts.find((p) => p.id === req.params.postId);
  if (!post) return res.status(404).json({ error: "Post not found" });
  res.json(post.comments || []);
});

// ===== Health check =====
app.get("/", (req, res) => {
  res.send("LMBQ backend is running");
});

// ===== Server start =====
const PORT = process.env.PORT || 3000;
const server = http.createServer(app);

server.listen(PORT, () => {
  console.log("LMBQ server listening on", PORT);
});