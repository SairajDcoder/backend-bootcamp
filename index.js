require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const NodeCache = require("node-cache");
const { body, validationResult } = require("express-validator");

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.json());
app.use(cors());

const cache = new NodeCache({ stdTTL: 600 });

const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGO_URI;

    if (!mongoURI) {
      console.error("❌ MONGO_URI is not set in .env");
      process.exit(1);
    }
    await mongoose.connect(mongoURI);
    console.log("✅ MongoDB connected");
  } catch (error) {
    console.error("❌ MongoDB connection error:", error.message);
    process.exit(1);
  }
};

const taskSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    complete: { type: Boolean, default: false },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true }
);

const Task = mongoose.model("Task", taskSchema);

const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true, trim: true },
    password: { type: String, required: true },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    timestamp: new Date(),
  });
});

const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-env";

const auth = (req, res, next) => {
  const raw = req.header("Authorization");
  const token = raw?.startsWith("Bearer ") ? raw.replace("Bearer ", "") : null;

  if (!token)
    return res.status(401).json({ error: "Access denied: missing token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { id: decoded.id };
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

const validateSignup = [
  body("username").isString().notEmpty().trim().isLength({ min: 3, max: 30 }),
  body("password").isString().notEmpty().isLength({ min: 6 }),
];

const validateLogin = [
  body("username").isString().notEmpty(),
  body("password").isString().notEmpty(),
];

const validateTaskCreate = [
  body("title").isString().notEmpty().trim().isLength({ min: 3 }),
  body("complete").optional().isBoolean(),
];

const validateTaskUpdate = [
  body("title").optional().isString().notEmpty().trim().isLength({ min: 3 }),
  body("complete").optional().isBoolean(),
];

app.post("/signup", validateSignup, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { username, password } = req.body;

    const existingUser = await User.findOne({ username });
    if (existingUser)
      return res.status(400).json({ error: "Username already exists" });

    const hash = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hash });
    await user.save();

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1h" });

    res.status(201).json({
      message: "User created successfully",
      token,
      user: {
        id: user._id,
        username: user.username,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ error: "Failed to create user" });
  }
});

app.post("/login", validateLogin, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/tasks", auth, async (req, res) => {
  try {
    const cacheKey = `tasks_${req.user.id}`;
    const cached = cache.get(cacheKey);
    if (cached) return res.json(cached);

    const tasks = await Task.find({ userId: req.user.id }).sort({
      createdAt: -1,
    });
    cache.set(cacheKey, tasks);
    res.json(tasks);
  } catch (error) {
    console.error("Get tasks error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/tasks", auth, validateTaskCreate, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { title, complete = false } = req.body;
    const task = new Task({ title, complete, userId: req.user.id });
    await task.save();

    cache.del(`tasks_${req.user.id}`);
    res.status(201).json(task);
  } catch (error) {
    console.error("Create task error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/tasks/:id", auth, async (req, res) => {
  try {
    const task = await Task.findOne({
      _id: req.params.id,
      userId: req.user.id,
    });
    if (!task) {
      return res.status(404).json({
        error: "Task not found",
        message: "No task exists with the provided id for this user",
      });
    }
    res.json({ message: "Task retrieved successfully!", task });
  } catch (error) {
    console.error("Error fetching task:", error);
    res
      .status(500)
      .json({ error: "Failed to fetch task", details: error.message });
  }
});

app.put("/tasks/:id", auth, validateTaskUpdate, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const task = await Task.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id },
      req.body,
      { new: true }
    );
    if (!task) return res.status(404).json({ error: "Task not found" });

    cache.del(`tasks_${req.user.id}`);
    res.json(task);
  } catch (error) {
    console.error("Update task error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete("/tasks/:id", auth, async (req, res) => {
  try {
    const task = await Task.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.id,
    });
    if (!task) return res.status(404).json({ error: "Task not found" });

    cache.del(`tasks_${req.user.id}`);
    res.status(200).json({ message: "Task deleted" });
  } catch (error) {
    console.error("Delete task error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

const startServer = async () => {
  try {
    await connectDB();
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📄 Task API endpoints:`);
      console.log(`   POST   /signup         - User signup`);
      console.log(`   POST   /login          - User login`);
      console.log(`   GET    /tasks          - Get all tasks (JWT)`);
      console.log(`   POST   /tasks          - Create task (JWT)`);
      console.log(`   GET    /tasks/:id      - Get task by id (JWT)`);
      console.log(`   PUT    /tasks/:id      - Update task (JWT)`);
      console.log(`   DELETE /tasks/:id      - Delete task (JWT)`);
      console.log(`🔐 Use header: Authorization: Bearer <token>`);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
};

module.exports = app;

if (require.main === module) {
  startServer();
}
