// server.js
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const path = require("path");

const authRoutes = require("./Routes/AuthRoutes");
const fileRoutes = require("./Routes/fileRoutes");
const searchRoutes = require("./Routes/SearchRoutes"); // 🔍 new

const app = express();

// Middleware
app.use(
  cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json());

// ------------------- FILE UPLOAD CONFIG -------------------
// Configure Multer storage
const storage = multer.diskStorage({
  destination: "./uploads", // folder where files are saved
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // unique filename
  },
});

const upload = multer({ storage });

// Route for file upload
app.post("/api/upload", upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ message: "No file uploaded" });

  res.json({
    message: "File uploaded successfully",
    filePath: `/uploads/${req.file.filename}`,
  });
});

// Serve uploaded files statically
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
// ----------------------------------------------------------

// Routes
app.use("/", authRoutes);
app.use("/api/files", fileRoutes);
app.use("/api", searchRoutes); // 🔍 search API

// MongoDB connection
mongoose
  .connect(
    "mongodb+srv://jwt:v3a4vJWs0I2N9sOl@cluster0.3ox3zzj.mongodb.net/user?retryWrites=true&w=majority&appName=Cluster0"
  )
  .then(() => {
    console.log("DB Connection Successful");
  })
  .catch((err) => {
    console.log("DB Connection Error:", err.message);
  });

// Start server
app.listen(4000, () => {
  console.log("Server Started on PORT 4000");
});
