
const router = require("express").Router();
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const uploadDir = path.join(__dirname, "..", "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const name = path.basename(file.originalname, ext);
    cb(null, `${name}-${Date.now()}${ext}`);
  }
});

const upload = multer({ storage });

// 📌 Upload multiple files
router.post("/", upload.array("files", 10), (req, res) => {
  const uploadedFiles = req.files.map(file => ({
    filename: file.filename,
    path: `/uploads/${file.filename}`,
    size: file.size,
    mimetype: file.mimetype,
    uploadedAt: new Date()
  }));

  res.json({ files: uploadedFiles });
});

// 📌 List all files
router.get("/", (req, res) => {
  fs.readdir(uploadDir, (err, files) => {
    if (err) return res.status(500).json({ error: err.message });

    const details = files.map(f => {
      const stats = fs.statSync(path.join(uploadDir, f));
      return {
        filename: f,
        size: (stats.size / (1024 * 1024)).toFixed(2) + " MB",
        modified: stats.mtime
      };
    });

    res.json({ files: details });
  });
});

// 📌 Download file
router.get("/download/:name", (req, res) => {
  const filePath = path.join(uploadDir, req.params.name);
  if (!fs.existsSync(filePath)) return res.status(404).send("File not found");
  res.download(filePath);
});

// 📌 Delete file
router.delete("/:name", (req, res) => {
  const filePath = path.join(uploadDir, req.params.name);
  if (!fs.existsSync(filePath)) return res.status(404).send("File not found");
  fs.unlinkSync(filePath);
  res.json({ message: "File deleted" });
});

module.exports = router;
