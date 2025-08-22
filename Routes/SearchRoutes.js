const express = require("express");
const router = express.Router();
// const File = require("../models/File"); // your File model
// const Folder = require("../models/Folder"); // your Folder model

// Search API
router.get("/search", async (req, res) => {
  try {
    const { q } = req.query;
    if (!q) return res.status(400).json({ error: "Query required" });

    // Case-insensitive regex search
    const files = await File.find({ name: { $regex: q, $options: "i" } });
    const folders = await Folder.find({ name: { $regex: q, $options: "i" } });

    res.json({ files, folders });
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
