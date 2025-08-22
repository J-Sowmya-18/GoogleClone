import express from "express";
import Folder from "../models/Folder.js";
import File from "../models/File.js";
const router = express.Router();

// Create folder
router.post("/folders", async (req, res) => {
  try {
    const { name, parent } = req.body;
    const folder = new Folder({ name, parent: parent || null });
    await folder.save();
    res.json(folder);
  } catch (err) {
    res.status(500).json({ error: "Error creating folder" });
  }
});

// Get all folders
router.get("/folders", async (req, res) => {
  const folders = await Folder.find();
  res.json(folders);
});

// Get files in a folder
router.get("/folders/:id/files", async (req, res) => {
  const files = await File.find({ folder: req.params.id });
  res.json(files);
});

// Upload file to a folder
router.post("/upload/:folderId", upload.single("file"), async (req, res) => {
  try {
    const file = new File({
      filename: req.file.filename,
      path: req.file.path,
      mimetype: req.file.mimetype,
      size: req.file.size,
      folder: req.params.folderId,
    });
    await file.save();
    res.json(file);
  } catch (err) {
    res.status(500).json({ error: "Error uploading file" });
  }
});

export default router;
