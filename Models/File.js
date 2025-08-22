// models/File.js
import mongoose from "mongoose";

const fileSchema = new mongoose.Schema({
  filename: String,
  path: String,
  mimetype: String,
  size: Number,
  createdAt: { type: Date, default: Date.now },
  folder: { type: mongoose.Schema.Types.ObjectId, ref: "Folder", default: null }, // link to folder
});

export default mongoose.model("File", fileSchema);
