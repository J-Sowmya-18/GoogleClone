// models/Folder.js
import mongoose from "mongoose";

const folderSchema = new mongoose.Schema({
  name: { type: String, required: true },
  parent: { type: mongoose.Schema.Types.ObjectId, ref: "Folder", default: null }, // null = root folder
  createdAt: { type: Date, default: Date.now },
});

export default mongoose.model("Folder", folderSchema);
