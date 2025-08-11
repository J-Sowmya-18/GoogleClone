import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

export function authMiddleware(req, res, next) {
  const token = req.header("Authorization")?.split(" ")[1]; // Expect: "Bearer <token>"

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // decoded contains { id: <userId> }
    next();
  } catch (err) {
    res.status(400).json({ error: "Invalid token." });
  }
}
