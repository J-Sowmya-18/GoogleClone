const { register, login } = require("../Controllers/AuthControllers");
const router = require("express").Router();

// ✅ Root POST route to stop 404
router.post("/", (req, res) => {
  res.status(200).json({ success: true, message: "POST / route working ✅" });
});

// Auth routes
router.post("/register", register);
router.post("/login", login);

module.exports = router;
