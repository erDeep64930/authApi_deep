const express = require("express");
const router = express.Router();

const { login, signup } = require("../controllers/Auth");

const { auth, isStudent, isAdmin } = require("../middleware/auth");

router.post("/login", login);
router.post("/signup", signup);

// testing protected routes for single middleware
router.get("/test", auth, (req, res) => {
  res.json({
    success: true,
    message: "welcome to protected route for test",
  });
});

// protected route

router.get("/student", auth, isStudent, (req, res) => {
  res.json({
    success: true,
    message: "welcome to protected route for students",
  });
});
router.get("/admin", auth, isAdmin, (req, res) => {
    res.json({
      success: true,
      message: "welcome to protected route for Admin",
    });
  });
module.exports = router;
