const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");

const protect = asyncHandler(async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ error: "Not authorized, please login" });
    }

    // Verify Token
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    // Get user id from token
    const user = await User.findById(verified.id).select("-password");

    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Not authorized, please loginxx" });
  }
});

module.exports = protect;
