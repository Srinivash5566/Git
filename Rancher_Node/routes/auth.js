const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const User = require("../models/user.model");

const JWT_SECRET = process.env.JWT_SECRET;

let OTP = null;
const transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.ethereal.email",
  port: 587,
  secure: false,
  auth: {
    user: `email.......................`,
    pass: `password......................`,
  },
});
// send OTP
router.post("/sendOtp", async (req, res) => {
  const { email } = req.body;
  let user = await User.findOne({ email });
  if (user) {
    return res.status(400).json({ message: "User already exists" });
  }
  OTP = Math.floor(1000 + Math.random() * 9000);

  const mailOps = {
    from: "rancher.akenterprise@gmail.com",
    to: email,
    subject: "One Time Password (OTP)",
    text: `Your One Time Password (OTP) is ${OTP}`,
  };
  await transporter.sendMail(mailOps, (err, info) => {
    if (err) {
      return res.status(500).json({ message: `Failed to send OTP ${err}` });
    }
    res.status(200).json({ message: "OTP sent successfully" });
  });
});

// Register Route
router.post("/register", async (req, res) => {
  const { userName, email, password, otp } = req.body;
  if (otp != OTP) {
    return res.status(400).json({ message: "Invalid OTP" });
  }
  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    user = new User({ userName, email, password: hashedPassword });
    await user.save();

    // Generate JWT Token
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });

    // Send back token, user details
    res.status(201).json({
      message: "User registered successfully",
      token,
      user: { userName, email },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// Login Route
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      // Send JSON response for invalid credentials
      return res.status(400).json({ message: "Enter the valid Email Address" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      // Send JSON response for invalid credentials
      return res.status(400).json({ message: "Enter the valid password" });
    }

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });
    res.json({
      token,
      user: { id: user.id, userName: user.userName, email: user.email },
    });
  } catch (err) {
    console.error(err.message);
    // Send JSON response for server error
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
