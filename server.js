// server.js
import express from "express";
import nodemailer from "nodemailer";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors({
  origin: "http://localhost:5173", // change as needed
  credentials: true
}));

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// OTP store (temporary memory for demo)
const otpStore = {};

// Setup mail transporter
const transporter = nodemailer.createTransport({
  service: "gmail", // or SMTP host
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ✅ 1. Check if email exists
app.post("/api/check-email", async (req, res) => {
  const { email } = req.body;
  const { data, error } = await supabase
    .from("profiles")
    .select("email")
    .eq("email", email)
    .single();

  if (error && error.code !== "PGRST116") {
    return res.status(500).json({ error: error.message });
  }

  if (data) {
    return res.json({ exists: true });
  } else {
    return res.json({ exists: false });
  }
});

// ✅ 2. Send OTP for signup
app.post("/api/send-otp", async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000);

  otpStore[email] = otp.toString();

  await transporter.sendMail({
    from: `"Your App" <${process.env.SMTP_USER}>`,
    to: email,
    subject: "Verify your email",
    html: `<p>Your OTP is <b>${otp}</b>. It is valid for 5 minutes.</p>`,
  });

  res.json({ success: true, message: "OTP sent" });

  // Optional: Set expiry
  setTimeout(() => delete otpStore[email], 300000);
});

// ✅ 3. Verify OTP & register user
app.post("/api/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (otpStore[email] !== otp) {
    return res.status(400).json({ success: false, message: "Invalid OTP" });
  }

  delete otpStore[email];
  const { data, error } = await supabase.auth.admin.createUser({
    email,
    email_confirm: true,
  });

  if (error) return res.status(500).json({ success: false, message: error.message });
  res.json({ success: true, message: "Email verified and account created" });
});

const PORT = process.env.PORT || 4012;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

