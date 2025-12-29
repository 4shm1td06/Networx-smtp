// server.js — Networx Backend (Persistent Auth)

import express from "express";
import nodemailer from "nodemailer";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";

dotenv.config();

const app = express();
const server = http.createServer(app);

// ===========================
//        MIDDLEWARES
// ===========================
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://localhost:5173",
      "https://networx-dusky.vercel.app",
      "https://chat.networxenterprise.co.in",
    ],
    credentials: true, // 🔥 REQUIRED FOR COOKIES
  })
);

// ===========================
//      SUPABASE SETUP
// ===========================
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ===========================
//      SMTP SETUP
// ===========================
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ===========================
//     IN-MEMORY STORES
// ===========================
const otpStore = new Map();

// ===========================
//      AUTH MIDDLEWARE
// ===========================
const requireAuth = async (req, res, next) => {
  const token = req.cookies.networx_session;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data.user) {
    return res.status(401).json({ error: "Invalid session" });
  }

  req.user = data.user;
  next();
};

// ===========================
//        AUTH ROUTES
// ===========================

// 🔐 LOGIN (Persistent)
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password,
  });

  if (error || !data.session) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  res.cookie("networx_session", data.session.access_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  });

  res.json({
    success: true,
    userId: data.user.id,
    email: data.user.email,
  });
});

// 🔄 RESTORE SESSION (FIXES REFRESH LOGOUT)
app.get("/api/me", async (req, res) => {
  const token = req.cookies.networx_session;
  if (!token) return res.status(401).json({ error: "Not logged in" });

  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data.user) {
    return res.status(401).json({ error: "Session expired" });
  }

  res.json({
    id: data.user.id,
    email: data.user.email,
  });
});

// 🚪 LOGOUT (ONLY WAY TO LOGOUT)
app.post("/api/logout", (req, res) => {
  res.clearCookie("networx_session", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  });
  res.json({ success: true });
});

// ===========================
//        OTP REGISTER
// ===========================
app.post("/api/send-otp", async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  otpStore.set(email, {
    otp,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  await transporter.sendMail({
    to: email,
    from: `"Networx" <${process.env.SMTP_USER}>`,
    subject: "Networx OTP",
    html: `<h2>Your OTP: ${otp}</h2>`,
  });

  res.json({ success: true });
});

app.post("/api/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const rec = otpStore.get(email);

  if (!rec || rec.otp !== otp || rec.expiresAt < Date.now()) {
    return res.status(400).json({ error: "Invalid OTP" });
  }

  rec.verified = true;
  res.json({ success: true });
});

app.post("/api/set-password", async (req, res) => {
  const { email, password } = req.body;
  const rec = otpStore.get(email);

  if (!rec?.verified) {
    return res.status(400).json({ error: "OTP not verified" });
  }

  await supabase.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
  });

  otpStore.delete(email);
  res.json({ success: true });
});

// ===========================
//      CONNECTION CODES
// ===========================
app.post("/api/generate-connection-code", requireAuth, async (req, res) => {
  const code = Math.random().toString(36).substring(2, 8).toUpperCase();
  const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

  const { data, error } = await supabase
    .from("connection_code")
    .insert({
      code,
      owner_user_id: req.user.id,
      expires_at: expiresAt,
    })
    .select()
    .single();

  if (error) return res.status(500).json({ error: "DB error" });

  res.json({ code: data.code, expiresAt });
});

// ===========================
//        MESSAGING
// ===========================
app.post("/api/send-message", requireAuth, async (req, res) => {
  const { receiverId, content } = req.body;

  await supabase.from("messages").insert({
    sender_id: req.user.id,
    receiver_id: receiverId,
    content,
  });

  res.json({ success: true });
});

app.post("/api/get-messages", requireAuth, async (req, res) => {
  const { partnerId } = req.body;

  const { data } = await supabase
    .from("messages")
    .select("*")
    .or(
      `and(sender_id.eq.${req.user.id},receiver_id.eq.${partnerId}),
       and(sender_id.eq.${partnerId},receiver_id.eq.${req.user.id})`
    )
    .order("created_at");

  res.json({ messages: data });
});

// ===========================
//        START SERVER
// ===========================
const PORT = process.env.PORT || 4012;
server.listen(PORT, () =>
  console.log(`🚀 Networx API running on port ${PORT}`)
);
