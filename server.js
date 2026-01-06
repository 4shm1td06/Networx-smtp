// server.js — Networx Auth + Connection (FIXED)

import express from "express";
import nodemailer from "nodemailer";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";

dotenv.config();
const app = express();

app.use(express.json());
app.use(cookieParser());

// ===========================
//        CORS
// ===========================
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://localhost:5173",
      "http://localhost:8080",
      "https://networx-dusky.vercel.app",
      "https://chat.networxenterprise.co.in",
      "https://networx-smtp.vercel.app",
    ],
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ===========================
//      Supabase Clients
// ===========================

// 🔐 Admin (SERVICE ROLE — RLS bypass)
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// 👤 Auth (ANON — normal users)
const supabaseAuth = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// ===========================
//      SMTP Setup
// ===========================
const smtpPort = Number(process.env.SMTP_PORT || 465);
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: smtpPort,
  secure: smtpPort === 465,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ===========================
//     In-Memory Stores
// ===========================
const otpStore = new Map();

// Cleanup OTPs
setInterval(() => {
  const now = Date.now();
  for (const [email, rec] of otpStore.entries()) {
    if (rec.expiresAt < now) otpStore.delete(email);
  }
}, 60 * 1000);

// ===========================
//        Send OTP Email
// ===========================
async function sendOtpEmail(email, otp) {
  const html = `
    <div style="font-family:sans-serif;background:#f9fafb;padding:20px;">
      <div style="max-width:500px;margin:auto;background:white;padding:25px;border-radius:8px;">
        <h2 style="color:#2563eb;">Networx Verification Code</h2>
        <p>Your OTP is:</p>
        <div style="text-align:center;margin:20px 0;">
          <span style="background:#2563eb;color:white;padding:10px 20px;font-size:22px;border-radius:6px;">
            ${otp}
          </span>
        </div>
        <p>This code expires in 5 minutes.</p>
      </div>
    </div>
  `;
  await transporter.sendMail({
    from: `"Networx Security" <${process.env.SMTP_USER}>`,
    to: email,
    subject: "Your Networx OTP Code",
    html,
  });
}

// ===========================================================
//                    AUTH ROUTES
// ===========================================================

// 🔍 Check Email
app.post("/api/check-email", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  const { data, error } = await supabaseAdmin.auth.admin.listUsers();
  if (error) return res.status(500).json({ error: "Server error" });

  const exists = data.users.some((u) => u.email === email);
  res.json({ exists });
});

// ✉️ Send OTP
app.post("/api/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  const { data } = await supabaseAdmin.auth.admin.listUsers();
  if (data.users.some((u) => u.email === email)) {
    return res.status(400).json({ error: "Email already registered" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore.set(email, {
    otp,
    expiresAt: Date.now() + 5 * 60 * 1000,
    verified: false,
  });

  await sendOtpEmail(email, otp);
  res.json({ success: true });
});

// 🔍 Verify OTP
app.post("/api/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const rec = otpStore.get(email);

  if (!rec || rec.otp !== otp || rec.expiresAt < Date.now()) {
    return res.status(400).json({ error: "Invalid or expired OTP" });
  }

  otpStore.set(email, { ...rec, verified: true });
  res.json({ success: true });
});

// 🔑 Create User
app.post("/api/set-password", async (req, res) => {
  const { email, password } = req.body;
  const rec = otpStore.get(email);

  if (!rec || !rec.verified) {
    return res.status(400).json({ error: "Email not verified" });
  }

  const { error } = await supabaseAdmin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
  });

  if (error) return res.status(500).json({ error: "User creation failed" });

  otpStore.delete(email);
  res.json({ success: true });
});

// 🔐 Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const { data, error } = await supabaseAuth.auth.signInWithPassword({
    email,
    password,
  });

  if (error) return res.status(401).json({ error: "Invalid credentials" });

  const maxAge = 10 * 365 * 24 * 60 * 60 * 1000;

  res.cookie("networx_token", data.session.access_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "None",
    maxAge,
  });

  res.cookie("networx_refresh", data.session.refresh_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "None",
    maxAge,
  });

  res.json({ success: true });
});

// 🔑 Current User (FIXED)
app.get("/api/me", async (req, res) => {
  const accessToken = req.cookies.networx_token;
  const refreshToken = req.cookies.networx_refresh;

  if (!accessToken && !refreshToken) {
    return res.status(401).json({ error: "Not logged in" });
  }

  try {
    const supabaseUser = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY,
      {
        global: {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        },
      }
    );

    let { data, error } = await supabaseUser.auth.getUser();

    if (error && refreshToken) {
      const { data: refreshed } =
        await supabaseUser.auth.refreshSession({
          refresh_token: refreshToken,
        });

      data = { user: refreshed.user };

      const maxAge = 10 * 365 * 24 * 60 * 60 * 1000;

      res.cookie("networx_token", refreshed.session.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "None",
        maxAge,
      });

      res.cookie("networx_refresh", refreshed.session.refresh_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "None",
        maxAge,
      });
    }

    if (!data?.user) {
      return res.status(401).json({ error: "Not logged in" });
    }

    res.json({ user: data.user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// 🔓 Logout
app.post("/api/logout", (req, res) => {
  res.clearCookie("networx_token", { sameSite: "None", secure: true });
  res.clearCookie("networx_refresh", { sameSite: "None", secure: true });
  res.json({ success: true });
});

// ===========================================================
//                START SERVER
// ===========================================================
const PORT = process.env.PORT || 4012;
if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () =>
    console.log(`🚀 Networx API running on port ${PORT}`)
  );
}

export default app;
