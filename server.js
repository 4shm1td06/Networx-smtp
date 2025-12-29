// server.js (Networx Auth + Connection + Messaging Server)
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
const allowedOrigins = [
  "http://localhost:8080",
  "http://localhost:5173",
  "http://localhost:3000",
  "https://networx-dusky.vercel.app",
  "https://chat.networxenterprise.co.in",
];

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Handle preflight requests
app.options("*", (req, res) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type,Authorization");
  res.sendStatus(200);

// ===========================
//      Supabase Setup
// ===========================
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

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

// Cleanup expired OTPs every minute
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
        <p>Hello,</p>
        <p>Your OTP is:</p>
        <div style="text-align:center;margin:20px 0;">
          <span style="background:#2563eb;color:white;padding:10px 20px;font-size:22px;border-radius:6px;">${otp}</span>
        </div>
        <p>This code expires in 5 minutes.</p>
      </div>
    </div>`;
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

  try {
    const { data, error } = await supabase.auth.admin.listUsers();
    if (error) throw error;
    const exists = data.users.some((u) => u.email === email);
    res.json({ exists });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ✉️ Send OTP
app.post("/api/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  try {
    const { data } = await supabase.auth.admin.listUsers();
    const exists = data.users.some((u) => u.email === email);
    if (exists) return res.status(400).json({ error: "Email already registered" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore.set(email, { otp, expiresAt: Date.now() + 5 * 60 * 1000 });

    await sendOtpEmail(email, otp);
    res.json({ message: "OTP sent" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// 🔍 Verify OTP
app.post("/api/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const rec = otpStore.get(email);
  if (!rec || rec.otp !== otp) return res.status(400).json({ error: "Invalid or expired OTP" });

  otpStore.set(email, { ...rec, verified: true });
  res.json({ success: true });
});

// 🔑 Set Password (Create User)
app.post("/api/set-password", async (req, res) => {
  const { email, password } = req.body;
  const rec = otpStore.get(email);
  if (!rec || !rec.verified) return res.status(400).json({ error: "Email not verified" });

  try {
    const { error } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
    });
    if (error) throw error;

    otpStore.delete(email);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// 🔐 Login with Cookie
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return res.status(401).json({ error: "Invalid credentials" });

    res.cookie("networx_token", data.session.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "None",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ success: true, userId: data.user.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ Get logged-in user
app.get("/api/me", async (req, res) => {
  const token = req.cookies.networx_token;
  if (!token) return res.status(401).json({ error: "Not logged in" });

  try {
    const { data: user, error } = await supabase.auth.getUser(token);
    if (error) return res.status(401).json({ error: "Invalid token" });

    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ✅ Logout
app.post("/api/logout", (req, res) => {
  res.clearCookie("networx_token");
  res.json({ success: true });
});

// ===========================================================
//              CONNECTION CODE SYSTEM
// ===========================================================
app.post("/api/generate-connection-code", async (req, res) => {
  const { ownerUserId, expirationMinutes = 15 } = req.body;
  if (!ownerUserId) return res.status(400).json({ error: "ownerUserId required" });

  try {
    const { data: userCheck, error: userErr } = await supabase
      .from("users")
      .select("id")
      .eq("id", ownerUserId)
      .single();
    if (userErr || !userCheck) return res.status(400).json({ error: "Invalid ownerUserId" });

    const code = Math.random().toString(36).substring(2, 8).toUpperCase();
    const expiresAt = new Date(Date.now() + expirationMinutes * 60 * 1000).toISOString();

    const { data: inserted, error: insertError } = await supabase
      .from("connection_code")
      .insert({
        code,
        owner_user_id: ownerUserId,
        verified: false,
        expires_at: expiresAt,
      })
      .select()
      .single();
    if (insertError) throw insertError;

    res.json({
      code: inserted.code,
      expiresAt: inserted.expires_at,
      codeId: inserted.id,
    });
  } catch (err) {
    console.error("generate-connection-code error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/get-latest-code", async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "userId required" });

  try {
    const { data, error } = await supabase
      .from("connection_code")
      .select("*")
      .eq("owner_user_id", userId)
      .order("created_at", { ascending: false })
      .limit(1)
      .single();
    if (error) return res.status(500).json({ error: "Server error" });
    if (!data) return res.status(404).json({ error: "No code found" });

    res.json({ codeData: data });
  } catch (err) {
    console.error("get-latest-code exception:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ===========================================================
//                    MESSAGING SYSTEM
// ===========================================================
app.post("/api/send-message", async (req, res) => {
  const { senderId, receiverId, content } = req.body;
  if (!senderId || !receiverId || !content) return res.status(400).json({ error: "Missing fields" });

  try {
    const { error } = await supabase
      .from("messages")
      .insert([{ sender_id: senderId, receiver_id: receiverId, content }]);
    if (error) throw error;

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Fetch all messages between two users
app.post("/api/get-messages", async (req, res) => {
  const { userId, partnerId } = req.body;
  if (!userId || !partnerId) return res.status(400).json({ error: "Missing fields" });

  try {
    const { data, error } = await supabase
      .from("messages")
      .select("*")
      .or(
        `(sender_id.eq.${userId},receiver_id.eq.${partnerId}),(sender_id.eq.${partnerId},receiver_id.eq.${userId})`
      )
      .order("created_at", { ascending: true });
    if (error) throw error;

    res.json({ messages: data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Mark message read & delete
app.post("/api/read-message", async (req, res) => {
  const { messageId } = req.body;
  try {
    await supabase.from("messages").update({ is_read: true }).eq("id", messageId);
    await supabase.from("messages").delete().eq("id", messageId);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- Get public.users ID by email ---
app.post("/api/get-user-id", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  try {
    const { data, error } = await supabase
      .from("users")
      .select("id")
      .eq("email", email)
      .single();
    if (error || !data) return res.status(404).json({ error: "User not found" });
    res.json({ id: data.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ===========================================================
//                START SERVER
// ===========================================================
const PORT = process.env.PORT || 4012;
if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => console.log(`🚀 Networx API running on ${PORT}`));
}

export default app;
