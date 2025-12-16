// server.js (Networx Auth + Connection + Messaging Server)
import express from "express";
import nodemailer from "nodemailer";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();
const app = express();
app.use(express.json());

// ===========================
//        CORS
// ===========================
app.use(
  cors({
    origin: [
      "http://localhost:8080",
      "http://localhost:5173",
      "http://localhost:3000",
      "https://networx-dusky.vercel.app",
      "https://chat.networxenterprise.co.in",
    ],
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

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
const connectionCodes = new Map();

// Cleanup expired OTPs and codes every minute
setInterval(() => {
  const now = Date.now();
  for (const [email, rec] of otpStore.entries()) {
    if (rec.expiresAt < now) otpStore.delete(email);
  }
  for (const [code, rec] of connectionCodes.entries()) {
    if (rec.expiresAt && rec.expiresAt < now) connectionCodes.delete(code);
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
    res.status(500).json({ error: "Server error" });
  }
});

// ✉️ Send OTP
app.post("/api/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required" });

  const { data } = await supabase.auth.admin.listUsers();
  const exists = data.users.some((u) => u.email === email);
  if (exists) return res.status(400).json({ error: "Email already registered" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore.set(email, { otp, expiresAt: Date.now() + 5 * 60 * 1000 });

  await sendOtpEmail(email, otp);
  res.json({ message: "OTP sent" });
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

  const { error } = await supabase.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
  });
  if (error) throw error;

  otpStore.delete(email);
  res.json({ success: true });
});

// 🔐 Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) return res.status(401).json({ error: "Invalid credentials" });

  res.json({ success: true, token: data.session.access_token, userId: data.user.id });
});

// ===========================================================
//              CONNECTION CODE SYSTEM
// ===========================================================

function generateShortCode() {
  return Math.random().toString(36).substring(2, 8).toUpperCase();
}

// ===========================
// Generate a connection code
// ===========================
app.post("/api/generate-connection-code", async (req, res) => {
  const { ownerUserId, expirationMinutes = 15 } = req.body;

  if (!ownerUserId) {
    return res.status(400).json({ error: "ownerUserId required" });
  }

  try {
    // 1️⃣ Confirm ownerUserId exists in public.users
    const { data: userCheck, error: userErr } = await supabase
      .from("users")
      .select("id")
      .eq("id", ownerUserId)
      .single();

    if (userErr || !userCheck) {
      return res.status(400).json({ error: "Invalid ownerUserId" });
    }

    // 2️⃣ Generate short code
    const code = Math.random().toString(36).substring(2, 8).toUpperCase();
    const expiresAt = new Date(Date.now() + expirationMinutes * 60 * 1000).toISOString();

    // 3️⃣ Insert into connection_code table
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



// ===========================
// Verify connection code
// ===========================
// app.post("/api/verify-connection-code", async (req, res) => {
//   const { code, verifyingUserId } = req.body;

//   if (!code || !verifyingUserId) {
//     return res.status(400).json({ success: false, message: "code and verifyingUserId required" });
//   }

//   try {
//     // 1️⃣ Fetch the code row (unverified)
//     const { data: codeRow, error: selectError } = await supabase
//       .from("codes")
//       .select("*")
//       .eq("code", code)
//       .eq("verified", false)
//       .maybeSingle(); // safe: returns null if not found

//     if (selectError) throw selectError;
//     if (!codeRow) return res.status(400).json({ success: false, message: "Invalid or already used code" });

//     // 2️⃣ Prevent self-connection
//     if (codeRow.owner_user_id === verifyingUserId) {
//       return res.status(400).json({ success: false, message: "Cannot use your own code" });
//     }

//     // 3️⃣ Check expiry
//     if (codeRow.expires_at && new Date(codeRow.expires_at).getTime() < Date.now()) {
//       return res.status(400).json({ success: false, message: "Code expired" });
//     }

//     // 4️⃣ Mark code as verified
//     const { data: updatedCode, error: updateError } = await supabase
//       .from("codes")
//       .update({ verified: true })
//       .eq("id", codeRow.id)
//       .select()
//       .single();
//     if (updateError) throw updateError;

//     // 5️⃣ Insert into connections table
//     const { data: connection, error: connError } = await supabase
//       .from("connections")
//       .insert({
//         user_a: codeRow.owner_user_id,
//         user_b: verifyingUserId,
//       })
//       .select()
//       .single();
//     if (connError) throw connError;

//     res.json({
//       success: true,
//       connectionId: connection.id,
//       userA: connection.user_a,
//       userB: connection.user_b,
//     });
//   } catch (err) {
//     console.error("verify-connection-code error:", err);
//     res.status(500).json({ success: false, message: "Server error" });
//   }
// });


// Get latest connection code for a user
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

    if (error) {
      console.error("get-latest-code error:", error);
      return res.status(500).json({ error: "Server error" });
    }

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

  const { error } = await supabase.from("messages").insert([{ sender_id: senderId, receiver_id: receiverId, content }]);
  if (error) return res.status(500).json({ error: error.message });

  res.json({ success: true });
});

app.post("/api/get-messages", async (req, res) => {
  const { userId, partnerId } = req.body;
  const { data, error } = await supabase
    .from("messages")
    .select("*")
    .or(`sender_id.eq.${userId},receiver_id.eq.${partnerId}`)
    .order("created_at", { ascending: true });

  if (error) return res.status(500).json({ error: error.message });

  res.json({ messages: data });
});

app.post("/api/read-message", async (req, res) => {
  const { messageId } = req.body;
  await supabase.from("messages").update({ is_read: true }).eq("id", messageId);
  await supabase.from("messages").delete().eq("id", messageId);
  res.json({ success: true });
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
    console.error("Server error fetching user ID:", err);
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
