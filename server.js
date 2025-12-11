// server.js (Networx Auth + Connection Server)
import express from "express";
import nodemailer from "nodemailer";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config();
const app = express();
app.use(express.json());

// ✅ CORS setup (local + prod)
app.use(
    cors({
        origin: ["http://localhost:8080", "https://networx-dusky.vercel.app"],
        methods: ["GET", "POST", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);

// 🔐 Supabase setup
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY
);

// 📧 SMTP setup (for OTP)
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

// 🔢 In-memory OTP + Code Stores
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

// ✉️ Helper - Send OTP
async function sendOtpEmail(email, otp) {
    const html = `
  <div style="font-family:sans-serif;background:#f9fafb;padding:20px;">
    <div style="max-width:500px;margin:auto;background:white;padding:25px;border-radius:8px;">
      <h2 style="color:#2563eb;">Networx Verification Code</h2>
      <p>Hello,</p>
      <p>Use the OTP below to verify your email and continue:</p>
      <div style="text-align:center;margin:20px 0;">
        <span style="background:#2563eb;color:white;padding:10px 20px;font-size:22px;border-radius:6px;">${otp}</span>
      </div>
      <p>This code will expire in <strong>5 minutes</strong>.</p>
      <hr style="margin-top:30px;">
      <p style="font-size:13px;color:#888;">— Networx Security Team</p>
    </div>
  </div>`;
    await transporter.sendMail({
        from: `"Networx Security" <${process.env.SMTP_USER}>`,
        to: email,
        subject: "Your Networx OTP Code",
        html,
    });
}

//
// =======================
//  AUTH ROUTES (your original code)
// =======================
//

app.post("/api/check-email", async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });
    try {
        const { data, error } = await supabase.auth.admin.listUsers();
        if (error) throw error;
        const exists = data.users.some((u) => u.email === email);
        res.json({ exists });
    } catch (err) {
        console.error("check-email error:", err.message);
        res.status(500).json({ error: "Server error" });
    }
});

app.post("/api/send-otp", async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });
    try {
        const { data, error } = await supabase.auth.admin.listUsers();
        if (error) throw error;
        const exists = data.users.some((u) => u.email === email);
        if (exists)
            return res.status(400).json({ error: "Email already registered" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpStore.set(email, { otp, expiresAt: Date.now() + 5 * 60 * 1000 });

        await sendOtpEmail(email, otp);
        console.log(`✅ OTP sent to ${email}`);
        res.json({ message: "OTP sent successfully" });
    } catch (err) {
        console.error("send-otp error:", err.message);
        res.status(500).json({ error: "Failed to send OTP" });
    }
});

app.post("/api/verify-otp", async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp)
        return res.status(400).json({ error: "Email and OTP required" });

    const record = otpStore.get(email);
    if (!record) return res.status(400).json({ error: "OTP expired or not found" });
    if (record.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });

    otpStore.set(email, { ...record, verified: true });
    console.log(`✅ Email verified: ${email}`);
    res.json({ success: true, message: "Email verified successfully" });
});

app.post("/api/set-password", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: "Email and password required" });

    const record = otpStore.get(email);
    if (!record || !record.verified)
        return res.status(400).json({ error: "Email not verified" });

    try {
        const { error } = await supabase.auth.admin.createUser({
            email,
            password,
            email_confirm: true,
        });
        if (error) throw error;

        otpStore.delete(email);
        console.log(`✅ New user created: ${email}`);
        res.json({ success: true });
    } catch (err) {
        console.error("set-password error:", err.message);
        res.status(500).json({ error: "Failed to register user" });
    }
});

app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: "Email and password required" });

    try {
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        res.json({ success: true, token: data.session.access_token });
    } catch (err) {
        console.error("login error:", err.message);
        res.status(401).json({ error: "Invalid credentials" });
    }
});

//
// =======================
//  CONNECTION CODE ROUTES
// =======================
//

// Generate new connection code
app.post("/api/generate-connection-code", async (req, res) => {
    try {
        const { userId, expirationMinutes, maxUses, isPermanent } = req.body;
        if (!userId) return res.status(400).json({ error: "userId required" });

        const code = Math.random().toString(36).substring(2, 8).toUpperCase();
        const expiresAt = isPermanent
            ? null
            : Date.now() + (expirationMinutes || 15) * 60 * 1000;

        connectionCodes.set(code, {
            userId,
            isPermanent,
            maxUses: maxUses || null,
            currentUses: 0,
            expiresAt,
        });

        console.log(`✅ Connection code generated for ${userId}: ${code}`);

        res.json({ code, expiresAt, isPermanent });
    } catch (err) {
        console.error("generate-connection-code error:", err);
        res.status(500).json({ error: "Failed to generate connection code" });
    }
});

// Verify a connection code
app.post("/api/verify-connection-code", async (req, res) => {
    try {
        const { code, requestingUserId } = req.body;
        if (!code || !requestingUserId)
            return res.status(400).json({ error: "Missing code or requestingUserId" });

        const record = connectionCodes.get(code);
        if (!record) return res.status(400).json({ success: false, message: "Invalid or expired code" });

        // Check expiry and usage limits
        if (record.expiresAt && Date.now() > record.expiresAt) {
            connectionCodes.delete(code);
            return res.status(400).json({ success: false, message: "Code expired" });
        }

        if (record.maxUses && record.currentUses >= record.maxUses) {
            connectionCodes.delete(code);
            return res.status(400).json({ success: false, message: "Code usage limit reached" });
        }

        record.currentUses += 1;
        connectionCodes.set(code, record);

        // (Optional) You can store this connection in Supabase
        await supabase.from("connections").insert([
            {
                user_id: record.userId,
                connected_user_id: requestingUserId,
                created_at: new Date().toISOString(),
            },
        ]);

        console.log(`✅ Code verified: ${code}, used by ${requestingUserId}`);
        res.json({
            success: true,
            connection: {
                name: "New Connection",
                code,
                connectedUser: requestingUserId,
            },
        });
    } catch (err) {
        console.error("verify-connection-code error:", err);
        res.status(500).json({ error: "Failed to verify connection code" });
    }
});

//
// 🚀 Start Server
//
const PORT = process.env.PORT || 4012;
if (process.env.NODE_ENV !== "production") {
    app.listen(PORT, () => console.log(`✅ Networx API running on port ${PORT}`));
}

export default app;
