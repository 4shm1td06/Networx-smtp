import express from "express";
import nodemailer from "nodemailer";
import { createClient } from "@supabase/supabase-js";
import webpush from "web-push";
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
      "http://localhost:3000",
      "http://localhost:8080",
      "https://networx-dusky.vercel.app",
      "https://chat.networxenterprise.co.in",
    ],
    credentials: true,
  })
);

// ===========================
//      Supabase Clients
// ===========================
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const supabaseAuth = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// ===========================
//   Web Push Notifications
// ===========================
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(
    process.env.VAPID_SUBJECT || "mailto:support@networx.com",
    process.env.VAPID_PUBLIC_KEY,
    process.env.VAPID_PRIVATE_KEY
  );
  console.log("✅ Web Push configured");
} else {
  console.warn("⚠️ VAPID keys not configured - push notifications disabled");
}

// ===========================
//      SMTP Setup
// ===========================
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: Number(process.env.SMTP_PORT || 465),
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ===========================
//     In-Memory OTP Store
// ===========================
const otpStore = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [email, rec] of otpStore.entries()) {
    if (rec.expiresAt < now) otpStore.delete(email);
  }
}, 60 * 1000);

// ===========================
//        Auth Routes
// ===========================

// ✅ Check Email
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
  if (data.users.some((u) => u.email === email))
    return res.status(400).json({ error: "Email already registered" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore.set(email, { otp, expiresAt: Date.now() + 5 * 60 * 1000, verified: false });

  await transporter.sendMail({
    from: `"Networx Security" <${process.env.SMTP_USER}>`,
    to: email,
    subject: "Your Networx OTP Code",
    html: `<h2>OTP: ${otp}</h2><p>Expires in 5 minutes</p>`,
  });

  res.json({ success: true });
});

// 🔍 Verify OTP
app.post("/api/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  const rec = otpStore.get(email);
  if (!rec || rec.otp !== otp || rec.expiresAt < Date.now())
    return res.status(400).json({ error: "Invalid or expired OTP" });

  otpStore.set(email, { ...rec, verified: true });
  res.json({ success: true });
});

// 🔑 Create User
app.post("/api/set-password", async (req, res) => {
  const { email, password } = req.body;
  const rec = otpStore.get(email);
  if (!rec || !rec.verified) return res.status(400).json({ error: "Email not verified" });

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

  const { data, error } = await supabaseAuth.auth.signInWithPassword({ email, password });
  if (error) return res.status(401).json({ error: "Invalid credentials" });

  res.json({
    success: true,
    accessToken: data.session.access_token,
    refreshToken: data.session.refresh_token,
    user: { id: data.user.id, email: data.user.email },
  });
});

// 🔑 Current User
app.get("/api/me", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "No token provided" });

  const token = authHeader.replace("Bearer ", "");

  try {
    const { data, error } = await supabaseAuth.auth.getUser(token);

    if (error || !data.user) {
      return res.status(401).json({ error: "Invalid token" });
    }

    res.json({ user: { id: data.user.id, email: data.user.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ===========================
//    Push Notification Routes
// ===========================

// 📱 Subscribe to Push Notifications
app.post("/api/push/subscribe", async (req, res) => {
  try {
    const { subscription } = req.body;

    if (!subscription) {
      return res.status(400).json({ error: "Subscription required" });
    }

    // Get user ID from auth token
    const authHeader = req.headers.authorization;
    let userId = null;

    if (authHeader) {
      const token = authHeader.replace("Bearer ", "");
      try {
        const { data } = await supabaseAuth.auth.getUser(token);
        userId = data.user?.id;
      } catch (err) {
        // User might not be logged in - still save subscription
        console.log("Anonymous subscription");
      }
    }

    // Save subscription to database
    const { error } = await supabaseAdmin.from("push_subscriptions").upsert({
      endpoint: subscription.endpoint,
      auth: subscription.keys?.auth,
      p256dh: subscription.keys?.p256dh,
      user_id: userId,
      created_at: new Date(),
    });

    if (error) {
      console.error("Database error:", error);
      return res.status(500).json({ error: "Failed to save subscription" });
    }

    res.json({ success: true, message: "Subscribed to push notifications" });
  } catch (error) {
    console.error("Subscribe error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// 📤 Send Push Notification to User
app.post("/api/push/send", async (req, res) => {
  try {
    const { userId, title, body, icon, badge, threadId } = req.body;

    if (!userId || !title || !body) {
      return res.status(400).json({ error: "userId, title, and body required" });
    }

    // Get user's push subscriptions
    const { data: subscriptions, error } = await supabaseAdmin
      .from("push_subscriptions")
      .select("*")
      .eq("user_id", userId);

    if (error) {
      console.error("Fetch subscriptions error:", error);
      return res.status(500).json({ error: "Failed to fetch subscriptions" });
    }

    if (!subscriptions || subscriptions.length === 0) {
      return res.json({ success: true, message: "No active subscriptions" });
    }

    const payload = JSON.stringify({
      title,
      body,
      icon: icon || "/icon-192x192.png",
      badge: badge || "/badge-72x72.png",
      data: {
        threadId,
        type: "message",
      },
    });

    let successCount = 0;
    let failureCount = 0;

    // Send to all subscriptions
    for (const sub of subscriptions) {
      try {
        const subscription = {
          endpoint: sub.endpoint,
          keys: {
            auth: sub.auth,
            p256dh: sub.p256dh,
          },
        };

        await webpush.sendNotification(subscription, payload);
        successCount++;
      } catch (pushError: any) {
        console.error("Push error:", pushError.message);

        // If subscription is invalid, remove it
        if (pushError.statusCode === 410) {
          await supabaseAdmin
            .from("push_subscriptions")
            .delete()
            .eq("endpoint", sub.endpoint);
        }

        failureCount++;
      }
    }

    res.json({
      success: true,
      message: `Sent to ${successCount} devices, ${failureCount} failed`,
      sent: successCount,
      failed: failureCount,
    });
  } catch (error) {
    console.error("Send notification error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// ❌ Unsubscribe from Push Notifications
app.post("/api/push/unsubscribe", async (req, res) => {
  try {
    const { endpoint } = req.body;

    if (!endpoint) {
      return res.status(400).json({ error: "Endpoint required" });
    }

    const { error } = await supabaseAdmin
      .from("push_subscriptions")
      .delete()
      .eq("endpoint", endpoint);

    if (error) {
      console.error("Delete error:", error);
      return res.status(500).json({ error: "Failed to unsubscribe" });
    }

    res.json({ success: true, message: "Unsubscribed from push notifications" });
  } catch (error) {
    console.error("Unsubscribe error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

const PORT = process.env.PORT || 4012;
app.listen(PORT, () => console.log(`🚀 Networx API running on port ${PORT}`));

export default app;
