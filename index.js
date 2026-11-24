const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const nodemailer = require("nodemailer");
const { default: z } = require("zod");
require("dotenv").config();

// ==========================================
// 1. APP CONFIGURATION
// ==========================================

const app = express();
const PORT = process.env.PORT || 5000;

app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    credentials: true,
  })
);

app.use(express.json());

// ==========================================
// 2. MONGODB CONFIGURATION
// ==========================================

const client = new MongoClient(process.env.MONGODB_URI, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
});

const database = client.db(process.env.DB_NAME);

let cachedClient = null;
let connectPromise = null;

// Collection references
let usersCollection;
let ticketsCollection;
let bookingsCollection;
let disputesCollection;
let auditLogsCollection;
let sessionCollection;
let otpsCollection;

// Connect to MongoDB
async function connectToMongoDB() {
  if (cachedClient) {
    return cachedClient;
  }

  if (connectPromise) {
    return connectPromise;
  }

  connectPromise = (async () => {
    try {
      await client.connect();

      // Initialize database collections
      usersCollection = database.collection("users");
      ticketsCollection = database.collection("tickets");
      bookingsCollection = database.collection("bookings");
      disputesCollection = database.collection("disputes");
      auditLogsCollection = database.collection("audit_logs");
      sessionCollection = database.collection("session");
      otpsCollection = database.collection("otps");

      cachedClient = client;

      console.log("MongoDB connected successfully.");

      return client;
    } catch (err) {
      connectPromise = null;
      throw err;
    }
  })();

  return connectPromise;
}

// Ensure database connection before handling requests
app.use(async (req, res, next) => {
  try {
    await connectToMongoDB();
    next();
  } catch (err) {
    console.error("Database initialization failed:", err);

    res.status(500).send({
      message: "Database connection failed.",
    });
  }
});

// ==========================================
// 3. NODEMAILER CONFIGURATION
// ==========================================

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.example.com",
  port: Number(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendNotificationEmail({ to, subject, html }) {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.log(
      `[Email Skipped - No SMTP Config] To: ${to} | Subject: ${subject}`
    );
    return;
  }

  try {
    await transporter.sendMail({
      from: `"Train Ticket Exchange" <${process.env.SMTP_USER}>`,
      to,
      subject,
      html,
    });
  } catch (mailErr) {
    console.error("Nodemailer send error:", mailErr.message);
  }
}

// ==========================================
// 4. COMMON MIDDLEWARE
// ==========================================

// Logger middleware
const logger = (req, res, next) => {
  console.log("logger logged", req.method, req.url);
  next();
};

app.use(logger);

// Verify token / active Better-Auth session
const verifyToken = async (req, res, next) => {
  try {
    let token = null;

    // 1. Check Bearer token from Authorization header
    const authHeader = req.headers?.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    }

    // 2. Fallback: Check Better-Auth session cookie
    if (!token && req.headers?.cookie) {
      const cookies = Object.fromEntries(
        req.headers.cookie.split(";").map((cookie) => {
          const [key, ...value] = cookie.trim().split("=");
          return [key, decodeURIComponent(value.join("="))];
        })
      );

      const rawCookie =
        cookies["better-auth.session_token"] ||
        cookies["__Secure-better-auth.session_token"];

      if (rawCookie) {
        token = rawCookie.split(".")[0];
      }
    }

    if (!token) {
      return res.status(401).send({ message: "Unauthorized Access." });
    }

    const session = await sessionCollection.findOne({ token: token });

    if (
      !session ||
      (session.expiresAt && new Date(session.expiresAt) < new Date())
    ) {
      return res.status(401).send({ message: "Unauthorized Access." });
    }

    // Support both ObjectId and string user IDs from Better-Auth
    const userFilter = ObjectId.isValid(session.userId)
      ? {
        $or: [
          { _id: new ObjectId(session.userId) },
          { _id: session.userId },
        ],
      }
      : { _id: session.userId };

    const user = await usersCollection.findOne(userFilter);

    if (!user) {
      return res.status(401).send({ message: "Unauthorized Access." });
    }

    req.user = user;
    req.session = session;
    next();
  } catch (err) {
    console.error("Auth error:", err);
    return res.status(401).send({ message: "Unauthorized Access." });
  }
};

// Authentication middleware
const requireAuth = async (req, res, next) => {
  try {
    let token = null;

    // 1. Check Bearer token from Authorization header
    const authHeader = req.headers?.authorization;

    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    }

    // 2. Fallback: Check Better Auth session cookie
    if (!token && req.headers?.cookie) {
      const cookies = Object.fromEntries(
        req.headers.cookie.split(";").map((cookie) => {
          const [key, ...value] = cookie.trim().split("=");

          return [key, decodeURIComponent(value.join("="))];
        })
      );

      const rawCookie =
        cookies["better-auth.session_token"] ||
        cookies["__Secure-better-auth.session_token"];

      if (rawCookie) {
        token = rawCookie.split(".")[0];
      }
    }

    if (!token) {
      return res.status(401).send({
        message: "Unauthorized Access.",
      });
    }

    // Find session
    const session = await sessionCollection.findOne({ token });

    if (
      !session ||
      (session.expiresAt && new Date(session.expiresAt) < new Date())
    ) {
      return res.status(401).send({
        message: "Session expired or invalid.",
      });
    }

    // Support both ObjectId and string user IDs
    const userFilter = ObjectId.isValid(session.userId)
      ? {
        $or: [
          { _id: new ObjectId(session.userId) },
          { _id: session.userId },
        ],
      }
      : { _id: session.userId };

    const user = await usersCollection.findOne(userFilter);

    if (!user) {
      return res.status(401).send({
        message: "Unauthorized Access.",
      });
    }

    req.user = user;
    req.session = session;

    next();
  } catch (err) {
    console.error("Authentication error:", err);

    return res.status(401).send({
      message: "Unauthorized Access.",
    });
  }
};

// Role-specific guards adapted for Train Ticket Exchange
const verifyBuyer = async (req, res, next) => {
  if (!["buyer", "seller", "admin"].includes(req.user?.role)) {
    return res.status(403).send({ message: "forbidden access." });
  }
  next();
};

const verifySeller = async (req, res, next) => {
  if (req.user?.role !== "seller" && req.user?.role !== "admin") {
    return res.status(403).send({ message: "forbidden access." });
  }
  next();
};

const verifyAdmin = async (req, res, next) => {
  if (req.user?.role !== "admin") {
    return res.status(403).send({ message: "forbidden access." });
  }
  next();
};

// Dynamic role guard helper
const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).send({
        message: "forbidden access.",
      });
    }
    next();
  };
};

// Seller NID KYC verification middleware
const verifyVerifiedSeller = (req, res, next) => {
  if (req.user?.kycStatus !== "verified" && req.user?.role !== "admin") {
    return res.status(403).send({
      message: "NID verification required to list tickets.",
    });
  }
  next();
};

// ==========================================
// 5. TASK 2.2: AUTHENTICATION VERIFICATION
// ==========================================

// Get current authenticated user
app.get("/api/me", requireAuth, (req, res) => {
  res.send({
    id: req.user._id,
    name: req.user.name,
    email: req.user.email,
    phone: req.user.phone,
    role: req.user.role || "buyer",
    kycStatus: req.user.kycStatus || "unverified",
    walletBalance: req.user.walletBalance || 0,
  });
});

// ==========================================
// 6. TASK 2.4: SELLER NID VERIFICATION (KYC)
// ==========================================

// KYC validation schema
const kycSchema = z.object({
  nidNumber: z
    .string()
    .trim()
    .regex(
      /^(\d{10}|\d{13}|\d{17})$/,
      "NID must be 10, 13, or 17 digits."
    ),

  nidPhotoUrl: z
    .string()
    .url("Valid NID photo URL is required."),

  selfieUrl: z
    .string()
    .url("Valid selfie photo URL is required."),
});

// 1. Seller submits NID and selfie
app.post("/api/kyc", requireAuth, async (req, res) => {
  try {
    const parsed = kycSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).send({
        message:
          parsed.error.issues[0]?.message || "Invalid KYC details.",
      });
    }

    if (req.user.kycStatus === "verified") {
      return res.status(400).send({
        message: "Your account is already NID verified.",
      });
    }

    const { nidNumber, nidPhotoUrl, selfieUrl } = parsed.data;

    // Prevent duplicate NID numbers
    const duplicateNid = await usersCollection.findOne({
      "nidData.nidNumber": nidNumber,
      _id: { $ne: req.user._id },
    });

    if (duplicateNid) {
      return res.status(409).send({
        message:
          "This NID number is already registered with another account.",
      });
    }

    const nidPayload = {
      nidNumber,
      nidPhotoUrl,
      selfieUrl,
      submittedAt: new Date(),
      rejectionReason: null,
    };

    await usersCollection.updateOne(
      { _id: req.user._id },
      {
        $set: {
          kycStatus: "pending",
          nidData: nidPayload,
          updatedAt: new Date(),
        },
      }
    );

    res.send({
      message: "KYC documents submitted for admin review.",
      kycStatus: "pending",
      nidData: nidPayload,
    });
  } catch (err) {
    console.error("KYC submission error:", err);

    res.status(500).send({
      message: "Failed to submit KYC documents.",
    });
  }
});

// 2. Admin fetches KYC submissions
app.get(
  "/api/admin/kyc",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const statusFilter = req.query.status || "pending";

      const query =
        statusFilter === "all"
          ? {
            kycStatus: {
              $in: ["pending", "verified", "rejected"],
            },
          }
          : { kycStatus: statusFilter };

      const applicants = await usersCollection
        .find(query, {
          projection: {
            password: 0,
          },
        })
        .sort({
          "nidData.submittedAt": -1,
          createdAt: -1,
        })
        .toArray();

      res.send(applicants);
    } catch (err) {
      console.error("Fetch admin KYC error:", err);

      res.status(500).send({
        message: "Failed to load KYC queue.",
      });
    }
  }
);

// 3. Admin approves or rejects KYC
app.patch(
  "/api/admin/kyc/:userId",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { action, rejectionReason } = req.body;

      if (!["approve", "reject"].includes(action)) {
        return res.status(400).send({
          message: "Action must be 'approve' or 'reject'.",
        });
      }

      if (action === "reject" && !rejectionReason?.trim()) {
        return res.status(400).send({
          message: "Please provide a reason when rejecting KYC.",
        });
      }

      const userFilter = ObjectId.isValid(userId)
        ? {
          $or: [
            { _id: new ObjectId(userId) },
            { _id: userId },
          ],
        }
        : { _id: userId };

      const targetUser = await usersCollection.findOne(userFilter);

      if (!targetUser) {
        return res.status(404).send({
          message: "User not found.",
        });
      }

      const nextKycStatus =
        action === "approve" ? "verified" : "rejected";

      const nextRole =
        action === "approve" && targetUser.role === "buyer"
          ? "seller"
          : targetUser.role;

      await usersCollection.updateOne(userFilter, {
        $set: {
          kycStatus: nextKycStatus,
          role: nextRole,
          "nidData.reviewedAt": new Date(),
          "nidData.reviewedBy": req.user._id,
          "nidData.rejectionReason":
            action === "reject" ? rejectionReason.trim() : null,
          updatedAt: new Date(),
        },
      });

      // Save audit log
      await auditLogsCollection.insertOne({
        action:
          action === "approve" ? "KYC_APPROVED" : "KYC_REJECTED",
        adminId: req.user._id,
        adminEmail: req.user.email,
        targetUserId: targetUser._id,
        targetUserEmail: targetUser.email,
        details: {
          nextKycStatus,
          rejectionReason:
            action === "reject" ? rejectionReason.trim() : null,
        },
        createdAt: new Date(),
      });

      // Send email notification
      if (targetUser.email) {
        await sendNotificationEmail({
          to: targetUser.email,

          subject:
            action === "approve"
              ? "NID Verified — You can now list tickets on Train Ticket Exchange"
              : "NID Verification Update — Train Ticket Exchange",

          html:
            action === "approve"
              ? `<p>Hi <strong>${targetUser.name}</strong>,</p>
                 <p>Your NID verification has been <strong>approved</strong>!
                 You can now list unused train tickets safely on Train Ticket Exchange.</p>`
              : `<p>Hi <strong>${targetUser.name}</strong>,</p>
                 <p>Your NID submission was <strong>rejected</strong> for the following reason:
                 <em>${rejectionReason.trim()}</em>.</p>
                 <p>Please re-submit clear photos from your profile.</p>`,
        });
      }

      res.send({
        message: `Seller KYC ${nextKycStatus} successfully.`,
        kycStatus: nextKycStatus,
      });
    } catch (err) {
      console.error("Admin KYC review error:", err);

      res.status(500).send({
        message: "Failed to update KYC status.",
      });
    }
  }
);

// ==========================================
// 7. TASK 2.3: EMAIL OTP VERIFICATION
// ==========================================

// 1. Send 6-digit OTP to user's email
app.post("/api/auth/send-otp", async (req, res) => {
  try {
    const { email, phone } = req.body;

    if (!email) {
      return res.status(400).send({
        message: "Email is required to send OTP.",
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const otpCode = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    // OTP expires after 5 minutes
    const expiredAt = new Date(Date.now() + 5 * 60 * 1000);

    await otpsCollection.updateOne(
      { email: cleanEmail },
      {
        $set: {
          email: cleanEmail,
          phone: phone || null,
          otp: otpCode,
          verified: false,
          expiredAt,
          createdAt: new Date(),
        },
      },
      { upsert: true }
    );

    await sendNotificationEmail({
      to: cleanEmail,
      subject: `${otpCode} is your Train Ticket Exchange verification code`,

      html: `
        <div style="font-family: sans-serif; padding: 16px;">
          <h2>Train Ticket Exchange Verification</h2>
          <p>Your 6-digit OTP code is:</p>

          <p style="
            font-size: 28px;
            font-weight: bold;
            letter-spacing: 4px;
            color: #059669;
          ">
            ${otpCode}
          </p>

          <p>This code expires in 5 minutes.</p>
        </div>
      `,
    });

    res.send({
      message: "OTP sent to your email.",
    });
  } catch (err) {
    console.error("Send OTP error:", err);

    res.status(500).send({
      message: "Failed to send OTP.",
    });
  }
});

// 2. Verify 6-digit OTP
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).send({
        message: "Email and OTP are required.",
      });
    }

    const record = await otpsCollection.findOne({
      email: email.trim().toLowerCase(),
      otp: otp.trim(),
    });

    if (!record || new Date(record.expiredAt) < new Date()) {
      return res.status(400).send({
        message: "Invalid or expired OTP code.",
      });
    }

    await otpsCollection.updateOne(
      { _id: record._id },
      {
        $set: {
          verified: true,
        },
      }
    );

    res.send({
      verified: true,
      message: "OTP verified successfully.",
    });
  } catch (err) {
    console.error("Verify OTP error:", err);

    res.status(500).send({
      message: "OTP verification failed.",
    });
  }
});

// 3. Resolve email by mobile number
app.post("/api/auth/resolve-identifier", async (req, res) => {
  try {
    const { identifier } = req.body;

    if (!identifier) {
      return res.status(400).send({
        message: "Email or mobile number is required.",
      });
    }

    const trimmed = identifier.trim();

    // If identifier is already an email
    if (trimmed.includes("@")) {
      return res.send({
        email: trimmed.toLowerCase(),
      });
    }

    // Find account using mobile number
    const user = await usersCollection.findOne({
      phone: trimmed,
    });

    if (!user) {
      return res.status(404).send({
        message: "No account found with this mobile number.",
      });
    }

    res.send({
      email: user.email,
    });
  } catch (err) {
    console.error("Resolve identifier error:", err);

    res.status(500).send({
      message: "Failed to look up account.",
    });
  }
});

// ==========================================
// 8. TASK 3.1: CREATE TICKET LISTING ENDPOINT
// ==========================================

const createTicketSchema = z.object({
  trainName: z.string().trim().min(2, "Train name is required"),
  trainNumber: z.string().trim().min(2, "Train number is required"),
  seatClass: z.string().trim().min(2, "Seat class is required").default("S_CHAIR"),
  fromStation: z.string().trim().min(2, "Departure station is required"),
  toStation: z.string().trim().min(2, "Destination station is required"),
  journeyDate: z
    .string()
    .trim()
    .regex(/^\d{4}-\d{2}-\d{2}$/, "Journey date must be YYYY-MM-DD"),
  departureTime: z.string().trim().min(2, "Departure time is required"),
  coach: z.string().trim().min(1, "Coach name is required"),
  seatNumber: z.string().trim().min(1, "Seat number is required"),
  pnr: z.string().trim().min(6, "Valid PNR number is required"),
  fare: z.coerce.number().positive("Fare must be greater than 0"),
  ticketFileUrl: z.string().url("Valid ticket image/PDF URL is required"),
});

// 1. POST /api/tickets — Create new ticket listing (NID-verified sellers only)
app.post("/api/tickets", requireAuth, verifyVerifiedSeller, async (req, res) => {
  try {
    // 1. Validate incoming payload with Zod
    const parsed = createTicketSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).send({
        message: parsed.error.issues[0]?.message || "Invalid ticket details.",
        errors: parsed.error.issues,
      });
    }

    const data = parsed.data;

    // 2. Reject identical origin and destination stations
    if (data.fromStation.toLowerCase() === data.toStation.toLowerCase()) {
      return res.status(400).send({
        message: "Departure and destination stations cannot be the same.",
      });
    }

    // 3. Reject expired / past journey dates (Bangladesh Time UTC+6)
    const todayBdt = new Date(Date.now() + 6 * 60 * 60 * 1000)
      .toISOString()
      .split("T")[0];
    if (data.journeyDate < todayBdt) {
      return res.status(400).send({
        message: "Cannot list a ticket for a past journey date.",
      });
    }

    // 4. Reject duplicate PNRs across active/pending/sold listings
    const cleanPnr = data.pnr.toUpperCase();
    const existingTicket = await ticketsCollection.findOne({
      pnr: cleanPnr,
      status: { $in: ["pending_approval", "available", "locked", "sold"] },
    });

    if (existingTicket) {
      return res.status(409).send({
        message: "A ticket with this PNR is already listed on the marketplace.",
      });
    }

    // 5. Insert ticket document with status: "pending_approval"
    const now = new Date();
    const newTicket = {
      sellerId: req.user._id.toString(),
      sellerName: req.user.name,
      sellerVerified: true,
      trainName: data.trainName,
      trainNumber: data.trainNumber,
      seatClass: data.seatClass.toUpperCase(),
      fromStation: data.fromStation,
      toStation: data.toStation,
      journeyDate: data.journeyDate,
      departureTime: data.departureTime,
      coach: data.coach.toUpperCase(),
      seatNumber: data.seatNumber.toUpperCase(),
      pnr: cleanPnr,
      fare: data.fare,
      platformFee: 25, // Flat BDT 25 escrow service fee
      ticketFileUrl: data.ticketFileUrl,
      status: "pending_approval",
      lockedBy: null,
      lockedUntil: null,
      createdAt: now,
      updatedAt: now,
    };

    const result = await ticketsCollection.insertOne(newTicket);

    // 6. Send confirmation email via Nodemailer
    if (req.user.email) {
      await sendNotificationEmail({
        to: req.user.email,
        subject: `Ticket Submitted for Review — ${data.trainName} (${data.journeyDate})`,
        html: `
          <div style="font-family: sans-serif; padding: 16px;">
            <h2>Ticket Listing Received</h2>
            <p>Hi ${req.user.name},</p>
            <p>Your ticket for <strong>${data.trainName} (${data.trainNumber})</strong> from <strong>${data.fromStation}</strong> to <strong>${data.toStation}</strong> on <strong>${data.journeyDate}</strong> has been submitted for admin verification.</p>
            <p>Once approved, it will go live on the marketplace with your seat number and PNR masked until escrow payment is completed.</p>
          </div>
        `,
      });
    }

    res.status(201).send({
      message: "Ticket submitted for admin approval.",
      ticketId: result.insertedId,
      status: "pending_approval",
    });
  } catch (err) {
    console.error("Create ticket error:", err);
    res.status(500).send({ message: "Failed to create ticket listing." });
  }
});

// 2. GET /api/tickets/my-listings — Fetch authenticated seller's own ticket listings
app.get("/api/tickets/my-listings", requireAuth, async (req, res) => {
  try {
    const listings = await ticketsCollection
      .find({ sellerId: req.user._id.toString() })
      .sort({ createdAt: -1 })
      .toArray();
    res.send(listings);
  } catch (err) {
    console.error("Fetch my listings error:", err);
    res.status(500).send({ message: "Failed to load your listings." });
  }
});

// ==========================================
// 9. ROOT & HEALTH ENDPOINTS
// ==========================================

app.get("/", (req, res) => {
  res.send("Server Is running!!!!");
});

app.get("/api/health", async (req, res) => {
  try {
    await database.command({ ping: 1 });

    res.send({
      status: "ok",
      database: process.env.DB_NAME,
      cached: Boolean(cachedClient),
    });
  } catch (err) {
    console.error("Health check error:", err);

    res.status(500).send({
      status: "error",
      message: "Database health check failed.",
    });
  }
});

// ==========================================
// 10. DISCONNECT MONGODB
// ==========================================

async function disconnectFromMongoDB() {
  await client.close();

  cachedClient = null;
  connectPromise = null;

  console.log("MongoDB connection closed.");
}

// 3. GET /api/admin/tickets/pending — Admin queue of pending (or all) ticket listings
app.get("/api/admin/tickets/pending", requireAuth, requireRole("admin"), async (req, res) => {
  try {
    const statusFilter = req.query.status || "pending_approval";

    const query =
      statusFilter === "all"
        ? {}
        : { status: statusFilter };

    const listings = await ticketsCollection
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();

    res.send(listings);
  } catch (err) {
    console.error("Fetch admin pending tickets error:", err);
    res.status(500).send({
      message: "Failed to load ticket approval queue.",
    });
  }
});

// 4. PATCH /api/admin/tickets/:id/review — Admin approves or rejects a ticket listing
app.patch(
  "/api/admin/tickets/:id/review",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { action, rejectionReason } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          message: "Invalid ticket ID.",
        });
      }

      if (!["approve", "reject"].includes(action)) {
        return res.status(400).send({
          message: "Action must be 'approve' or 'reject'.",
        });
      }

      if (action === "reject" && !rejectionReason?.trim()) {
        return res.status(400).send({
          message: "Please provide a reason when rejecting a ticket.",
        });
      }

      const ticketFilter = { _id: new ObjectId(id) };
      const targetTicket = await ticketsCollection.findOne(ticketFilter);

      if (!targetTicket) {
        return res.status(404).send({
          message: "Ticket listing not found.",
        });
      }

      const nextStatus = action === "approve" ? "available" : "rejected";
      const cleanReason =
        action === "reject" ? rejectionReason.trim() : null;
      const now = new Date();

      await ticketsCollection.updateOne(ticketFilter, {
        $set: {
          status: nextStatus,
          rejectionReason: cleanReason,
          reviewedAt: now,
          reviewedBy: req.user._id.toString(),
          reviewedByEmail: req.user.email,
          updatedAt: now,
        },
      });

      // Record compliance audit log in audit_logs collection
      await auditLogsCollection.insertOne({
        action: action === "approve" ? "TICKET_APPROVED" : "TICKET_REJECTED",
        adminId: req.user._id,
        adminEmail: req.user.email,
        targetTicketId: targetTicket._id,
        targetSellerId: targetTicket.sellerId,
        details: {
          trainName: targetTicket.trainName,
          trainNumber: targetTicket.trainNumber,
          fromStation: targetTicket.fromStation,
          toStation: targetTicket.toStation,
          journeyDate: targetTicket.journeyDate,
          pnr: targetTicket.pnr,
          previousStatus: targetTicket.status,
          nextStatus,
          rejectionReason: cleanReason,
        },
        createdAt: now,
      });

      // Notify seller via Nodemailer
      const sellerFilter = ObjectId.isValid(targetTicket.sellerId)
        ? {
          $or: [
            { _id: new ObjectId(targetTicket.sellerId) },
            { _id: targetTicket.sellerId },
          ],
        }
        : { _id: targetTicket.sellerId };

      const sellerUser = await usersCollection.findOne(sellerFilter);

      if (sellerUser?.email) {
        await sendNotificationEmail({
          to: sellerUser.email,
          subject:
            action === "approve"
              ? `Ticket Approved & Live — ${targetTicket.trainName} (${targetTicket.journeyDate})`
              : `Ticket Listing Rejected — ${targetTicket.trainName} (${targetTicket.journeyDate})`,
          html:
            action === "approve"
              ? `<div style="font-family: sans-serif; padding: 16px;">
                   <h2>Your Ticket Is Now Live!</h2>
                   <p>Hi <strong>${sellerUser.name || targetTicket.sellerName}</strong>,</p>
                   <p>Your ticket for <strong>${targetTicket.trainName} (${targetTicket.trainNumber})</strong> from <strong>${targetTicket.fromStation}</strong> to <strong>${targetTicket.toStation}</strong> on <strong>${targetTicket.journeyDate}</strong> has been <strong>approved</strong> and is now live on the marketplace.</p>
                 </div>`
              : `<div style="font-family: sans-serif; padding: 16px;">
                   <h2>Ticket Listing Update</h2>
                   <p>Hi <strong>${sellerUser.name || targetTicket.sellerName}</strong>,</p>
                   <p>Your ticket listing for <strong>${targetTicket.trainName} (${targetTicket.trainNumber})</strong> on <strong>${targetTicket.journeyDate}</strong> was <strong>rejected</strong>.</p>
                   <p><strong>Reason:</strong> ${cleanReason}</p>
                 </div>`,
        });
      }

      res.send({
        message:
          action === "approve"
            ? "Ticket approved and published to marketplace."
            : "Ticket rejected successfully.",
        status: nextStatus,
      });
    } catch (err) {
      console.error("Admin ticket review error:", err);
      res.status(500).send({
        message: "Failed to review ticket listing.",
      });
    }
  }
);


// 5. GET /api/tickets — Public search & masked marketplace listings
app.get("/api/tickets", async (req, res) => {
  try {
    const { from, to, date } = req.query;

    const filter = {
      status: "available",
    };

    if (from && String(from).trim()) {
      const escapedFrom = String(from)
        .trim()
        .replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      filter.fromStation = { $regex: new RegExp(escapedFrom, "i") };
    }

    if (to && String(to).trim()) {
      const escapedTo = String(to)
        .trim()
        .replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      filter.toStation = { $regex: new RegExp(escapedTo, "i") };
    }

    if (date && String(date).trim()) {
      filter.journeyDate = String(date).trim();
    }

    const tickets = await ticketsCollection
      .find(filter, {
        projection: {
          seatNumber: 0,
          pnr: 0,
          ticketFileUrl: 0,
          sellerPhone: 0,
          phone: 0,
        },
      })
      .sort({ journeyDate: 1, departureTime: 1, createdAt: -1 })
      .toArray();

    res.send(tickets);

  } catch (err) {
    console.error("Public ticket search error:", err);
    res.status(500).send({
      message: "Failed to load available tickets.",
    });
  }
})


// ==========================================
// PHASE 4: ATOMIC 10-MINUTE TICKET LOCKING
// ==========================================

// 1. POST /api/tickets/:id/lock — Atomically acquire a 10-minute checkout lock
app.post("/api/tickets/:id/lock", requireAuth, async (res, req) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        message: "Invalid ticket ID.",
      });
    }

    const ticketObjectId = new ObjectId(id);
    const currentUserId = req.user._id.toString();

    const existingTicket = await ticketsCollection.findOne({ _id: ticketObjectId });
    if (!existingTicket) {
      return res.status(404).send({
        message: "Ticket listing not found.",
      });
    }

    if (existingTicket.sellerId === currentUserId) {
      return res.status(400).send({
        message: "You cannot lock or purchase your own ticket listing.",
      });
    }

    if (existingTicket.status === "sold") {
      return res.status(409).send({
        message: "This ticket has already been sold.",
      });
    }

    const lockedResult = await ticketsCollection.findOneAndUpdate(
      {
        _id: ticketObjectId,
        $or: [
          { status: "available" },
          { status: "locked", lockedUntil: { $lt: now } },
        ],
      },
      {
        $set: {
          status: "locked",
          lockedBy: currentUserId,
          lockedUntil,
          updatedAt: now,
        },
      },
      {
        returnDocument: "after",
        projection: {
          seatNumber: 0,
          pnr: 0,
          ticketFileUrl: 0,
          sellerPhone: 0,
          phone: 0,
        },
      }
    );

    if (!lockedResult) {
      return res.status(409).send({
        message:
          "This ticket is currently locked by another buyer during checkout.",
      });
    }

    res.send({
      message: "Ticket locked for 10 minutes.",
      ticket: lockedResult,
      lockedUntil: lockedResult.lockedUntil,
      lockedUntilMs: new Date(lockedResult.lockedUntil).getTime(),
    });

  } catch (err) {
    console.error("Atomic ticket lock error:", err);
    res.status(500).send({
      message: "Failed to lock ticket for checkout.",
    });
  }
});

// 2. POST /api/tickets/:id/unlock — Release active checkout lock early
app.post("/api/tickets/:id/unlock", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        message: "Invalid ticket ID.",
      });
    }

    const ticketObjectId = new ObjectId(id);
    const currentUserId = req.user._id.toString();
    const isAdmin = req.user.role === "admin";

    const existingTicket = await ticketsCollection.findOne({ _id: ticketObjectId });
    if (!existingTicket) {
      return res.status(404).send({
        message: "Ticket listing not found.",
      });
    }

    if (existingTicket.status === "sold") {
      return res.status(400).send({
        message: "Sold tickets cannot be unlocked.",
      });
    }

    const unlockFilter = isAdmin
      ? { _id: ticketObjectId, status: "locked" }
      : { _id: ticketObjectId, status: "locked", lockedBy: currentUserId };

    const updated = await ticketsCollection.findOneAndUpdate(
      unlockFilter,
      {
        $set: {
          status: "available",
          lockedBy: null,
          lockedUntil: null,
          updatedAt: new Date(),
        },
      },
      {
        returnDocument: "after",
        projection: {
          seatNumber: 0,
          pnr: 0,
          ticketFileUrl: 0,
          sellerPhone: 0,
          phone: 0,
        },
      }
    );

    if (!updated) {
      return res.status(403).send({
        message:
          "No active lock held by your account was found for this ticket.",
      });
    }

    res.send({
      message: "Ticket lock released.",
      ticket: updated,
    });
  } catch (err) {
    console.error("Ticket unlock error:", err);
    res.status(500).send({
      message: "Failed to unlock ticket.",
    });
  }
})


// ==========================================
// 11. START LOCAL SERVER
// ==========================================

async function startServer() {
  try {
    await connectToMongoDB();

    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
    });
  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
}

// Start server only when running this file directly
if (require.main === module) {
  startServer();
}

// Export Express app for Vercel
module.exports = app;