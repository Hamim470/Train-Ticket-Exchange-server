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
let paymentsCollection;
let escrowSettlementsCollection;


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
      paymentsCollection = database.collection("payments");
      escrowSettlementsCollection = database.collection("escrow_settlements");

      await ticketsCollection.createIndex(
        { pnr: 1 },
        {
          unique: true,
          name: "unique_active_ticket_pnr",
          partialFilterExpression: {
            status: { $in: ["pending_approval", "available", "locked", "sold"] },
          },
        }
      );
      await bookingsCollection.createIndex(
        { paymentId: 1 },
        { unique: true, name: "unique_booking_payment" }
      );
      await paymentsCollection.createIndex(
        { tranId: 1 },
        { unique: true, name: "unique_payment_transaction" }
      );
      await disputesCollection.createIndex(
        { bookingId: 1 },
        { unique: true, name: "unique_dispute_booking" }
      );
      await escrowSettlementsCollection.createIndex(
        { bookingId: 1 },
        { unique: true, name: "unique_escrow_settlement_booking" }
      );

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

// Make sure this middleware is active near the top of index.js so SSLCOMMERZ form POST callbacks parse properly:
app.use(express.urlencoded({ extended: true }));

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
        token = rawCookie; // Use full JWT for verification
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
        token = rawCookie; // Use full JWT for verification
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

    let result;
    try {
      result = await ticketsCollection.insertOne(newTicket);
    } catch (err) {
      if (err.code === 11000) {
        return res.status(409).send({
          message: "A ticket with this PNR is already listed on the marketplace.",
        });
      }
      throw err;
    }

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
});


// ==========================================
// PHASE 4: ATOMIC 10-MINUTE TICKET LOCKING
// ==========================================

// 1. POST /api/tickets/:id/lock — Atomically acquire a 10-minute checkout lock
app.post("/api/tickets/:id/lock", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        message: "Invalid ticket ID.",
      });
    }

    const ticketObjectId = new ObjectId(id);
    const currentUserId = req.user._id.toString();
    const now = new Date();
    const lockedUntil = new Date(now.getTime() + 10 * 60 * 1000);

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
        sellerId: { $ne: currentUserId },
        status: { $ne: "sold" },
        $or: [
          { status: "available" },
          {
            status: "locked",
            lockedUntil: { $lt: now },
            activePaymentId: { $in: [null, undefined] },
          },
          {
            status: "locked",
            lockedBy: currentUserId,
            activePaymentId: { $in: [null, undefined] },
          },
        ],
      },
      {
        $set: {
          status: "locked",
          lockedBy: currentUserId,
          lockedUntil,
          activePaymentId: null,
          updatedAt: now,
        },
      },
      {
        returnDocument: "after",
        projection: {
          seatNumber: 0,
          coach: 0,
          pnr: 0,
          ticketFileUrl: 0,
          sellerPhone: 0,
          phone: 0,
          sellerEmail: 0,
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

    if (existingTicket.activePaymentId) {
      return res.status(409).send({
        message: "A payment is in progress for this ticket and it cannot be unlocked.",
      });
    }

    const unlockFilter = isAdmin
      ? {
        _id: ticketObjectId,
        status: "locked",
        $or: [{ activePaymentId: { $exists: false } }, { activePaymentId: null }],
      }
      : {
        _id: ticketObjectId,
        status: "locked",
        lockedBy: currentUserId,
        $or: [{ activePaymentId: { $exists: false } }, { activePaymentId: null }],
      };

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
});


// ==========================================
// PHASE 4.3: SSLCOMMERZ ESCROW PAYMENT FLOW
// ==========================================
const SSLCZ_STORE_ID = process.env.SSLCZ_STORE_ID || "coxro6a633b240ed49";
const SSLCZ_STORE_PASSWD = process.env.SSLCZ_STORE_PASSWD || "";
const SSLCZ_IS_LIVE = process.env.SSLCZ_IS_LIVE === "true";

const SSLCZ_BASE_URL = SSLCZ_IS_LIVE
  ? "https://securepay.sslcommerz.com"
  : "https://sandbox.sslcommerz.com";

const SERVER_BASE_URL = (process.env.SERVER_URL || "http://localhost:5000").replace(/\/$/, "");
const CLIENT_BASE_URL = (process.env.CLIENT_URL || "http://localhost:3000").replace(/\/$/, "");

const userIdFilter = (id) =>
  ObjectId.isValid(String(id))
    ? { $or: [{ _id: new ObjectId(String(id)) }, { _id: String(id) }] }
    : { _id: id };

const callSslczMerchantApi = async (parameters) => {
  const apiUrl = new URL(
    `${SSLCZ_BASE_URL}/validator/api/merchantTransIDvalidationAPI.php`
  );
  for (const [key, value] of Object.entries({
    store_id: SSLCZ_STORE_ID,
    store_passwd: SSLCZ_STORE_PASSWD,
    format: "json",
    v: "1",
    ...parameters,
  })) {
    apiUrl.searchParams.set(key, String(value));
  }

  const response = await fetch(apiUrl.toString());
  if (!response.ok) {
    throw new Error(`SSLCOMMERZ merchant API returned HTTP ${response.status}.`);
  }
  return response.json();
};

const finalizeVerifiedFailedPayment = async (tranId) => {
  if (typeof tranId !== "string" || tranId.length > 30 || !SSLCZ_STORE_PASSWD) {
    return false;
  }

  const gatewayStatus = await callSslczMerchantApi({ tran_id: tranId });
  const status = String(gatewayStatus.status || "").toUpperCase();
  if (
    gatewayStatus.APIConnect !== "DONE" ||
    gatewayStatus.tran_id !== tranId ||
    !["FAILED", "CANCELLED"].includes(status) ||
    (gatewayStatus.store_id && gatewayStatus.store_id !== SSLCZ_STORE_ID)
  ) {
    return false;
  }

  const payment = await paymentsCollection.findOne({
    tranId,
    status: { $in: ["initiated", "init_unknown"] },
  });
  if (!payment) {
    return false;
  }

  const session = client.startSession();
  try {
    let updated = false;
    await session.withTransaction(async () => {
      const paymentUpdate = await paymentsCollection.updateOne(
        {
          _id: payment._id,
          status: { $in: ["initiated", "init_unknown"] },
        },
        {
          $set: { status: status.toLowerCase(), updatedAt: new Date() },
        },
        { session }
      );
      if (paymentUpdate.modifiedCount !== 1) {
        return;
      }

      await ticketsCollection.updateOne(
        {
          _id: payment.ticketId,
          status: "locked",
          lockedBy: payment.buyerId,
          activePaymentId: payment._id,
        },
        {
          $set: {
            status: "available",
            lockedBy: null,
            lockedUntil: null,
            updatedAt: new Date(),
          },
          $unset: { activePaymentId: "" },
        },
        { session }
      );
      updated = true;
    });
    return updated;
  } finally {
    await session.endSession();
  }
};

const callSslczRefundApi = (parameters) => callSslczMerchantApi(parameters);

const verifyAndFinalizeSslczPayment = async (valId, tranId) => {
  const payment = await paymentsCollection.findOne({ tranId });
  if (!payment) {
    return { ok: false, status: 404, message: "Payment record not found." };
  }

  // Idempotent check if IPN and success_url arrive back-to-back
  if (payment.status === "completed" && payment.bookingId) {
    const existingBooking = await bookingsCollection.findOne({
      _id: new ObjectId(payment.bookingId),
    });
    const soldTicket = await ticketsCollection.findOne({
      _id: payment.ticketId,
    });
    return {
      ok: true,
      alreadyConfirmed: true,
      booking: existingBooking,
      ticket: soldTicket,
    };
  }

  if (!["initiated", "init_unknown"].includes(payment.status)) {
    return {
      ok: false,
      status: 409,
      message: `Payment cannot be finalized from status "${payment.status}".`,
    };
  }

  if (!valId) {
    return { ok: false, status: 400, message: "Missing val_id from SSLCOMMERZ." };
  }

  const validationUrl = new URL(
    `${SSLCZ_BASE_URL}/validator/api/validationserverAPI.php`
  );
  validationUrl.searchParams.set("val_id", valId);
  validationUrl.searchParams.set("store_id", SSLCZ_STORE_ID);
  validationUrl.searchParams.set("store_passwd", SSLCZ_STORE_PASSWD);
  validationUrl.searchParams.set("v", "1");
  validationUrl.searchParams.set("format", "json");

  const verifyResponse = await fetch(validationUrl.toString());
  if (!verifyResponse.ok) {
    throw new Error(`SSLCOMMERZ validation returned HTTP ${verifyResponse.status}.`);
  }
  const verifyData = await verifyResponse.json();

  const validStatuses = ["VALID", "VALIDATED"];
  const paidAmount = Number(verifyData.amount);
  const expectedAmount = Number(payment.amount);

  if (
    !validStatuses.includes(String(verifyData.status || "").toUpperCase()) ||
    verifyData.tran_id !== tranId ||
    (verifyData.store_id && verifyData.store_id !== SSLCZ_STORE_ID) ||
    !Number.isFinite(paidAmount) ||
    !Number.isFinite(expectedAmount) ||
    Math.round(paidAmount * 100) !== Math.round(expectedAmount * 100) ||
    String(verifyData.currency || "").toUpperCase() !== "BDT"
  ) {
    return {
      ok: false,
      status: 400,
      message: "SSLCOMMERZ payment validation failed or amount mismatched.",
    };
  }

  const now = new Date();
  const bookingId = new ObjectId();
  const session = client.startSession();
  let finalization;

  try {
    await session.withTransaction(async () => {
      const currentPayment = await paymentsCollection.findOne(
        { _id: payment._id },
        { session }
      );
      if (currentPayment?.status === "completed" && currentPayment.bookingId) {
        const existingBooking = await bookingsCollection.findOne(
          { _id: currentPayment.bookingId },
          { session }
        );
        const existingTicket = await ticketsCollection.findOne(
          { _id: currentPayment.ticketId },
          { session }
        );
        finalization = {
          ok: true,
          alreadyConfirmed: true,
          booking: existingBooking,
          ticket: existingTicket,
        };
        return;
      }

      if (!["initiated", "init_unknown"].includes(currentPayment?.status)) {
        throw Object.assign(new Error("Payment is no longer active."), {
          code: "PAYMENT_NOT_ACTIVE",
        });
      }

      const soldTicket = await ticketsCollection.findOneAndUpdate(
        {
          _id: payment.ticketId,
          status: "locked",
          lockedBy: payment.buyerId,
          activePaymentId: payment._id,
        },
        {
          $set: {
            status: "sold",
            soldTo: payment.buyerId,
            soldAt: now,
            bookingId,
            lockedBy: null,
            lockedUntil: null,
            updatedAt: now,
          },
          $unset: { activePaymentId: "" },
        },
        { returnDocument: "after", session }
      );

      if (!soldTicket) {
        throw Object.assign(new Error("The ticket payment lock is unavailable."), {
          code: "TICKET_LOCK_UNAVAILABLE",
        });
      }

      const bookingDoc = {
        _id: bookingId,
        ticketId: soldTicket._id,
        paymentId: payment._id,
        buyerId: payment.buyerId,
        buyerEmail: payment.buyerEmail,
        sellerId: soldTicket.sellerId,
        sellerName: soldTicket.sellerName || "",
        gateway: "sslcommerz",
        cardType: verifyData.card_type || verifyData.card_brand || "SSLCOMMERZ",
        tranId: payment.tranId,
        valId,
        bankTranId: verifyData.bank_tran_id || "",
        fare: payment.fare,
        platformFee: payment.platformFee,
        amount: payment.amount,
        storeAmount: Number(verifyData.store_amount || payment.amount),
        escrowStatus: "held",
        bookingStatus: "confirmed",
        journeyDate: soldTicket.journeyDate,
        departureTime: soldTicket.departureTime,
        trainName: soldTicket.trainName,
        trainNumber: soldTicket.trainNumber,
        fromStation: soldTicket.fromStation,
        toStation: soldTicket.toStation,
        unlockedDetails: {
          coach: soldTicket.coach,
          seatNumber: soldTicket.seatNumber,
          pnr: soldTicket.pnr,
          ticketFileUrl: soldTicket.ticketFileUrl,
        },
        createdAt: now,
        updatedAt: now,
      };

      await bookingsCollection.insertOne(bookingDoc, { session });

      const paymentUpdate = await paymentsCollection.updateOne(
        { _id: payment._id, status: { $in: ["initiated", "init_unknown"] } },
        {
          $set: {
            status: "completed",
            valId,
            bankTranId: verifyData.bank_tran_id || "",
            cardType: verifyData.card_type || "",
            bookingId,
            validationResponse: verifyData,
            confirmedAt: now,
            updatedAt: now,
          },
        },
        { session }
      );

      if (paymentUpdate.modifiedCount !== 1) {
        throw Object.assign(new Error("Payment state changed during finalization."), {
          code: "PAYMENT_NOT_ACTIVE",
        });
      }

      finalization = {
        ok: true,
        booking: bookingDoc,
        ticket: soldTicket,
      };
    });
  } catch (err) {
    if (err.code === "TICKET_LOCK_UNAVAILABLE") {
      await paymentsCollection.updateOne(
        { _id: payment._id, status: { $in: ["initiated", "init_unknown"] } },
        {
          $set: {
            status: "refund_required",
            valId,
            bankTranId: verifyData.bank_tran_id || "",
            validationResponse: verifyData,
            updatedAt: new Date(),
          },
        }
      );
      return {
        ok: false,
        status: 409,
        message: "Payment was received but the ticket lock is unavailable; a refund is required.",
      };
    }
    if (err.code === "PAYMENT_NOT_ACTIVE") {
      const updatedPayment = await paymentsCollection.findOne({ _id: payment._id });
      if (updatedPayment?.status === "completed" && updatedPayment.bookingId) {
        return {
          ok: true,
          alreadyConfirmed: true,
          booking: await bookingsCollection.findOne({ _id: updatedPayment.bookingId }),
          ticket: await ticketsCollection.findOne({ _id: updatedPayment.ticketId }),
        };
      }
      return { ok: false, status: 409, message: err.message };
    }
    throw err;
  } finally {
    await session.endSession();
  }

  return finalization;
};

// 1. POST /api/payments/initiate — Create SSLCOMMERZ checkout session
app.post("/api/payments/initiate", requireAuth, async (req, res) => {
  try {
    const { ticketId } = req.body;

    if (!ticketId || !ObjectId.isValid(ticketId)) {
      return res.status(400).send({ message: "Valid ticketId is required." });
    }

    if (!SSLCZ_STORE_PASSWD) {
      return res.status(500).send({
        message: "SSLCZ_STORE_PASSWD is not configured on the server.",
      });
    }

    const ticketObjectId = new ObjectId(ticketId);
    const buyerId = req.user._id.toString();
    const ticket = await ticketsCollection.findOne({ _id: ticketObjectId });

    if (!ticket) {
      return res.status(404).send({ message: "Ticket listing not found." });
    }

    if (ticket.sellerId === buyerId) {
      return res.status(400).send({
        message: "You cannot purchase your own ticket listing.",
      });
    }

    const now = new Date();
    const lockExpiresAt = ticket.lockedUntil ? new Date(ticket.lockedUntil) : null;

    if (
      ticket.status !== "locked" ||
      ticket.lockedBy !== buyerId ||
      !lockExpiresAt ||
      lockExpiresAt <= now
    ) {
      return res.status(409).send({
        message:
          "Your 10-minute checkout lock is missing or has expired. Please lock the ticket again.",
      });
    }

    const fare = Number(ticket.fare || 0);
    const platformFee = Number(ticket.platformFee ?? 25);
    const totalAmount = fare + platformFee;
    const paymentId = new ObjectId();
    const tranId = `TTE_${paymentId.toString()}`;

    const paymentDoc = {
      _id: paymentId,
      ticketId: ticket._id,
      buyerId,
      buyerEmail: req.user.email || "buyer@trainticketexchange.bd",
      buyerName: req.user.name || "Verified Buyer",
      sellerId: ticket.sellerId,
      gateway: "sslcommerz",
      tranId,
      fare,
      platformFee,
      amount: totalAmount,
      currency: "BDT",
      status: "initiated",
      lockedUntil: lockExpiresAt,
      createdAt: now,
      updatedAt: now,
    };

    const paymentSession = client.startSession();
    try {
      await paymentSession.withTransaction(async () => {
        const lockUpdate = await ticketsCollection.updateOne(
          {
            _id: ticket._id,
            status: "locked",
            lockedBy: buyerId,
            lockedUntil: { $gt: now },
            $or: [
              { activePaymentId: { $exists: false } },
              { activePaymentId: null },
            ],
          },
          { $set: { activePaymentId: paymentDoc._id, updatedAt: now } },
          { session: paymentSession }
        );

        if (lockUpdate.modifiedCount !== 1) {
          throw Object.assign(new Error("A payment is already active for this ticket."), {
            code: "ACTIVE_PAYMENT_EXISTS",
          });
        }

        await paymentsCollection.insertOne(paymentDoc, { session: paymentSession });
      });
    } catch (err) {
      if (err.code === "ACTIVE_PAYMENT_EXISTS") {
        return res.status(409).send({
          message: "A payment is already active for this ticket.",
        });
      }
      throw err;
    } finally {
      await paymentSession.endSession();
    }

    const sslPayload = new URLSearchParams({
      store_id: SSLCZ_STORE_ID,
      store_passwd: SSLCZ_STORE_PASSWD,
      total_amount: String(totalAmount),
      currency: "BDT",
      tran_id: tranId,
      success_url: `${SERVER_BASE_URL}/api/payments/sslcommerz/success`,
      fail_url: `${SERVER_BASE_URL}/api/payments/sslcommerz/fail`,
      cancel_url: `${SERVER_BASE_URL}/api/payments/sslcommerz/cancel`,
      ipn_url: `${SERVER_BASE_URL}/api/payments/confirm`,
      shipping_method: "NO",
      product_name: `${ticket.trainName} (${ticket.fromStation} to ${ticket.toStation})`,
      product_category: "Train Ticket Escrow",
      product_profile: "non-physical-goods",
      cus_name: req.user.name || "TTE Buyer",
      cus_email: req.user.email || "buyer@trainticketexchange.bd",
      cus_add1: "Bangladesh",
      cus_city: "Dhaka",
      cus_country: "Bangladesh",
      cus_phone: req.user.phone || "01700000000",
      value_a: ticket._id.toString(),
      value_b: buyerId,
    });

    let sslData;
    try {
      const sslResponse = await fetch(`${SSLCZ_BASE_URL}/gwprocess/v4/api.php`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: sslPayload.toString(),
      });
      if (!sslResponse.ok) {
        throw new Error(`SSLCOMMERZ session API returned HTTP ${sslResponse.status}.`);
      }
      sslData = await sslResponse.json();
    } catch (err) {
      await paymentsCollection.updateOne(
        { _id: paymentDoc._id, status: "initiated" },
        { $set: { status: "init_unknown", updatedAt: new Date() } }
      );
      throw err;
    }

    if (sslData.status !== "SUCCESS" || !sslData.GatewayPageURL) {
      await paymentsCollection.updateOne(
        { _id: paymentDoc._id },
        {
          $set: {
            status: "init_failed",
            gatewayError: sslData.failedreason || "Failed to create SSLCOMMERZ session",
            updatedAt: new Date(),
          },
        }
      );
      await ticketsCollection.updateOne(
        { _id: ticket._id, activePaymentId: paymentDoc._id },
        { $unset: { activePaymentId: "" }, $set: { updatedAt: new Date() } }
      );

      return res.status(502).send({
        message:
          sslData.failedreason || "SSLCOMMERZ session initiation failed.",
      });
    }

    await paymentsCollection.updateOne(
      { _id: paymentDoc._id },
      {
        $set: {
          sessionKey: sslData.sessionkey || "",
          gatewayPageUrl: sslData.GatewayPageURL,
          updatedAt: new Date(),
        },
      }
    );

    res.status(201).send({
      message: "SSLCOMMERZ checkout session created.",
      paymentId: paymentDoc._id.toString(),
      tranId,
      sessionKey: sslData.sessionkey,
      gatewayPageUrl: sslData.GatewayPageURL,
      amount: totalAmount,
    });

  } catch (err) {
    console.error("SSLCOMMERZ initiate error:", err);
    res.status(500).send({
      message: "Failed to initiate SSLCOMMERZ payment.",
    });
  }
});

// SSLCOMMERZ callback routes must exist before any payment-initiation request.
app.post("/api/payments/confirm", async (req, res) => {
  try {
    const valId = req.body.val_id || req.body.valId;
    const tranId = req.body.tran_id || req.body.tranId;
    const ipnStatus = String(req.body.status || "").toUpperCase();

    if (typeof tranId !== "string" || tranId.length > 30) {
      return res.status(400).send({ message: "Invalid or missing tran_id in IPN payload." });
    }

    if (["FAILED", "CANCELLED"].includes(ipnStatus)) {
      const updated = await finalizeVerifiedFailedPayment(tranId);
      return res.status(updated ? 200 : 202).send({
        message: updated
          ? `Payment marked as ${ipnStatus.toLowerCase()}.`
          : "Failure notification is not verified; no payment state was changed.",
      });
    }

    const result = await verifyAndFinalizeSslczPayment(valId, tranId);
    if (!result.ok) {
      return res.status(result.status || 400).send({ message: result.message });
    }

    return res.send({ message: "Payment validated via SSLCOMMERZ and escrow activated." });
  } catch (err) {
    console.error("SSLCOMMERZ IPN confirm error:", err);
    return res.status(500).send({ message: "Failed to process SSLCOMMERZ confirmation." });
  }
});

app.post("/api/payments/sslcommerz/success", async (req, res) => {
  try {
    const valId = req.body.val_id;
    const tranId = req.body.tran_id;
    const ticketId = req.body.value_a || "";
    if (typeof valId !== "string" || typeof tranId !== "string" || tranId.length > 30) {
      return res.redirect(`${CLIENT_BASE_URL}/tickets?payment=error`);
    }
    const result = await verifyAndFinalizeSslczPayment(valId, tranId);

    if (!result.ok) {
      return res.redirect(
        `${CLIENT_BASE_URL}/checkout/${ticketId}?payment=failed&reason=${encodeURIComponent(result.message)}`
      );
    }

    return res.redirect(
      `${CLIENT_BASE_URL}/checkout/${ticketId}?payment=success&tranId=${encodeURIComponent(tranId)}`
    );
  } catch (err) {
    console.error("SSLCOMMERZ success redirect error:", err);
    return res.redirect(`${CLIENT_BASE_URL}/tickets?payment=error`);
  }
});

app.post("/api/payments/sslcommerz/fail", async (req, res) => {
  const tranId = req.body.tran_id;
  const ticketId = req.body.value_a || "";
  if (typeof tranId === "string") {
    try {
      await finalizeVerifiedFailedPayment(tranId);
    } catch (err) {
      console.error("SSLCOMMERZ failure callback verification error:", err);
    }
  }
  return res.redirect(`${CLIENT_BASE_URL}/checkout/${ticketId}?payment=failed`);
});

app.post("/api/payments/sslcommerz/cancel", async (req, res) => {
  const tranId = req.body.tran_id;
  const ticketId = req.body.value_a || "";
  if (typeof tranId === "string") {
    try {
      await finalizeVerifiedFailedPayment(tranId);
    } catch (err) {
      console.error("SSLCOMMERZ cancellation callback verification error:", err);
    }
  }
  return res.redirect(`${CLIENT_BASE_URL}/checkout/${ticketId}?payment=cancelled`);
});

app.get("/api/payments/status/:tranId", requireAuth, async (req, res) => {
  try {
    const buyerId = req.user._id.toString();
    const payment = await paymentsCollection.findOne({ tranId: req.params.tranId, buyerId });
    if (!payment) {
      return res.status(404).send({ message: "Payment record not found." });
    }

    if (payment.status !== "completed" || !payment.bookingId) {
      return res.send({ status: payment.status, booking: null });
    }

    const booking = await bookingsCollection.findOne({
      _id: payment.bookingId,
      buyerId,
    });
    return res.send({ status: "completed", booking });
  } catch (err) {
    console.error("Payment status fetch error:", err);
    return res.status(500).send({ message: "Failed to fetch payment status." });
  }
});

app.patch("/api/bookings/:id/confirm-journey", requireAuth, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).send({ message: "Invalid booking ID." });
  }

  const bookingId = new ObjectId(req.params.id);
  const buyerId = req.user._id.toString();
  const now = new Date();
  const session = client.startSession();

  try {
    let releasedBooking;
    await session.withTransaction(async () => {
      releasedBooking = await bookingsCollection.findOneAndUpdate(
        { _id: bookingId, buyerId, escrowStatus: "held" },
        { $set: { escrowStatus: "released", releasedAt: now, updatedAt: now } },
        { returnDocument: "after", session }
      );

      if (!releasedBooking) {
        throw Object.assign(new Error("Booking is not eligible for release."), {
          code: "ESCROW_NOT_HELD",
        });
      }

      const sellerUpdate = await usersCollection.updateOne(
        userIdFilter(releasedBooking.sellerId),
        { $inc: { walletBalance: Number(releasedBooking.fare) } },
        { session }
      );
      if (sellerUpdate.matchedCount !== 1) {
        throw new Error("Booking seller account was not found.");
      }

      await escrowSettlementsCollection.insertOne(
        {
          bookingId,
          action: "release",
          status: "completed",
          amount: Number(releasedBooking.fare),
          completedAt: now,
          createdAt: now,
          updatedAt: now,
        },
        { session }
      );
    });

    return res.send({ message: "Escrow released to the seller wallet.", booking: releasedBooking });
  } catch (err) {
    if (err.code === "ESCROW_NOT_HELD") {
      const booking = await bookingsCollection.findOne({ _id: bookingId, buyerId });
      if (booking?.escrowStatus === "released") {
        return res.send({ message: "Escrow was already released.", booking });
      }
      return res.status(409).send({ message: "Booking is not eligible for release." });
    }
    console.error("Journey confirmation error:", err);
    return res.status(500).send({ message: "Failed to release escrow." });
  } finally {
    await session.endSession();
  }
});

app.post("/api/bookings/:id/dispute", requireAuth, async (req, res) => {
  if (!ObjectId.isValid(req.params.id)) {
    return res.status(400).send({ message: "Invalid booking ID." });
  }

  const reason = typeof req.body.reason === "string" ? req.body.reason.trim() : "";
  const description =
    typeof req.body.description === "string" ? req.body.description.trim() : "";
  if (!reason || reason.length > 100 || description.length < 10 || description.length > 2000) {
    return res.status(400).send({
      message: "A dispute reason and details of 10-2000 characters are required.",
    });
  }

  const bookingId = new ObjectId(req.params.id);
  const buyerId = req.user._id.toString();
  const now = new Date();
  const session = client.startSession();

  try {
    let dispute;
    await session.withTransaction(async () => {
      const booking = await bookingsCollection.findOneAndUpdate(
        { _id: bookingId, buyerId, escrowStatus: "held" },
        { $set: { escrowStatus: "frozen", updatedAt: now } },
        { returnDocument: "after", session }
      );
      if (!booking) {
        throw Object.assign(new Error("Booking is not eligible for a dispute."), {
          code: "ESCROW_NOT_HELD",
        });
      }

      dispute = {
        bookingId,
        buyerId,
        sellerId: booking.sellerId,
        reason,
        description,
        status: "open",
        createdAt: now,
        updatedAt: now,
      };
      await disputesCollection.insertOne(dispute, { session });
    });

    return res.status(201).send({ message: "Dispute opened; escrow is frozen.", dispute });
  } catch (err) {
    if (err.code === "ESCROW_NOT_HELD" || err.code === 11000) {
      return res.status(409).send({
        message: "Booking is not eligible for a new dispute.",
      });
    }
    console.error("Booking dispute error:", err);
    return res.status(500).send({ message: "Failed to open dispute." });
  } finally {
    await session.endSession();
  }
});

app.get(
  "/api/admin/disputes",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const statusFilter = String(req.query.status || "open").toLowerCase();
      const match =
        statusFilter === "all"
          ? {}
          : statusFilter === "resolved"
            ? { status: "resolved" }
            : statusFilter === "open"
              ? { status: { $in: ["open", "refund_processing"] } }
              : null;
      if (!match) {
        return res.status(400).send({ message: "Invalid dispute status filter." });
      }

      const disputes = await disputesCollection
        .aggregate([
          { $match: match },
          { $sort: { createdAt: -1 } },
          {
            $lookup: {
              from: "bookings",
              localField: "bookingId",
              foreignField: "_id",
              as: "booking",
            },
          },
          {
            $unwind: {
              path: "$booking",
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $project: {
              _id: 1,
              bookingId: 1,
              buyerId: 1,
              sellerId: 1,
              reason: 1,
              description: 1,
              amount: 1,
              fare: 1,
              status: 1,
              resolution: 1,
              adminNote: 1,
              createdAt: 1,
              resolvedAt: 1,
              trainName: "$booking.trainName",
              trainNumber: "$booking.trainNumber",
              fromStation: "$booking.fromStation",
              toStation: "$booking.toStation",
              journeyDate: "$booking.journeyDate",
              pnr: "$booking.unlockedDetails.pnr",
              seatNumber: "$booking.unlockedDetails.seatNumber",
              coach: "$booking.unlockedDetails.coach",
              ticketFileUrl: "$booking.unlockedDetails.ticketFileUrl",
              escrowStatus: "$booking.escrowStatus",
            },
          },
        ])
        .toArray();
      return res.send(disputes);
    } catch (err) {
      console.error("Fetch admin disputes error:", err);
      return res.status(500).send({ message: "Failed to fetch disputes." });
    }
  }
);

app.patch(
  "/api/admin/disputes/:id/resolve",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).send({ message: "Invalid dispute ID." });
    }

    const action = req.body.action;
    if (!["release", "refund"].includes(action)) {
      return res.status(400).send({ message: "Action must be 'release' or 'refund'." });
    }

    const adminNote = typeof req.body.adminNote === "string" ? req.body.adminNote.trim() : "";
    if (adminNote.length > 2000) {
      return res.status(400).send({ message: "Admin note must be 2000 characters or fewer." });
    }

    const disputeId = new ObjectId(req.params.id);
    const now = new Date();

    if (action === "release") {
      const session = client.startSession();
      try {
        let booking;
        await session.withTransaction(async () => {
          const dispute = await disputesCollection.findOne(
            { _id: disputeId, status: "open" },
            { session }
          );
          if (!dispute) {
            throw Object.assign(new Error("Dispute is not open."), { code: "DISPUTE_NOT_OPEN" });
          }

          booking = await bookingsCollection.findOneAndUpdate(
            { _id: dispute.bookingId, escrowStatus: "frozen" },
            { $set: { escrowStatus: "released", releasedAt: now, updatedAt: now } },
            { returnDocument: "after", session }
          );
          if (!booking) {
            throw Object.assign(new Error("Escrow is not frozen."), { code: "ESCROW_NOT_FROZEN" });
          }

          const sellerUpdate = await usersCollection.updateOne(
            userIdFilter(booking.sellerId),
            { $inc: { walletBalance: Number(booking.fare) } },
            { session }
          );
          if (sellerUpdate.matchedCount !== 1) {
            throw new Error("Booking seller account was not found.");
          }

          const disputeUpdate = await disputesCollection.updateOne(
            { _id: disputeId, status: "open" },
            {
              $set: {
                status: "resolved",
                resolution: "release",
                adminNote,
                resolvedBy: req.user._id,
                resolvedAt: now,
                updatedAt: now,
              },
            },
            { session }
          );
          if (disputeUpdate.modifiedCount !== 1) {
            throw Object.assign(new Error("Dispute state changed during resolution."), {
              code: "DISPUTE_NOT_OPEN",
            });
          }
          const previousSettlement = await escrowSettlementsCollection.findOne(
            { bookingId: booking._id },
            { session }
          );
          if (previousSettlement) {
            if (
              previousSettlement.action !== "refund" ||
              !["cancelled", "failed"].includes(previousSettlement.status)
            ) {
              throw Object.assign(new Error("A different settlement is already in progress."), {
                code: "SETTLEMENT_IN_PROGRESS",
              });
            }
            const settlementUpdate = await escrowSettlementsCollection.updateOne(
              { _id: previousSettlement._id, status: previousSettlement.status },
              {
                $set: {
                  action: "release",
                  status: "completed",
                  amount: Number(booking.fare),
                  completedAt: now,
                  updatedAt: now,
                },
              },
              { session }
            );
            if (settlementUpdate.modifiedCount !== 1) {
              throw Object.assign(new Error("Settlement state changed during resolution."), {
                code: "SETTLEMENT_IN_PROGRESS",
              });
            }
          } else {
            await escrowSettlementsCollection.insertOne(
              {
                bookingId: booking._id,
                disputeId,
                action: "release",
                status: "completed",
                amount: Number(booking.fare),
                completedAt: now,
                createdAt: now,
                updatedAt: now,
              },
              { session }
            );
          }
          await auditLogsCollection.insertOne(
            {
              action: "ESCROW_RELEASED",
              adminId: req.user._id,
              adminEmail: req.user.email,
              targetBookingId: booking._id,
              targetDisputeId: disputeId,
              details: {
                settlement: "seller_wallet",
                amount: Number(booking.fare),
                adminNote,
              },
              createdAt: now,
            },
            { session }
          );
        });
        return res.send({ message: "Dispute resolved; escrow released to seller wallet.", booking });
      } catch (err) {
        if (["DISPUTE_NOT_OPEN", "ESCROW_NOT_FROZEN", "SETTLEMENT_IN_PROGRESS"].includes(err.code)) {
          return res.status(409).send({ message: err.message });
        }
        console.error("Dispute release error:", err);
        return res.status(500).send({ message: "Failed to release disputed escrow." });
      } finally {
        await session.endSession();
      }
    }

    const dispute = await disputesCollection.findOne({ _id: disputeId });
    if (!dispute) {
      return res.status(404).send({ message: "Dispute not found." });
    }

    let booking = await bookingsCollection.findOne({
      _id: dispute.bookingId,
      escrowStatus: { $in: ["frozen", "refund_processing"] },
    });
    if (!booking) {
      return res.status(409).send({ message: "Dispute escrow is not available for refund." });
    }

    let settlement = await escrowSettlementsCollection.findOne({ bookingId: booking._id });
    if (settlement && settlement.action !== "refund") {
      return res.status(409).send({ message: "A different escrow settlement already exists." });
    }

    let shouldSubmitRefund = false;
    if (!settlement && (!booking.bankTranId || !SSLCZ_STORE_PASSWD)) {
      return res.status(503).send({
        message: "Refund cannot be submitted: bank transaction ID or gateway credentials are missing.",
      });
    }

    if (!settlement) {
      const session = client.startSession();
      const settlementId = new ObjectId();
      const refundReference = `TTER${booking._id.toString()}`;
      try {
        await session.withTransaction(async () => {
          const currentDispute = await disputesCollection.findOne(
            { _id: disputeId, status: "open" },
            { session }
          );
          if (!currentDispute) {
            throw Object.assign(new Error("Dispute is not open."), { code: "DISPUTE_NOT_OPEN" });
          }

          const changed = await bookingsCollection.updateOne(
            { _id: booking._id, escrowStatus: "frozen" },
            { $set: { escrowStatus: "refund_processing", updatedAt: now } },
            { session }
          );
          if (changed.modifiedCount !== 1) {
            throw Object.assign(new Error("Escrow is not frozen."), { code: "ESCROW_NOT_FROZEN" });
          }

          const disputeUpdate = await disputesCollection.updateOne(
            { _id: disputeId, status: "open" },
            {
              $set: {
                status: "refund_processing",
                adminNote,
                resolvedBy: req.user._id,
                updatedAt: now,
              },
            },
            { session }
          );
          if (disputeUpdate.modifiedCount !== 1) {
            throw Object.assign(new Error("Dispute state changed during refund reservation."), {
              code: "DISPUTE_NOT_OPEN",
            });
          }
          await escrowSettlementsCollection.insertOne(
            {
              _id: settlementId,
              bookingId: booking._id,
              disputeId,
              action: "refund",
              status: "submitting",
              amount: Number(booking.amount),
              refundReference,
              createdAt: now,
              updatedAt: now,
            },
            { session }
          );
          await auditLogsCollection.insertOne(
            {
              action: "ESCROW_REFUND_REQUESTED",
              adminId: req.user._id,
              adminEmail: req.user.email,
              targetBookingId: booking._id,
              targetDisputeId: disputeId,
              details: {
                gateway: "sslcommerz",
                amount: Number(booking.amount),
                adminNote,
              },
              createdAt: now,
            },
            { session }
          );
        });
        settlement = await escrowSettlementsCollection.findOne({ _id: settlementId });
        booking.escrowStatus = "refund_processing";
        shouldSubmitRefund = true;
      } catch (err) {
        if (["DISPUTE_NOT_OPEN", "ESCROW_NOT_FROZEN", 11000].includes(err.code)) {
          return res.status(409).send({ message: "A settlement is already being processed." });
        }
        console.error("Refund reservation error:", err);
        return res.status(500).send({ message: "Failed to reserve refund settlement." });
      } finally {
        await session.endSession();
      }
    }

    if (settlement.status === "submitting" && shouldSubmitRefund) {
      try {
        const refundResponse = await callSslczRefundApi({
          bank_tran_id: booking.bankTranId,
          refund_amount: Number(booking.amount).toFixed(2),
          refund_remarks: `Dispute refund ${booking._id}`,
          refe_id: settlement.refundReference,
        });
        const refundRefId = refundResponse.refund_ref_id;
        if (
          String(refundResponse.status || "").toLowerCase() !== "success" ||
          !refundRefId
        ) {
          await escrowSettlementsCollection.updateOne(
            { _id: settlement._id, status: "submitting" },
            {
              $set: {
                status: "submission_unknown",
                providerResponse: refundResponse,
                updatedAt: new Date(),
              },
            }
          );
          return res.status(502).send({
            message: "Refund submission could not be confirmed. Reconcile with SSLCOMMERZ before retrying.",
          });
        }

        await escrowSettlementsCollection.updateOne(
          { _id: settlement._id, status: "submitting" },
          {
            $set: {
              status: "processing",
              refundRefId,
              providerResponse: refundResponse,
              updatedAt: new Date(),
            },
          }
        );
        settlement.status = "processing";
        settlement.refundRefId = refundRefId;
      } catch (err) {
        await escrowSettlementsCollection.updateOne(
          { _id: settlement._id, status: "submitting" },
          { $set: { status: "submission_unknown", updatedAt: new Date() } }
        );
        console.error("SSLCOMMERZ refund submission error:", err);
        return res.status(502).send({
          message: "Refund submission outcome is unknown. Reconcile with SSLCOMMERZ before retrying.",
        });
      }
    }

    if (settlement.status === "submitting") {
      return res.status(202).send({
        message: "Refund submission is reserved or has an unknown outcome; do not retry the gateway request.",
      });
    }

    if (settlement.status === "processing") {
      if (!SSLCZ_STORE_PASSWD) {
        return res.status(503).send({ message: "SSLCZ_STORE_PASSWD is not configured." });
      }
      try {
        const refundStatus = await callSslczRefundApi({
          refund_ref_id: settlement.refundRefId,
        });
        const status = String(refundStatus.status || "").toLowerCase();

        if (status === "refunded") {
          const session = client.startSession();
          try {
            await session.withTransaction(async () => {
              const changed = await bookingsCollection.updateOne(
                { _id: booking._id, escrowStatus: "refund_processing" },
                { $set: { escrowStatus: "refunded", refundedAt: new Date(), updatedAt: new Date() } },
                { session }
              );
              if (changed.modifiedCount !== 1) {
                throw Object.assign(new Error("Refund was already settled."), { code: "ALREADY_SETTLED" });
              }

              const disputeUpdate = await disputesCollection.updateOne(
                { _id: disputeId, status: "refund_processing" },
                {
                  $set: {
                    status: "resolved",
                    resolution: "refund",
                    resolvedAt: new Date(),
                    updatedAt: new Date(),
                  },
                },
                { session }
              );
              if (disputeUpdate.modifiedCount !== 1) {
                throw Object.assign(new Error("Dispute state changed during refund settlement."), {
                  code: "ALREADY_SETTLED",
                });
              }
              const settlementUpdate = await escrowSettlementsCollection.updateOne(
                { _id: settlement._id, status: "processing" },
                { $set: { status: "completed", completedAt: new Date(), providerStatus: refundStatus, updatedAt: new Date() } },
                { session }
              );
              if (settlementUpdate.modifiedCount !== 1) {
                throw Object.assign(new Error("Settlement state changed during refund settlement."), {
                  code: "ALREADY_SETTLED",
                });
              }
              await auditLogsCollection.insertOne(
                {
                  action: "ESCROW_REFUNDED",
                  adminId: req.user._id,
                  adminEmail: req.user.email,
                  targetBookingId: booking._id,
                  targetDisputeId: disputeId,
                  details: {
                    gateway: "sslcommerz",
                    refundRefId: settlement.refundRefId,
                    amount: Number(booking.amount),
                    adminNote,
                  },
                  createdAt: new Date(),
                },
                { session }
              );
            });
            return res.send({ message: "SSLCOMMERZ refund completed and dispute resolved." });
          } catch (err) {
            if (err.code === "ALREADY_SETTLED") {
              const currentBooking = await bookingsCollection.findOne({ _id: booking._id });
              if (currentBooking?.escrowStatus === "refunded") {
                return res.send({ message: "Refund was already settled." });
              }
              return res.status(409).send({ message: "Refund settlement state changed concurrently." });
            }
            throw err;
          } finally {
            await session.endSession();
          }
        }

        if (status === "cancelled") {
          const session = client.startSession();
          try {
            await session.withTransaction(async () => {
              const settlementUpdate = await escrowSettlementsCollection.updateOne(
                { _id: settlement._id, status: "processing" },
                { $set: { status: "cancelled", providerStatus: refundStatus, updatedAt: new Date() } },
                { session }
              );
              const bookingUpdate = await bookingsCollection.updateOne(
                { _id: booking._id, escrowStatus: "refund_processing" },
                { $set: { escrowStatus: "frozen", updatedAt: new Date() } },
                { session }
              );
              const disputeUpdate = await disputesCollection.updateOne(
                { _id: disputeId, status: "refund_processing" },
                { $set: { status: "open", updatedAt: new Date() } },
                { session }
              );
              if (
                settlementUpdate.modifiedCount !== 1 ||
                bookingUpdate.modifiedCount !== 1 ||
                disputeUpdate.modifiedCount !== 1
              ) {
                throw new Error("Refund cancellation state changed concurrently.");
              }
            });
          } finally {
            await session.endSession();
          }
          return res.status(409).send({ message: "SSLCOMMERZ cancelled the refund; dispute remains open." });
        }

        return res.status(202).send({
          message: "Refund is still processing with SSLCOMMERZ.",
          refundStatus: status || "unknown",
        });
      } catch (err) {
        console.error("SSLCOMMERZ refund status error:", err);
        return res.status(502).send({ message: "Failed to query SSLCOMMERZ refund status." });
      }
    }

    return res.status(409).send({
      message: `Refund is in state "${settlement.status}" and requires gateway reconciliation.`,
    });
  }
);


// ==========================================
// PHASE 5.1: BUYER BOOKINGS & UNMASKED HANDOVER
// ==========================================
// ==========================================
// PHASE 5.1: BUYER BOOKINGS & UNMASKED HANDOVER
// ==========================================

app.get("/api/bookings/my", requireAuth, async (req, res) => {
  try {
    const buyerId = req.user._id.toString();

    const bookings = await bookingsCollection
      .aggregate([
        { $match: { buyerId } },
        { $sort: { createdAt: -1 } },
        {
          $addFields: {
            ticketObjId: {
              $cond: [
                { $eq: [{ $type: "$ticketId" }, "objectId"] },
                "$ticketId",
                {
                  $convert: {
                    input: "$ticketId",
                    to: "objectId",
                    onError: null,
                    onNull: null,
                  },
                },
              ],
            },
            sellerObjId: {
              $cond: [
                { $eq: [{ $type: "$sellerId" }, "objectId"] },
                "$sellerId",
                {
                  $convert: {
                    input: "$sellerId",
                    to: "objectId",
                    onError: null,
                    onNull: null,
                  },
                },
              ],
            },
          },
        },
        {
          $lookup: {
            from: "tickets",
            localField: "ticketObjId",
            foreignField: "_id",
            as: "ticketDoc",
          },
        },
        {
          $unwind: {
            path: "$ticketDoc",
            preserveNullAndEmptyArrays: true,
          },
        },
        {
          $lookup: {
            from: "users",
            localField: "sellerObjId",
            foreignField: "_id",
            as: "sellerDoc",
          },
        },
        {
          $unwind: {
            path: "$sellerDoc",
            preserveNullAndEmptyArrays: true,
          },
        },
        {
          $project: {
            _id: 1,
            ticketId: 1,
            paymentId: 1,
            buyerId: 1,
            sellerId: 1,
            tranId: 1,
            gateway: 1,
            cardType: 1,
            fare: 1,
            platformFee: 1,
            amount: 1,
            escrowStatus: 1,
            bookingStatus: 1,
            createdAt: 1,
            confirmedAt: 1,
            releasedAt: 1,
            // Joined ticket fields (unmasked exclusively for this buyer)
            trainName: { $ifNull: ["$ticketDoc.trainName", "$trainName"] },
            trainNumber: { $ifNull: ["$ticketDoc.trainNumber", "$trainNumber"] },
            seatClass: { $ifNull: ["$ticketDoc.seatClass", "S_CHAIR"] },
            fromStation: { $ifNull: ["$ticketDoc.fromStation", "$fromStation"] },
            toStation: { $ifNull: ["$ticketDoc.toStation", "$toStation"] },
            journeyDate: { $ifNull: ["$ticketDoc.journeyDate", "$journeyDate"] },
            departureTime: {
              $ifNull: ["$ticketDoc.departureTime", "$departureTime"],
            },
            coach: {
              $ifNull: ["$ticketDoc.coach", "$unlockedDetails.coach"],
            },
            seatNumber: {
              $ifNull: ["$ticketDoc.seatNumber", "$unlockedDetails.seatNumber"],
            },
            pnr: {
              $ifNull: ["$ticketDoc.pnr", "$unlockedDetails.pnr"],
            },
            ticketFileUrl: {
              $ifNull: [
                "$ticketDoc.ticketFileUrl",
                "$unlockedDetails.ticketFileUrl",
              ],
            },
            // Joined seller contact & verification
            sellerName: {
              $ifNull: ["$sellerDoc.name", "$sellerName"],
            },
            sellerPhone: {
              $ifNull: [
                "$sellerDoc.phone",
                {
                  $ifNull: ["$ticketDoc.sellerPhone", "$ticketDoc.phone"],
                },
              ],
            },
            sellerVerified: {
              $eq: ["$sellerDoc.kycStatus", "verified"],
            },
          },
        },
      ])
      .toArray();

    res.send(bookings);
  } catch (err) {
    console.error("Fetch buyer bookings error:", err);
    res.status(500).send({
      message: "Failed to load your bookings.",
    });
  }
});

// ==========================================
// PHASE 5.2: "REACHED SAFELY" & ESCROW RELEASE
// ==========================================
app.patch("/api/bookings/:id/confirm-journey", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        message: "Invalid booking ID.",
      });
    }

    const bookingObjectId = new ObjectId(id);
    const buyerId = req.user._id.toString();
    const now = new Date();

    const existingBooking = await bookingsCollection.findOne({ _id: bookingObjectId });
    if (!existingBooking) {
      return res.status(404).send({
        message: "Booking not found.",
      });
    }

    if (existingBooking.buyerId !== buyerId) {
      return res.status(403).send({
        message: "Only the buyer of this booking can confirm journey completion.",
      });
    }

    if (existingBooking.escrowStatus === "frozen") {
      return res.status(409).send({
        message:
          "Escrow is currently frozen due to an active dispute and cannot be released directly.",
      });
    }

    if (existingBooking.escrowStatus === "released") {
      return res.status(409).send({
        message: "Escrow funds have already been released to the seller.",
      });
    }

    // Atomically transition booking escrowStatus from "held" to "released"
    const releasedBooking = await bookingsCollection.findOneAndUpdate(
      {
        _id: bookingObjectId,
        buyerId,
        escrowStatus: "held",
      },
      {
        $set: {
          escrowStatus: "released",
          journeyConfirmedAt: now,
          releasedAt: now,
          updatedAt: now,
        },
      },
      {
        returnDocument: "after",
      }
    );

    if (!releasedBooking) {
      return res.status(409).send({
        message: "Unable to release escrow. Booking state may have changed.",
      });
    }

    const sellerPayoutAmount = Number(releasedBooking.fare ?? releasedBooking.amount ?? 0);

    // Credit seller's walletBalance (supports ObjectId or string _id in Better-Auth user collection)
    const sellerFilter = ObjectId.isValid(releasedBooking.sellerId)
      ? {
        $or: [
          { _id: new ObjectId(releasedBooking.sellerId) },
          { _id: releasedBooking.sellerId },
        ],
      }
      : { _id: releasedBooking.sellerId };

    await usersCollection.updateOne(sellerFilter, {
      $inc: { walletBalance: sellerPayoutAmount },
      $set: { updatedAt: now },
    });

    await ticketsCollection.updateOne(
      { _id: new ObjectId(releasedBooking.ticketId) },
      {
        $set: {
          escrowStatus: "released",
          journeyCompletedAt: now,
          updatedAt: now,
        },
      }
    );

    res.send({
      message: `Journey confirmed! ৳${sellerPayoutAmount} released to the seller's wallet.`,
      booking: releasedBooking,
      creditedAmount: sellerPayoutAmount,
    });

  } catch (err) {
    console.error("Confirm journey / escrow release error:", err);
    res.status(500).send({
      message: "Failed to confirm journey and release escrow.",
    });
  }
});



// ==========================================
// PHASE 5.3: DISPUTE REPORTING & ADMIN RESOLUTION
// ==========================================
// Helper to match Better-Auth user by string or ObjectId _id
const buildUserIdFilter = (userId) => {
  if (!userId) return null;
  if (ObjectId.isValid(userId)) {
    return {
      $or: [{ _id: new ObjectId(userId) }, { _id: userId }],
    };
  }
  return { _id: userId };
}

// 1. POST /api/bookings/:id/dispute — Buyer reports fraud/issue and freezes escrow
app.post("/api/bookings/:id/dispute", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason, description } = req.body;

    if (!ObjectId.isValid(id)) {
      return res.status(400).send({
        message: "Invalid booking ID.",
      });
    }

    const trimmedReason = String(reason || "").trim();
    const trimmedDescription = String(description || "").trim();

    if (!trimmedReason || trimmedDescription.length < 10) {
      return res.status(400).send({
        message:
          "Please select a dispute reason and provide at least 10 characters of details.",
      });
    }

    const bookingObjectId = new ObjectId(id);
    const buyerId = req.user._id.toString();
    const now = new Date();

    const booking = await bookingsCollection.findOne({ _id: bookingObjectId });
    if (!booking) {
      return res.status(404).send({
        message: "Booking not found.",
      });
    }

    if (booking.buyerId !== buyerId) {
      return res.status(403).send({
        message: "Only the buyer of this booking can report a dispute.",
      });
    }

    if (booking.escrowStatus !== "held") {
      return res.status(409).send({
        message: `Cannot open a dispute because escrow status is currently '${booking.escrowStatus}'.`,
      });
    }

    const frozenBooking = await bookingsCollection.findOneAndUpdate(
      {
        _id: bookingObjectId,
        buyerId,
        escrowStatus: "held",
      },
      {
        $set: {
          escrowStatus: "frozen",
          disputedAt: now,
          updatedAt: now,
        },
      },
      {
        returnDocument: "after",
      }
    );

    if (!frozenBooking) {
      return res.status(409).send({
        message:
          "Booking escrow could not be frozen. It may have already been released or disputed.",
      });
    }

    const disputeDoc = {
      bookingId: frozenBooking._id,
      ticketId: frozenBooking.ticketId,
      buyerId,
      buyerEmail: req.user.email || frozenBooking.buyerEmail || "",
      buyerName: req.user.name || "",
      sellerId: frozenBooking.sellerId,
      sellerName: frozenBooking.sellerName || "",
      amount: Number(frozenBooking.amount || 0),
      fare: Number(frozenBooking.fare ?? frozenBooking.amount ?? 0),
      reason: trimmedReason,
      description: trimmedDescription,
      status: "open",
      resolution: null,
      adminNote: "",
      resolvedBy: null,
      createdAt: now,
      updatedAt: now,
    };

    const insertResult = await disputesCollection.insertOne(disputeDoc);
    const createdDispute = {
      _id: insertResult.insertedId,
      ...disputeDoc,
    };

    await bookingsCollection.updateOne(
      { _id: frozenBooking._id },
      {
        $set: {
          disputeId: insertResult.insertedId,
        },
      }
    );

    res.status(201).send({
      message:
        "Dispute submitted. Escrow funds are now frozen pending admin review.",
      dispute: createdDispute,
      booking: {
        ...frozenBooking,
        disputeId: insertResult.insertedId,
      },
    });
  } catch (err) {
    console.error("Create booking dispute error:", err);
    res.status(500).send({
      message: "Failed to submit dispute report.",
    });
  }

});

// 2. GET /api/admin/disputes — Admin queue of disputes joined with booking & ticket info
app.get(
  "/api/admin/disputes",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const statusFilter = String(req.query.status || "all").toLowerCase();
      const matchStage =
        statusFilter === "open" || statusFilter === "resolved"
          ? { status: statusFilter }
          : {};

      const disputes = await disputesCollection
        .aggregate([
          { $match: matchStage },
          { $sort: { createdAt: -1 } },
          {
            $addFields: {
              bookingObjId: {
                $cond: [
                  { $eq: [{ $type: "$bookingId" }, "objectId"] },
                  "$bookingId",
                  {
                    $convert: {
                      input: "$bookingId",
                      to: "objectId",
                      onError: null,
                      onNull: null,
                    },
                  },
                ],
              },
            },
          },
          {
            $lookup: {
              from: "bookings",
              localField: "bookingObjId",
              foreignField: "_id",
              as: "bookingDoc",
            },
          },
          {
            $unwind: {
              path: "$bookingDoc",
              preserveNullAndEmptyArrays: true,
            },
          },
          {
            $project: {
              _id: 1,
              bookingId: 1,
              ticketId: 1,
              buyerId: 1,
              buyerEmail: 1,
              buyerName: 1,
              sellerId: 1,
              sellerName: 1,
              amount: 1,
              fare: 1,
              reason: 1,
              description: 1,
              status: 1,
              resolution: 1,
              adminNote: 1,
              resolvedBy: 1,
              resolvedAt: 1,
              createdAt: 1,
              escrowStatus: "$bookingDoc.escrowStatus",
              tranId: "$bookingDoc.tranId",
              trainName: "$bookingDoc.trainName",
              trainNumber: "$bookingDoc.trainNumber",
              fromStation: "$bookingDoc.fromStation",
              toStation: "$bookingDoc.toStation",
              journeyDate: "$bookingDoc.journeyDate",
              pnr: "$bookingDoc.unlockedDetails.pnr",
              seatNumber: "$bookingDoc.unlockedDetails.seatNumber",
              coach: "$bookingDoc.unlockedDetails.coach",
              ticketFileUrl: "$bookingDoc.unlockedDetails.ticketFileUrl",
            },
          },
        ])
        .toArray();

      res.send(disputes);
    } catch (err) {
      console.error("Admin fetch disputes error:", err);
      res.status(500).send({
        message: "Failed to load disputes queue.",
      });
    }
  });

// 3. PATCH /api/admin/disputes/:id/resolve — Admin refunds buyer or releases payout to seller
app.patch(
  "/api/admin/disputes/:id/resolve",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { resolution, adminNote } = req.body;

      if (!ObjectId.isValid(id)) {
        return res.status(400).send({
          message: "Invalid dispute ID.",
        });
      }

      if (!["refund_buyer", "release_seller"].includes(resolution)) {
        return res.status(400).send({
          message:
            "Resolution must be either 'refund_buyer' or 'release_seller'.",
        });
      }

      const disputeObjectId = new ObjectId(id);
      const adminId = req.user._id.toString();
      const now = new Date();
      const trimmedNote = String(adminNote || "").trim();

      if (!dispute) {
        return res.status(404).send({
          message: "Dispute record not found.",
        });
      }

      if (dispute.status === "resolved") {
        return res.status(409).send({
          message: "This dispute has already been resolved.",
        });
      }

      const booking = await bookingsCollection.findOne({
        _id: new ObjectId(dispute.bookingId),
      });
      if (!booking) {
        return res.status(404).send({
          message: "Associated booking not found.",
        });
      }

      const nextEscrowStatus =
        resolution === "refund_buyer" ? "refunded" : "released";

      const creditAmount =
        resolution === "refund_buyer"
          ? Number(booking.amount ?? dispute.amount ?? 0)
          : Number(booking.fare ?? booking.amount ?? dispute.fare ?? 0);

      const targetUserId =
        resolution === "refund_buyer" ? booking.buyerId : booking.sellerId;

      const userFilter = buildUserIdFilter(targetUserId);
      if (userFilter && creditAmount > 0) {
        await usersCollection.updateOne(userFilter, {
          $inc: { walletBalance: creditAmount },
          $set: { updatedAt: now },
        });
      }

      const updatedBooking = await bookingsCollection.findOneAndUpdate(
        { _id: booking._id },
        {
          $set: {
            escrowStatus: nextEscrowStatus,
            resolvedAt: now,
            updatedAt: now,
          },
        },
        { returnDocument: "after" }
      );

      const updatedDispute = await disputesCollection.findOneAndUpdate(
        { _id: disputeObjectId, status: "open" },
        {
          $set: {
            status: "resolved",
            resolution,
            adminNote: trimmedNote,
            creditedAmount: creditAmount,
            resolvedBy: adminId,
            resolvedAt: now,
            updatedAt: now,
          },
        },
        { returnDocument: "after" }
      );

      // Write audit log entry
      const auditEntry = {
        action:
          resolution === "refund_buyer"
            ? "DISPUTE_REFUND_BUYER"
            : "DISPUTE_RELEASE_SELLER",
        targetType: "dispute",
        targetId: disputeObjectId,
        bookingId: booking._id,
        ticketId: booking.ticketId,
        actorId: adminId,
        actorEmail: req.user.email || "",
        resolution,
        escrowStatus: nextEscrowStatus,
        creditedAmount: creditAmount,
        recipientUserId: targetUserId,
        note: trimmedNote,
        createdAt: now,
      };

      await auditLogsCollection.insertOne(auditEntry);

      res.send({
        message:
          resolution === "refund_buyer"
            ? `Dispute resolved: ৳${creditAmount} refunded to buyer's wallet.`
            : `Dispute resolved: ৳${creditAmount} released to seller's wallet.`,
        dispute: updatedDispute,
        booking: updatedBooking,
      });

    } catch (err) {
      console.error("Resolve dispute error:", err);
      res.status(500).send({
        message: "Failed to resolve dispute.",
      });
    }
  });



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