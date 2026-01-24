const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { ethers } = require('ethers');
const Web3 = require('web3');
const { Resend } = require('resend');
const { initializeServer, getContracts } = require('./contractConfigGenerator');
require('dotenv').config();
const fs = require('fs');
const axios = require('axios');
const path = require('path');
const rateLimit = require('express-rate-limit');
// ABI מינימלי רק לפונקציה שאנחנו צריכים
const verifyOwnershipABI = [
  {
      "inputs": [
          { "internalType": "address", "name": "owner", "type": "address" },
          { "internalType": "string", "name": "productBarcode", "type": "string" }
      ],
      "name": "verifyOwnershipByBarcode",
      "outputs": [{ "internalType": "bool", "name": "", "type": "bool" }],
      "stateMutability": "view",
      "type": "function"
  }
];
const app = express();
app.set('trust proxy', 1);
app.use(express.json());

// הגדרות CORS
const allowedOrigins = [
  'http://localhost:5173',
  'https://www.ultrashop.tech',
  'https://ultrashop.tech'
];
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000);
const RATE_LIMIT_MAX_IP = Number(process.env.RATE_LIMIT_MAX_IP || 60);
// -------------------- 10-min refresh + subscription guard --------------------
const CONFIG_REFRESH_MS = 10 * 60 * 1000; // 10 minutes
let refreshingConfigs = false;

// Track which contract addresses are already subscribed (prevents duplicates)
const activeSubscriptions = new Map(); // addressLower -> Array(subscriptions)
const accessLimiterIP = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX_IP,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // curl/postman
    if (!allowedOrigins.includes(origin)) {
      return callback(new Error('Not allowed by CORS'));
    }
    return callback(null, true);
  },
  credentials: true
}));

// --- משתני סביבה ---
const MONGO_URI = process.env.MONGO_URI;
const SERVER_PRIVATE_KEY = process.env.SERVER_PRIVATE_KEY;
const WEBSOCKET_URL_API = process.env.WEBSOCKET_URL_API;
const EMAIL_API_KEY = process.env.EMAILP; 
const PORT = process.env.PORT || 5000;

// אתחול Resend API
const resend = new Resend(EMAIL_API_KEY);

// --- הגדרת Volume ו-Data Directory ---
const DATA_DIR = process.env.RAILWAY_ENVIRONMENT ? '/app/data' : './';

if (!fs.existsSync(DATA_DIR)) {
    try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    } catch (err) {
        console.error('Error creating data directory:', err);
    }
}

const processedEventsFile = path.join(DATA_DIR, 'processedEvents.json');
const lastProcessedBlockFile = path.join(DATA_DIR, 'lastProcessedBlock.json');
const pidFile = path.join(DATA_DIR, 'server.pid');

fs.writeFileSync(pidFile, process.pid.toString());

// --- חיבור ל-MongoDB ---
mongoose
  .connect(MONGO_URI)
  .then(async () => {
    console.log('Server Connected to MongoDB');
    try {
      const clientCollection = mongoose.connection.collection('clients');
      const indexes = await clientCollection.indexes();
      const oldIndex = indexes.find(idx => idx.name === 'walletAddress_1');
      
      if (oldIndex) {
        console.log('Dropping old conflicting index (walletAddress_1)...');
        await clientCollection.dropIndex('walletAddress_1');
        console.log('Old index dropped.');
      }
    } catch (err) {
      if (err.code !== 27) console.error('Index warning:', err.message);
    }
  })
  .catch((err) => console.error('MongoDB error', err));

// --- Schemas ---

const ClientSchema = new mongoose.Schema({
  walletAddress: { type: String, required: true },
  storeContractAddress: { type: String, required: true },
  name: String,
  email: String,
  phone: String,
  physicalAddress: String,
  registeredAt: { type: Date, default: Date.now },
  lastEmailSent: { type: Date }
});

ClientSchema.index({ walletAddress: 1, storeContractAddress: 1 }, { unique: true });
const AccessNonceSchema = new mongoose.Schema({
  walletAddress: { type: String, required: true, index: true },
  nonce: { type: String, required: true, unique: true, index: true },
  origin: { type: String, required: true },
  chainId: { type: Number },
  createdAt: { type: Date, default: Date.now, expires: 300 } ,
  purpose: { type: String, default: "user" }, // "user" | "admin"
  storeAddress: { type: String },
});

function requireAllowedOrigin(req, res) {
  const origin = req.headers.origin;
  if (!origin || !allowedOrigins.includes(origin)) {
    res.status(403).json({ error: 'Bad origin' });
    return null;
  }
  return origin;
}

app.post("/api/admin/challenge", accessLimiterIP, walletLimiter, async (req, res) => {
  const origin = requireAllowedOrigin(req, res);
  if (!origin) return;

  const { walletAddress, storeAddress, chainId } = req.body;
  if (!walletAddress || !storeAddress) return res.status(400).json({ error: "Missing walletAddress/storeAddress" });

  const nonce = crypto.randomBytes(16).toString("hex");

  await AccessNonce.create({
    walletAddress: normAddr(walletAddress),
    nonce,
    origin,
    chainId: chainId ? Number(chainId) : undefined,
    purpose: "admin",
    storeAddress: normAddr(storeAddress),
    createdAt: new Date(),
  });

  res.json({ success: true, nonce, ttlMs: 300000 });
});

app.post("/api/admin/login", accessLimiterIP, walletLimiter, async (req, res) => {
  const origin = requireAllowedOrigin(req, res);
  if (!origin) return;

  const { walletAddress, storeAddress, signature, timestamp, nonce, chainId } = req.body;
  if (!walletAddress || !storeAddress || !signature || !timestamp || !nonce) {
    return res.status(400).json({ error: "Missing parameters" });
  }

  // 1) timestamp max-age
  const ts = Number(timestamp);
  const timeDiff = Math.abs(Date.now() - ts);
  if (!Number.isFinite(timeDiff) || timeDiff > ACCESS_MSG_MAX_AGE_MS) {
    return res.status(400).json({ error: "Signature expired" });
  }

  // 2) nonce must exist (one-time use) + must match admin + store + origin
  const nonceDoc = await AccessNonce.findOne({
    walletAddress: normAddr(walletAddress),
    nonce: String(nonce),
    origin,
    purpose: "admin",
    storeAddress: normAddr(storeAddress),
  });
  if (!nonceDoc) return res.status(400).json({ error: "Invalid or used nonce" });

  if (chainId && nonceDoc.chainId && Number(chainId) !== Number(nonceDoc.chainId)) {
    await AccessNonce.deleteOne({ _id: nonceDoc._id });
    return res.status(400).json({ error: "ChainId mismatch" });
  }

  // 3) build message (bind EVERYTHING)
  const msg = [
    "UltraShop Admin Login",
    `Domain: ${origin}`,
    `Wallet: ${normAddr(walletAddress)}`,
    `Store: ${normAddr(storeAddress)}`,
    `Timestamp: ${ts}`,
    `Nonce: ${String(nonce)}`,
    `ChainId: ${chainId ? Number(chainId) : ""}`,
  ].join("\n");

  // 4) verify signature
  const recovered = ethers.verifyMessage(msg, signature);
  if (normAddr(recovered) !== normAddr(walletAddress)) {
    await AccessNonce.deleteOne({ _id: nonceDoc._id });
    return res.status(401).json({ error: "Invalid signature" });
  }

  // 5) invalidate nonce now
  await AccessNonce.deleteOne({ _id: nonceDoc._id });

  // 6) verify ownership (choose ONE)
  // (A) Stronger: read on-chain contractOwner()
  // 6) verify ownership (Using Ethers.js)
  try {
    // 1. Setup provider for Base Chain
    const provider = new ethers.JsonRpcProvider('https://mainnet.base.org');
    
    // 2. Define ABI (Check if your contract uses 'owner' or 'contractOwner')
    const ownerAbi = ["function contractOwner() view returns (address)"]; 
    // OR if standard Ownable: ["function owner() view returns (address)"]

    // 3. Create contract instance
    const contract = new ethers.Contract(storeAddress, ownerAbi, provider);

    // 4. Call function
    const owner = await contract.contractOwner(); // Or contract.owner();

    if (normAddr(owner) !== normAddr(walletAddress)) {
      return res.status(403).json({ error: "Not contract owner" });
    }
  } catch (e) {
    console.error("Contract Verification Error:", e); // <--- LOG THE ACTUAL ERROR
    return res.status(500).json({ error: "Failed to verify contract owner" });
  }

  // 7) issue JWT
  const token = signAdminJwt({
    walletAddress: normAddr(walletAddress),
    storeAddress: normAddr(storeAddress),
    origin,
    chainId: chainId ? Number(chainId) : undefined,
  });

  res.json({ success: true, token, expiresIn: ADMIN_JWT_TTL_SECONDS });
});


const AccessNonce = mongoose.model('AccessNonce', AccessNonceSchema);
// --- Schema לתוכן מוסתר (IPFS) ---
const HiddenContentSchema = new mongoose.Schema({
  storeContractAddress: { type: String, required: true },
  productBarcode: { type: String, required: true },
  ipfsHash: { type: String, required: true }, // ה-CID של הקובץ
  updatedAt: { type: Date, default: Date.now }
});

// אינדקס ייחודי: לכל מוצר בחנות יש רק קובץ מוסתר אחד
HiddenContentSchema.index({ storeContractAddress: 1, productBarcode: 1 }, { unique: true });

const HiddenContent = mongoose.model('HiddenContent', HiddenContentSchema);

const StoreSchema = new mongoose.Schema({
  smartContractAddress: { type: String, required: true, unique: true },
  ownerAddress: String,
  passwordHash: String,
  registeredAt: { type: Date, default: Date.now },
  webhookUrl: { type: String }, // <--- הוסף שדה זה
  
  // pending password flow... (השאר את השאר אותו דבר)
  pendingPasswordEnc: String,
  pendingTokenEnc: String,
  pendingTokenHash: String,
  pendingExpiresAt: Date,
  passwordClaimedAt: Date,
});


function sha256(x) {
  return crypto.createHash('sha256').update(String(x)).digest('hex');
}

const ENC_KEY = process.env.ADMIN_PASS_ENC_KEY; 
// MUST be 32 bytes for aes-256-gcm. Example: a 64-hex string.

function encryptText(plain) {
  const key = Buffer.from(ENC_KEY, 'hex'); // 32 bytes
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64'); // iv(12)+tag(16)+ciphertext
}

function decryptText(b64) {
  const buf = Buffer.from(String(b64), 'base64');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const enc = buf.subarray(28);
  const key = Buffer.from(ENC_KEY, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString('utf8');
}

// פונקציית עזר לשליחת וובהוק
async function dispatchWebhook(storeAddress, eventType, payload) {
  try {
      // מציאת החנות וה-URL שלה
      const store = await Store.findOne({ 
          smartContractAddress: { $regex: new RegExp(`^${normAddr(storeAddress)}$`, 'i') } 
      });

      if (store && store.webhookUrl) {
          console.log(`🚀 Triggering Webhook for ${storeAddress} [${eventType}]`);
          
          // שליחת המידע
          await axios.post(store.webhookUrl, {
              event: eventType,
              timestamp: Date.now(),
              store: storeAddress,
              data: payload
          }, { timeout: 5000 }); // Timeout של 5 שניות שלא יתקע את השרת
      }
  } catch (error) {
      console.error(`❌ Webhook failed for ${storeAddress}:`, error.message);
  }
}

function normStoreKey(s) {
  return String(s || '').trim().toLowerCase()
}

// --- הגדרת Webhook לחנות ---
app.post("/api/store/set-webhook", requireAdminAuth, async (req, res) => {
  try {
      const { webhookUrl } = req.body;
      const storeAddress = req.admin.storeAddress;

      // עדכון כתובת ה-Webhook ב-DB
      await Store.findOneAndUpdate(
          { smartContractAddress: { $regex: new RegExp(`^${normAddr(storeAddress)}$`, 'i') } },
          { webhookUrl: webhookUrl },
          { upsert: true }
      );

      return res.json({ success: true, message: "Webhook updated successfully" });
  } catch (e) {
      console.error("set-webhook error:", e);
      return res.status(500).json({ success: false, error: "Server error" });
  }
});

// --- שליפת ה-Webhook הנוכחי (כדי להציג למנהל) ---
app.post("/api/store/get-webhook", requireAdminAuth, async (req, res) => {
  try {
      const storeAddress = req.admin.storeAddress;
      const store = await Store.findOne({ 
          smartContractAddress: { $regex: new RegExp(`^${normAddr(storeAddress)}$`, 'i') } 
      });

      return res.json({ success: true, webhookUrl: store?.webhookUrl || "" });
  } catch (e) {
      return res.status(500).json({ success: false, error: "Server error" });
  }
});


// --- Schema חדשה להזמנות (CQRS) ---
// --- Schema להזמנות עם Snapshot של פרטי לקוח ---
const OrderSchema = new mongoose.Schema({
  receiptId: { type: Number, required: true, unique: true },
  clientAddress: { type: String, required: true, index: true },
  storeContractAddress: String,
  productBarcode: String,
  productName: String,
  price: Number,
  timestamp: Number,
  isRefunded: { type: Boolean, default: false },
  // הוספת שדות Snapshot כדי שהמידע יישמר גם אם הלקוח נמחק
  clientSnapshot: {
    name: String,
    email: String,
    phone: String,
    physicalAddress: String
  }
});

const Client = mongoose.model('Client', ClientSchema);
const Store = mongoose.model('Store', StoreSchema);
const Order = mongoose.model('Order', OrderSchema);

const signerWallet = new ethers.Wallet(SERVER_PRIVATE_KEY);
const ACCESS_MSG_MAX_AGE_MS = Number(process.env.ACCESS_MSG_MAX_AGE_MS || 60_000); // 60s

const RATE_LIMIT_MAX_WALLET = Number(process.env.RATE_LIMIT_MAX_WALLET || 30);

function normAddr(a) {
  return String(a || '').trim().toLowerCase();
}


// wallet-based limiter (simple in-memory)
const walletHits = new Map();
function walletLimiter(req, res, next) {
  const addr = normAddr(req.body?.walletAddress);
  const now = Date.now();

  if (!addr) return next();

  const rec = walletHits.get(addr) || { resetAt: now + RATE_LIMIT_WINDOW_MS, count: 0 };
  if (now > rec.resetAt) {
    rec.resetAt = now + RATE_LIMIT_WINDOW_MS;
    rec.count = 0;
  }
  rec.count += 1;
  walletHits.set(addr, rec);

  if (rec.count > RATE_LIMIT_MAX_WALLET) {
    return res.status(429).json({ error: 'Too many requests (wallet rate limit)' });
  }
  next();
}

// Optional: cleanup map occasionally
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of walletHits.entries()) {
    if (now > v.resetAt + RATE_LIMIT_WINDOW_MS) walletHits.delete(k);
  }
}, 5 * 60 * 1000);

const websocketUrl = `wss://base-mainnet.g.alchemy.com/v2/${WEBSOCKET_URL_API}`;
const web3 = new Web3(
  new Web3.providers.WebsocketProvider(websocketUrl, {
    reconnect: { auto: true, delay: 10000, onTimeout: false },
  })
);

const EMAIL_SPACING_MS = 1000; // 1 second per email (your requirement)
let lastEmailSentAt = 0;
let emailQueue = Promise.resolve();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function sendEmail(to, subject, text) {
  if (!to || !String(to).includes("@")) {
    console.log(`Skipping email, invalid address: ${to}`);
    return;
  }

  // Enqueue every email send to ensure spacing globally
  emailQueue = emailQueue.then(async () => {
      // Ensure 1s spacing since the last send
      const now = Date.now();
      const waitMs = Math.max(0, EMAIL_SPACING_MS - (now - lastEmailSentAt));
      if (waitMs > 0) await sleep(waitMs);

      try {
        const { data, error } = await resend.emails.send({
          from: process.env.EMAIL,
          to: [to],
          subject,
          text,
        });

        if (error) {
          console.error("Resend API Error:", error);
          return;
        }

        lastEmailSentAt = Date.now();
        console.log(`Email sent successfully to ${to}, ID: ${data.id}`);
      } catch (err) {
        console.error("Email sending failed:", err);
      }
    })
    .catch((e) => {
      // keep queue alive even if one email fails
      console.error("Email queue error:", e);
    });

  return emailQueue;
}

// Helper: Get client specific to a store
async function getClientFromDB(walletAddress, storeAddress) {
  if (!walletAddress || !storeAddress) return null;
  return await Client.findOne({
    walletAddress: { $regex: new RegExp('^' + walletAddress + '$', 'i') },
    storeContractAddress: { $regex: new RegExp('^' + storeAddress + '$', 'i') }
  });
}

// --- API Routes ---

app.get('/', (req, res) => {
    res.send('Server is running healthy via Resend API!');
});

app.post('/api/access-challenge', accessLimiterIP, walletLimiter, async (req, res) => {
  const origin = requireAllowedOrigin(req, res);
  if (!origin) return;

  const { walletAddress, chainId } = req.body;

  if (!walletAddress) return res.status(400).json({ error: 'Missing walletAddress' });

  const nonce = crypto.randomBytes(16).toString('hex');

  try {
    await AccessNonce.create({
      walletAddress: normAddr(walletAddress),
      nonce,
      origin,
      chainId: chainId ? Number(chainId) : undefined,
      createdAt: new Date()
    });

    res.json({ success: true, nonce, ttlMs: 300000 });
  } catch (e) {
    console.error('access-challenge error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});


// --- 1. העלאת תוכן מוסתר (לבעל החנות) ---
app.post("/api/store/upload-hidden-content", requireAdminAuth, async (req, res) => {
  try {
    const storeAddress = req.admin.storeAddress;
    const { productBarcode, ipfsHash } = req.body;

    if (!productBarcode) return res.status(400).json({ success: false, error: "Missing productBarcode" });
    if (!ipfsHash) return res.status(400).json({ success: false, error: "Missing ipfsHash" });

    const barcode = String(productBarcode).trim();
    const cid = String(ipfsHash).trim();

    // Replace HiddenContent with your real model name
    const doc = await HiddenContent.findOneAndUpdate(
      { storeContractAddress: normAddr(storeAddress), productBarcode: barcode },
      { $set: { ipfsHash: cid, updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } },
      { upsert: true, new: true }
    ).lean();

    return res.json({ success: true, data: { productBarcode: doc.productBarcode, ipfsHash: doc.ipfsHash } });
  } catch (e) {
    console.error("upload-hidden-content error:", e);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});

// --- 2. קבלת תוכן מוסתר (ללקוח - עם אימות חתימה ובלוקצ'יין) ---
app.post('/api/access-hidden-content', accessLimiterIP, walletLimiter, async (req, res) => {
  const origin = requireAllowedOrigin(req, res);
  if (!origin) return;

  const {
    walletAddress,
    signature,
    timestamp,
    storeAddress,
    productBarcode,
    nonce,
    chainId
  } = req.body;

  if (!walletAddress || !signature || !timestamp || !storeAddress || !productBarcode || !nonce) {
    return res.status(400).json({ error: 'Missing parameters' });
  }

  try {
    // 1) Timestamp max-age
    const ts = Number(timestamp);
    const timeDiff = Math.abs(Date.now() - ts);
    if (!Number.isFinite(timeDiff) || timeDiff > ACCESS_MSG_MAX_AGE_MS) {
      return res.status(400).json({ error: 'Signature expired' });
    }

    // 2) Validate nonce exists (and belongs to wallet+origin) -> one-time use
    const nonceDoc = await AccessNonce.findOne({
      walletAddress: normAddr(walletAddress),
      nonce: String(nonce),
      origin
    });

    if (!nonceDoc) {
      return res.status(400).json({ error: 'Invalid or used nonce' });
    }

    // Optional chain binding
    if (chainId && nonceDoc.chainId && Number(chainId) !== Number(nonceDoc.chainId)) {
      await AccessNonce.deleteOne({ _id: nonceDoc._id });
      return res.status(400).json({ error: 'ChainId mismatch' });
    }

    // 3) Build message (bind EVERYTHING)
    const msg = [
      `UltraShop Hidden Content Access`,
      `Domain: ${origin}`,
      `Wallet: ${normAddr(walletAddress)}`,
      `Store: ${normAddr(storeAddress)}`,
      `Barcode: ${String(productBarcode)}`,
      `Timestamp: ${ts}`,
      `Nonce: ${String(nonce)}`,
      `ChainId: ${chainId ? Number(chainId) : ''}`,
    ].join('\n');

    // 4) Verify signature
    const recovered = ethers.verifyMessage(msg, signature);
    if (normAddr(recovered) !== normAddr(walletAddress)) {
      await AccessNonce.deleteOne({ _id: nonceDoc._id });
      return res.status(401).json({ error: 'Invalid signature' });
    }

    // 5) Invalidate nonce now (prevents replay)
    await AccessNonce.deleteOne({ _id: nonceDoc._id });

    // 6) Derive invoices() from store contract (DON'T trust client invoiceContractAddress)
    const invoicesAbi = [{
      "inputs": [],
      "name": "invoices",
      "outputs": [{ "internalType": "address", "name": "", "type": "address" }],
      "stateMutability": "view",
      "type": "function"
    }];

    const store = new web3.eth.Contract(invoicesAbi, storeAddress);

    let invoicesAddress;
    try {
      invoicesAddress = await store.methods.invoices().call();
    } catch (e) {
      return res.status(500).json({ error: 'Failed to read invoices() from store contract' });
    }

    // 7) Verify ownership on invoices contract
    const invoices = new web3.eth.Contract(verifyOwnershipABI, invoicesAddress);
    const isOwner = await invoices.methods.verifyOwnershipByBarcode(walletAddress, productBarcode).call();

    if (!isOwner) {
      return res.status(403).json({ error: 'Access Denied: You do not own this product NFT.' });
    }

    // 8) Fetch hidden content from DB (store bound)
    const content = await HiddenContent.findOne({
      storeContractAddress: normAddr(storeAddress),
      productBarcode: productBarcode
    });

    if (!content) {
      return res.status(404).json({ error: 'No hidden content found for this product.' });
    }

    console.log(`Access granted to ${walletAddress} for product ${productBarcode}`);
    res.json({ success: true, ipfsHash: content.ipfsHash });

  } catch (error) {
    console.error('Access content error:', error);

    if (String(error?.message || '').includes('execution reverted') || String(error?.message || '').includes('call exception')) {
      return res.status(500).json({ error: 'Blockchain verification failed. Check store contract.' });
    }

    res.status(500).json({ error: 'Server error during verification' });
  }
});

app.get('/api/check/:wallet', async (req, res) => {
  try {
    const wallet = String(req.params.wallet || '').trim();
    const storeAddress = String(req.query.storeAddress || '').trim();

    if (!normAddr(wallet)) return res.status(400).json({ error: "Missing wallet" });
    if (!normAddr(storeAddress)) return res.status(400).json({ error: "Missing storeAddress" });

    const client = await Client.findOne({
      walletAddress: { $regex: new RegExp(`^${normAddr(wallet)}$`, 'i') },
      storeContractAddress: { $regex: new RegExp(`^${normAddr(storeAddress)}$`, 'i') },
    }).lean();

    return res.json({ isRegistered: !!client, clientData: client || null });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});


// --- מחיקת הרשמה מאובטחת (חתימה + Timestamp) ---
app.post('/api/unregister', async (req, res) => {
  const { walletAddress, storeAddress, signature, timestamp } = req.body;

  if (!walletAddress || !storeAddress || !signature || !timestamp) {
    return res.status(400).json({ error: 'Missing parameters' });
  }

  try {
    const wallet = normAddr(walletAddress);
    const store = normAddr(storeAddress);

    const ts = Number(timestamp);
    if (!Number.isFinite(ts)) {
      return res.status(400).json({ error: 'Invalid timestamp' });
    }

    // 1) Time window (5 minutes)
    const timeDiff = Math.abs(Date.now() - ts);
    if (timeDiff > 5 * 60 * 1000) {
      return res.status(400).json({ error: 'Signature expired' });
    }

    // 2) Recover signer from signature (bind storeAddress too)
    const message = `I confirm that I want to delete my account: ${wallet} in store: ${store} at ${ts}`;
    const recoveredAddress = normAddr(ethers.verifyMessage(message, signature));

    // 3) Verify signer is the wallet owner
    if (recoveredAddress !== wallet) {
      return res.status(401).json({ error: 'Invalid signature. You are not the owner.' });
    }

    // 4) Delete ONLY for this store (because DB is wallet+store unique)
    const result = await Client.deleteMany({
      walletAddress: { $regex: new RegExp(`^${wallet}$`, 'i') },
      storeContractAddress: { $regex: new RegExp(`^${store}$`, 'i') },
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'User not found for this store' });
    }

    console.log(`User ${wallet} securely unregistered from store ${store}.`);
    return res.json({ success: true, deletedCount: result.deletedCount });
  } catch (error) {
    console.error('Unregister error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});


// --- API לשמירת הזמנה מיידית מהפרונט (Snapshot) ---
app.post('/api/register-order', async (req, res) => {
  const { receiptId, walletAddress, storeAddress, productBarcode, productName, price, timestamp } = req.body;

  try {
      // 1. שליפת פרטי הלקוח הנוכחיים מה-DB
      const client = await Client.findOne({
          walletAddress: { $regex: new RegExp('^' + walletAddress + '$', 'i') },
          storeContractAddress: { $regex: new RegExp('^' + storeAddress + '$', 'i') }
      });

      const snapshot = client ? {
          name: client.name,
          email: client.email,
          phone: client.phone,
          physicalAddress: client.physicalAddress
      } : { name: "Unknown", email: "Unknown", phone: "Unknown", physicalAddress: "Unknown" };

      // 2. שמירת ההזמנה (upsert - אם כבר קיימת מה-Listener, נעדכן אותה)
      const order = await Order.findOneAndUpdate(
          { receiptId: Number(receiptId) },
          {
              receiptId: Number(receiptId),
              clientAddress: walletAddress.toLowerCase(),
              storeContractAddress: storeAddress,
              productBarcode: productBarcode,
              productName: productName,
              price: Number(price),
              timestamp: Number(timestamp),
              clientSnapshot: snapshot // שמירת הפרטים הקבועים
          },
          { upsert: true, new: true }
      );

      console.log(`✅ Order ${receiptId} registered via API manually.`);
      res.json({ success: true, order });

  } catch (error) {
      console.error("Error registering order via API:", error);
      res.status(500).json({ error: error.message });
  }
});

// --- Endpoint לשליפת הזמנה בודדת לפי מספר קבלה (כולל Snapshot) ---
app.post("/api/store/get-order", requireAdminAuth, async (req, res) => {
  try {
    const { receiptId } = req.body;
    
    // שליפת ההזמנה מה-DB
    const order = await Order.findOne({ receiptId: Number(receiptId) }).lean();

    if (!order) {
        return res.status(404).json({ success: false, error: "Order not found in DB" });
    }

    return res.json({ success: true, order });
  } catch (e) {
    console.error("get-order error:", e);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});

app.post('/api/register-store', async (req, res) => {
  const { smartContractAddress, ownerAddress } = req.body;

  try {
    const storeAddr = normStoreKey(smartContractAddress);
    const owner = normStoreKey(ownerAddress);

    if (!storeAddr || !owner) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    const now = new Date();
    const pendingTtlMs = 15 * 60 * 1000;

    let store = await Store.findOne({ smartContractAddress: storeAddr });

    // already claimed -> never show again
    if (store?.passwordClaimedAt) {
      return res.status(409).json({
        success: false,
        code: "PASSWORD_ALREADY_CLAIMED",
        message: "Password already claimed and cannot be shown again.",
      });
    }

    // pending exists & valid -> return SAME password+token (retry safe)
    if (
      store?.pendingPasswordEnc &&
      store?.pendingTokenEnc &&
      store?.pendingTokenHash &&
      store?.pendingExpiresAt &&
      now < store.pendingExpiresAt
    ) {
      const rawPassword = decryptText(store.pendingPasswordEnc);
      const token = decryptText(store.pendingTokenEnc);

      return res.json({
        success: true,
        password: rawPassword,
        passwordToken: token,
        ttlMs: store.pendingExpiresAt.getTime() - now.getTime(),
        reused: true,
      });
    }

    // create new pending
    const rawPassword = crypto.randomBytes(12).toString('base64url');
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(rawPassword, salt);

    const token = crypto.randomBytes(32).toString('base64url');
    const tokenHash = sha256(token);

    const update = {
      smartContractAddress: storeAddr,
      ownerAddress: owner,
      passwordHash: hash,
      registeredAt: store?.registeredAt || now,

      pendingPasswordEnc: encryptText(rawPassword),
      pendingTokenEnc: encryptText(token),
      pendingTokenHash: tokenHash,
      pendingExpiresAt: new Date(Date.now() + pendingTtlMs),
      passwordClaimedAt: null,
    };

    store = await Store.findOneAndUpdate(
      { smartContractAddress: storeAddr },
      update,
      { new: true, upsert: true }
    );

    return res.json({
      success: true,
      password: rawPassword,
      passwordToken: token,
      ttlMs: pendingTtlMs,
      reused: false,
    });
  } catch (error) {
    console.error('register-store error:', error);
    return res.status(500).json({ success: false, message: 'Failed to register store' });
  }
});

app.post('/api/register-store/claim', async (req, res) => {
  const { smartContractAddress, ownerAddress, passwordToken } = req.body;

  try {
    const storeAddr = normStoreKey(smartContractAddress);
    const owner = normStoreKey(ownerAddress);

    if (!storeAddr || !owner || !passwordToken) {
      return res.status(400).json({ success: false, message: "Missing fields" });
    }

    const store = await Store.findOne({ smartContractAddress: storeAddr });
    if (!store) return res.status(404).json({ success: false, message: "Store not found" });

    if (store.passwordClaimedAt) {
      return res.json({ success: true, alreadyClaimed: true });
    }

    if (normStoreKey(store.ownerAddress) !== owner) {
      return res.status(403).json({ success: false, message: "Owner mismatch" });
    }

    const tokenHash = sha256(passwordToken);
    if (!store.pendingTokenHash || store.pendingTokenHash !== tokenHash) {
      return res.status(401).json({ success: false, message: "Invalid token" });
    }

    if (!store.pendingExpiresAt || new Date() > store.pendingExpiresAt) {
      return res.status(410).json({ success: false, message: "Token expired, regenerate password" });
    }

    store.passwordClaimedAt = new Date();
    store.pendingPasswordEnc = null;
    store.pendingTokenEnc = null;
    store.pendingTokenHash = null;
    store.pendingExpiresAt = null;

    await store.save();

    return res.json({ success: true });
  } catch (e) {
    console.error('claim error:', e);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});


// --- 1. תיקון Endpoint לשליפת פרטי לקוח ---
app.post("/api/store/get-client-details", requireAdminAuth, async (req, res) => {
  try {
    const { clientAddress } = req.body;
    const storeAddress = req.admin.storeAddress;

    if (!clientAddress) return res.status(400).json({ success: false, error: "Missing clientAddress" });

    // תיקון: חיפוש Case Insensitive (אותיות גדולות/קטנות) ומדויק
    const client = await Client.findOne({
      walletAddress: { $regex: new RegExp(`^${clientAddress.trim()}$`, 'i') },
      storeContractAddress: { $regex: new RegExp(`^${storeAddress.trim()}$`, 'i') },
    }).lean();

    if (!client) return res.status(404).json({ success: false, error: "Client not found" });

    return res.json({
      success: true,
      data: {
        name: client.name,
        email: client.email,
        phone: client.phone,
        physicalAddress: client.physicalAddress,
        wallet: client.walletAddress,
      },
    });
  } catch (e) {
    console.error("get-client-details error:", e);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});

// --- 2. תיקון Endpoint לשליפת הזמנות לקוח ---
app.post("/api/store/get-client-orders", requireAdminAuth, async (req, res) => {
  try {
    const { clientAddress } = req.body;
    const storeAddress = req.admin.storeAddress;

    if (!clientAddress) return res.status(400).json({ success: false, error: "Missing clientAddress" });

    // גם כאן, שימוש ב-RegExp לחיפוש מדויק
    const orders = await Order.find({
      storeContractAddress: { $regex: new RegExp(`^${storeAddress.trim()}$`, 'i') },
      clientAddress: { $regex: new RegExp(`^${clientAddress.trim()}$`, 'i') },
    })
      .sort({ timestamp: -1 })
      .lean();

    return res.json({ success: true, orders });
  } catch (e) {
    console.error("get-client-orders error:", e);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});

app.post('/api/sign-purchase', async (req, res) => {
  const { walletAddress, productBarcode, amount } = req.body;
  try {
    const client = await Client.findOne({
      walletAddress: { $regex: new RegExp('^' + walletAddress + '$', 'i') }
    });

    if (!client) {
      return res.status(403).json({ error: 'Client not registered. Please register first.' });
    }

    const deadline = Math.floor(Date.now() / 1000) + 300;

    const messageHash = ethers.solidityPackedKeccak256(
      ['address', 'string', 'uint256', 'uint256'],
      [walletAddress, productBarcode, amount, deadline]
    );

    const signature = await signerWallet.signMessage(ethers.getBytes(messageHash));

    res.json({ success: true, signature, deadline });
  } catch (error) {
    console.error('Signing error:', error);
    res.status(500).json({ error: 'Failed to sign purchase' });
  }
});

const jwt = require("jsonwebtoken");

const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET;
const ADMIN_JWT_TTL_SECONDS = Number(process.env.ADMIN_JWT_TTL_SECONDS || 12 * 60 * 60);

function signAdminJwt(payload) {
  if (!ADMIN_JWT_SECRET) throw new Error("Missing ADMIN_JWT_SECRET");
  return jwt.sign(payload, ADMIN_JWT_SECRET, { expiresIn: ADMIN_JWT_TTL_SECONDS });
}

function requireAdminAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing auth token" });

    const decoded = jwt.verify(token, ADMIN_JWT_SECRET);
    req.admin = decoded; // { walletAddress, storeAddress, origin, chainId, iat, exp }
    return next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid/expired token" });
  }
}


// --- Endpoint לשליפת כל הלקוחות של החנות (עבור רשימת תפוצה/אימיילים) ---
// --- Endpoint לשליפת כל הלקוחות של החנות (עבור רשימת תפוצה/אימיילים) ---
app.post("/api/store/get-all-clients", requireAdminAuth, async (req, res) => {
  try {
    const storeAddress = req.admin.storeAddress;

    // תיקון: שימוש ב-RegExp כדי להתעלם מאותיות גדולות/קטנות ולוודא התאמה מלאה
    const clients = await Client.find({
      storeContractAddress: { $regex: new RegExp(`^${storeAddress.trim()}$`, 'i') },
    })
      .sort({ createdAt: -1 })
      .select("name email phone walletAddress physicalAddress createdAt")
      .lean();

    return res.json({
      success: true,
      clients: clients.map((c) => ({
        name: c.name,
        email: c.email,
        phone: c.phone,
        walletAddress: c.walletAddress,
        physicalAddress: c.physicalAddress,
        createdAt: c.createdAt,
      })),
    });
  } catch (e) {
    console.error("get-all-clients error:", e);
    return res.status(500).json({ success: false, error: "Server error" });
  }
});

app.post('/api/register', async (req, res) => {
  const { walletAddress, name, email, phone, physicalAddress, storeAddress } = req.body;
  
  if (!storeAddress) {
      return res.status(400).json({ error: 'Store address is required' });
  }

  try {
    const existingClient = await Client.findOne({ 
        walletAddress: { $regex: new RegExp('^' + normAddr(walletAddress) + '$', 'i') },
        storeContractAddress: { $regex: new RegExp('^' + normAddr(storeAddress) + '$', 'i') }
    });

    let shouldSendEmail = true;
    if (existingClient && existingClient.lastEmailSent) {
        const timeDiff = Date.now() - new Date(existingClient.lastEmailSent).getTime();
        if (timeDiff < 60000) { 
            console.log(`Skipping email for ${email} - already sent in the last minute.`);
            shouldSendEmail = false;
        }
    }

    const updateData = { 
        walletAddress, 
        name, 
        email, 
        phone, 
        physicalAddress,
        storeContractAddress: storeAddress 
    };

    if (shouldSendEmail) {
        updateData.lastEmailSent = new Date();
    }

    const newClient = await Client.findOneAndUpdate(
      { 
          walletAddress: { $regex: new RegExp('^' + walletAddress + '$', 'i') },
          storeContractAddress: { $regex: new RegExp('^' + storeAddress + '$', 'i') }
      },
      updateData,
      { new: true, upsert: true }
    );

    if (storeAddress && shouldSendEmail) {
      try {
        const contracts = getContracts();
        const contractConfig = contracts.find(
          (c) => String(c.address).toLowerCase() === String(storeAddress).toLowerCase()
        );

        if (contractConfig) {
          const clientEmailContent = `Dear ${name},

Thank you for registering with ${contractConfig.companyName}. Here are your details:
Address: ${physicalAddress}
Phone: ${phone}
Wallet: ${walletAddress}

If you need any assistance, send email to support@ultrashop.tech.

Best regards,
${contractConfig.companyName} Team`;

          const companyEmailContent = `New client registration:

Name: ${name}
Email: ${email}
Address: ${physicalAddress}
Phone: ${phone}
Wallet: ${walletAddress}
`;

          await Promise.all([
            sendEmail(email, `Welcome to ${contractConfig.companyName}!`, clientEmailContent),
            sendEmail(contractConfig.companyEmail, `New Client Registration - ${name}`, companyEmailContent)
          ]);

          console.log(`Registration emails sent via Resend to ${email}`);
        }
      } catch (emailError) {
        console.error('Error triggering registration emails:', emailError);
      }
    }
    dispatchWebhook(storeAddress, 'new_client', {
      name,
      email,
      phone,
      physicalAddress,
      walletAddress
  });
    res.json({ success: true, client: newClient });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// --- Web3 Logic & Persistence ---

function loadJsonSafe(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch (e) {
    console.error(`Failed to read/parse ${filePath}:`, e);
    return fallback;
  }
}

let processedEvents = loadJsonSafe(processedEventsFile, {});
let lastProcessedBlocks = loadJsonSafe(lastProcessedBlockFile, {});

function normalizeLogIndex(x) {
  if (x === undefined || x === null) return null;
  if (typeof x === 'number' && Number.isFinite(x)) return x;
  if (typeof x === 'string') {
    const s = x.trim();
    if (!s) return null;
    if (s.startsWith('0x')) {
      const n = parseInt(s, 16);
      return Number.isFinite(n) ? n : null;
    }
    const n = Number(s);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function getEventKeyFromAny(ev) {
  const txHash = ev?.transactionHash || ev?.transaction_hash || ev?.hash;
  const li =
    normalizeLogIndex(ev?.logIndex) ??
    normalizeLogIndex(ev?.log_index) ??
    normalizeLogIndex(ev?.raw?.logIndex) ??
    normalizeLogIndex(ev?.raw?.log_index) ??
    normalizeLogIndex(ev?.log?.logIndex) ??
    normalizeLogIndex(ev?.log?.log_index) ??
    normalizeLogIndex(ev?.index) ??
    normalizeLogIndex(ev?.idx);

  if (txHash && li !== null) return `${String(txHash)}:${li}`;

  const fallbackPayload = {
    txHash: txHash || 'NO_TX',
    event: ev?.event || ev?.name || 'NO_EVENT',
    topics0: ev?.topics?.[0] || ev?.raw?.topics?.[0] || null,
    blockNumber: ev?.blockNumber || ev?.block_number || null,
    address: ev?.address || null,
    returnValues: ev?.returnValues || null,
  };

  const digest = crypto.createHash('sha1').update(JSON.stringify(fallbackPayload)).digest('hex');
  return `${String(txHash || 'NO_TX')}:${digest}`;
}

function saveProcessedEventKey(key) {
  processedEvents[key] = true;
  fs.writeFileSync(processedEventsFile, JSON.stringify(processedEvents, null, 2));
}

function saveLastProcessedBlock(contractAddress, blockNumber) {
  lastProcessedBlocks[contractAddress] = blockNumber;
  fs.writeFileSync(lastProcessedBlockFile, JSON.stringify(lastProcessedBlocks, null, 2));
}

async function fetchHistoricalEventsFromBlockscout(contractAddress) {
  const historicalEvents = [];
  const baseUrl = 'https://base.blockscout.com/api';

  try {
    console.log(`Fetching historical events for contract: ${contractAddress}`);
    let response;
    let logs = [];

    try {
      response = await axios.get(`${baseUrl}/v2/addresses/${contractAddress}/logs`, {
        params: { type: 'JSON' },
        timeout: 30000,
      });
      if (response.data && response.data.items) logs = response.data.items;
    } catch (v2Error) {
      console.log('V2 API failed, trying v1 API...');
      try {
        response = await axios.get(`${baseUrl}/api`, {
          params: {
            module: 'logs',
            action: 'getLogs',
            address: contractAddress,
            fromBlock: '0',
            toBlock: 'latest',
          },
          timeout: 30000,
        });
        if (response.data && response.data.result) logs = response.data.result;
      } catch (v1Error) {
        console.log('V1 API failed, trying alternative approach...');
        response = await axios.get(`${baseUrl}/api`, {
          params: {
            module: 'account',
            action: 'txlist',
            address: contractAddress,
            startblock: 0,
            endblock: 99999999,
            sort: 'desc',
          },
          timeout: 30000,
        });

        if (response.data && response.data.result) {
          const transactions = response.data.result;
          console.log(`Found ${transactions.length} transactions for contract ${contractAddress}`);

          for (const tx of transactions.slice(0, 100)) {
            try {
              const receipt = await web3.eth.getTransactionReceipt(tx.hash);
              if (receipt && receipt.logs) {
                for (const lg of receipt.logs) {
                  if (String(lg.address).toLowerCase() === String(contractAddress).toLowerCase()) {
                    logs.push({
                      transactionHash: tx.hash,
                      blockNumber: parseInt(tx.blockNumber),
                      address: lg.address,
                      topics: lg.topics,
                      data: lg.data,
                      logIndex: lg.logIndex,
                    });
                  }
                }
              }
              await new Promise((resolve) => setTimeout(resolve, 50));
            } catch (receiptError) {
              continue;
            }
          }
        }
      }
    }

    console.log(`Found ${logs.length} logs for contract ${contractAddress}`);

    for (const lg of logs) {
      const txHash = lg.transactionHash || lg.transaction_hash || lg.hash;
      if (!txHash) continue;

      const logIndex =
        normalizeLogIndex(lg.logIndex) ??
        normalizeLogIndex(lg.log_index) ??
        normalizeLogIndex(lg.index) ??
        normalizeLogIndex(lg.idx) ??
        0;

      const ev = {
        transactionHash: txHash,
        blockNumber: parseInt(lg.blockNumber || lg.block_number || lg.blockNum),
        logIndex,
        address: lg.address,
        topics: lg.topics || [],
        data: lg.data || '0x',
      };

      const key = getEventKeyFromAny(ev);
      if (processedEvents[key]) continue;

      historicalEvents.push(ev);
    }

    return historicalEvents;
  } catch (error) {
    console.error('Error fetching historical events:', error.message);
    return [];
  }
}

async function decodeEventFromLog(log, contractConfig) {
  try {
    const contract = new web3.eth.Contract(contractConfig.abi, contractConfig.address);

    for (const eventName of Object.keys(contractConfig.eventHandlers)) {
      try {
        const eventAbi = contractConfig.abi.find((item) => item.type === 'event' && item.name === eventName);
        if (!eventAbi) continue;

        const eventSignature = web3.eth.abi.encodeEventSignature(eventAbi);
        if (!log.topics || log.topics[0] !== eventSignature) continue;

        const decodedEvent = web3.eth.abi.decodeLog(eventAbi.inputs, log.data, log.topics.slice(1));

        return {
          event: eventName,
          returnValues: decodedEvent,
          transactionHash: log.transactionHash,
          blockNumber: log.blockNumber,
          logIndex: log.logIndex,
          address: log.address,
          topics: log.topics,
          data: log.data,
        };
      } catch (decodeError) {
        continue;
      }
    }
    return null;
  } catch (error) {
    console.error('Error decoding event from log:', error);
    return null;
  }
}

async function processHistoricalEvents(contractConfig) {
  try {
    console.log(`Processing historical events for contract: ${contractConfig.address}`);

    const historicalLogs = await fetchHistoricalEventsFromBlockscout(contractConfig.address);
    if (historicalLogs.length === 0) return;

    historicalLogs.sort((a, b) => a.blockNumber - b.blockNumber || a.logIndex - b.logIndex);

    for (const lg of historicalLogs) {
      try {
        const preKey = getEventKeyFromAny(lg);
        if (processedEvents[preKey]) continue;

        const decodedEvent = await decodeEventFromLog(lg, contractConfig);
        if (!decodedEvent) continue;

        const evKey = getEventKeyFromAny(decodedEvent);
        if (processedEvents[evKey]) continue;

        if (contractConfig.eventHandlers[decodedEvent.event]) {
          console.log(`Processing historical event: ${decodedEvent.event} ${evKey}`);
          const tx = await web3.eth.getTransaction(decodedEvent.transactionHash);
          const senderAddress = tx?.from ? tx.from.toString() : '';

          await contractConfig.eventHandlers[decodedEvent.event](decodedEvent.returnValues, contractConfig, senderAddress);

          saveProcessedEventKey(evKey);
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      } catch (error) {
        console.error('Error processing historical event:', error);
      }
    }

    if (historicalLogs.length > 0) {
      const lastBlock = Math.max(...historicalLogs.map((l) => l.blockNumber));
      saveLastProcessedBlock(contractConfig.address, lastBlock);
    }
  } catch (error) {
    console.error('Error in processHistoricalEvents:', error);
  }
}

async function processAllContracts() {
  try {
    const contracts = getContracts();
    if (!contracts) throw new Error('No contract configurations available');

    for (const contractConfig of contracts) {
      await processHistoricalEvents(contractConfig);
      subscribeToContractEvents(contractConfig);
    }
  } catch (error) {
    console.error('Error in processAllContracts:', error);
  }
}

async function refreshInitializeServerAndProcess() {
  if (refreshingConfigs) {
    console.log("⏳ Refresh already running, skipping...");
    return;
  }

  refreshingConfigs = true;

  try {
    console.log("🔄 Refreshing (initializeServer) + syncing contracts list...");

    await initializeServer(eventHandlers);
    console.log("✅ initializeServer refreshed.");

    // Re-read contracts after initializeServer regenerated config
    const contracts = getContracts();
    if (!contracts || !Array.isArray(contracts)) {
      throw new Error("getContracts() returned no configs");
    }

    // For each contract: process historical + subscribe (subscribe guarded)
    for (const contractConfig of contracts) {
      await processHistoricalEvents(contractConfig);
      subscribeToContractEvents(contractConfig);
    }

    console.log(`✅ Refresh done. Contracts seen: ${contracts.length}`);
  } catch (e) {
    console.error("❌ Refresh failed:", e);
  } finally {
    refreshingConfigs = false;
  }
}

setInterval(() => {
  refreshInitializeServerAndProcess().catch((e) => console.error("Refresh interval error:", e));
}, CONFIG_REFRESH_MS);


async function processEvent(event, contractConfig) {
  const key = getEventKeyFromAny(event);

  if (processedEvents[key]) {
    console.log(`Skipping already processed event: ${key}`);
    return false;
  }

  const eventName = event.event;
  if (!contractConfig.eventHandlers[eventName]) return false;

  console.log(`Processing event: ${eventName} ${key}`);

  const tx = await web3.eth.getTransaction(event.transactionHash);
  const senderAddress = tx?.from ? tx.from.toString() : '';

  await contractConfig.eventHandlers[eventName](event.returnValues, contractConfig, senderAddress);

  saveProcessedEventKey(key);
  return true;
}

function subscribeToContractEvents(contractConfig) {
  const addr = String(contractConfig.address || "").toLowerCase();
  if (!addr) return;

  if (activeSubscriptions.has(addr)) {
    console.log(`Already subscribed: ${addr}`);
    return;
  }

  const contract = new web3.eth.Contract(contractConfig.abi, contractConfig.address);
  const handlerEventNames = Object.keys(contractConfig.eventHandlers || {});

  console.log(
    `Subscribing to ${handlerEventNames.length} handler events for ${contractConfig.address}`
  );

  const subs = [];

  for (const eventName of handlerEventNames) {
    const evFn = contract.events[eventName];
    if (typeof evFn !== "function") continue;

    const sub = evFn
      .call(contract.events, { fromBlock: "latest" })
      .on("data", async (event) => {
        try {
          console.log(`New real-time event: ${event.event} tx=${event.transactionHash}`);
          await processEvent(event, contractConfig);
        } catch (e) {
          console.error(`Error processing realtime event ${eventName}:`, e);
        }
      })
      .on("error", (error) => {
        console.error(`Error in event subscription (${eventName}):`, error);
      });

    subs.push(sub);
  }

  activeSubscriptions.set(addr, subs);
}


// --- Event Handlers (Using Resend) ---

async function handleNewProductAdditions(eventData, contractConfig) {
  try {
    const clients = await Client.find({ 
        storeContractAddress: { $regex: new RegExp('^' + contractConfig.address + '$', 'i') },
        email: { $exists: true, $ne: null } 
    });
    
    if (clients.length === 0) return;

    const emails = clients.map((c) => c.email).filter(Boolean);
    if (emails.length === 0) return;

    const price = Number(eventData.price || 0);
    const disc = Number(eventData.discountPercentage || 0);
    const discountedPrice = (price * (100 - disc)) / 100;
    const description = (eventData.description || '').toString().replace(/[$~*^]/g, '');

    await sendEmail(
      process.env.EMAIL, 
      `New Product: ${eventData.barcode} Now Available!`,
      `Hello,

We are thrilled to announce the launch of our new product: ${eventData.barcode}!

Product Details:
- Barcode: ${eventData.barcode}
- Description: ${description}
- Regular Price: ${price / 1e6} $USDC
- Discount: ${disc}%
- Discounted Price: ${discountedPrice / 1e6} $USDC
- Available Quantity: ${eventData.quantity}

Visit https://www.Ultrashop.tech/shop/${contractConfig.companyUrl}/products/${eventData.barcode}

Best regards,
${contractConfig.companyName} Team`
    );
    
    console.log(`Product announcement processed for ${clients.length} clients.`);
  } catch (error) {
    console.error('Handler error:', error);
  }
}

async function handleProductSales(eventData, contractConfig, senderAddress) {
  try {
    const walletToSearch = eventData.clientAddress || senderAddress;
    
    // שליפת הלקוח כדי ליצור Snapshot
    const client = await getClientFromDB(walletToSearch, contractConfig.address);

    const snapshot = client ? {
        name: client.name,
        email: client.email,
        phone: client.phone,
        physicalAddress: client.physicalAddress
    } : null;

    // --- Indexing Order to MongoDB (CQRS) with Snapshot ---
    try {
        await Order.findOneAndUpdate(
            { receiptId: Number(eventData.receiptId) },
            {
                receiptId: Number(eventData.receiptId),
                clientAddress: walletToSearch.toLowerCase(),
                storeContractAddress: contractConfig.address,
                productBarcode: eventData.productBarcode,
                productName: (eventData.ProductDesc || eventData.description || '').replace(/[$~*^]/g, ''),
                price: Number(eventData.amountPaid) / 1e6,
                timestamp: Number(eventData.timestamp),
                clientSnapshot: snapshot // עדכון ה-Snapshot
            },
            { upsert: true }
        );
        console.log(`✅ Order ${eventData.receiptId} indexed/updated in MongoDB`);
    } catch (dbError) {
        console.error('Failed to save order to DB:', dbError.message);
    } 
    // ----------------------------------------

    // חישוב משתנים - העברנו את זה למעלה כדי שיהיה זמין לשני האימיילים
    const productDesc = (eventData.ProductDesc || eventData.description || '').toString().replace(/[$~*^]/g, '');
    const ts = Number(eventData.timestamp || 0);
    const tsText = ts ? new Date(ts * 1000).toLocaleString() : 'N/A';
    const amountPaid = Number(eventData.amountPaid || 0);

    // 1. שליחת אימייל לבעל החנות (תמיד נשלח, גם אם אין לקוח ב-DB)
    try {
        await sendEmail(
          contractConfig.companyEmail,
          `Sale Notification: (${eventData.productBarcode})`,
          `A sale has been completed.

Receipt ID: ${eventData.receiptId}
Product: ${eventData.productBarcode}
Price: ${amountPaid / 1e6} $USDC

Customer Info (From DB):
Name: ${client?.name || 'Unknown (Not registered)'}
Email: ${client?.email || 'Unknown'}
Phone: ${client?.phone || 'Unknown'}
Wallet: ${walletToSearch}
Address: ${client?.physicalAddress || 'Unknown'}

Please process the order.`
        );
        console.log(`Email sent to store owner for receipt ${eventData.receiptId}`);
    } catch (storeEmailErr) {
        console.error("Failed to send email to store owner:", storeEmailErr);
    }

    // 2. בדיקה אם אפשר לשלוח ללקוח
    if (!client || !client.email) {
      console.warn(`Client not found or no email. Skipping CLIENT email for wallet: ${walletToSearch}`);
      return; // עכשיו ה-return עוצר רק את השליחה ללקוח
    }

    // שליחת אימייל ללקוח
    await sendEmail(
      client.email,
      `Thank You for Your Purchase from ${contractConfig.companyName}!`,
      `Hello ${client.name || ''},

Thank you for your purchase. Here are your transaction details:
Receipt ID: ${eventData.receiptId}
Timestamp: ${tsText}
Product Barcode: ${eventData.productBarcode}
Product Description: ${productDesc}
Price: ${amountPaid / 1e6} $USDC

Shipping Address: ${client.physicalAddress || ''}

Best regards,
${contractConfig.companyName} Team`
    );

    await dispatchWebhook(contractConfig.address, 'new_order', {
      // פרטי העסקה
      receiptId: Number(eventData.receiptId),
      productBarcode: eventData.productBarcode,
      productName: (eventData.ProductDesc || eventData.description || '').replace(/[$~*^]/g, ''),
      price: Number(eventData.amountPaid) / 1e6,
      transactionHash: eventData.transactionHash,
      timestamp: Date.now(),

      // פרטי הלקוח (אם קיים ב-DB)
      customer: {
          wallet: walletToSearch,
          name: client?.name || "Unknown",
          email: client?.email || "Unknown",
          phone: client?.phone || "Unknown",
          physicalAddress: client?.physicalAddress || "Unknown"
      }
  });

  } catch (error) {
    console.error('handleProductSales error:', error);
  }
}

async function handleRefund(eventData, contractConfig, senderAddress) {
  try {
    const client = await getClientFromDB(eventData.clientAddress || senderAddress, contractConfig.address);
    
    // --- Update MongoDB Order Status ---
    try {
        await Order.updateOne(
            { receiptId: Number(eventData.receiptId) },
            { isRefunded: true }
        );
        console.log(`✅ Order ${eventData.receiptId} marked as refunded in DB`);
    } catch (dbError) {
        console.error('Failed to update refund status in DB:', dbError.message);
    }
    // -----------------------------------

    if (!client || !client.email) return;

    const refundAmount = Number(eventData.refundAmount || 0);

    await sendEmail(
      client.email,
      `Refund Processed`,
      `Hello ${client.name || ''},

Your refund request has been processed successfully.

Receipt ID: ${eventData.receiptId}
Refund Amount: ${refundAmount / 1e6} $USDC

Best regards,
${contractConfig.companyName} Team`
    );
  } catch (error) {
    console.error('Refund handler error:', error);
  }
}

async function handleMoreInfo(eventData, contractConfig, senderAddress) {
  try {
    const client = await getClientFromDB(senderAddress, contractConfig.address);
    const clientName = client ? client.name : 'Unknown';

    await sendEmail(
      contractConfig.companyEmail,
      'Additional Purchase Information',
      `Hello,

Additional information received for Invoice ID: ${eventData.invoiceId}
Amount: ${eventData.amount}

From Client (DB): ${clientName} (${senderAddress})

Best regards,
Ultrashop.tech Team`
    );
  } catch (e) {
    console.error('handleMoreInfo error:', e);
  }
}

async function handleFinishedDist(eventData, contractConfig) {
  await sendEmail(
    contractConfig.companyEmail,
    'Balance Distributed Successfully',
    `Hello,

A balance of ${Number(eventData.totalBalance || 0) / 1e6} $USDC has been successfully distributed to all eligible participants.

Best regards,
Ultrashop.tech Team`
  );
}

async function handleWorkerPayment(eventData, contractConfig) {
  await sendEmail(
    contractConfig.companyEmail,
    'Worker Payment Processed',
    `Hello,

A payment of ${Number(eventData.amount || 0) / 1e6} $USDC has been made to the worker with the address: ${eventData.workerAddress}.

Best regards,
Ultrashop.tech Team`
  );
}

async function handleDistribution(eventData, contractConfig) {
  await sendEmail(
    contractConfig.companyEmail,
    'Distribution Started',
    `Hello,

A new distribution has started with the following details:

Distribution ID: ${eventData.distributionId}
Amount to Distribute: ${Number(eventData.amountToDistribute || 0) / 1e6} $USDC

Best regards,
Ultrashop.tech Team`
  );
}

async function handleCampaignCreated(eventData, contractConfig) {
  try {
    const contract = new web3.eth.Contract(contractConfig.abi, contractConfig.address);
    const campaign = await contract.methods.getCampaign(eventData.campaignId).call();
    await sendEmail(
      campaign.phoneNumber,
      'Campaign Created - Waiting for Approval',
      `Your campaign (ID: ${eventData.campaignId}) has been created and is waiting for approval.`
    );
    await sendEmail('support@ultrashop.tech', 'New Campaign Needs Approval', `Review needed for ID: ${eventData.campaignId}`);
  } catch (e) {
    console.error(e);
  }
}

async function handleCampaignVerified(eventData, contractConfig) {
  try {
    const contract = new web3.eth.Contract(contractConfig.abi, contractConfig.address);
    const campaign = await contract.methods.getCampaign(eventData.campaignId).call();
    await sendEmail(campaign.phoneNumber, 'Campaign Verified', `Congratulations! Your campaign (ID: ${eventData.campaignId}) is live.`);
  } catch (e) {
    console.error(e);
  }
}

async function handleDonationReceived(eventData, contractConfig) {
  try {
    const contract = new web3.eth.Contract(contractConfig.abi, contractConfig.address);
    const campaign = await contract.methods.getCampaign(eventData.campaignId).call();
    await sendEmail(
      campaign.phoneNumber,
      'New Investment Received',
      `Your campaign (ID: ${eventData.campaignId}) has received ${Number(eventData.amount || 0) / 1e6} $USDC.`
    );
  } catch (e) {
    console.error(e);
  }
}

async function handleCampaignWithdrawn(eventData, contractConfig) {
  try {
    const contract = new web3.eth.Contract(contractConfig.abi, contractConfig.address);
    const campaign = await contract.methods.getCampaign(eventData.campaignId).call();
    await sendEmail(
      campaign.phoneNumber,
      'Campaign Funds Withdrawn',
      `You have successfully withdrawn ${Number(eventData.amount || 0) / 1e6} $USDC.`
    );
  } catch (e) {
    console.error(e);
  }
}

async function handleCampaignClosed(eventData, contractConfig) {
  try {
    const contract = new web3.eth.Contract(contractConfig.abi, contractConfig.address);
    const campaign = await contract.methods.getCampaign(eventData.campaignId).call();
    await sendEmail(campaign.phoneNumber, 'Campaign Closed', `Your campaign (ID: ${eventData.campaignId}) has been closed.`);
  } catch (e) {
    console.error(e);
  }
}

async function handleCampaignStopped(eventData, contractConfig) {
  try {
    const contract = new web3.eth.Contract(contractConfig.abi, contractConfig.address);
    const campaign = await contract.methods.getCampaign(eventData.campaignId).call();
    await sendEmail(campaign.phoneNumber, 'Campaign Stopped for Review', `Your campaign (ID: ${eventData.campaignId}) has been stopped for review.`);
  } catch (e) {
    console.error(e);
  }
}

const eventHandlers = {
  handleCampaignCreated,
  handleCampaignVerified,
  handleDonationReceived,
  handleCampaignWithdrawn,
  handleCampaignClosed,
  handleCampaignStopped,
  handleNewProductAdditions,
  handleProductSales,
  handleMoreInfo,
  handleRefund,
  handleDistribution,
  handleFinishedDist,
  handleWorkerPayment,
};

// --- ריסטארט אוטומטי לניקוי זיכרון ---
// --- ריסטארט אוטומטי לניקוי זיכרון ---
const RESTART_INTERVAL = 60 * 60 * 1000; // 1 שעה

setTimeout(async () => {
    console.log('⏰ Hourly restart triggered. Starting cleanup...');

    try {
        // 1. ניתוק יזום של MongoDB
        if (mongoose.connection.readyState !== 0) {
            await mongoose.disconnect();
            console.log('✅ MongoDB disconnected.');
        }

        // 2. ניתוק יזום של Web3 WebSocket
        if (web3 && web3.currentProvider && web3.currentProvider.disconnect) {
            web3.currentProvider.disconnect();
            console.log('✅ Web3 WebSocket disconnected.');
        }
    } catch (error) {
        console.error('⚠️ Error during cleanup:', error);
    } finally {
        console.log('💀 Killing process now.');
        // שימוש ב-1 במקום 0 כדי להבטיח ש-Railway יבין שצריך להפעיל מחדש (Restart Policy)
        process.exit(1); 
    }
}, RESTART_INTERVAL);

app.listen(PORT, "0.0.0.0", async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log("Starting Web3 Event Listeners...");

  try {
    await refreshInitializeServerAndProcess(); // initial boot run
    console.log("✅ Web3 Listeners Initialized (initial).");
  } catch (error) {
    console.error("❌ Error initializing Web3 server:", error);
  }
});


module.exports = { eventHandlers };