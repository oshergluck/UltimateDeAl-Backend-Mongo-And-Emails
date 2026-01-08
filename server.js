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

const app = express();
app.use(express.json());

// הגדרות CORS
const allowedOrigins = [
    'http://localhost:5173',
    'https://www.ultrashop.tech',
    'https://ultrashop.tech'
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            return callback(null, true); 
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

const StoreSchema = new mongoose.Schema({
  smartContractAddress: { type: String, required: true, unique: true },
  ownerAddress: String,
  passwordHash: String,
  registeredAt: { type: Date, default: Date.now },
});

// --- Schema חדשה להזמנות (CQRS) ---
const OrderSchema = new mongoose.Schema({
  receiptId: { type: Number, required: true, unique: true },
  clientAddress: { type: String, required: true, index: true },
  storeContractAddress: String,
  productBarcode: String,
  productName: String,
  price: Number,
  timestamp: Number,
  isRefunded: { type: Boolean, default: false }
});

const Client = mongoose.model('Client', ClientSchema);
const Store = mongoose.model('Store', StoreSchema);
const Order = mongoose.model('Order', OrderSchema);

const signerWallet = new ethers.Wallet(SERVER_PRIVATE_KEY);

const websocketUrl = `wss://base-mainnet.g.alchemy.com/v2/${WEBSOCKET_URL_API}`;
const web3 = new Web3(
  new Web3.providers.WebsocketProvider(websocketUrl, {
    reconnect: { auto: true, delay: 10000, onTimeout: false },
  })
);

// --- פונקציית שליחת אימייל ---
async function sendEmail(to, subject, text) {
  if (!to || !String(to).includes('@')) {
      console.log(`Skipping email, invalid address: ${to}`);
      return;
  }
  
  try {
    const { data, error } = await resend.emails.send({
      from: process.env.EMAIL,
      to: [to],
      subject: subject,
      text: text,
    });

    if (error) {
      console.error('Resend API Error:', error);
      return;
    }

    console.log(`Email sent successfully to ${to}, ID: ${data.id}`);
  } catch (err) {
    console.error('Email sending failed:', err);
  }
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

app.get('/api/check/:wallet', async (req, res) => {
  try {
    const client = await Client.findOne({
      walletAddress: { $regex: new RegExp('^' + req.params.wallet + '$', 'i') }
    });
    
    res.json({ isRegistered: !!client, clientData: client });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- מחיקת הרשמה מאובטחת (חתימה + Timestamp) ---
app.post('/api/unregister', async (req, res) => {
    const { walletAddress, signature, timestamp } = req.body;

    if (!walletAddress || !signature || !timestamp) {
        return res.status(400).json({ error: 'Missing parameters' });
    }

    try {
        // 1. בדיקת זמנים - למנוע Replay Attack (חלון של 5 דקות)
        const timeDiff = Math.abs(Date.now() - timestamp);
        if (timeDiff > 5 * 60 * 1000) {
            return res.status(400).json({ error: 'Signature expired' });
        }

        // 2. שחזור הכתובת מהחתימה
        const message = `I confirm that I want to delete my account: ${walletAddress.toLowerCase()} at ${timestamp}`;
        const recoveredAddress = ethers.verifyMessage(message, signature);

        // 3. אימות שהחותם הוא הבעלים
        if (recoveredAddress.toLowerCase() !== walletAddress.toLowerCase()) {
            return res.status(401).json({ error: 'Invalid signature. You are not the owner.' });
        }

        // 4. ביצוע המחיקה
        const result = await Client.deleteMany({
            walletAddress: { $regex: new RegExp('^' + walletAddress + '$', 'i') }
        });

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        console.log(`User ${walletAddress} securely unregistered.`);
        res.json({ success: true });

    } catch (error) {
        console.error('Unregister error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/register-store', async (req, res) => {
  const { smartContractAddress, ownerAddress } = req.body;
  try {
    const rawPassword = crypto.randomBytes(6).toString('hex');
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(rawPassword, salt);

    await Store.findOneAndUpdate(
      { smartContractAddress },
      { ownerAddress, passwordHash: hash },
      { new: true, upsert: true }
    );
    res.json({ success: true, password: rawPassword });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to register store' });
  }
});

app.post('/api/store/get-client-details', async (req, res) => {
  const { storeAddress, password, clientAddress } = req.body;
  try {
    const store = await Store.findOne({ smartContractAddress: storeAddress });
    if (!store) return res.status(404).json({ error: 'Store not found' });

    const isMatch = await bcrypt.compare(password, store.passwordHash);
    if (!isMatch) return res.status(401).json({ error: 'Invalid Password' });

    const client = await Client.findOne({
      walletAddress: { $regex: new RegExp('^' + clientAddress + '$', 'i') },
      storeContractAddress: { $regex: new RegExp('^' + storeAddress + '$', 'i') }
    });

    if (!client) return res.status(404).json({ error: 'Client not found in database for this store' });

    res.json({
      success: true,
      data: {
        name: client.name,
        email: client.email,
        phone: client.phone,
        physicalAddress: client.physicalAddress,
        wallet: client.walletAddress,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Endpoint מאובטח לשליפת הזמנות לבעל החנות ---
app.post('/api/store/get-client-orders', async (req, res) => {
    const { storeAddress, password, clientAddress } = req.body;

    try {
        const store = await Store.findOne({ smartContractAddress: storeAddress });
        if (!store) return res.status(404).json({ error: 'Store not found' });

        const isMatch = await bcrypt.compare(password, store.passwordHash);
        if (!isMatch) return res.status(401).json({ error: 'Invalid Password' });

        const orders = await Order.find({ 
            clientAddress: clientAddress.toLowerCase(),
            storeContractAddress: { $regex: new RegExp('^' + storeAddress + '$', 'i') }
        }).sort({ timestamp: -1 });

        res.json({ success: true, orders });

    } catch (error) {
        console.error('Error fetching client orders:', error);
        res.status(500).json({ error: 'Server error' });
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

// --- Endpoint לשליפת כל הלקוחות של החנות (עבור רשימת תפוצה/אימיילים) ---
app.post('/api/store/get-all-clients', async (req, res) => {
  const { storeAddress, password } = req.body;
  try {
    // 1. אימות חנות
    const store = await Store.findOne({ smartContractAddress: storeAddress });
    if (!store) return res.status(404).json({ error: 'Store not found' });

    // 2. אימות סיסמה
    const isMatch = await bcrypt.compare(password, store.passwordHash);
    if (!isMatch) return res.status(401).json({ error: 'Invalid Password' });

    // 3. שליפת כל הלקוחות ששייכים לחנות הזו
    const clients = await Client.find({
      storeContractAddress: { $regex: new RegExp('^' + storeAddress + '$', 'i') }
    }).select('name email walletAddress phone'); // מחזירים רק פרטים רלוונטיים

    res.json({ success: true, clients });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/register', async (req, res) => {
  const { walletAddress, name, email, phone, physicalAddress, storeAddress } = req.body;
  
  if (!storeAddress) {
      return res.status(400).json({ error: 'Store address is required' });
  }

  try {
    const existingClient = await Client.findOne({ 
        walletAddress: { $regex: new RegExp('^' + walletAddress + '$', 'i') },
        storeContractAddress: { $regex: new RegExp('^' + storeAddress + '$', 'i') }
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

If you need any assistance, kindly reply to this email.

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
    const contract = new web3.eth.Contract(contractConfig.abi, contractConfig.address);
    const handlerEventNames = Object.keys(contractConfig.eventHandlers || {});

    console.log(
        `Subscribing to ${handlerEventNames.length} handler events for ${contractConfig.address}`
    );

    for (const eventName of handlerEventNames) {
        const evFn = contract.events[eventName];
        if (typeof evFn !== 'function') continue;

        evFn.call(contract.events, { fromBlock: 'latest' })
            .on('data', async (event) => {
                try {
                    console.log(`New real-time event: ${event.event} tx=${event.transactionHash}`);
                    await processEvent(event, contractConfig);
                } catch (e) {
                    console.error(`Error processing realtime event ${eventName}:`, e);
                }
            })
            .on('error', (error) => {
                console.error(`Error in event subscription (${eventName}):`, error);
            });
    }
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
    
    // --- Indexing Order to MongoDB (CQRS) ---
    try {
        await Order.create({
            receiptId: Number(eventData.receiptId),
            clientAddress: walletToSearch.toLowerCase(),
            storeContractAddress: contractConfig.address,
            productBarcode: eventData.productBarcode,
            productName: (eventData.ProductDesc || eventData.description || '').replace(/[$~*^]/g, ''),
            price: Number(eventData.amountPaid) / 1e6,
            timestamp: Number(eventData.timestamp)
        });
        console.log(`✅ Order ${eventData.receiptId} indexed to MongoDB`);
    } catch (dbError) {
        console.error('Failed to save order to DB:', dbError.message);
    }
    // ----------------------------------------

    const client = await getClientFromDB(walletToSearch, contractConfig.address);

    if (!client || !client.email) {
      console.error(`Client not found or no email for sale. Wallet: ${walletToSearch}`);
      return;
    }

    const productDesc = (eventData.ProductDesc || eventData.description || '').toString().replace(/[$~*^]/g, '');
    const ts = Number(eventData.timestamp || 0);
    const tsText = ts ? new Date(ts * 1000).toLocaleString() : 'N/A';
    const amountPaid = Number(eventData.amountPaid || 0);

    // ללקוח
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

    // לחנות
    await sendEmail(
      contractConfig.companyEmail,
      `Sale Notification: (${eventData.productBarcode})`,
      `A sale has been completed.

Receipt ID: ${eventData.receiptId}
Product: ${eventData.productBarcode}
Price: ${amountPaid / 1e6} $USDC

Customer Info (From DB):
Name: ${client.name || ''}
Email: ${client.email || ''}
Phone: ${client.phone || ''}
Wallet: ${client.walletAddress || ''}
Address: ${client.physicalAddress || ''}

Please process the order.`
    );
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

app.listen(PORT, '0.0.0.0', async () => {
    console.log(`🚀 Server running on port ${PORT}`);
  console.log('Starting Web3 Event Listeners...');

  initializeServer(eventHandlers)
    .then(async () => {
      console.log('✅ Web3 Listeners Initialized.');
      await processAllContracts();
      console.log('✅ Historical Events Processed.');
    })
    .catch((error) => {
      console.error('❌ Error initializing Web3 server:', error);
    });
});

module.exports = { eventHandlers };