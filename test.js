const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { ethers } = require('ethers');
const Web3 = require('web3');
const nodemailer = require('nodemailer');
const { initializeServer, getContracts } = require('./contractConfigGenerator');
require('dotenv').config();
const fs = require('fs');
const axios = require('axios');

const app = express();
app.use(express.json());
app.use(cors());

const MONGO_URI = process.env.MONGO_URI;
const SERVER_PRIVATE_KEY = process.env.SERVER_PRIVATE_KEY;
const WEBSOCKET_URL_API = process.env.WEBSOCKET_URL_API;
const EMAIL_USER = process.env.EMAIL;
const EMAIL_PASS = process.env.EMAILP;
const PORT = process.env.PORT || 5000;

fs.writeFileSync('server.pid', process.pid.toString());

mongoose
  .connect(MONGO_URI)
  .then(() => console.log('Server Connected to MongoDB'))
  .catch((err) => console.error('MongoDB error', err));

const ClientSchema = new mongoose.Schema({
  walletAddress: { type: String, required: true, unique: true },
  name: String,
  email: String,
  phone: String,
  physicalAddress: String,
  registeredAt: { type: Date, default: Date.now },
});

const StoreSchema = new mongoose.Schema({
  smartContractAddress: { type: String, required: true, unique: true },
  ownerAddress: String,
  passwordHash: String,
  registeredAt: { type: Date, default: Date.now },
});

const Client = mongoose.model('Client', ClientSchema);
const Store = mongoose.model('Store', StoreSchema);

const signerWallet = new ethers.Wallet(SERVER_PRIVATE_KEY);

const websocketUrl = `wss://base-mainnet.g.alchemy.com/v2/${WEBSOCKET_URL_API}`;
const web3 = new Web3(
  new Web3.providers.WebsocketProvider(websocketUrl, {
    reconnect: { auto: true, delay: 10000, onTimeout: false },
  })
);

const transporter = nodemailer.createTransport({
  host: 'mail.privateemail.com',
  port: 465,
  secure: true,
  auth: { user: EMAIL_USER, pass: EMAIL_PASS },
});

app.get('/api/check/:wallet', async (req, res) => {
  try {
    const client = await Client.findOne({
      walletAddress: { $regex: new RegExp('^' + req.params.wallet + '$', 'i') },
    });
    res.json({ isRegistered: !!client, clientData: client });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/unregister/:wallet', async (req, res) => {
  try {
    await Client.findOneAndDelete({
      walletAddress: { $regex: new RegExp('^' + req.params.wallet + '$', 'i') },
    });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
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
    });
    if (!client) return res.status(404).json({ error: 'Client not found in database' });

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

app.post('/api/sign-purchase', async (req, res) => {
  const { walletAddress, productBarcode, amount } = req.body;
  try {
    const client = await Client.findOne({
      walletAddress: { $regex: new RegExp('^' + walletAddress + '$', 'i') },
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

app.post('/api/register', async (req, res) => {
  const { walletAddress, name, email, phone, physicalAddress, storeAddress } = req.body;
  try {
    const newClient = await Client.findOneAndUpdate(
      { walletAddress: { $regex: new RegExp('^' + walletAddress + '$', 'i') } },
      { walletAddress, name, email, phone, physicalAddress },
      { new: true, upsert: true }
    );

    if (storeAddress) {
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

          await transporter.sendMail({
            from: EMAIL_USER,
            to: email,
            subject: `Welcome to ${contractConfig.companyName}!`,
            text: clientEmailContent,
          });

          await transporter.sendMail({
            from: EMAIL_USER,
            to: contractConfig.companyEmail,
            subject: `New Client Registration - ${name}`,
            text: companyEmailContent,
          });

          console.log(
            `Registration emails sent for client ${email} and store ${contractConfig.companyEmail}`
          );
        } else {
          console.log(`Store config not found for address ${storeAddress}, emails skipped.`);
        }
      } catch (emailError) {
        console.error('Error sending registration emails:', emailError);
      }
    }

    res.json({ success: true, client: newClient });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

const processedEventsFile = './processedEvents.json';
const lastProcessedBlockFile = './lastProcessedBlock.json';

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

    console.log(`Collected ${historicalEvents.length} unprocessed log entries for ${contractAddress}`);
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

    const abiEvents = new Set(
        (contractConfig.abi || [])
            .filter(x => x && x.type === 'event' && x.name)
            .map(x => x.name)
    );

    const handlerEventNames = Object.keys(contractConfig.eventHandlers || {});

    console.log(
        `Subscribing to ${handlerEventNames.length} handler events for ${contractConfig.address} (${contractConfig.companyName || 'N/A'})`
    );

    for (const eventName of handlerEventNames) {
        if (!abiEvents.has(eventName)) {
            console.error(
                `Skipping subscription: event "${eventName}" not found in ABI for ${contractConfig.address} (${contractConfig.companyName || 'N/A'})`
            );
            continue;
        }

        const evFn = contract.events[eventName];
        if (typeof evFn !== 'function') {
            console.error(
                `Skipping subscription: contract.events["${eventName}"] is not a function for ${contractConfig.address} (${contractConfig.companyName || 'N/A'})`
            );
            continue;
        }

        evFn.call(contract.events, { fromBlock: 'latest' })
            .on('data', async (event) => {
                try {
                    console.log(
                        `New real-time event received: ${event.event} tx=${event.transactionHash} logIndex=${event.logIndex}`
                    );
                    await processEvent(event, contractConfig);
                } catch (e) {
                    console.error(`Error processing realtime event ${eventName}:`, e);
                }
            })
            .on('error', (error) => {
                console.error(`Error in event subscription (${eventName}) for ${contractConfig.address}:`, error);
            });
    }
}


async function getClientFromDB(walletAddress) {
  if (!walletAddress) return null;
  return await Client.findOne({
    walletAddress: { $regex: new RegExp('^' + walletAddress + '$', 'i') },
  });
}

async function sendEmail(to, subject, text) {
  if (!to || !String(to).includes('@')) return;
  try {
    await transporter.sendMail({
      from: EMAIL_USER,
      to: to,
      subject: subject,
      text: text,
    });
    console.log(`Email sent to ${to}`);
  } catch (error) {
    console.error('Email error:', error);
  }
}

async function handleNewProductAdditions(eventData, contractConfig) {
  try {
    const clients = await Client.find({ email: { $exists: true, $ne: null } });
    if (clients.length === 0) return;

    const emails = clients.map((c) => c.email).filter(Boolean).join(',');
    if (!emails) return;

    const price = Number(eventData.price || 0);
    const disc = Number(eventData.discountPercentage || 0);
    const discountedPrice = (price * (100 - disc)) / 100;

    const description = (eventData.description || '').toString().replace(/[$~*^]/g, '');

    const mailOptions = {
      from: EMAIL_USER,
      to: EMAIL_USER,
      bcc: emails,
      subject: `New Product: ${eventData.barcode} Now Available!`,
      text: `Hello,

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
${contractConfig.companyName} Team`,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Product announcement email sent to ${clients.length} clients.`);
  } catch (error) {
    console.error('Email error:', error);
  }
}

async function handleProductSales(eventData, contractConfig, senderAddress) {
  try {
    console.log('handleProductSales keys:', Object.keys(eventData || {}));

    const walletToSearch = eventData.clientAddress || senderAddress;
    const client = await getClientFromDB(walletToSearch);

    if (!client) {
      console.error(`Client not found in DB for sale. Wallet: ${walletToSearch}`);
      return;
    }

    if (!client.email || !String(client.email).includes('@')) {
      console.error(`Client email missing/invalid for wallet ${walletToSearch}`);
      return;
    }

    const productDescRaw =
      eventData.ProductDesc ??
      eventData.productDesc ??
      eventData.description ??
      eventData.productDescription ??
      eventData.ProductDescription ??
      '';

    const productDesc = productDescRaw.toString().replace(/[$~*^]/g, '');

    const ts = Number(eventData.timestamp || 0);
    const tsText = ts ? new Date(ts * 1000).toLocaleString() : 'N/A';

    const amountPaid = Number(eventData.amountPaid || 0);

    const toStore = contractConfig.companyEmail;
    if (!toStore || !String(toStore).includes('@')) {
      console.error(`Store email missing/invalid for company ${contractConfig.companyName}`);
      return;
    }

    const mailOptionsToClient = {
      from: EMAIL_USER,
      to: client.email,
      subject: `Thank You for Your Purchase from ${contractConfig.companyName}!`,
      text: `Hello ${client.name || ''},

Thank you for your purchase. Here are your transaction details:
Receipt ID: ${eventData.receiptId}
Timestamp: ${tsText}
Product Barcode: ${eventData.productBarcode}
Product Description: ${productDesc}
Price: ${amountPaid / 1e6} $USDC

Shipping Address: ${client.physicalAddress || ''}

Best regards,
${contractConfig.companyName} Team`,
    };

    const mailOptionsToStore = {
      from: EMAIL_USER,
      to: toStore,
      subject: `Sale Notification: (${eventData.productBarcode})`,
      text: `A sale has been completed.

Receipt ID: ${eventData.receiptId}
Product: ${eventData.productBarcode}
Price: ${amountPaid / 1e6} $USDC

Customer Info (From DB):
Name: ${client.name || ''}
Email: ${client.email || ''}
Phone: ${client.phone || ''}
Wallet: ${client.walletAddress || ''}
Address: ${client.physicalAddress || ''}

Please process the order.`,
    };

    await transporter.sendMail(mailOptionsToClient);
    await transporter.sendMail(mailOptionsToStore);
    console.log(`Sale emails sent for receipt ${eventData.receiptId}`);
  } catch (error) {
    console.error('handleProductSales error:', error);
  }
}

async function handleRefund(eventData, contractConfig, senderAddress) {
  try {
    const client = await getClientFromDB(eventData.clientAddress || senderAddress);
    if (!client) return;
    if (!client.email || !String(client.email).includes('@')) return;

    const refundAmount = Number(eventData.refundAmount || 0);

    const mailOptionsToClient = {
      from: EMAIL_USER,
      to: client.email,
      subject: `Refund Processed`,
      text: `Hello ${client.name || ''},

Your refund request has been processed successfully.

Receipt ID: ${eventData.receiptId}
Refund Amount: ${refundAmount / 1e6} $USDC

Best regards,
${contractConfig.companyName} Team`,
    };

    await transporter.sendMail(mailOptionsToClient);
    console.log(`Refund email sent to ${client.email}`);
  } catch (error) {
    console.error('Email error:', error);
  }
}

async function handleMoreInfo(eventData, contractConfig, senderAddress) {
  try {
    const client = await getClientFromDB(senderAddress);
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
