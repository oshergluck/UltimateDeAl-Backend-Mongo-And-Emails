const Web3 = require("web3");
const fs = require("fs");
require("dotenv").config();

// Import required ABIs
const abiClient = require("./abi.json");
const FundraisingABI = require("./FundraisingABI.json");
const ListingUltimateDeAlABI = require("./ListingUltimateDeAl.json");

class ContractConfigGenerator {
  constructor() {
    const wsUrl = `wss://base-mainnet.g.alchemy.com/v2/${process.env.WEBSOCKET_URL_API}`;

    this.provider = new Web3.providers.WebsocketProvider(wsUrl, {
      reconnect: { auto: true, delay: 10000, onTimeout: false },
      // these options help some WS setups
      clientConfig: { keepalive: true, keepaliveInterval: 60000 },
    });

    this.web3 = new Web3(this.provider);

    this.listingContract = new this.web3.eth.Contract(
      ListingUltimateDeAlABI,
      process.env.LISTING_CONTRACT_ADDRESS
    );

    // Used for polling fallback (when ABI has no events)
    this._lastStoresFingerprint = "";
    this._pollInterval = null;

    // basic provider diagnostics
    this.provider.on("connect", () => console.log("✅ WS connected:", wsUrl));
    this.provider.on("error", (e) => console.error("❌ WS error:", e?.message || e));
    this.provider.on("end", (e) => console.error("❌ WS ended:", e?.message || e));
  }

  generateBaseFundraisingConfig(handlers) {
    return {
      address: process.env.FUNDRAISING_ADDRESS,
      abi: FundraisingABI,
      eventHandlers: {
        CampaignCreated: handlers.handleCampaignCreated,
        campaignVerified: handlers.handleCampaignVerified,
        DonationReceived: handlers.handleDonationReceived,
        CampaignWithdrawn: handlers.handleCampaignWithdrawn,
        CampaignClosed: handlers.handleCampaignClosed,
        CampaignStopped: handlers.handleCampaignStopped,
      },
    };
  }

  generateStoreConfig(store, handlers) {
    return {
      address: store.smartContractAddress,
      abi: abiClient,
      secretKey: process.env.CONTRACT1_SECRET_KEY,

      // ✅ matches the NEW getAllStores() tuple fields
      companyName: store.name,
      companyEmail: store.contactInfo,
      companyUrl: store.urlPath,

      // Optional extras if you want to keep them (won't break anything)
      picture: store.picture,
      description: store.description,
      category: store.category,
      creationDate: store.creationDate,
      expirationDate: store.expirationDate,
      promotionExpirationDate: store.promotionExpirationDate,
      hidden: store.hidden,

      // If you merge voting info (below), these may exist:
      city: store.city,
      storeOwner: store.storeOwner,
      votingSystemAddress: store.votingSystemAddress,
      ERCUltra: store.ERCUltra,
      invoicesOfStore: store.invoicesOfStore,
      encrypted: store.encrypted,

      eventHandlers: {
        ProductAdded: handlers.handleNewProductAdditions,
        NewReceipt: handlers.handleProductSales,
        AmountPurchasedMoreInfo: handlers.handleMoreInfo,
        ClientRefunded: handlers.handleRefund,
        DistributionStarted: handlers.handleDistribution,
        BalanceDistributed: handlers.handleFinishedDist,
        WorkerGotPayed: handlers.handleWorkerPayment,
      },
    };
  }

  /**
   * NEW ABI: getAllStores() returns TWO arrays:
   *  - Store[]      (basic store data)
   *  - StoreVoting[](voting/invoices/city/owner/encrypted)
   */
  async fetchAllStoresMerged() {
    const result = await this.listingContract.methods.getAllStores().call();

    // Web3 often returns an object with numeric keys: { '0': [...], '1': [...] }
    const stores = result?.[0] || result?.["0"] || [];
    const voting = result?.[1] || result?.["1"] || [];

    // Merge by index (contract returns aligned arrays)
    const merged = stores.map((s, i) => {
      const v = voting[i] || {};
      return { ...s, ...v };
    });

    return merged;
  }

  async generateContractConfigs(handlers) {
    try {
      // Start with the fundraising contract
      const contracts = [this.generateBaseFundraisingConfig(handlers)];

      // Get all stores from the listing contract (NEW ABI)
      const stores = await this.fetchAllStoresMerged();

      console.log(`Found ${stores.length} stores`);

      for (const store of stores) {
        // sanity checks to avoid crashing on weird store entries
        if (!store?.smartContractAddress || !store?.urlPath) continue;

        const storeConfig = this.generateStoreConfig(store, handlers);
        contracts.push(storeConfig);
        console.log(`Generated config for store: ${store.name} (${store.urlPath})`);
      }

      // Save configurations to file
      const configPath = "./contractsConfig.json";
      fs.writeFileSync(configPath, JSON.stringify(contracts, null, 2));
      console.log(`Saved ${contracts.length} contract configurations to ${configPath}`);

      return contracts;
    } catch (error) {
      console.error("Error in generateContractConfigs:", error);
      console.error("Error details:", { message: error.message, stack: error.stack });
      throw error;
    }
  }

  /**
   * If ListingUltimateDeAl ABI includes events -> listen.
   * If it DOES NOT (your pasted ABI has no events) -> fallback to polling getAllStores().
   */
  async watchForNewStores(handlers) {
    const abiHasEvents = Array.isArray(ListingUltimateDeAlABI)
      ? ListingUltimateDeAlABI.some((x) => x && x.type === "event")
      : false;

    if (abiHasEvents) {
      try {
        this.listingContract.events
          .allEvents()
          .on("data", async (event) => {
            // event.event is the EVENT NAME (not the function name)
            const name = (event?.event || "").toLowerCase();

            // try to be tolerant with naming
            const looksLikeStoreEvent =
              name.includes("register") ||
              name.includes("store") ||
              name.includes("newstore") ||
              name.includes("storecreated");

            if (looksLikeStoreEvent) {
              console.log("🆕 Store-related event detected, regenerating configurations...");
              await this.generateContractConfigs(handlers);
            }
          })
          .on("error", (error) => {
            console.error("Error watching for new stores (events):", error);
          });

        console.log("👂 Watching for new stores via EVENTS...");
        return;
      } catch (error) {
        console.error("Error setting up event watcher, falling back to polling:", error);
      }
    }

    // ---- Polling fallback (works even if ABI has no events) ----
    console.log("👂 Watching for new stores via POLLING (ABI has no events)...");
    const pollMs = Number(process.env.STORES_POLL_MS || 20000);

    const fingerprint = (stores) =>
      `${stores.length}:${stores
        .map((s) => `${s.urlPath}|${String(s.smartContractAddress).toLowerCase()}`)
        .join(",")}`;

    // prime fingerprint
    try {
      const stores = await this.fetchAllStoresMerged();
      this._lastStoresFingerprint = fingerprint(stores);
    } catch (e) {
      console.error("Initial polling fetch failed:", e?.message || e);
      this._lastStoresFingerprint = "";
    }

    this._pollInterval = setInterval(async () => {
      try {
        const stores = await this.fetchAllStoresMerged();
        const fp = fingerprint(stores);

        if (fp !== this._lastStoresFingerprint) {
          this._lastStoresFingerprint = fp;
          console.log("🆕 Stores changed, regenerating configurations...");
          await this.generateContractConfigs(handlers);
        }
      } catch (e) {
        console.error("Polling stores failed:", e?.message || e);
      }
    }, pollMs);
  }

  stopWatching() {
    if (this._pollInterval) clearInterval(this._pollInterval);
    this._pollInterval = null;

    try {
      this.provider?.disconnect?.(1000, "shutdown");
    } catch {}
  }
}

let configGenerator;
let theContracts;

async function initializeServer(handlers) {
  try {
    configGenerator = new ContractConfigGenerator();

    // Generate initial configurations with handlers
    theContracts = await configGenerator.generateContractConfigs(handlers);

    // Start watching for new stores (events if available, else polling)
    await configGenerator.watchForNewStores(handlers);

    return theContracts;
  } catch (error) {
    console.error("Failed to initialize server:", error);
    throw error;
  }
}

// Export both functions
module.exports = {
  initializeServer,
  getContracts: () => theContracts,
};
