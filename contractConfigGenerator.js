const Web3 = require('web3');
const fs = require('fs');
require('dotenv').config();

// Import required ABIs
const abiClient = require('./abi.json');
const FundraisingABI = require('./FundraisingABI.json');
const ListingUltimateDeAlABI = require('./ListingUltimateDeAl.json');

class ContractConfigGenerator {
    constructor() {
        this.web3 = new Web3(new Web3.providers.WebsocketProvider(
            `wss://base-mainnet.g.alchemy.com/v2/${process.env.WEBSOCKET_URL_API}`,
            {
                reconnect: {
                    auto: true,
                    delay: 10000,
                    onTimeout: false
                }
            }
        ));
        
        this.listingContract = new this.web3.eth.Contract(
            ListingUltimateDeAlABI,
            process.env.LISTING_CONTRACT_ADDRESS
        );
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
                CampaignStopped: handlers.handleCampaignStopped
            }
        };
    }

    generateStoreConfig(store, handlers) {
        return {
            address: store.smartContractAddress,
            abi: abiClient,
            secretKey: process.env.CONTRACT1_SECRET_KEY,
            companyName: store.name,
            companyEmail: store.contactInfo,
            companyUrl: store.urlPath,
            eventHandlers: {
                ProductAdded: handlers.handleNewProductAdditions,
                NewReceipt: handlers.handleProductSales,
                AmountPurchasedMoreInfo: handlers.handleMoreInfo,
                ClientRefunded: handlers.handleRefund,
                DistributionStarted: handlers.handleDistribution,
                BalanceDistributed: handlers.handleFinishedDist,
                WorkerGotPayed: handlers.handleWorkerPayment
            }
        };
    }

    async generateContractConfigs(handlers) {
        try {
            // Start with the fundraising contract
            const contracts = [this.generateBaseFundraisingConfig(handlers)];

            // Get all stores from the listing contract
            const result = await this.listingContract.methods.getAllStores().call();
            
            // The stores are in result['0']
            const stores = result['0'];
            
            console.log(`Found ${stores.length} stores`);
            
            // Add configurations for each store
            for (const store of stores) {
                const storeConfig = this.generateStoreConfig(store, handlers);
                contracts.push(storeConfig);
                console.log(`Generated config for store: ${store.name}`);
            }
            
            // Save configurations to file
            const configPath = './contractsConfig.json';
            fs.writeFileSync(configPath, JSON.stringify(contracts, null, 2));
            console.log(`Saved ${contracts.length} contract configurations to ${configPath}`);
            
            return contracts;
        } catch (error) {
            console.error('Error in generateContractConfigs:', error);
            console.error('Error details:', {
                message: error.message,
                stack: error.stack
            });
            throw error;
        }
    }

    async watchForNewStores(handlers) {
        try {
            // Watch all events and filter for store registration
            this.listingContract.events.allEvents()
                .on('data', async (event) => {
                    if (event.event === 'registerStore') {
                        console.log('New store registered, regenerating configurations...');
                        await this.generateContractConfigs(handlers);
                    }
                })
                .on('error', error => {
                    console.error('Error watching for new stores:', error);
                });
        } catch (error) {
            console.error('Error setting up store watcher:', error);
        }
    }
}

let configGenerator;
let theContracts;

async function initializeServer(handlers) {
    try {
        configGenerator = new ContractConfigGenerator();
        
        // Generate initial configurations with handlers
        theContracts = await configGenerator.generateContractConfigs(handlers);
        
        // Start watching for new stores
        await configGenerator.watchForNewStores(handlers);
        
        return theContracts;
    } catch (error) {
        console.error('Failed to initialize server:', error);
        throw error;
    }
}

// Export both functions
module.exports = {
    initializeServer,
    getContracts: () => theContracts
};