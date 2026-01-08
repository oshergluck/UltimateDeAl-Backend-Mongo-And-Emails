# Ultrashop Backend Server

This is the backend server for the **Ultrashop** decentralized platform. It bridges the gap between the blockchain (Base Network) and the frontend application.

The server handles user registration, listens to smart contract events via Web3, manages off-chain database records (MongoDB), and sends transactional emails using **Resend**.

## 🚀 Deployment (Recommended)

**This server is optimized to run on [Railway](https://railway.app/).**

Railway is recommended because this server requires:
1.  **Persistent Storage:** To keep track of processed blockchain events (`processedEvents.json`) and prevent double-processing or missing events during restarts.
2.  **Long-running Process:** The Web3 WebSocket connection needs to stay alive to listen for real-time events.

### Railway Setup Instructions
1.  Connect your GitHub repository to Railway.
2.  Add the Environment Variables (see below).
3.  **Crucial Step:** Add a **Volume** in Railway.
    * Mount path: `/app/data`
    * This ensures that event logs and the server PID are not lost during deployments.

---

## 🛠️ Features

* **Web3 Event Listener:** Listens to real-time events from multiple smart contracts on the Base network (Sales, Campaigns, Distributions, etc.).
* **Historical Event Sync:** On startup, fetches and processes missed events from Blockscout API.
* **User Registration:** Stores user details (encrypted/hashed where necessary) in MongoDB, linked specifically to store smart contracts.
* **Email Notifications:** Sends transactional emails (Welcome, Purchase Confirmation, Campaign Updates) using the **Resend API**.
* **Cryptographic Signing:** Signs purchase hashes to verify user registration on-chain without exposing private data.
* **Spam Prevention:** Includes logic to prevent sending duplicate emails within short timeframes.
* **Auto-Restart:** Automatically restarts every hour to prevent memory leaks (handled gracefully via PID checks).

## 🔑 Environment Variables

Create a `.env` file in the root directory (or set these in Railway) based on `.env.example`:

| Variable | Description |
| :--- | :--- |
| `EMAILP` | Your **Resend API Key** (starts with `re_...`). |
| `WEBSOCKET_URL_API` | Your **Alchemy** (or other provider) WebSocket key for Base Mainnet. |
| `MONGO_URI` | Connection string for your MongoDB database. |
| `SERVER_PRIVATE_KEY` | Private key of the server's admin wallet. Used for signing verification hashes (should handle 0 funds, acting as an admin signer). |
| `EMAIL` | The "From" email address. Use `onboarding@resend.dev` for testing or your verified domain in production. |
| `PORT` | Port to run the server (Default: `5000`). |
| `DATA_DIR` | Directory for persistent data. Set to `/app/data` for Railway. |
| `FUNDRAISING_ADDRESS` | Address of the fundraising master contract. |
| `LISTING_CONTRACT_ADDRESS` | Address of the listing master contract. |

## 📦 Installation & Local Development

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/your-repo-name.git](https://github.com/your-username/your-repo-name.git)
    cd your-repo-name
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    ```

3.  **Configure Environment:**
    Rename `.env.example` to `.env` and fill in your keys.

4.  **Run the server:**
    ```bash
    node server.js
    ```

## 📡 API Endpoints

* `GET /` - Health check.
* `GET /api/check/:wallet?storeAddress=0x...` - Check if a wallet is registered for a specific store.
* `POST /api/register` - Register a new client to a specific store.
* `POST /api/sign-purchase` - Generate a cryptographic signature for a purchase transaction.
* `POST /api/register-store` - Register a new store configuration.
* `DELETE /api/unregister/:wallet` - Remove a user from the database.

## 🧱 Project Structure

* `server.js`: Main entry point. Handles Express setup, DB connection, and Web3 listeners.
* `contractConfigGenerator.js`: (Required dependency) Helper module to generate contract ABIs and configurations.
* `/data`: Stores JSON files for tracking processed blockchain events (persisted via Volume in production).

## ⚠️ Notes

* **Indexes:** The server automatically handles MongoDB indexing migration (dropping old `walletAddress_1` in favor of a compound unique index with `storeContractAddress`).
* **Resend Domain:** For production, ensure you verify your domain in the [Resend Dashboard](https://resend.com/domains) and update the `EMAIL` env var to avoid landing in spam folders.

## 📄 License

[MIT](LICENSE)