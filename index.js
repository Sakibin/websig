
const approve_ID = "signalweb";
const approve_KEY = "FBX7858";
const axios = require('axios');
const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const path = require('path');
const fs = require('fs');

//hj
// Initialize Firebase Admin SDK
const serviceAccount = { "type": "service_account",
     "project_id": "sakibin-75f62",
     "private_key_id": "129481e6e985a985066270b28e322679b1f6bea5",
     "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/Mv5rVQMLQ/AA\nn+DXoLToPZsWQjAfxMq+XXyL59hTnOXBtWB2i6gzH3/n3hSVyfQBMr08LuCSQ50R\nfqyoWuLr9NIR+2tR8RjcVp0tIu9/uHYswEqs3TCKpmjhWNOAQeEHz/7UtADzZRVL\nv1XWZCeN8I4hHRKpLO+l8QtQbqhwMSyYS5NZBrLlKhj0tEFtl8vUzZmfhQ3uRXOL\nMNtOeswoo4gJUZ64y8drNf0mH+wP+1sDaZ6svE2sTV0Mt4/inu1ytV5GVhsSxUkM\nDTk9CQxiueLLkHDgHOjCwZyURqwXMSBj9oyMIakyg/ATW/WGvJ6scCWxrTnnn82a\nD33jQA4hAgMBAAECggEACU+a6zArI0fOLsGaafXGCY9Cd62GeW2Ub/vOfmOuebfo\nymuiRHOdn8u3Z1u9xeOdUdeeNomT3xuS0RDJqLMwXMxB1KVZPxbOHqDLK7EJV79s\nZdaBbHSjEgVzkxHHzvWmV0KORt5zM2cnR9aMABJFiNh/m2Y2i+2HyB16bxLMehYd\nVKdl5vDwQSjbZJ2Cy5P/jOZ0faWGZLXeikNe3gRl72twQPA2hSBFlYW+yDE6dmK9\nAMqisF0s9aZEpZgkjvEzjMg1qC9xfDkw10odAkiwl7kuO+fEPpAA1+vruY3qjn3J\n30LVNhfeRlh9v3BrAw3eqhZ0ol89zXKTwyutkhBiKQKBgQDxGIM3Q1gZ13smnF1A\nRFum/5ohweEkPL7JpGRNCkoFgXCwsDB7eTdW3pcVcHOKJViFDr9TGsB3AdxZbUYE\nkbTzqoRGYZoJGdU9ljlbyVkxnm3YmwH+CYpX3hRnSerymANjZy5mgSsTXXNK8kMU\nPkV++u8Wlcqfon8X3iNQ2v0VZQKBgQDLBNZ5A6/dlnAOLmVo8xuRKzBjhgvdpIKs\nTB2FNheDP6dWNwqkKeYeqxNFFSqLk/1nvZZ78FM+rRH6XocmPaRZ9XODv5aETYIb\ni2iYoyg5YpNaRojm4U0b6JX5iKHm8eVRGMzDWLkxWSeUFu/a3kXQuh4O7BaREgqs\nsLKQRsqYDQKBgHsf9pr5ZHvGBNmCD0lr35aYgGFu/wifkRuvPZ3ufED1itRhFlFo\nZS+S+3tycz8AtYU2M9VAGzxrkdmFqbVZqBysX2MGI0E0lScfmelbGZbyfsyY1Nqk\niqc2/hqFsFv17/0Ky7KDkrkQB3ol4MXsy1b+1a0mEFWYCenpgwWe4JLVAoGBAKk9\nojEFgtD9PPKFeOJxbzSoRVFiCHg/UPOjDCTlf9pY8P1tKwDJMN22DX1UdMAgoWme\n4Vj2cd7Y1hjaPl4BmwWnGSHmT+qA1opxv8MmmDymUWI7VJrrjKVMUeHQJe9pDZp6\nSxA54UAjK1xHdrIFAzxKOw6Dfxh2atGlB2ZArVjtAoGBAOI5W7J9SWGVdt/ahHB6\nzC4rUfNj7jqQ7Ri1t/BSVq1HyHQS0fXgda85Z7TeLBtt259UYZyNPbTGcYZty777\nVKN0rC+YtjvDGFW5vF1CAR367QHwhx2ujnYwV28YLY6Q/m1QKzvd5ePp8GHALngy\nuq35HKEw9sD4uy7w13EQ5IHs\n-----END PRIVATE KEY-----\n",
     "client_email": "firebase-adminsdk-osh5o@sakibin-75f62.iam.gserviceaccount.com",
     "client_id": "112381259901301320288",
     "auth_uri": "https://accounts.google.com/o/oauth2/auth",
     "token_uri": "https://oauth2.googleapis.com/token",
     "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
     "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-osh5o%40sakibin-75f62.iam.gserviceaccount.com",
     "universe_domain": "googleapis.com"};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: "sakibin-75f62.appspot.com"
});

const app = express();
const port = 6000;

// Simple in-memory user store (in production, use a database)
const users = new Map();
const USERS_DB_PATH = path.join(__dirname, 'users.json');
const CHAT_DIR = path.join(__dirname, 'chat');
const NOTIF_PATH = path.join(__dirname, 'notifications.json');
if (!fs.existsSync(CHAT_DIR)) fs.mkdirSync(CHAT_DIR);

// Helper: Get chat file path for user (by email)
function getChatFilePathByEmail(email) {
  // Sanitize email for filename (allow @ and .)
  return path.join(CHAT_DIR, `${email}.json`);
}

// Helper: Read chat for user (by email)
function readUserChatByEmail(email) {
  const file = getChatFilePathByEmail(email);
  if (fs.existsSync(file)) {
    try {
      return JSON.parse(fs.readFileSync(file, 'utf-8'));
    } catch {
      return [];
    }
  }
  return [];
}

// Helper: Write chat for user (by email)
function writeUserChatByEmail(email, chatArr) {
  fs.writeFileSync(getChatFilePathByEmail(email), JSON.stringify(chatArr, null, 2), 'utf-8');
}

// Load users from JSON file
function loadUsersFromFile() {
  if (fs.existsSync(USERS_DB_PATH)) {
    try {
      const data = fs.readFileSync(USERS_DB_PATH, 'utf-8');
      const obj = JSON.parse(data);
      users.clear();
      Object.entries(obj).forEach(([userId, userData]) => {
        users.set(userId, userData);
      });
    } catch (e) {
      console.error('Failed to load users.json:', e.message);
    }
  }
}

// Save users to JSON file
function saveUsersToFile() {
  const obj = {};
  users.forEach((data, userId) => {
    obj[userId] = data;
  });
  fs.writeFileSync(USERS_DB_PATH, JSON.stringify(obj, null, 2), 'utf-8');
}

// Load users at startup
loadUsersFromFile();

// Helper: Load notifications
function loadNotifications() {
  if (fs.existsSync(NOTIF_PATH)) {
    try {
      return JSON.parse(fs.readFileSync(NOTIF_PATH, 'utf-8'));
    } catch {
      return [];
    }
  }
  return [];
}

// Helper: Save notifications
function saveNotifications(list) {
  fs.writeFileSync(NOTIF_PATH, JSON.stringify(list, null, 2), 'utf-8');
}

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// Optional: Endpoint to verify ID tokens (for authenticated requests)

app.get('/alldl', async (req, res) => {
    const url = req.query.url;

    if (!url) {
        return res.status(400).send('Please provide a URL as a query parameter.');
    }

    try {
        const data = await alldown(url);
        res.json(data);
    } catch (error) {
        res.status(500).send('Error processing the request');
    }
});

const BASE_API_URL = "https://alltradingapi.com/signal_list_gen_vip/qx_api";
const HR_TRADING_API_URL = "https://api.hrtradingzone.com/generator/generator_saiful_off.php";

const baseApiUrl = async () => {
  const base = await axios.get(
    `https://raw.githubusercontent.com/Mostakim0978/D1PT0/refs/heads/main/baseApiUrl.json`,
  );
  return base.data.api;
};

// Formatted signal data
app.get("/api/signal", async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    // Verify user and check coins
    const decodedToken = await admin.auth().verifyIdToken(token);
    const userId = decodedToken.uid;
    const userData = users.get(userId);

    if (!userData) {
      return res.status(404).json({ error: 'User not found' });
    }

    const {
      start,
      end,
      duration,
      currency_pairs,
      percentage_min = 90,
    } = req.query;

    // --- BINOLA/OTC coin deduction logic ---
    // List of OTC assets (should match binola.html)
    const otcPairs = [
      "AUDCHF-OTC", "AUDJPY-OTC", "AUDUSD-OTC", "AUS200-OTC", "BCHUSD-OTC", "BNBUSD-OTC", "BTCUSD-OTC",
      "DOTUSD-OTC", "ETHUSD-OTC", "EURAUD-OTC", "EURCAD-OTC", "EURGBP-OTC", "EURJPY-OTC", "EURUSD-OTC",
      "FR40-OTC", "GBPAUD-OTC", "GBPCAD-OTC", "GBPCHF-OTC", "GBPUSD-OTC", "GER30-OTC", "HK33-OTC",
      "J225-OTC", "NEARUSD-OTC", "NZDUSD-OTC", "SOLUSD-OTC", "SPN35-OTC", "TONUSD-OTC", "UK100-OTC",
      "US100-OTC", "US2000-OTC", "US500-OTC", "USDBDT-OTC", "USDBRL-OTC", "USDCAD-OTC", "USDCHF-OTC",
      "USDJPY-OTC", "USDX-OTC", "WIFUSD-OTC", "XAGUSD-OTC", "XAUUSD-OTC", "XBRUSD-OTC", "XNGUSD-OTC",
      "XPDUSD-OTC", "XPTUSD-OTC", "XTIUSD-OTC"
    ];
    let isBinola = false;
    if (currency_pairs) {
      const pairs = currency_pairs.split(',').map(s => s.trim().toUpperCase());
      isBinola = pairs.some(pair =>
        pair.endsWith('-OTC') || otcPairs.includes(pair)
      );
    }
    const coinsToDeduct = isBinola ? 2 : 1;

    // Check if user has enough coins (premium or not)
    if (userData.coins < coinsToDeduct) {
      return res.status(403).json({ 
        error: 'Insufficient coins', 
        coins: userData.coins,
        isPremium: userData.isPremium 
      });
    }

    const apiUrl = `${BASE_API_URL}?start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}&duration=${encodeURIComponent(duration)}&currency_pairs=${encodeURIComponent(currency_pairs)}&operation_mode=normal&percentage_min=${percentage_min}&apply_filter=1&is_separate=1&backtest_advanced=off`;

    const response = await axios.get(apiUrl);
    const data = response.data;

    const formattedResponse = {
      execution_details: {
        execution_time: data.detalhes_execucao?.tempo_execucao || "",
        timezone: data.detalhes_execucao?.fuso_horario || "",
        date: data.detalhes_execucao?.data || "",
        creator: "Prime",
      },
      signals: (data.signals || []).map(signal => ({
        asset: signal.ativos.replace("_otc", ""),
        entry_time: signal.entrada,
        main_direction: signal.direcao_principal === "put" ? "sell" : "buy"
      }))
    };

    // Deduct coin for all users (premium and free)
    userData.coins -= coinsToDeduct;
    userData.signalsUsed += 1;
    users.set(userId, userData);
    saveUsersToFile(); // Save changes to file

    res.json({
      ...formattedResponse,
      userCoins: userData.coins,
      isPremium: userData.isPremium
    });
  } catch (error) {
    console.error("Error fetching signal:", error.message);
    res.status(500).json({ error: "Failed to fetch signal data" });
  }
});

// Raw response
app.get("/api/signals", async (req, res) => {
  try {
    const {
      start,
      end,
      duration,
      currency_pairs,
      percentage_min = 90,
    } = req.query;

    const apiUrl = `${BASE_API_URL}?start=${encodeURIComponent(start)}&end=${encodeURIComponent(end)}&duration=${encodeURIComponent(duration)}&currency_pairs=${encodeURIComponent(currency_pairs)}&operation_mode=normal&percentage_min=${percentage_min}&apply_filter=1&is_separate=1&backtest_advanced=off`;

    const response = await axios.get(apiUrl);
    res.json(response.data);
  } catch (error) {
    console.error("Error fetching raw signal data:", error.message);
    res.status(500).json({ error: "Failed to fetch signals" });
  }
});

app.get('/gptgo', async (req, res) => {
  const userPrompt = req.query.prompt || "Hello";
  const uid = req.query.uid || "webuser";
  try {
    // Deduct 1 coin for each AI response if user exists
    let userData = null;
    if (users.has(uid)) {
      userData = users.get(uid);
      if (userData.coins <= 0) {
        return res.status(403).json({ status: false, error: "Insufficient coins" });
      }
    }
    const baseUrl = await baseApiUrl();
    const response = await axios.get(
      `${baseUrl}/gemini2?text=${encodeURIComponent(userPrompt)}&senderID=${uid}`
    );
    const mg = response.data.response;

    // Deduct 1 coin and save if user exists
    if (userData) {
      userData.coins -= 1;
      users.set(uid, userData);
      saveUsersToFile();
    }

    res.json({ status: true, gpt: mg, userCoins: userData ? userData.coins : undefined });
  } catch (err) {
    res.status(500).json({ status: false, error: err.message });
  }
});

app.get('/download', async (req, res) => {
    const url = req.query.url;
    const fileName = 'high_quality_video.mp4';

    try {
        // Fetch the video using Axios
        const response = await axios({
            url,
            method: 'GET',
            responseType: 'stream', // Important to handle large video files
        });

        // Set the headers to prompt a download in the browser
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        res.setHeader('Content-Type', 'video/mp4');

        // Pipe the Axios response directly to the client
        response.data.pipe(res);

    } catch (error) {
        console.error('Error downloading video:', error);
        res.status(500).send('Error downloading video');
    }
});

app.post('/verifyToken', async (req, res) => {
  const idToken = req.body.token;

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);

    // Initialize user with 20 free coins if not exists
    const userId = decodedToken.uid;    if (!users.has(userId)) {
      users.set(userId, {
        email: decodedToken.email,
        coins: 20,
        isPremium: false,
        signalsUsed: 0,
        emailVerified: decodedToken.email_verified || false
      });
      saveUsersToFile();
    }

    res.status(200).send({
      ...decodedToken,
      userData: users.get(userId)
    });
  } catch (error) {
    res.status(401).send('Unauthorized');
  }
});

// Password reset endpoint
app.post('/api/auth/reset-password', async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    // Generate password reset link using Firebase Admin SDK
    const link = await admin.auth().generatePasswordResetLink(email);
    
    // In a real application, you would send this link via email
    // For now, we'll just return it in the response
    res.json({ 
      success: true, 
      message: 'Password reset link generated successfully',
      resetLink: link // Remove this in production
    });
  } catch (error) {
    console.error('Error generating password reset link:', error);
    res.status(500).json({ error: 'Failed to generate password reset link' });
  }
});

// Email verification endpoint
app.post('/api/auth/send-verification', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    const userId = decodedToken.uid;
    
    // Generate email verification link
    const link = await admin.auth().generateEmailVerificationLink(decodedToken.email);
    
    // In a real application, you would send this link via email
    // For now, we'll just return it in the response
    res.json({ 
      success: true, 
      message: 'Email verification link generated successfully',
      verificationLink: link // Remove this in production
    });
  } catch (error) {
    console.error('Error generating email verification link:', error);
    res.status(500).json({ error: 'Failed to generate email verification link' });
  }
});

// Get user profile
app.get('/api/profile', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    const userId = decodedToken.uid;
    const userData = users.get(userId) || { coins: 20, isPremium: false, signalsUsed: 0 };

    // Update email verification status from Firebase
    userData.emailVerified = decodedToken.email_verified || false;
    users.set(userId, userData);
    saveUsersToFile();

    // Ensure admin property is included if present
    const profile = {
      email: userData.email,
      coins: userData.coins,
      isPremium: userData.isPremium,
      signalsUsed: userData.signalsUsed,
      emailVerified: userData.emailVerified,
      ...(userData.admin !== undefined ? { admin: userData.admin } : {})
    };

    res.json(profile);
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Upgrade to premium
app.post('/api/upgrade-premium', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    const userId = decodedToken.uid;

    if (users.has(userId)) {
      const userData = users.get(userId);
      userData.isPremium = true;
      users.set(userId, userData);
      saveUsersToFile(); // Save changes to file
      res.json({ success: true, userData });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Admin login page
app.get('/admin', (req, res) => {
  const password = req.query.pass;
  // Check for admin password OR adminrole in user data
  if (password === '14133504') {
    return res.sendFile(path.join(__dirname, 'public', 'ad14133.html'));
  }

  // Check for Firebase token in Authorization header
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) {
    admin.auth().verifyIdToken(token)
      .then(decodedToken => {
        const userId = decodedToken.uid;
        const userData = users.get(userId);
        if (userData && userData.adminrole === true) {
          return res.sendFile(path.join(__dirname, 'public', 'ad14133.html'));
        }
        // Not admin, show login page
        res.send(loginPage(password));
      })
      .catch(() => {
        res.send(loginPage(password));
      });
    return;
  }

  // Show password input page
  function loginPage(password) {
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Admin Access</title>
      <style>
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          background: linear-gradient(135deg, #1e3c72, #2a5298);
          margin: 0;
          padding: 0;
          display: flex;
          justify-content: center;
          align-items: center;
          min-height: 100vh;
          color: white;
        }
        .login-container {
          background: rgba(255, 255, 255, 0.1);
          backdrop-filter: blur(10px);
          border-radius: 15px;
          padding: 40px;
          box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
          border: 1px solid rgba(255, 255, 255, 0.2);
          text-align: center;
          min-width: 300px;
        }
        h1 {
          color: #ffcc00;
          margin-bottom: 30px;
          text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
        }
        .input-group {
          margin-bottom: 20px;
        }
        input[type="password"] {
          width: 100%;
          padding: 15px;
          border: 1px solid rgba(255, 255, 255, 0.3);
          border-radius: 8px;
          background: rgba(255, 255, 255, 0.1);
          color: white;
          font-size: 16px;
          box-sizing: border-box;
        }
        input[type="password"]::placeholder {
          color: rgba(255, 255, 255, 0.6);
        }
        input[type="password"]:focus {
          outline: none;
          border-color: #ffcc00;
          box-shadow: 0 0 10px rgba(255, 204, 0, 0.3);
        }
        .btn {
          background: #ffcc00;
          color: #000;
          border: none;
          padding: 15px 30px;
          border-radius: 8px;
          cursor: pointer;
          font-weight: bold;
          font-size: 16px;
          transition: all 0.3s;
          width: 100%;
        }
        .btn:hover {
          background: #ffaa00;
          transform: translateY(-2px);
        }
        .error {
          color: #ff4444;
          margin-top: 15px;
          font-size: 14px;
        }
        .icon {
          font-size: 48px;
          margin-bottom: 20px;
          color: #ffcc00;
        }
      </style>
    </head>
    <body>
      <div class="login-container">
        <div class="icon">🔐</div>
        <h1>Admin Access</h1>
        <form method="GET" action="/admin">
          <div class="input-group">
            <input type="password" name="pass" placeholder="Enter admin password" required autofocus>
          </div>
          <button type="submit" class="btn">Access Admin Panel</button>
        </form>
        ${password ? '<div class="error">❌ Invalid password. Please try again.</div>' : ''}
      </div>
      <script>
        document.querySelector('input[type="password"]').focus();
        document.querySelector('input[type="password"]').addEventListener('keypress', function(e) {
          if (e.key === 'Enter') {
            document.querySelector('form').submit();
          }
        });
      </script>
    </body>
    </html>
    `;
  }

  res.send(loginPage(password));
});

// Get all users (admin only)
app.get('/api/admin/users', (req, res) => {
  const password = req.query.pass;
  if (password !== 'SRFG566') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const allUsers = [];
  users.forEach((userData, userId) => {
    allUsers.push({
      userId,
      email: userData.email,
      coins: userData.coins,
      isPremium: userData.isPremium,
      signalsUsed: userData.signalsUsed
    });
  });

  res.json(allUsers);
});

// Update user coins and premium status (admin only)
app.post('/api/admin/update-user', (req, res) => {
  const password = req.query.pass;
  if (password !== 'SRFG566') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { userId, coins, isPremium } = req.body;

  if (users.has(userId)) {
    const userData = users.get(userId);
    userData.coins = parseInt(coins) || 0;
    userData.isPremium = isPremium === true || isPremium === 'true';
    users.set(userId, userData);
    saveUsersToFile(); // Save changes to file

    res.json({ success: true, userData });
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// Delete user (admin only)
app.delete('/api/admin/delete-user', (req, res) => {
  const password = req.query.pass;
  if (password !== 'SRFG566') {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { userId } = req.body;

  if (users.has(userId)) {
    users.delete(userId);
    saveUsersToFile(); // Save changes to file
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// HR Trading Zone API endpoint
app.get("/api/hr-signals", async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    // Verify user and check coins
    const decodedToken = await admin.auth().verifyIdToken(token);
    const userId = decodedToken.uid;
    const userData = users.get(userId);

    if (!userData) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if user has enough coins (premium or not)
    if (userData.coins <= 0) {
      return res.status(403).json({ 
        error: 'Insufficient coins', 
        coins: userData.coins,
        isPremium: userData.isPremium 
      });
    }

    const {
      percentage = 90,
      timeframe = 'M1',
      daysanalyze = 19,
      martingle = 0,
      direction = 'BOTH',
      pairname = 'USDJPY',
      startTime = '00:00',
      endTime = '23:59',
      filtertype = 3,
      timezone = 'Asia/Kolkata'
    } = req.query;

    const apiUrl = `${HR_TRADING_API_URL}?percentage=${percentage}&timeframe=${timeframe}&daysanalyze=${daysanalyze}&martingle=${martingle}&direction=${direction}&pairname=${pairname}&startTime=${encodeURIComponent(startTime)}&endTime=${encodeURIComponent(endTime)}&filtertype=${filtertype}&timezone=${encodeURIComponent(timezone)}`;

    const response = await axios.get(apiUrl);

    // Format the response to match your existing structure
    const formattedResponse = {
      execution_details: {
        execution_time: new Date().toISOString(),
        timezone: timezone,
        date: new Date().toLocaleDateString(),
        creator: "HR Trading Zone",
      },
      signals: (response.data || []).map(signal => ({
        asset: signal.pair,
        entry_time: signal.time,
        main_direction: signal.direction.toLowerCase() === 'down' ? 'sell' : 'buy',
        movement: signal.movement,
        candle_time: signal.candle_time
      }))
    };

    // Deduct coin for all users (premium and free)
    userData.coins -= 1;
    userData.signalsUsed += 1;
    users.set(userId, userData);
    saveUsersToFile(); // Save changes to file

    res.json({
      ...formattedResponse,
      userCoins: userData.coins,
      isPremium: userData.isPremium
    });
  } catch (error) {
    console.error("Error fetching HR trading signals:", error.message);
    res.status(500).json({ error: "Failed to fetch HR trading signals" });
  }
});

// --- Live Chat System ---

// User sends message
app.post('/api/chat/send', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    const userId = decodedToken.uid;
    const userData = users.get(userId);
    if (!userData) return res.status(404).json({ error: 'User not found' });
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });
    const chatArr = readUserChatByEmail(userData.email);
    chatArr.push({ from: 'user', text: message, time: Date.now() });
    writeUserChatByEmail(userData.email, chatArr);
    res.json({ success: true });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// User fetches chat
app.get('/api/chat/history', async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    const userId = decodedToken.uid;
    const userData = users.get(userId);
    if (!userData) return res.status(404).json({ error: 'User not found' });
    const chatArr = readUserChatByEmail(userData.email);
    res.json({ chat: chatArr });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Admin fetches all chats
app.get('/api/admin/chats', (req, res) => {
  const password = req.query.pass;
  if (password !== 'SRFG566') return res.status(401).json({ error: 'Unauthorized' });
  const chats = [];
  users.forEach((user, userId) => {
    const chatArr = readUserChatByEmail(user.email);
    if (chatArr.length > 0) {
      chats.push({
        userId,
        email: user.email,
        chat: chatArr
      });
    }
  });
  res.json(chats);
});

// Admin replies to user
app.post('/api/admin/chat/reply', (req, res) => {
  // REMOVE password check for admin reply
  // const password = req.query.pass;
  // if (password !== 'SRFG566') return res.status(401).json({ error: 'Unauthorized' });

  // Ensure body is parsed
  let userId, message;
  if (req.body && typeof req.body === 'object') {
    userId = req.body.userId;
    message = req.body.message;
  } else {
    // Try to parse if not already parsed
    try {
      const body = JSON.parse(req.body);
      userId = body.userId;
      message = body.message;
    } catch {
      return res.status(400).json({ error: 'Invalid JSON body' });
    }
  }

  if (!userId || !message) return res.status(400).json({ error: 'Missing userId or message' });
  if (users.has(userId)) {
    const userData = users.get(userId);
    const chatArr = readUserChatByEmail(userData.email);
    chatArr.push({ from: 'admin', text: message, time: Date.now() });
    writeUserChatByEmail(userData.email, chatArr);
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

// --- Admin Notification API ---

// Admin: Send notification
app.post('/api/admin/notification', (req, res) => {
  const password = req.query.pass;
  if (password !== 'SRFG566') return res.status(401).json({ error: 'Unauthorized' });
  const { message, type } = req.body;
  if (!message || typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({ error: 'Message required' });
  }
  const notifList = loadNotifications();
  const notif = {
    id: Date.now(),
    message: message.trim(),
    time: Date.now(),
    type: typeof type === 'string' ? type : 'info'
  };
  notifList.unshift(notif); // latest first
  saveNotifications(notifList);
  res.json({ success: true, notif });
});

// Admin: List notifications
app.get('/api/admin/notification', (req, res) => {
  const password = req.query.pass;
  if (password !== 'SRFG566') return res.status(401).json({ error: 'Unauthorized' });
  const notifList = loadNotifications();
  res.json(notifList);
});

// User: Get latest notification
app.get('/api/notification', (req, res) => {
  const notifList = loadNotifications();
  if (notifList.length > 0) {
    const { id, message, time, type } = notifList[0];
    res.json({ id, message, time, type: type || 'info' });
  } else {
    res.json({});
  }
});

// --- License check (system license) ---
(async () => {
  try {
    const resp = await axios.get('https://raw.githubusercontent.com/Sakibin/web/refs/heads/main/keybind.json');
    const user = (resp.data.users || []).find(
      u => u.name === approve_ID && u.key === approve_KEY
    );
    if (!user || user.status !== "active") {
      console.log("please get key from owner");
      process.exit(1);
    }
  } catch (e) {
    console.log("please get key from owner");
    process.exit(1);
  }
})();

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
