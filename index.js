const axios = require('axios');
const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const path = require('path');
const fs = require('fs');




const app = express();
const port = 3000;

// Simple in-memory user store (in production, use a database)
const users = new Map();
const USERS_DB_PATH = path.join(__dirname, 'users.json');

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

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

app.get('/imgdl', async (req, res) => {
  const imageUrl = req.query.url;

  try {
    // Use axios to fetch the image from the URL
    const response = await axios({
      url: imageUrl,
      method: 'GET',
      responseType: 'stream'
    });

    // Set headers for the download
    res.setHeader('Content-Disposition', 'attachment; filename="downloaded-image.png"');
    res.setHeader('Content-Type', 'image/png');

    // Pipe the image data to the response
    response.data.pipe(res);
  } catch (error) {
    console.error('Error downloading image:', error);
    res.status(500).send('Error downloading image.');
  }
});


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

    // Check if user has enough coins or is premium
    if (!userData.isPremium && userData.coins <= 0) {
      return res.status(403).json({ 
        error: 'Insufficient coins', 
        coins: userData.coins,
        isPremium: userData.isPremium 
      });
    }

    const {
      start,
      end,
      duration,
      currency_pairs,
      percentage_min = 90,
    } = req.query;

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

    // Deduct coin for non-premium users
    if (!userData.isPremium) {
      userData.coins -= 1;
      userData.signalsUsed += 1;
      users.set(userId, userData);
      saveUsersToFile(); // Save changes to file
    }

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




app.get('/ephoto', async (req, res) => {
    const { number, text } = req.query;
    if (!number || !text) {
        return res.status(400).send('Missing number or text parameter');
    }

    const urls = {
        "1": "https://en.ephoto360.com/create-a-cloud-text-effect-in-the-sky-618.html",
        "2": "https://en.ephoto360.com/create-colorful-neon-light-text-effects-online-797.html",
        "3": "https://en.ephoto360.com/naruto-shippuden-logo-style-text-effect-online-808.html",
        "4": "https://en.ephoto360.com/create-online-3d-comic-style-text-effects-817.html",
        "5": "https://en.ephoto360.com/write-text-on-wet-glass-online-589.html",
        "6": "https://en.ephoto360.com/write-in-sand-summer-beach-online-576.html",
        "7": "https://en.ephoto360.com/green-neon-text-effect-395.html",
        "8": "https://en.ephoto360.com/text-firework-effect-356.html",
        "9": "https://en.ephoto360.com/online-hot-metallic-effect-341.html",
        "10": "https://en.ephoto360.com/paint-splatter-text-effect-72.html",
        "11": "https://en.ephoto360.com/create-digital-glitch-text-effects-online-767.html",
    };

    const url = urls[number];

    if (!url) {
        return res.status(400).send('Invalid number parameter');
    }

    try {
        const photo360 = new Photo360(url);
        photo360.setName(text);
        const imgUrl = await photo360.execute();

        if (imgUrl.imageUrl) {
            const imageResponse = await axios.get(imgUrl.imageUrl, { responseType: 'arraybuffer' });
            res.set('Content-Type', 'image/png');
            res.send(imageResponse.data);
        } else {
            res.status(500).send('Failed to generate image');
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});


app.get('/gptgo', async (req, res) => {
  const userPrompt = req.query.prompt || "Hello";
  const uid = req.query.uid || "webuser";
  try {
    const baseUrl = await baseApiUrl();
    const response = await axios.get(
      `${baseUrl}/gemini2?text=${encodeURIComponent(userPrompt)}&senderID=${uid}`
    );
    const mg = response.data.response;
    res.json({ status: true, gpt: mg });
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
        coins: 5,
        isPremium: false,
        signalsUsed: 0
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

    res.json(userData);
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
  if (password === '14133504') {
    return res.sendFile(path.join(__dirname, 'public', 'ad14133.html'));
  }

  // Show password input page
  const loginPage = `
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
        // Focus on password input
        document.querySelector('input[type="password"]').focus();

        // Add enter key support
        document.querySelector('input[type="password"]').addEventListener('keypress', function(e) {
          if (e.key === 'Enter') {
            document.querySelector('form').submit();
          }
        });
      </script>
    </body>
    </html>
  `;

  res.send(loginPage);
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

    // Check if user has enough coins or is premium
    if (!userData.isPremium && userData.coins <= 0) {
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

    // Deduct coin for non-premium users
    if (!userData.isPremium) {
      userData.coins -= 1;
      userData.signalsUsed += 1;
      users.set(userId, userData);
      saveUsersToFile(); // Save changes to file
    }

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

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});