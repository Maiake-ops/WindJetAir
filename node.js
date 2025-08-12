const express = require('express');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

// File paths
const LOG_FILE = path.join(__dirname, 'log.txt');
const USERS_FILE = path.join(__dirname, 'users.json');

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false // Allow inline scripts for your HTML
}));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Max 5 attempts per IP
  message: { success: false, message: "Too many attempts. Try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// Initialize files if they don't exist
async function initializeFiles() {
  try {
    if (!fsSync.existsSync(USERS_FILE)) {
      await fs.writeFile(USERS_FILE, '[]');
      console.log('Created users.json file');
    }
    if (!fsSync.existsSync(LOG_FILE)) {
      await fs.writeFile(LOG_FILE, '');
      console.log('Created log.txt file');
    }
  } catch (error) {
    console.error('Error initializing files:', error);
  }
}

// Utility functions
async function logActivity(message) {
  try {
    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] ${message}\n`;
    await fs.appendFile(LOG_FILE, logEntry);
  } catch (error) {
    console.error('Error writing to log:', error);
  }
}

async function readUsers() {
  try {
    const data = await fs.readFile(USERS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading users:', error);
    return [];
  }
}

async function writeUsers(users) {
  try {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
  } catch (error) {
    console.error('Error writing users:', error);
    throw error;
  }
}

function validateInput(username, password) {
  const errors = [];
  
  if (!username || typeof username !== 'string') {
    errors.push('Username is required');
  } else if (username.length < 3 || username.length > 20) {
    errors.push('Username must be 3-20 characters long');
  } else if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
    errors.push('Username can only contain letters, numbers, underscores, and hyphens');
  }
  
  if (!password || typeof password !== 'string') {
    errors.push('Password is required');
  } else if (password.length < 6) {
    errors.push('Password must be at least 6 characters long');
  } else if (password.length > 100) {
    errors.push('Password is too long');
  }
  
  return errors;
}

function getClientInfo(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
             req.socket.remoteAddress || 
             'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  return { ip, userAgent };
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Dashboard route (protected)
app.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/');
  }
  
      res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Dashboard</title>
      <style>
        body { 
          font-family: Arial, sans-serif; 
          padding: 20px; 
          background: linear-gradient(135deg, #ff9a56 0%, #ff6b35 100%);
          color: white;
          min-height: 100vh;
        }
        .container { 
          max-width: 600px; 
          margin: 0 auto; 
          background: rgba(255, 255, 255, 0.1);
          backdrop-filter: blur(20px);
          border-radius: 20px;
          padding: 40px;
          box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }
        h1 { text-align: center; margin-bottom: 30px; }
        .logout-btn { 
          background: linear-gradient(135deg, #ff4757, #ff3742); 
          color: white; 
          padding: 12px 24px; 
          border: none; 
          border-radius: 12px; 
          cursor: pointer; 
          font-weight: 600;
          transition: all 0.3s ease;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }
        .logout-btn:hover {
          transform: translateY(-2px);
          box-shadow: 0 10px 25px rgba(255, 71, 87, 0.4);
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Welcome to Dashboard</h1>
        <p>Hello, ${req.session.username}!</p>
        <p>You are successfully logged in.</p>
        <button class="logout-btn" onclick="fetch('/logout', {method: 'POST'}).then(() => window.location.href = '/')">Logout</button>
      </div>
    </body>
    </html>
  `);
});

// SIGNUP endpoint
app.post('/signup', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    const { ip, userAgent } = getClientInfo(req);
    
    // Validate input
    const errors = validateInput(username, password);
    if (errors.length > 0) {
      await logActivity(`SIGNUP_FAILED: Invalid input from ${ip} - ${errors.join(', ')}`);
      return res.json({ success: false, message: errors[0] });
    }
    
    // Check if username exists
    const users = await readUsers();
    const existingUser = users.find(user => user.username.toLowerCase() === username.toLowerCase());
    
    if (existingUser) {
      await logActivity(`SIGNUP_FAILED: Username '${username}' already exists - IP: ${ip}`);
      return res.json({ success: false, message: "Username already exists!" });
    }
    
    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Create new user
    const newUser = {
      id: Date.now(),
      username: username,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      lastLogin: null
    };
    
    users.push(newUser);
    await writeUsers(users);
    
    await logActivity(`SIGNUP_SUCCESS: User '${username}' created - IP: ${ip}, UserAgent: ${userAgent}`);
    
    res.json({ 
      success: true, 
      message: "Account created successfully! You can now sign in." 
    });
    
  } catch (error) {
    console.error('Signup error:', error);
    await logActivity(`SIGNUP_ERROR: ${error.message} - IP: ${getClientInfo(req).ip}`);
    res.status(500).json({ 
      success: false, 
      message: "Server error. Please try again later." 
    });
  }
});

// LOGIN endpoint
app.post('/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    const { ip, userAgent } = getClientInfo(req);
    
    // Validate input
    const errors = validateInput(username, password);
    if (errors.length > 0) {
      await logActivity(`LOGIN_FAILED: Invalid input from ${ip} - ${errors.join(', ')}`);
      return res.json({ success: false, message: "Invalid username or password" });
    }
    
    // Find user
    const users = await readUsers();
    const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
    
    if (!user) {
      await logActivity(`LOGIN_FAILED: Username '${username}' not found - IP: ${ip}`);
      return res.json({ success: false, message: "Invalid username or password" });
    }
    
    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if (!passwordMatch) {
      await logActivity(`LOGIN_FAILED: Wrong password for '${username}' - IP: ${ip}`);
      return res.json({ success: false, message: "Invalid username or password" });
    }
    
    // Update last login
    user.lastLogin = new Date().toISOString();
    await writeUsers(users);
    
    // Create session
    req.session.userId = user.id;
    req.session.username = user.username;
    
    await logActivity(`LOGIN_SUCCESS: User '${username}' logged in - IP: ${ip}, UserAgent: ${userAgent}`);
    
    res.json({ 
      success: true, 
      message: "Login successful!",
      redirectUrl: "/dashboard"
    });
    
  } catch (error) {
    console.error('Login error:', error);
    await logActivity(`LOGIN_ERROR: ${error.message} - IP: ${getClientInfo(req).ip}`);
    res.status(500).json({ 
      success: false, 
      message: "Server error. Please try again later." 
    });
  }
});

// LOGOUT endpoint
app.post('/logout', (req, res) => {
  if (req.session.userId) {
    const { ip } = getClientInfo(req);
    logActivity(`LOGOUT: User '${req.session.username}' logged out - IP: ${ip}`);
    
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destroy error:', err);
      }
      res.json({ success: true, message: "Logged out successfully" });
    });
  } else {
    res.json({ success: false, message: "Not logged in" });
  }
});

// Admin endpoint to view logs (basic protection)
app.get('/admin/logs', async (req, res) => {
  try {
    // Simple password protection (use proper auth in production)
    const auth = req.headers.authorization;
    if (!auth || auth !== 'Bearer admin123') {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const logs = await fs.readFile(LOG_FILE, 'utf-8');
    res.set('Content-Type', 'text/plain');
    res.send(logs);
  } catch (error) {
    res.status(500).json({ error: 'Could not read logs' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    success: false, 
    message: 'Internal server error' 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    success: false, 
    message: 'Endpoint not found' 
  });
});

// Start server
async function startServer() {
  await initializeFiles();
  
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    logActivity('SERVER_START: Authentication server started');
  });
}

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nReceived SIGINT. Shutting down gracefully...');
  logActivity('SERVER_STOP: Authentication server shutting down');
  process.exit(0);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  logActivity(`UNCAUGHT_EXCEPTION: ${error.message}`);
  process.exit(1);
});

startServer().catch(console.error);
