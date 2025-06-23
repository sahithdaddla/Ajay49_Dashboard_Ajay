// Required modules
const express = require('express');
const { Pool } = require('pg');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const winston = require('winston');
const path = require('path');
const fs = require('fs');
const { combine, timestamp, printf, colorize } = winston.format;

// Load environment variables
if (fs.existsSync(path.join(__dirname, 'server.env'))) {
  dotenv.config({ path: path.join(__dirname, 'server.env') });
} else {
  dotenv.config();
}

const app = express();

// Enhanced Logging Setup
const logDir = 'logs';
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

const logFormat = printf(({ level, message, timestamp, stack }) => {
  return `${timestamp} [${level}]: ${stack || message}`;
});

const logger = winston.createLogger({
  level: 'debug',
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    logFormat
  ),
  transports: [
    new winston.transports.Console({
      format: combine(
        colorize(),
        timestamp({ format: 'HH:mm:ss' }),
        printf(info => `${info.timestamp} [${info.level}]: ${info.message}`)
      )
    }),
    new winston.transports.File({ filename: path.join(logDir, 'combined.log'), level: 'info' }),
    new winston.transports.File({ filename: path.join(logDir, 'errors.log'), level: 'error' }),
    new winston.transports.File({
      filename: path.join(logDir, 'auth.log'),
      level: 'debug',
      format: combine(timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), printf(({ message }) => message))
    })
  ]
});

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'Abderoiouwi@12342';
const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '7d';
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || '44.223.23.145';
const SECURE_COOKIES = process.env.SECURE_COOKIES === 'true';
const SAME_SITE = process.env.SAME_SITE || 'lax';

// Middleware
app.use(cors({
  origin: [
    'http://44.223.23.145:8012', // Login
    'http://44.223.23.145:8011', // Dashboard
    'http://44.223.23.145:8013', // Signup
    'http://44.223.23.145:8010'  // Forgot Password
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info(`Request: ${req.method} ${req.url} ${res.statusCode} - ${duration}ms`);
  });
  next();
});

// PostgreSQL Pool
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT
});

// JWT Middleware
const verifyToken = (req, res, next) => {
  const token = req.cookies.accessToken || req.headers.authorization?.split(' ')[1];
  if (!token) {
    logger.warn('Access denied: No token provided');
    return res.status(401).json({ error: 'Access denied, no token provided' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      logger.warn('Token expired, attempting refresh');
      return handleTokenRefresh(req, res, next);
    }
    logger.error(`Invalid token: ${err.message}`);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

async function handleTokenRefresh(req, res, next) {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    logger.warn('Refresh token required');
    return res.status(401).json({ error: 'Refresh token required' });
  }
  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    const result = await pool.query(
      'SELECT * FROM sessions WHERE token = $1 AND user_id = $2 AND expires_at > NOW()',
      [refreshToken, decoded.userId]
    );
    if (result.rows.length === 0) {
      logger.error('Invalid refresh token');
      throw new Error('Invalid refresh token');
    }
    const user = await pool.query('SELECT id, email FROM users WHERE id = $1', [decoded.userId]);
    if (!user.rows[0]) {
      logger.error('User not found for refresh token');
      throw new Error('User not found');
    }
    const newAccessToken = jwt.sign(
      { userId: user.rows[0].id, email: user.rows[0].email },
      JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_EXPIRY }
    );
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: SECURE_COOKIES,
      sameSite: SAME_SITE,
      maxAge: 15 * 60 * 1000,
      domain: COOKIE_DOMAIN,
      path: '/'
    });
    req.user = decoded;
    logger.info(`Token refreshed for user: ${user.rows[0].email}`);
    next();
  } catch (err) {
    logger.error(`Token refresh error: ${err.message}`);
    res.status(401).json({ error: 'Session expired. Please login again.' });
  }
}

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    logger.warn('Login attempt with missing credentials');
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      logger.error(`Login failed: User not found for email ${email}`);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logger.error(`Login failed: Invalid password for email ${email}`);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const accessToken = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_EXPIRY }
    );
    const refreshToken = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: REFRESH_TOKEN_EXPIRY }
    );

    await pool.query(
      'INSERT INTO sessions (user_id, token, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL \'7 days\')',
      [user.id, refreshToken, req.ip, req.get('User-Agent')]
    );

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: SECURE_COOKIES,
      sameSite: SAME_SITE,
      maxAge: 15 * 60 * 1000,
      domain: COOKIE_DOMAIN,
      path: '/'
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: SECURE_COOKIES,
      sameSite: SAME_SITE,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      domain: COOKIE_DOMAIN,
      path: '/'
    });

    logger.info(`User logged in: ${email}`);
    res.json({
      accessToken,
      user: { id: user.id, email: user.email }
    });
  } catch (err) {
    logger.error(`Login error: ${err.message}`);
    res.status(500).json({ error: 'Server error' });
  }
});

// Profile endpoint
app.get('/api/profile', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, username, profile_image FROM users WHERE id = $1', [req.user.userId]);
    const user = result.rows[0];

    if (!user) {
      logger.error(`Profile not found for user ID: ${req.user.userId}`);
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      profile: {
        id: user.id,
        email: user.email,
        username: user.username || user.email.split('@')[0],
        profile_image: user.profile_image || null
      }
    });
    logger.info(`Profile retrieved for user: ${user.email}`);
  } catch (err) {
    logger.error(`Profile error: ${err.message}`);
    res.status(500).json({ error: 'Server error' });
  }
});

// Logout endpoint
app.post('/api/logout', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (refreshToken) {
    try {
      await pool.query('DELETE FROM sessions WHERE token = $1', [refreshToken]);
      logger.info('Session deleted for refresh token');
    } catch (err) {
      logger.error(`Logout session deletion error: ${err.message}`);
    }
  }
  res.clearCookie('accessToken', { domain: COOKIE_DOMAIN, path: '/' });
  res.clearCookie('refreshToken', { domain: COOKIE_DOMAIN, path: '/' });
  logger.info('User logged out');
  res.json({ message: 'Logged out successfully' });
});

// Sample protected route
app.get('/dashboard', verifyToken, (req, res) => {
  logger.info(`Dashboard accessed by user: ${req.user.email}`);
  res.send('Welcome to the dashboard!');
});

// Environment log
logger.info('Environment Configuration:', {
  DB_USER: process.env.DB_USER,
  DB_HOST: process.env.DB_HOST,
  DB_NAME: process.env.DB_NAME,
  DB_PASSWORD: '****',
  DB_PORT: process.env.DB_PORT,
  FRONTEND_URL: process.env.FRONTEND_URL,
  JWT_SECRET: process.env.JWT_SECRET ? '****' : 'Not set',
  PORT: process.env.PORT,
  NODE_ENV: process.env.NODE_ENV,
  COOKIE_DOMAIN: COOKIE_DOMAIN,
  SECURE_COOKIES: SECURE_COOKIES,
  SAME_SITE: SAME_SITE
});

const PORT = process.env.PORT || 3404;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});
