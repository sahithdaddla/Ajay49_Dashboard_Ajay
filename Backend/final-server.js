const express = require('express');
const { Pool } = require('pg');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const retry = require('async-retry');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const winston = require('winston');
const { combine, timestamp, printf, colorize } = winston.format;

// Load environment variables with explicit path for Docker
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
  return `${timestamp} [${level}] ${stack || message}`;
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
        printf(info => `${info.timestamp} [${info.level}] ${info.message}`)
      )
    }),
    new winston.transports.File({ 
      filename: path.join(logDir, 'combined.log'),
      level: 'info'
    }),
    new winston.transports.File({ 
      filename: path.join(logDir, 'errors.log'),
      level: 'error'
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'auth.log'),
      level: 'debug',
      format: combine(
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        printf(({ message }) => message)
      )
    })
  ]
});

// Environment logging
logger.info('Environment Configuration:', {
  DB_USER: process.env.DB_USER,
  DB_HOST: process.env.DB_HOST,
  DB_NAME: process.env.DB_NAME,
  DB_PASSWORD: '****',
  DB_PORT: process.env.DB_PORT,
  FRONTEND_URL: process.env.FRONTEND_URL,
  JWT_SECRET: process.env.JWT_SECRET ? '****' : 'Not set',
  PORT: process.env.PORT,
  NODE_ENV: process.env.NODE_ENV
});

// Server Configuration
const allowedOrigins = [
  'http://44.223.23.145:8012',
  'http://44.223.23.145:8013',
  'http://44.223.23.145:8010',
  'http://44.223.23.145:3404',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:5502',
  'http://localhost:8012',
  'http://localhost:8013',
  'http://localhost:8010',
  process.env.FRONTEND_URL || 'http://44.223.23.145:3404',
];

// Enhanced CORS setup
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin) || 
        origin.includes('localhost') || 
        origin.includes('127.0.0.1')) {
      callback(null, true);
    } else {
      logger.warn(`CORS blocked: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Serve uploads with proper CORS headers
app.use('/uploads', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
}, express.static(path.join(__dirname, 'Uploads')));

// Serve frontend static files
const frontendPath = path.join(__dirname, '../frontend');
app.use(express.static(frontendPath));

app.get('/login', (req, res) => {
  res.sendFile(path.join(frontendPath, 'login/index.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(frontendPath, 'signup/index.html'));
});

app.get('/forgot', (req, res) => {
  res.sendFile(path.join(frontendPath, 'forgot/index.html'));
});

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  const { method, originalUrl, ip } = req;

  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info(`${method} ${originalUrl} ${res.statusCode} ${duration}ms - ${ip}`);
    
    if (originalUrl.includes('/auth') || originalUrl.includes('/login') || 
        originalUrl.includes('/logout') || originalUrl.includes('/signup') || 
        originalUrl.includes('/forgot')) {
      logger.debug(`Auth Request: ${method} ${originalUrl}`, {
        headers: req.headers,
        body: method === 'POST' ? req.body : null
      });
    }
  });

  next();
});

// Database Configuration
const poolConfig = {
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'postgres-ajay',
  database: process.env.DB_NAME || 'new_employee_db',
  password: process.env.DB_PASSWORD || 'admin123',
  port: process.env.DB_PORT || 5432,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20
};

const pool = new Pool(poolConfig);

pool.on('connect', (client) => {
  logger.debug('Database client connected');
  client.query('SET statement_timeout = 30000');
});

pool.on('error', (err) => {
  logger.error('Unexpected error on idle client', err);
  process.exit(-1);
});

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'Abderoiouwi@12342';
const ACCESS_TOKEN_EXPIRY = '58m';
const REFRESH_TOKEN_EXPIRY = '7d';

const verifyToken = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    logger.warn('Access denied: No token provided');
    return res.status(401).json({ error: 'Access denied, no token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    logger.debug(`Authenticated request from: ${decoded.email}`);
    next();
  } catch (err) {
    logger.error('Token verification failed:', err.message);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
};

// File Upload Configuration
const storage = multer.diskStorage({
  destination: './Uploads/',
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG and GIF are allowed.'), false);
  }
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Database Initialization
async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const tables = await client.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    
    const tableNames = tables.rows.map(row => row.table_name);
    
    if (!tableNames.includes('users')) {
      await client.query(`
        CREATE TABLE users (
          id SERIAL PRIMARY KEY,
          username VARCHAR(50) UNIQUE NOT NULL,
          email VARCHAR(100) UNIQUE NOT NULL,
          password TEXT NOT NULL,
          profile_image TEXT,
          is_verified BOOLEAN DEFAULT FALSE,
          reset_token TEXT,
          reset_token_expiry TIMESTAMP,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);
    }
    
    if (!tableNames.includes('sessions')) {
      await client.query(`
        CREATE TABLE sessions (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
          token TEXT NOT NULL,
          ip_address TEXT,
          user_agent TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          expires_at TIMESTAMP NOT NULL
        )
      `);
    }
    
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
    `);
    
    await client.query('COMMIT');
    logger.info('Database schema verified/initialized successfully');
  } catch (err) {
    await client.query('ROLLBACK');
    logger.error('Database initialization failed:', err);
    throw err;
  } finally {
    client.release();
  }
}

// Database Connection with Retry
async function connectWithRetry() {
  return retry(
    async () => {
      const client = await pool.connect();
      try {
        await client.query('SELECT 1');
        logger.info('Successfully connected to PostgreSQL');
        await initializeDatabase();
      } finally {
        client.release();
      }
    },
    {
      retries: 10,
      factor: 2,
      minTimeout: 1000,
      maxTimeout: 10000,
      onRetry: (err, attempt) => {
        logger.warn(`Retry attempt ${attempt}: ${err.message}`);
        if (attempt === 10) {
          logger.error('Maximum retry attempts reached. Exiting...');
          process.exit(1);
        }
      }
    }
  );
}

connectWithRetry().catch(err => {
  logger.error('Fatal database connection error:', err);
  process.exit(1);
});

// API Endpoints

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Astrolite Tech Solutions API',
    version: '1.0.0',
    endpoints: {
      health: '/api/health',
      signup: '/api/signup',
      login: '/api/login',
      profile: '/api/profile'
    }
  });
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    const dbCheck = await pool.query('SELECT version()');
    const uptime = process.uptime();
    
    res.json({ 
      status: 'healthy',
      db: {
        connected: true,
        version: dbCheck.rows[0].version.split(' ')[1]
      },
      uptime: `${Math.floor(uptime / 60)} minutes`,
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      memory: process.memoryUsage()
    });
  } catch (err) {
    logger.error('Health check failed:', err);
    res.status(503).json({ 
      status: 'unhealthy',
      error: err.message,
      db: { connected: false },
      timestamp: new Date().toISOString()
    });
  }
});

// Signup endpoint
app.post('/api/signup', upload.single('profileImage'), async (req, res) => {
  const { username, email, password } = req.body;
  
  if (!username || !email || !password) {
    logger.warn('Signup attempt with missing fields');
    return res.status(400).json({ error: 'Missing required fields' });
  }
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    logger.warn(`Invalid email format: ${email}`);
    return res.status(400).json({ error: 'Invalid email format' });
  }
  
  if (password.length < 8) {
    logger.warn('Password too short');
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  try {
    const userExists = await pool.query(
      'SELECT id FROM users WHERE email = $1 OR username = $2', 
      [email, username]
    );
    
    if (userExists.rows.length > 0) {
      logger.warn(`Signup attempt with existing email/username: ${email}/${username}`);
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const profileImage = req.file ? `/uploads/${req.file.filename}` : null;
    
    const result = await pool.query(
      `INSERT INTO users 
       (username, email, password, profile_image) 
       VALUES ($1, $2, $3, $4) 
       RETURNING id, username, email, profile_image, created_at`,
      [username, email, hashedPassword, profileImage]
    );

    const verificationToken = jwt.sign(
      { userId: result.rows[0].id, email }, 
      JWT_SECRET, 
      { expiresIn: '1d' }
    );

    logger.debug(`Verification token generated for ${email}`);
    
    res.status(201).json({ 
      message: 'User created successfully.',
      user: result.rows[0],
      verificationToken
    });
  } catch (err) {
    logger.error('Signup error:', err);
    
    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }
    
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    logger.warn('Login attempt with missing credentials');
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const result = await pool.query(
      'SELECT id, username, email, password, profile_image FROM users WHERE email = $1', 
      [email]
    );
    
    if (result.rows.length === 0) {
      logger.warn(`Login attempt for non-existent email: ${email}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      logger.warn(`Invalid password attempt for email: ${email}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const accessToken = jwt.sign(
      { userId: user.id, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: ACCESS_TOKEN_EXPIRY }
    );
    
    const refreshToken = jwt.sign(
      { userId: user.id }, 
      JWT_SECRET, 
      { expiresIn: REFRESH_TOKEN_EXPIRY }
    );

    await pool.query(
      'INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.id, refreshToken, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)]
    );

    logger.debug(`User ${email} logged in successfully`);

    res.cookie('token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 58 * 60 * 1000 // 58 minutes
    });
    
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    const { password: _, ...userData } = user;
    
    res.json({
      message: 'Login successful',
      user: userData,
      accessToken,
      refreshToken
    });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

// Forgot password endpoint
app.post('/api/forgot', async (req, res) => {
  const { email, newPassword, confirmNewPassword } = req.body;
  
  if (!email || !newPassword || !confirmNewPassword) {
    logger.warn('Forgot password attempt with missing fields');
    return res.status(400).json({ error: 'Email, new password, and confirm password are required' });
  }

  if (newPassword !== confirmNewPassword) {
    logger.warn('Forgot password attempt with mismatched passwords');
    return res.status(400).json({ error: 'Passwords do not match' });
  }

  const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
  if (!passwordRegex.test(newPassword)) {
    logger.warn('Forgot password attempt with invalid password format');
    return res.status(400).json({ error: 'Password must be at least 8 characters and include uppercase, number, and symbol' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      logger.warn(`Forgot password attempt for non-existent email: ${email}`);
      return res.status(404).json({ error: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await pool.query(
      'UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE email = $2',
      [hashedPassword, email]
    );

    logger.debug(`Password reset successful for ${email}`);
    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    logger.error('Forgot password error:', err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Email check endpoint
app.post('/check-email-data', async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    logger.warn('Email check attempt with missing email');
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    res.json({ exists: result.rows.length > 0 });
  } catch (err) {
    logger.error('Email check error:', err);
    res.status(500).json({ error: 'Failed to check email' });
  }
});

// Profile endpoint
app.get('/api/profile', verifyToken, async (req, res) => {
  try {
    const { userId } = req.user;

    const result = await pool.query(
      'SELECT id, username, email, profile_image FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      logger.warn(`Profile fetch attempt for non-existent user: ${userId}`);
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    
    const profileData = {
      ...user,
      profile_image: user.profile_image 
        ? `${req.protocol}://${req.get('host')}${user.profile_image}`
        : null
    };

    res.json({
      message: 'Profile fetched successfully',
      profile: profileData
    });
  } catch (err) {
    logger.error('Profile fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Logout endpoint
app.post('/api/logout', verifyToken, async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    await pool.query('DELETE FROM sessions WHERE token = $1', [refreshToken]);

    res.clearCookie('token');
    res.clearCookie('refreshToken');

    logger.debug('User logged out successfully');
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    logger.error('Logout error:', err);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  
  logger.error('Error:', {
    statusCode,
    message,
    path: req.path,
    method: req.method,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });

  res.status(statusCode).json({
    error: {
      message,
      ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    }
  });
});

// Server startup
const PORT = process.env.PORT || 3404;
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Server running on port ${PORT}`);
  logger.info(`Allowed CORS origins: ${allowedOrigins.join(', ')}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.info(`Database host: ${poolConfig.host}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    pool.end(() => {
      logger.info('Database pool closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    pool.end(() => {
      logger.info('Database pool closed');
      process.exit(0);
    });
  });
});

// Log rotation
function rotateLogs() {
  const files = fs.readdirSync(logDir);
  const dateStr = new Date().toISOString().split('T')[0];
  
  files.forEach(file => {
    if (file.endsWith('.log') && !file.includes(dateStr)) {
      const oldPath = path.join(logDir, file);
      const newPath = `${oldPath}-${dateStr}`;
      fs.renameSync(oldPath, newPath);
    }
  });
}

setInterval(() => {
  const now = new Date();
  if (now.getHours() === 0 && now.getMinutes() === 0) {
    rotateLogs();
  }
}, 60 * 1000);
