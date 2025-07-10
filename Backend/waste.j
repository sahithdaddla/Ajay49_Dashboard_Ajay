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
const WebSocket = require('ws');
const { v4: uuidv4 } = require('uuid');

if (fs.existsSync(path.join(__dirname, 'server.env'))) {
  dotenv.config({ path: path.join(__dirname, 'server.env') });
} else {
  dotenv.config();
}

const app = express();

const uploadDir = './Uploads/';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

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

const allowedOrigins = [
  'http://44.223.23.145:8012',
  'http://44.223.23.145:8013',
  'http://44.223.23.145:8057',
  'http://44.223.23.145:8010',
  'http://44.223.23.145:3404',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:5502',
  'http://localhost:8012',
  'http://localhost:8013',
  'http://localhost:8057',
  'http://localhost:8010',
  process.env.FRONTEND_URL || 'http://44.223.23.145:3404',
];

app.use(cors({
  origin: (origin, callback) => {
    logger.debug(`CORS request from: ${origin}`);
    if (!origin || allowedOrigins.includes(origin) || origin === 'null') {
      callback(null, true);
    } else {
      logger.warn(`CORS blocked: ${origin}`);
      callback(new Error(`CORS policy: Origin ${origin} not allowed`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use('/uploads', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
}, express.static(path.join(__dirname, 'Uploads')));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  const start = Date.now();
  const { method, originalUrl, ip } = req;

  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info(`${method} ${originalUrl} ${res.statusCode} ${duration}ms - ${ip}`);

    if (originalUrl.includes('/auth') || originalUrl.includes('/login') || originalUrl.includes('/logout')) {
      logger.debug(`Auth Request: ${method} ${originalUrl}`, {
        headers: req.headers,
        body: method === 'POST' ? req.body : null
      });
    }
  });

  next();
});

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'postgres-ajay',
  database: process.env.DB_NAME || 'new_employee_db',
  password: process.env.DB_PASSWORD || 'admin123',
  port: process.env.DB_PORT || 5432,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 20
});

pool.on('connect', (client) => {
  logger.debug('Database client connected');
});

pool.on('error', (err) => {
  logger.error('Database pool error:', err);
});

const JWT_SECRET = process.env.JWT_SECRET || 'Abderoiouwi@12342';
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';
const verifyToken = (req, res, next) => {
  const token = req.cookies.accessToken || req.headers.authorization?.split(' ')[1];

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
  limits: { fileSize: 5 * 1024 * 1024 }
});

const WS_PORT = 3939;
const wss = new WebSocket.Server({ port: WS_PORT });
const activeClients = new Map();

wss.on('connection', (ws) => {
  const clientId = uuidv4();
  logger.info(`New WebSocket client connected: ${clientId}`);
  activeClients.set(clientId, ws);

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'login') {
        logger.info(`Received login data from client ${clientId}`);
        
        const empDetails = {
          type: 'emp_details',
          data: {
            name: data.name,
            email: data.email,
            emp_id: data.emp_id
          }
        };
        
        activeClients.forEach((client, id) => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(empDetails));
            logger.debug(`Sent employee details to client ${id}`);
          }
        });
      }
    } catch (error) {
      logger.error('Error processing WebSocket message:', error);
    }
  });

  ws.on('close', () => {
    logger.info(`WebSocket client disconnected: ${clientId}`);
    activeClients.delete(clientId);
  });

  ws.on('error', (error) => {
    logger.error(`WebSocket error for client ${clientId}:`, error);
  });
});

logger.info(`WebSocket server running on ws://44.223.23.145:${WS_PORT}`);

async function initializeDatabase() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS user_accounts (
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
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS auth_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES user_accounts(id) ON DELETE CASCADE,
        token TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS personnel (
        emp_id VARCHAR(50) PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        job_role VARCHAR(100),
        location VARCHAR(100),
        department VARCHAR(100),
        hire_date DATE,
        phone VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    const check = await client.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_name = 'personnel' AND column_name = 'emp_id'
    `);

    if (check.rows.length === 0) {
      throw new Error('Failed to create emp_id column in personnel table');
    }

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_email ON user_accounts(email);
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON auth_sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON auth_sessions(token);
      CREATE INDEX IF NOT EXISTS idx_personnel_email ON personnel(email);
    `);

    await client.query('COMMIT');
    logger.info('Database schema initialized successfully');
  } catch (err) {
    await client.query('ROLLBACK');
    logger.error('Database initialization failed:', err);
    throw err;
  } finally {
    client.release();
  }
}

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

app.get('/api/health', async (req, res) => {
  try {
    const dbCheck = await pool.query('SELECT 1');
    const uptime = process.uptime();

    const tableCheck = await pool.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_name = 'personnel'
    `);

    const hasEmpId = tableCheck.rows.some(row => row.column_name === 'emp_id');

    res.json({
      status: hasEmpId ? 'healthy' : 'degraded',
      db: dbCheck ? 'connected' : 'disconnected',
      tables: tableCheck.rows,
      uptime: `${Math.floor(uptime / 60)} minutes`,
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      websocket_clients: activeClients.size
    });
  } catch (err) {
    logger.error('Health check failed:', err);
    res.status(503).json({
      status: 'unhealthy',
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

app.post('/check-email-data', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const result = await pool.query('SELECT id FROM user_accounts WHERE email = $1', [email]);
    res.json({ exists: result.rows.length > 0 });
  } catch (err) {
    logger.error('Check email error:', err);
    res.status(500).json({ error: 'Error checking email availability' });
  }
});

app.post('/api/signup', upload.single('profileImage'), async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const emailRegex = /^[a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*@(gmail\.com|outlook\.com)$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: 'Only gmail.com or outlook.com domains allowed' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  try {
    const userExists = await pool.query(
      'SELECT id FROM user_accounts WHERE email = $1 OR username = $2',
      [email, username]
    );

    if (userExists.rows.length > 0) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const profileImage = req.file ? `/uploads/${req.file.filename}` : null;

    const result = await pool.query(
      `INSERT INTO user_accounts
       (username, email, password, profile_image)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username, email, profile_image, created_at`,
      [username, email, hashedPassword, profileImage]
    );

    const verificationToken = jwt.sign(
      { userId: result.rows[0].id, email: result.rows[0].email },
      JWT_SECRET,
      { expiresIn: '1d' }
    );

    logger.debug(`Verification token generated for ${email}`);

    res.status(201).json({
      message: 'User created successfully.',
      user: result.rows[0]
    });
  } catch (err) {
    logger.error('Signup error:', err);

    if (req.file) {
      fs.unlink(req.file.path, () => {});
    }

    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const result = await pool.query(
      'SELECT id, username, email, password, profile_image FROM user_accounts WHERE email = $1',
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
      'INSERT INTO auth_sessions (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.id, refreshToken, new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)]
    );

    logger.debug(`User ${email} logged in successfully`);

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    const { password: _, ...userData } = user;

    let personnelData = null;
    try {
      const personnelResult = await pool.query(
        'SELECT emp_id, name, email, job_role, location, department, hire_date, phone FROM personnel WHERE email = $1',
        [email]
      );
      personnelData = personnelResult.rows.length > 0 ? personnelResult.rows[0] : null;
    } catch (personnelErr) {
      logger.warn('Personnel data fetch failed, proceeding without:', personnelErr.message);
      personnelData = null;
    }

    res.json({
      message: 'Login successful',
      user: userData,
      personnel: personnelData,
      accessToken,
      refreshToken
    });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

app.get('/api/personnel', verifyToken, async (req, res) => {
  try {
    const { email } = req.user;
    const result = await pool.query(
      'SELECT emp_id, name, email, job_role, location, department, hire_date, phone FROM personnel WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Personnel details not found' });
    }

    res.json({
      message: 'Personnel details fetched successfully',
      personnel: result.rows[0]
    });
  } catch (err) {
    logger.error('Personnel fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch personnel details' });
  }
});

app.get('/api/profile', verifyToken, async (req, res) => {
  try {
    const { userId } = req.user;

    const result = await pool.query(
      'SELECT id, username, email, profile_image FROM user_accounts WHERE id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
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

app.post('/api/logout', verifyToken, async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    await pool.query('DELETE FROM auth_sessions WHERE token = $1', [refreshToken]);

    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');

    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    logger.error('Logout error:', err);
    res.status(500).json({ error: 'Logout failed' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const result = await pool.query(
      'SELECT id FROM user_accounts WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      logger.warn(`Password reset attempt for non-existent email: ${email}`);
      return res.status(404).json({ error: 'Email not found' });
    }

    const resetToken = jwt.sign(
      { userId: result.rows[0].id, email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    await pool.query(
      'UPDATE user_accounts SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3',
      [resetToken, new Date(Date.now() + 60 * 60 * 1000), email]
    );

    logger.debug(`Password reset token generated for ${email}`);

    res.json({ message: 'Password reset link sent to your email.' });
  } catch (err) {
    logger.error('Forgot password error:', err);
    res.status(500).json({ error: 'Failed to process request. Please try again.' });
  }
});

app.post('/api/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token is required' });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    const session = await pool.query(
      'SELECT * FROM auth_sessions WHERE token = $1 AND expires_at > NOW()',
      [refreshToken]
    );

    if (session.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    const user = await pool.query(
      'SELECT id, email FROM user_accounts WHERE id = $1',
      [decoded.userId]
    );

    if (user.rows.length === 0) {
      return res.status(401).json({ error: 'User not found' });
    }

    const newAccessToken = jwt.sign(
      { userId: user.rows[0].id, email: user.rows[0].email },
      JWT_SECRET,
      { expiresIn: ACCESS_TOKEN_EXPIRY }
    );

    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });

    res.json({
      message: 'Token refreshed successfully',
      accessToken: newAccessToken
    });
  } catch (err) {
    logger.error('Token refresh error:', err);
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await pool.query(
      'SELECT * FROM user_accounts WHERE reset_token = $1 AND reset_token_expiry > NOW() AND id = $2',
      [token, decoded.userId]
    );

    if (user.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await pool.query(
      'UPDATE user_accounts SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE id = $2',
      [hashedPassword, decoded.userId]
    );

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    logger.error('Password reset error:', err);
    res.status(401).json({ error: 'Invalid or expired token' });
  }
});

app.use((err, req, res, next) => {
  logger.error('Server error:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method
  });

  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: 'File upload error: ' + err.message });
  }

  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3404;
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info(`HTTP server running on port ${PORT}`);
  logger.info(`WebSocket server running on port ${WS_PORT}`);
  logger.info(`Allowed CORS origins: ${allowedOrigins.join(', ')}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down gracefully...');
  
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.close();
    }
  });
  wss.close();
  
  server.close(() => {
    logger.info('HTTP server closed');
    
    pool.end(() => {
      logger.info('Database pool closed');
      process.exit(0);
    });
  });
});

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
