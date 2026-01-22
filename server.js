require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

/* -------------------- DATABASE -------------------- */
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'YOUR_DB_PASSWORD',
  database: 'user_info'
});

/* -------------------- STEP 6: AUTH MIDDLEWARE -------------------- */
function authenticate(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized: token missing' });
  }

  const token = header.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ message: 'Forbidden: invalid or expired token' });
  }
}

/* -------------------- STEP 7: RBAC -------------------- */
function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied: role restriction' });
    }
    next();
  };
}

/* -------------------- STEP 8: ABAC (DEPARTMENT) -------------------- */
function departmentOnly(dept) {
  return (req, res, next) => {
    if (req.user.department !== dept) {
      return res.status(403).json({ message: 'Access denied: department restriction' });
    }
    next();
  };
}

/* -------------------- STEP 9: OWNERSHIP -------------------- */
function ownershipCheck(req, res, next) {
  const requestedId = Number(req.params.id);

  if (req.user.role === 'admin') {
    return next();
  }

  if (req.user.id !== requestedId) {
    return res.status(403).json({ message: 'Access denied: not resource owner' });
  }

  next();
}

/* -------------------- STEP 10: CUSTOM RULES -------------------- */
function workingHoursOnly(req, res, next) {
  const hour = new Date().getHours();
  if (hour < 8 || hour > 18) {
    return res.status(403).json({ message: 'Access denied: outside working hours' });
  }
  next();
}

/* -------------------- STEP 4.3: REGISTER -------------------- */
app.post('/register', async (req, res) => {
  const { username, password, role, department } = req.body;

  if (!username || !password || !role || !department) {
    return res.status(400).json({ message: 'Missing fields' });
  }

  try {
    const [existing] = await pool.query(
      'SELECT id FROM users WHERE username = ?',
      [username]
    );

    if (existing.length > 0) {
      return res.status(409).json({ message: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await pool.query(
      'INSERT INTO users (username, password, role, department) VALUES (?, ?, ?, ?)',
      [username, hashedPassword, role, department]
    );

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

/* -------------------- STEP 5: LOGIN (JWT) -------------------- */
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      {
        id: user.id,
        role: user.role,
        department: user.department
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch {
    res.status(500).json({ message: 'Server error' });
  }
});

/* -------------------- PROTECTED EXAMPLES -------------------- */

// Admin only
app.get('/admin', authenticate, authorizeRoles('admin'), (req, res) => {
  res.json({ message: 'Admin access granted' });
});

// Admin + Manager
app.get(
  '/management',
  authenticate,
  authorizeRoles('admin', 'manager'),
  (req, res) => {
    res.json({ message: 'Management access granted' });
  }
);

// Department-based
app.get(
  '/finance',
  authenticate,
  departmentOnly('finance'),
  (req, res) => {
    res.json({ message: 'Finance resource access granted' });
  }
);

// Ownership-based
app.get(
  '/users/:id',
  authenticate,
  ownershipCheck,
  (req, res) => {
    res.json({ message: 'User data access granted' });
  }
);

// Combined rules
app.get(
  '/secure',
  authenticate,
  authorizeRoles('manager'),
  departmentOnly('IT'),
  workingHoursOnly,
  (req, res) => {
    res.json({ message: 'Custom rule access granted' });
  }
);

/* -------------------- SERVER -------------------- */
app.listen(3000, () => {
  console.log('Server running on port 3000');
});
