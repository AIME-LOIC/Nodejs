require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());


const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'user_info'
});

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


function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied: role restriction' });
    }
    next();
  };
}


function departmentOnly(dept) {
  return (req, res, next) => {
    if (req.user.department !== dept) {
      return res.status(403).json({ message: 'Access denied: department restriction' });
    }
    next();
  };
}
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

function workingHoursOnly(req, res, next) {
  const hour = new Date().getHours();
  if (hour < 8 || hour > 18) {
    return res.status(403).json({ message: 'Access denied: outside working hours' });
  }
  next();
}


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
      return res.status(409).json({ message: 'User already exists' });
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


app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials ( invalid username or password )' });
    }

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({ message: 'Invalid credentials ( invalid username or password )' });
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
  }  catch (err) {
  console.error(err);
  res.status(500).json({ message: 'Server error' });
}

});



app.get('/admin', authenticate, authorizeRoles('admin'), (req, res) => {
  res.json({ message: 'Admin access granted' });
});


app.get('/management',
  authenticate,
  authorizeRoles('admin', 'manager'),
  (req, res) => {
    res.json({ message: 'Management access granted' });
  }
);


app.get(
  '/finance',
  authenticate,
  departmentOnly('finance'),
  (req, res) => {
    res.json({ message: 'Finance resource access granted' });
  }
);


app.get('/users/:id',
  authenticate,
  ownershipCheck,
  (req, res) => {
    res.json({ message: 'User data access granted' });
  }
);


app.get('/secure',
  authenticate,
  authorizeRoles('manager'),
  departmentOnly('IT'),
  workingHoursOnly,
  (req, res) => {
    res.json({ message: 'Custom rule access granted' });
  }
);


app.listen(3000, () => {
  console.log('Server running on port 3000');
});
