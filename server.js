// ============================================
// FILE STRUCTURE:
// ============================================
// backend/
// ├── server.js (main file)
// ├── config/
// │   └── db.js
// ├── middleware/
// │   └── auth.js
// ├── routes/
// │   ├── userRoutes.js
// │   ├── hospitalRoutes.js
// │   ├── pharmacyRoutes.js
// │   ├── doctorRoutes.js
// │   └── medicineRoutes.js
// ├── controllers/
// │   ├── userController.js
// │   ├── hospitalController.js
// │   ├── pharmacyController.js
// │   ├── doctorController.js
// │   └── medicineController.js
// └── package.json

// ============================================
// 1. package.json
// ============================================
/*
{
  "name": "mediconnect-backend",
  "version": "1.0.0",
  "description": "Backend for MediConnect Healthcare Platform",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "pg": "^8.11.3",
    "bcrypt": "^5.1.1",
    "jsonwebtoken": "^9.0.2",
    "dotenv": "^16.3.1",
    "cors": "^2.8.5",
    "express-validator": "^7.0.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
*/

// ============================================
// 2. .env (Create this file in root)
// ============================================
/*
PORT=5000
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_password
DB_NAME=mediconnect
JWT_SECRET=your_super_secret_jwt_key_change_this_in_production
JWT_EXPIRE=7d
NODE_ENV=development
*/

// ============================================
// 3. config/db.js - Database Configuration
// ============================================
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

pool.on('connect', () => {
  console.log('✅ Database connected successfully');
});

pool.on('error', (err) => {
  console.error('❌ Unexpected database error:', err);
  process.exit(-1);
});

module.exports = pool;

// ============================================
// 4. middleware/auth.js - Authentication Middleware
// ============================================
const jwt = require('jsonwebtoken');

const authMiddleware = (userType) => {
  return async (req, res, next) => {
    try {
      // Get token from header
      const token = req.headers.authorization?.split(' ')[1];
      
      if (!token) {
        return res.status(401).json({ 
          success: false, 
          message: 'Access denied. No token provided.' 
        });
      }

      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Check user type if specified
      if (userType && decoded.userType !== userType) {
        return res.status(403).json({ 
          success: false, 
          message: 'Access denied. Insufficient permissions.' 
        });
      }

      req.user = decoded;
      next();
    } catch (error) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid token.' 
      });
    }
  };
};

module.exports = authMiddleware;

// ============================================
// 5. controllers/userController.js - User Controller
// ============================================
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../config/db');

// Generate JWT Token
const generateToken = (id, userType) => {
  return jwt.sign({ id, userType }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRE,
  });
};

// User Registration
const registerUser = async (req, res) => {
  try {
    const { full_name, email, password, phone, address, city, state, pincode, date_of_birth, gender } = req.body;

    // Check if user exists
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    // Insert user
    const result = await pool.query(
      `INSERT INTO users (full_name, email, password_hash, phone, address, city, state, pincode, date_of_birth, gender) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING user_id, full_name, email`,
      [full_name, email, password_hash, phone, address, city, state, pincode, date_of_birth, gender]
    );

    const user = result.rows[0];
    const token = generateToken(user.user_id, 'user');

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: { user, token }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// User Login
const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check user exists
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Check password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = generateToken(user.user_id, 'user');

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          user_id: user.user_id,
          full_name: user.full_name,
          email: user.email
        },
        token
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Search Doctors
const searchDoctors = async (req, res) => {
  try {
    const { specialization, city, hospital_name } = req.query;
    
    let query = `
      SELECT d.*, h.hospital_name, h.address, h.city, h.phone as hospital_phone
      FROM doctors d
      JOIN hospitals h ON d.hospital_id = h.hospital_id
      WHERE d.is_available = true AND h.is_active = true
    `;
    const params = [];
    let paramCount = 1;

    if (specialization) {
      query += ` AND d.specialization ILIKE $${paramCount}`;
      params.push(`%${specialization}%`);
      paramCount++;
    }

    if (city) {
      query += ` AND h.city ILIKE $${paramCount}`;
      params.push(`%${city}%`);
      paramCount++;
    }

    if (hospital_name) {
      query += ` AND h.hospital_name ILIKE $${paramCount}`;
      params.push(`%${hospital_name}%`);
      paramCount++;
    }

    query += ' ORDER BY d.full_name';

    const result = await pool.query(query, params);

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

// Search Medicines
const searchMedicines = async (req, res) => {
  try {
    const { medicine_name, city, category } = req.query;
    
    let query = `
      SELECT m.*, p.pharmacy_name, p.address, p.city, p.phone as pharmacy_phone
      FROM medicines m
      JOIN pharmacies p ON m.pharmacy_id = p.pharmacy_id
      WHERE m.is_available = true AND m.stock_quantity > 0 AND p.is_active = true
    `;
    const params = [];
    let paramCount = 1;

    if (medicine_name) {
      query += ` AND (m.medicine_name ILIKE $${paramCount} OR m.generic_name ILIKE $${paramCount})`;
      params.push(`%${medicine_name}%`);
      paramCount++;
    }

    if (city) {
      query += ` AND p.city ILIKE $${paramCount}`;
      params.push(`%${city}%`);
      paramCount++;
    }

    if (category) {
      query += ` AND m.category ILIKE $${paramCount}`;
      params.push(`%${category}%`);
      paramCount++;
    }

    query += ' ORDER BY m.medicine_name';

    const result = await pool.query(query, params);

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

module.exports = {
  registerUser,
  loginUser,
  searchDoctors,
  searchMedicines
};

// ============================================
// 6. controllers/hospitalController.js
// ============================================
const hospitalRegister = async (req, res) => {
  try {
    const { hospital_name, email, password, phone, address, city, state, pincode, registration_number, hospital_type } = req.body;

    const hospitalExists = await pool.query('SELECT * FROM hospitals WHERE email = $1', [email]);
    if (hospitalExists.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Hospital already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const result = await pool.query(
      `INSERT INTO hospitals (hospital_name, email, password_hash, phone, address, city, state, pincode, registration_number, hospital_type) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING hospital_id, hospital_name, email`,
      [hospital_name, email, password_hash, phone, address, city, state, pincode, registration_number, hospital_type]
    );

    const hospital = result.rows[0];
    const token = generateToken(hospital.hospital_id, 'hospital');

    res.status(201).json({
      success: true,
      message: 'Hospital registered successfully',
      data: { hospital, token }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const hospitalLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query('SELECT * FROM hospitals WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const hospital = result.rows[0];
    const isMatch = await bcrypt.compare(password, hospital.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = generateToken(hospital.hospital_id, 'hospital');

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        hospital: {
          hospital_id: hospital.hospital_id,
          hospital_name: hospital.hospital_name,
          email: hospital.email
        },
        token
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

module.exports = {
  hospitalRegister,
  hospitalLogin
};

// ============================================
// 7. controllers/pharmacyController.js
// ============================================
const pharmacyRegister = async (req, res) => {
  try {
    const { pharmacy_name, email, password, phone, address, city, state, pincode, license_number, operating_hours } = req.body;

    const pharmacyExists = await pool.query('SELECT * FROM pharmacies WHERE email = $1', [email]);
    if (pharmacyExists.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Pharmacy already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const result = await pool.query(
      `INSERT INTO pharmacies (pharmacy_name, email, password_hash, phone, address, city, state, pincode, license_number, operating_hours) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING pharmacy_id, pharmacy_name, email`,
      [pharmacy_name, email, password_hash, phone, address, city, state, pincode, license_number, operating_hours]
    );

    const pharmacy = result.rows[0];
    const token = generateToken(pharmacy.pharmacy_id, 'pharmacy');

    res.status(201).json({
      success: true,
      message: 'Pharmacy registered successfully',
      data: { pharmacy, token }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const pharmacyLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query('SELECT * FROM pharmacies WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const pharmacy = result.rows[0];
    const isMatch = await bcrypt.compare(password, pharmacy.password_hash);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = generateToken(pharmacy.pharmacy_id, 'pharmacy');

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        pharmacy: {
          pharmacy_id: pharmacy.pharmacy_id,
          pharmacy_name: pharmacy.pharmacy_name,
          email: pharmacy.email
        },
        token
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

module.exports = {
  pharmacyRegister,
  pharmacyLogin
};

// ============================================
// 8. controllers/doctorController.js
// ============================================
const addDoctor = async (req, res) => {
  try {
    const { full_name, specialization, qualification, experience_years, phone, email, consultation_fee, 
            available_days, available_time_from, available_time_to, room_number } = req.body;
    
    const hospital_id = req.user.id; // From auth middleware

    const result = await pool.query(
      `INSERT INTO doctors (hospital_id, full_name, specialization, qualification, experience_years, phone, email, 
       consultation_fee, available_days, available_time_from, available_time_to, room_number) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [hospital_id, full_name, specialization, qualification, experience_years, phone, email, 
       consultation_fee, available_days, available_time_from, available_time_to, room_number]
    );

    res.status(201).json({
      success: true,
      message: 'Doctor added successfully',
      data: result.rows[0]
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const getDoctorsByHospital = async (req, res) => {
  try {
    const hospital_id = req.user.id;

    const result = await pool.query(
      'SELECT * FROM doctors WHERE hospital_id = $1 ORDER BY full_name',
      [hospital_id]
    );

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const updateDoctor = async (req, res) => {
  try {
    const { doctor_id } = req.params;
    const hospital_id = req.user.id;
    const updates = req.body;

    // Check if doctor belongs to this hospital
    const checkDoctor = await pool.query(
      'SELECT * FROM doctors WHERE doctor_id = $1 AND hospital_id = $2',
      [doctor_id, hospital_id]
    );

    if (checkDoctor.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Doctor not found' });
    }

    // Build dynamic update query
    const fields = Object.keys(updates);
    const values = Object.values(updates);
    const setClause = fields.map((field, index) => `${field} = $${index + 1}`).join(', ');

    const result = await pool.query(
      `UPDATE doctors SET ${setClause} WHERE doctor_id = $${fields.length + 1} AND hospital_id = $${fields.length + 2} RETURNING *`,
      [...values, doctor_id, hospital_id]
    );

    res.json({
      success: true,
      message: 'Doctor updated successfully',
      data: result.rows[0]
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const deleteDoctor = async (req, res) => {
  try {
    const { doctor_id } = req.params;
    const hospital_id = req.user.id;

    const result = await pool.query(
      'DELETE FROM doctors WHERE doctor_id = $1 AND hospital_id = $2 RETURNING *',
      [doctor_id, hospital_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Doctor not found' });
    }

    res.json({
      success: true,
      message: 'Doctor deleted successfully'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

module.exports = {
  addDoctor,
  getDoctorsByHospital,
  updateDoctor,
  deleteDoctor
};

// ============================================
// 9. controllers/medicineController.js
// ============================================
const addMedicine = async (req, res) => {
  try {
    const { medicine_name, generic_name, manufacturer, category, dosage_form, strength, price, 
            stock_quantity, expiry_date, requires_prescription, description } = req.body;
    
    const pharmacy_id = req.user.id;

    const result = await pool.query(
      `INSERT INTO medicines (pharmacy_id, medicine_name, generic_name, manufacturer, category, dosage_form, 
       strength, price, stock_quantity, expiry_date, requires_prescription, description) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [pharmacy_id, medicine_name, generic_name, manufacturer, category, dosage_form, 
       strength, price, stock_quantity, expiry_date, requires_prescription, description]
    );

    res.status(201).json({
      success: true,
      message: 'Medicine added successfully',
      data: result.rows[0]
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const getMedicinesByPharmacy = async (req, res) => {
  try {
    const pharmacy_id = req.user.id;

    const result = await pool.query(
      'SELECT * FROM medicines WHERE pharmacy_id = $1 ORDER BY medicine_name',
      [pharmacy_id]
    );

    res.json({
      success: true,
      count: result.rows.length,
      data: result.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const updateMedicine = async (req, res) => {
  try {
    const { medicine_id } = req.params;
    const pharmacy_id = req.user.id;
    const updates = req.body;

    const checkMedicine = await pool.query(
      'SELECT * FROM medicines WHERE medicine_id = $1 AND pharmacy_id = $2',
      [medicine_id, pharmacy_id]
    );

    if (checkMedicine.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Medicine not found' });
    }

    const fields = Object.keys(updates);
    const values = Object.values(updates);
    const setClause = fields.map((field, index) => `${field} = $${index + 1}`).join(', ');

    const result = await pool.query(
      `UPDATE medicines SET ${setClause} WHERE medicine_id = $${fields.length + 1} AND pharmacy_id = $${fields.length + 2} RETURNING *`,
      [...values, medicine_id, pharmacy_id]
    );

    res.json({
      success: true,
      message: 'Medicine updated successfully',
      data: result.rows[0]
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

const deleteMedicine = async (req, res) => {
  try {
    const { medicine_id } = req.params;
    const pharmacy_id = req.user.id;

    const result = await pool.query(
      'DELETE FROM medicines WHERE medicine_id = $1 AND pharmacy_id = $2 RETURNING *',
      [medicine_id, pharmacy_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Medicine not found' });
    }

    res.json({
      success: true,
      message: 'Medicine deleted successfully'
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};

module.exports = {
  addMedicine,
  getMedicinesByPharmacy,
  updateMedicine,
  deleteMedicine
};

// ============================================
// 10. routes/userRoutes.js
// ============================================
const express = require('express');
const router = express.Router();
const { registerUser, loginUser, searchDoctors, searchMedicines } = require('../controllers/userController');
const authMiddleware = require('../middleware/auth');

router.post('/register', registerUser);
router.post('/login', loginUser);
router.get('/search/doctors', authMiddleware('user'), searchDoctors);
router.get('/search/medicines', authMiddleware('user'), searchMedicines);

module.exports = router;

// ============================================
// 11. routes/hospitalRoutes.js
// ============================================
const hospitalRouter = express.Router();
const { hospitalRegister, hospitalLogin } = require('../controllers/hospitalController');
const { addDoctor, getDoctorsByHospital, updateDoctor, deleteDoctor } = require('../controllers/doctorController');

hospitalRouter.post('/register', hospitalRegister);
hospitalRouter.post('/login', hospitalLogin);
hospitalRouter.post('/doctors', authMiddleware('hospital'), addDoctor);
hospitalRouter.get('/doctors', authMiddleware('hospital'), getDoctorsByHospital);
hospitalRouter.put('/doctors/:doctor_id', authMiddleware('hospital'), updateDoctor);
hospitalRouter.delete('/doctors/:doctor_id', authMiddleware('hospital'), deleteDoctor);

module.exports = hospitalRouter;

// ============================================
// 12. routes/pharmacyRoutes.js
// ============================================
const pharmacyRouter = express.Router();
const { pharmacyRegister, pharmacyLogin } = require('../controllers/pharmacyController');
const { addMedicine, getMedicinesByPharmacy, updateMedicine, deleteMedicine } = require('../controllers/medicineController');

pharmacyRouter.post('/register', pharmacyRegister);
pharmacyRouter.post('/login', pharmacyLogin);
pharmacyRouter.post('/medicines', authMiddleware('pharmacy'), addMedicine);
pharmacyRouter.get('/medicines', authMiddleware('pharmacy'), getMedicinesByPharmacy);
pharmacyRouter.put('/medicines/:medicine_id', authMiddleware('pharmacy'), updateMedicine);
pharmacyRouter.delete('/medicines/:medicine_id', authMiddleware('pharmacy'), deleteMedicine);

module.exports = pharmacyRouter;

// ============================================
// 13. server.js - Main Server File
// ============================================
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api/users', require('./routes/userRoutes'));
app.use('/api/hospitals', require('./routes/hospitalRoutes'));
app.use('/api/pharmacies', require('./routes/pharmacyRoutes'));

// Health check
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'MediConnect API is running' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    success: false, 
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 API available at http://localhost:${PORT}/api`);
});