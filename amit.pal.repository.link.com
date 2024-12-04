mkdir rbac-system
cd rbac-system
npm init -y
npm install express bcryptjs jsonwebtoken mongoose dotenv
npm install --save-dev nodemonrbac-system/
├── .env
├── config/
│   └── db.js
├── models/
│   ├── User.js
│   └── Role.js
├── routes/
│   ├── auth.js
│   └── user.js
├── controllers/
│   ├── authController.js
│   └── userController.js
├── middleware/
│   ├── authMiddleware.js
│   └── roleMiddleware.js
└── app.jsDB_URI=mongodb://localhost:27017/rbac
JWT_SECRET=your_jwt_secret
PORT=5000const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config();

const connectDB = async () => {
    try {
        await mongoose.connect(process.env.DB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log('Database connected');
    } catch (error) {
        console.error('Database connection failed', error);
        process.exit(1);
    }
};

module.exports = connectDB;
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: mongoose.Schema.Types.ObjectId, ref: 'Role', required: true }
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

// Method to compare password
UserSchema.methods.matchPassword = async function(enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);const mongoose = require('mongoose');

const RoleSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    permissions: { type: [String], default: [] }
});

module.exports = mongoose.model('Role', RoleSchema);const User = require('../models/User');
const Role = require('../models/Role');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const registerUser = async (req, res) => {
    const { username, email, password, roleName } = req.body;

    try {
        const role = await Role.findOne({ name: roleName });
        if (!role) return res.status(400).json({ message: 'Role not found' });

        const userExists = await User.findOne({ email });
        if (userExists) return res.status(400).json({ message: 'User already exists' });

        const user = new User({ username, email, password, role: role._id });
        await user.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
};

const loginUser = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email }).populate('role');
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        const isMatch = await user.matchPassword(password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ userId: user._id, role: user.role.name }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }module.exports = { registerUser, loginUser };const jwt = require('jsonwebtoken');

const protect = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

module.exports = protect;const roleBasedAccess = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) {
        return res.status(403).json({ message: 'Access denied' });
    }
    next();
};

module.exports = roleBasedAccess;const express = require('express');
const { registerUser, loginUser } = require('../controllers/authController');
const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);

module.exports = routerconst express = require('express');
const protect = require('../middleware/authMiddleware');
const roleBasedAccess = require('../middleware/roleMiddleware');
const router = express.Router();

router.get('/admin-dashboard', protect, roleBasedAccess(['Admin']), (req, res) => {
    res.send('Admin Dashboard');
});

router.get('/user-dashboard', protect, roleBasedAccess(['User', 'Admin']), (req, res) => {
    res.send('User Dashboard');
});

module.exports = router;const express = require('express');
const dotenv = require('dotenv');
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');

dotenv.config();
connectDB();

const app = express();
app.use(express.json());

app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
