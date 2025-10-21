import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import morgan from 'morgan';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();

console.log('🚀 Starting D.Watson Pharmacy Server...');
console.log('📋 Environment:', process.env.NODE_ENV || 'development');
console.log('🔧 Port:', process.env.PORT || 5000);
console.log('🗄️ MongoDB URI:', process.env.MONGODB_URI ? 'Set (hidden)' : 'Not set - using default');
console.log('⏰ Server start time:', new Date().toISOString());

const app = express();
const port = process.env.PORT || 5000;
const mongoUri = process.env.MONGODB_URI || process.env.MONGO_URL || 'mongodb+srv://onlydevsx_db_user:aN0cWgqkOWo4rhiD@cluster0.jfuzynl.mongodb.net/sales_dashboard?retryWrites=true&w=majority&appName=Cluster0';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(morgan('dev'));

console.log('✅ Middleware configured: CORS, JSON parsing, Morgan logging');

// Mongo connection
console.log('🔄 Attempting to connect to MongoDB...');
console.log('🔗 Connection string:', mongoUri.replace(/\/\/.*@/, '//***:***@')); // Hide credentials

mongoose
  .connect(mongoUri, { autoIndex: true })
  .then(() => {
    console.log('✅ MongoDB connected successfully!');
    console.log('📊 Database name:', mongoose.connection.db.databaseName);
  })
  .catch((err) => {
    console.error('❌ MongoDB connection failed!');
    console.error('🔍 Error details:', err.message);
    console.error('💡 Check your MONGODB_URI environment variable');
    process.exit(1);
  });

// Schemas/Models
const BranchSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    address: { type: String, default: '' },
    phone: { type: String, default: '' },
    email: { type: String, default: '' }
  },
  { timestamps: true }
);

const CategorySchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true },
    description: { type: String, default: '' },
    color: { type: String, default: 'primary' }
  },
  { timestamps: true }
);

// Group Schema
const GroupSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true },
    description: { type: String, default: '' },
    permissions: [{ type: String }],
    isDefault: { type: Boolean, default: false }
  },
  { timestamps: true }
);

// User Schema
const UserSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true },
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group', required: true },
    branches: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Branch' }],
    isActive: { type: Boolean, default: true },
    lastLogin: { type: Date }
  },
  { timestamps: true }
);

const SaleSchema = new mongoose.Schema(
  {
    branchId: { type: mongoose.Schema.Types.ObjectId, ref: 'Branch', required: true },
    categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
    date: { type: Date, required: true },
    items: [
      {
        sku: String,
        name: String,
        quantity: Number,
        unitPrice: Number,
        cost: Number
      }
    ],
    total: { type: Number, required: true },
    costTotal: { type: Number, required: true },
    profit: { type: Number, required: true },
    category: { type: String, required: true },
    notes: { type: String, default: '' }
  },
  { timestamps: true }
);

const SettingsSchema = new mongoose.Schema(
  {
    companyName: { type: String, default: 'D.Watson Group of Pharmacy' },
    currency: { type: String, default: 'PKR' },
    dateFormat: { type: String, default: 'DD/MM/YYYY' },
    itemsPerPage: { type: Number, default: 10 },
    defaultCostPercent: { type: Number, default: 70 }
  },
  { timestamps: true }
);

const Branch = mongoose.model('Branch', BranchSchema);
const Category = mongoose.model('Category', CategorySchema);
const Group = mongoose.model('Group', GroupSchema);
const User = mongoose.model('User', UserSchema);
const Sale = mongoose.model('Sale', SaleSchema);
const Settings = mongoose.model('Settings', SettingsSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'pharmacy_sales_secret_key';

// Authentication Middleware - Enhanced with debugging
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      console.log('❌ Authentication failed: No token provided');
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('🔍 Decoded token:', decoded);
    
    const user = await User.findById(decoded.id).populate('groupId');
    console.log('🔍 User from DB:', JSON.stringify(user, null, 2));
    
    if (!user) {
      console.log('❌ Authentication failed: User not found in database');
      return res.status(401).json({ error: 'Invalid token or user not found.' });
    }
    
    if (!user.isActive) {
      console.log('❌ Authentication failed: User is not active');
      return res.status(401).json({ error: 'Invalid token or inactive user.' });
    }
    
    // Ensure user has group information
    if (!user.groupId) {
      console.log('❌ Authentication failed: User has no group assigned');
      return res.status(401).json({ error: 'User has no group assigned.' });
    }
    
    // Ensure group has permissions
    if (!user.groupId.permissions || !Array.isArray(user.groupId.permissions)) {
      console.log('❌ Authentication failed: Group has no permissions defined');
      return res.status(401).json({ error: 'Group has no permissions defined.' });
    }
    
    console.log('🔍 User permissions:', user.groupId.permissions);
    
    req.user = user;
    next();
  } catch (error) {
    console.error('❌ Authentication error:', error);
    res.status(401).json({ error: 'Invalid token.' });
  }
};

// Admin Middleware - Enhanced with debugging
const isAdmin = (req, res, next) => {
  console.log('🔍 Checking admin permissions...');
  console.log('🔍 User object:', JSON.stringify(req.user, null, 2));
  
  // Check if user exists
  if (!req.user) {
    console.log('❌ Admin check failed: No user found in request');
    return res.status(401).json({ error: 'Access denied. No user found.' });
  }
  
  // Check if user has group information
  if (!req.user.groupId) {
    console.log('❌ Admin check failed: No group information found for user');
    return res.status(403).json({ error: 'Access denied. User has no group assigned.' });
  }
  
  // Check if group has permissions
  if (!req.user.groupId.permissions || !Array.isArray(req.user.groupId.permissions)) {
    console.log('❌ Admin check failed: No permissions found for group');
    return res.status(403).json({ error: 'Access denied. Group has no permissions defined.' });
  }
  
  console.log('🔍 User permissions:', req.user.groupId.permissions);
  
  // Check if user has admin permission
  if (!req.user.groupId.permissions.includes('admin')) {
    console.log('❌ Admin check failed: User does not have admin permission');
    return res.status(403).json({ error: 'Access denied. Admin privileges required.' });
  }
  
  console.log('✅ Admin permission check passed');
  next();
};

// Debug endpoint - Check user permissions
app.get('/api/debug/user', authenticate, (req, res) => {
  res.json({
    user: req.user,
    permissions: req.user.groupId.permissions,
    isAdmin: req.user.groupId.permissions.includes('admin')
  });
});

// Fix admin endpoint - Simple fix for 403 errors
app.post('/api/fix-admin', async (req, res) => {
  try {
    console.log('🔧 Fixing admin permissions...');
    
    // Find or create admin group with all permissions
    let adminGroup = await Group.findOne({ name: 'Admin' });
    
    if (!adminGroup) {
      adminGroup = new Group({
        name: 'Admin',
        description: 'System administrators with full access',
        permissions: ['admin', 'dashboard', 'categories', 'sales', 'reports', 'branches', 'groups', 'users', 'settings'],
        isDefault: true
      });
      await adminGroup.save();
      console.log('✅ Created Admin group');
    } else {
      // Make sure it has all permissions
      adminGroup.permissions = ['admin', 'dashboard', 'categories', 'sales', 'reports', 'branches', 'groups', 'users', 'settings'];
      await adminGroup.save();
      console.log('✅ Updated Admin group permissions');
    }
    
    // Update admin user
    const adminUser = await User.findOne({ username: 'admin' });
    
    if (adminUser) {
      adminUser.groupId = adminGroup._id;
      adminUser.isActive = true;
      await adminUser.save();
      console.log('✅ Updated admin user');
      
      res.json({ 
        success: true, 
        message: 'Admin fixed successfully! Please log out and log back in.',
        permissions: adminGroup.permissions
      });
    } else {
      res.status(404).json({ error: 'Admin user not found' });
    }
  } catch (error) {
    console.error('❌ Fix failed:', error);
    res.status(500).json({ error: error.message });
  }
});

// Create new admin endpoint - Backup solution
app.post('/api/create-new-admin', async (req, res) => {
  try {
    console.log('🔧 Creating new admin user...');
    
    // Find or create admin group
    let adminGroup = await Group.findOne({ name: 'Admin' });
    
    if (!adminGroup) {
      adminGroup = new Group({
        name: 'Admin',
        description: 'System administrators with full access',
        permissions: ['admin', 'dashboard', 'categories', 'sales', 'reports', 'branches', 'groups', 'users', 'settings'],
        isDefault: true
      });
      await adminGroup.save();
    }
    
    // Create new admin user
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash('superadmin123', salt);
    
    const newAdmin = new User({
      username: 'superadmin',
      fullName: 'Super Administrator',
      email: 'superadmin@dwatson.com',
      password: hashedPassword,
      groupId: adminGroup._id,
      branches: [] // Will get all branches
    });
    
    await newAdmin.save();
    
    res.json({ 
      success: true, 
      message: 'New admin user created',
      username: 'superadmin',
      password: 'superadmin123'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Health endpoint
app.get('/api/health', (req, res) => {
  const healthData = { 
    ok: true, 
    environment: process.env.NODE_ENV || 'development',
    port: port,
    timestamp: new Date().toISOString(),
    mongodb: {
      connected: mongoose.connection.readyState === 1,
      state: ['disconnected', 'connected', 'connecting', 'disconnecting'][mongoose.connection.readyState]
    },
    uptime: process.uptime()
  };
  
  console.log('🏥 Health check requested:', healthData);
  res.json(healthData);
});

// Authentication Routes - Enhanced
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
    
    const user = await User.findOne({ username }).populate('groupId');
    console.log('🔍 Login attempt for user:', username);
    console.log('🔍 User from DB:', JSON.stringify(user, null, 2));
    
    if (!user) {
      console.log('❌ Login failed: User not found');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (!user.isActive) {
      console.log('❌ Login failed: User is not active');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      console.log('❌ Login failed: Password does not match');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Fetch the user again to ensure we have the latest data
    const updatedUser = await User.findById(user._id).populate('groupId');
    console.log('🔍 Updated user with group info:', JSON.stringify(updatedUser, null, 2));
    
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1d' });
    
    res.json({
      token,
      user: {
        id: updatedUser._id,
        username: updatedUser.username,
        fullName: updatedUser.fullName,
        email: updatedUser.email,
        groupId: updatedUser.groupId,
        branches: updatedUser.branches,
        permissions: updatedUser.groupId.permissions
      }
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/logout', authenticate, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    // Fetch the user again to ensure we have the latest data
    const user = await User.findById(req.user._id).populate('groupId');
    console.log('🔍 /api/auth/me user:', JSON.stringify(user, null, 2));
    
    res.json({
      id: user._id,
      username: user.username,
      fullName: user.fullName,
      email: user.email,
      groupId: user.groupId,
      branches: user.branches,
      permissions: user.groupId.permissions
    });
  } catch (error) {
    console.error('❌ Get user error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
// Add this endpoint to create a fresh admin user
app.post('/api/create-fresh-admin', async (req, res) => {
  try {
    console.log('Creating fresh admin user...');
    
    // Find or create admin group
    let adminGroup = await Group.findOne({ name: 'Admin' });
    
    if (!adminGroup) {
      adminGroup = new Group({
        name: 'Admin',
        description: 'System administrators with full access',
        permissions: ['admin', 'dashboard', 'categories', 'sales', 'reports', 'branches', 'groups', 'users', 'settings'],
        isDefault: true
      });
      await adminGroup.save();
      console.log('Admin group created');
    }
    
    // Delete existing admin users to avoid conflicts
    await User.deleteMany({ username: { $in: ['admin', 'superadmin', 'myadmin'] } });
    
    // Create new admin user
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash('myadmin123', salt);
    
    const adminUser = new User({
      username: 'myadmin',
      fullName: 'My Administrator',
      email: 'myadmin@dwatson.com',
      password: hashedPassword,
      groupId: adminGroup._id,
      branches: []
    });
    
    await adminUser.save();
    console.log('Admin user created');
    
    res.json({ 
      success: true, 
      message: 'Fresh admin user created successfully',
      username: 'myadmin',
      password: 'myadmin123'
    });
  } catch (error) {
    console.error('Error creating fresh admin:', error);
    res.status(500).json({ error: error.message });
  }
});
// Simple HTML page to trigger admin creation
app.get('/create-admin-page', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Create Admin User</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        button { padding: 10px 15px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        #result { margin-top: 20px; padding: 10px; background: #f8f9fa; border-radius: 4px; }
      </style>
    </head>
    <body>
      <h1>Create Admin User</h1>
      <button onclick="createAdmin()">Create Admin User</button>
      <div id="result">Click the button to create an admin user</div>
      
      <script>
        async function createAdmin() {
          document.getElementById('result').innerHTML = 'Creating admin user...';
          
          try {
            const response = await fetch('/api/create-fresh-admin', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json'
              }
            });
            
            const data = await response.json();
            
            if (data.success) {
              document.getElementById('result').innerHTML = 
                '<h3>Success!</h3>' +
                '<p>Username: <strong>' + data.username + '</strong></p>' +
                '<p>Password: <strong>' + data.password + '</strong></p>' +
                '<p>Go to the <a href="/">login page</a> and use these credentials.</p>';
            } else {
              document.getElementById('result').innerHTML = '<p style="color: red;">Error: ' + data.error + '</p>';
            }
          } catch (error) {
            document.getElementById('result').innerHTML = '<p style="color: red;">Error: ' + error.message + '</p>';
          }
        }
      </script>
    </body>
    </html>
  `);
});
// Settings API
app.get('/api/settings', authenticate, async (req, res) => {
  try {
    let settings = await Settings.findOne();
    if (!settings) {
      settings = await Settings.create({});
    }
    res.json(settings);
  } catch (error) {
    console.error('Error fetching settings:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/settings', authenticate, isAdmin, async (req, res) => {
  try {
    const update = {
      companyName: req.body.companyName ?? 'D.Watson Group of Pharmacy',
      currency: req.body.currency ?? 'PKR',
      dateFormat: req.body.dateFormat ?? 'DD/MM/YYYY',
      itemsPerPage: Number(req.body.itemsPerPage ?? 10),
      defaultCostPercent: req.body.defaultCostPercent !== undefined ? Number(req.body.defaultCostPercent) : undefined
    };
    
    // Remove undefined to avoid overwriting with undefined
    Object.keys(update).forEach((k) => update[k] === undefined && delete update[k]);
    
    const settings = await Settings.findOneAndUpdate({}, update, { new: true, upsert: true });
    res.json(settings);
  } catch (error) {
    console.error('Error updating settings:', error);
    res.status(400).json({ error: error.message });
  }
});

// Branches CRUD
app.get('/api/branches', authenticate, async (req, res) => {
  console.log('📋 GET /api/branches - Fetching all branches');
  try {
    // If user is not admin, only return assigned branches
    const filter = {};
    if (!req.user.groupId.permissions.includes('admin')) {
      filter._id = { $in: req.user.branches };
    }
    
    const branches = await Branch.find(filter).sort({ createdAt: -1 });
    console.log(`✅ Found ${branches.length} branches`);
    res.json(branches);
  } catch (error) {
    console.error('❌ Error fetching branches:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/branches', authenticate, isAdmin, async (req, res) => {
  console.log('➕ POST /api/branches - Creating new branch:', req.body);
  try {
    const name = (req.body.name || '').trim();
    if (!name) return res.status(400).json({ error: 'Name is required' });
    // Enforce unique name (case-insensitive)
    const exists = await Branch.findOne({ name: { $regex: `^${name}$`, $options: 'i' } });
    if (exists) return res.status(409).json({ error: 'Branch with this name already exists' });
    const branch = await Branch.create({ ...req.body, name });
    console.log('✅ Branch created successfully:', branch._id);
    res.status(201).json(branch);
  } catch (error) {
    console.error('❌ Error creating branch:', error.message);
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/branches/:id', authenticate, isAdmin, async (req, res) => {
  console.log('✏️ PUT /api/branches/:id - Updating branch', req.params.id, req.body);
  try {
    const id = req.params.id;
    const payload = { ...req.body };

    // Normalize name if provided
    if (payload.name !== undefined && payload.name !== null) {
      payload.name = String(payload.name).trim();

      // Fetch current branch to compare names
      const current = await Branch.findById(id);
      if (!current) {
        console.log('❌ Branch not found for update:', id);
        return res.status(404).json({ error: 'Branch not found' });
      }

      // Simple case-insensitive comparison
      const currentName = String(current.name || '').toLowerCase().trim();
      const newName = payload.name.toLowerCase().trim();
      const nameChanged = currentName !== newName;

      console.log('🔍 Name comparison:', { currentName, newName, nameChanged });

      // Only enforce uniqueness if the name is actually changing
      if (nameChanged) {
        const exists = await Branch.findOne({
          _id: { $ne: id },
          name: { $regex: `^${payload.name}$`, $options: 'i' }
        });
        if (exists) {
          console.log('❌ Duplicate name found:', payload.name);
          return res.status(409).json({ error: 'Branch with this name already exists' });
        }
      }
    }
    
    const updated = await Branch.findByIdAndUpdate(id, payload, { new: true });
    if (!updated) {
      console.log('❌ Branch not found after update attempt:', id);
      return res.status(404).json({ error: 'Branch not found' });
    }
    
    console.log('✅ Branch updated successfully:', updated._id);
    res.json(updated);
  } catch (error) {
    console.error('❌ Error updating branch:', error.message);
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/branches/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const branch = await Branch.findByIdAndDelete(req.params.id);
    if (!branch) {
      return res.status(404).json({ error: 'Branch not found' });
    }
    // Also delete all sales associated with this branch
    await Sale.deleteMany({ branchId: req.params.id });
    // Remove branch from all users
    await User.updateMany(
      { branches: req.params.id },
      { $pull: { branches: req.params.id } }
    );
    res.json({ ok: true });
  } catch (error) {
    console.error('❌ Error deleting branch:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Categories CRUD
app.get('/api/categories', authenticate, async (req, res) => {
  console.log('🏷️ GET /api/categories - Fetching all categories');
  try {
    const categories = await Category.find().sort({ createdAt: -1 });
    console.log(`✅ Found ${categories.length} categories`);
    res.json(categories);
  } catch (error) {
    console.error('❌ Error fetching categories:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/categories', authenticate, isAdmin, async (req, res) => {
  console.log('➕ POST /api/categories - Creating new category:', req.body);
  try {
    const category = await Category.create(req.body);
    console.log('✅ Category created successfully:', category._id);
    res.status(201).json(category);
  } catch (error) {
    console.error('❌ Error creating category:', error.message);
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/categories/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const updated = await Category.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updated) {
      return res.status(404).json({ error: 'Category not found' });
    }
    res.json(updated);
  } catch (error) {
    console.error('❌ Error updating category:', error.message);
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/categories/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const category = await Category.findByIdAndDelete(req.params.id);
    if (!category) {
      return res.status(404).json({ error: 'Category not found' });
    }
    res.json({ ok: true });
  } catch (error) {
    console.error('❌ Error deleting category:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Groups CRUD - FIXED
app.get('/api/groups', authenticate, isAdmin, async (req, res) => {
  console.log('👥 GET /api/groups - Fetching all groups');
  try {
    const groups = await Group.find().sort({ createdAt: -1 });
    console.log(`✅ Found ${groups.length} groups`);
    res.json(groups);
  } catch (error) {
    console.error('❌ Error fetching groups:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/groups', authenticate, isAdmin, async (req, res) => {
  try {
    const { name, description, permissions } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Group name is required' });
    }
    
    // Check if group with same name already exists
    const existingGroup = await Group.findOne({ name });
    if (existingGroup) {
      return res.status(400).json({ error: 'Group with this name already exists' });
    }
    
    const group = new Group({ name, description, permissions });
    await group.save();
    
    res.status(201).json(group);
  } catch (error) {
    console.error('Error creating group:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/groups/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const { name, description, permissions } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Group name is required' });
    }
    
    // Check if group with same name already exists (excluding current group)
    const existingGroup = await Group.findOne({ 
      name, 
      _id: { $ne: req.params.id } 
    });
    
    if (existingGroup) {
      return res.status(400).json({ error: 'Group with this name already exists' });
    }
    
    const group = await Group.findByIdAndUpdate(
      req.params.id,
      { name, description, permissions },
      { new: true }
    );
    
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    res.json(group);
  } catch (error) {
    console.error('Error updating group:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/groups/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const group = await Group.findByIdAndDelete(req.params.id);
    
    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }
    
    // Update all users with this group to have no group
    await User.updateMany(
      { groupId: req.params.id },
      { $unset: { groupId: 1 } }
    );
    
    res.json({ message: 'Group deleted successfully' });
  } catch (error) {
    console.error('Error deleting group:', error);
    res.status(500).json({ error: error.message });
  }
});

// Users CRUD - FIXED
app.get('/api/users', authenticate, isAdmin, async (req, res) => {
  console.log('👤 GET /api/users - Fetching all users');
  try {
    const users = await User.find()
      .populate('groupId', 'name permissions')
      .sort({ createdAt: -1 });
    console.log(`✅ Found ${users.length} users`);
    res.json(users);
  } catch (error) {
    console.error('❌ Error fetching users:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/users', authenticate, isAdmin, async (req, res) => {
  try {
    const { username, fullName, email, password, groupId, branches } = req.body;
    
    if (!username || !fullName || !email || !password || !groupId) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    // Check if user with same username or email already exists
    const existingUser = await User.findOne({
      $or: [
        { username },
        { email }
      ]
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User with this username or email already exists' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const user = new User({
      username,
      fullName,
      email,
      password: hashedPassword,
      groupId,
      branches
    });
    
    await user.save();
    
    // Populate group for response
    await user.populate('groupId', 'name permissions');
    
    res.status(201).json(user);
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/users/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const { username, fullName, email, password, groupId, branches, isActive } = req.body;
    
    if (!username || !fullName || !email || !groupId) {
      return res.status(400).json({ error: 'Username, full name, email, and group are required' });
    }
    
    // Check if user with same username or email already exists (excluding current user)
    const existingUser = await User.findOne({
      $or: [
        { username },
        { email }
      ],
      _id: { $ne: req.params.id }
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User with this username or email already exists' });
    }
    
    const updateData = {
      username,
      fullName,
      email,
      groupId,
      branches,
      isActive
    };
    
    // Only update password if provided
    if (password) {
      const salt = await bcrypt.genSalt(10);
      updateData.password = await bcrypt.hash(password, salt);
    }
    
    const user = await User.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    ).populate('groupId', 'name permissions');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/users/:id', authenticate, isAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: error.message });
  }
});

// Sales CRUD
app.get('/api/sales', authenticate, async (req, res) => {
  console.log('💰 GET /api/sales - Fetching sales with filters:', req.query);
  try {
    const filter = {};
    
    // Build filter from query parameters
    if (req.query.branchId && req.query.branchId !== 'undefined' && req.query.branchId.trim() !== '') {
      filter.branchId = req.query.branchId;
    }
    
    if (req.query.categoryId && req.query.categoryId !== 'undefined' && req.query.categoryId.trim() !== '') {
      filter.categoryId = req.query.categoryId;
    }
    
    if (req.query.from || req.query.to) {
      filter.date = {};
      if (req.query.from) {
        filter.date.$gte = new Date(req.query.from);
      }
      if (req.query.to) {
        filter.date.$lte = new Date(req.query.to);
      }
    }
    
    // If user is not admin, filter by user's assigned branches
    if (!req.user.groupId.permissions.includes('admin')) {
      filter.branchId = { $in: req.user.branches };
    }
    
    const sales = await Sale.find(filter)
      .sort({ date: -1 })
      .populate('branchId', 'name')
      .populate('categoryId', 'name');
    
    console.log(`✅ Found ${sales.length} sales records`);
    res.json(sales);
  } catch (error) {
    console.error('❌ Error fetching sales:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/sales', authenticate, async (req, res) => {
  console.log('➕ POST /api/sales - Creating new sale:', req.body);
  try {
    // Copy request data
    const data = { ...req.body };

    // If category string missing, fetch from Category model
    if (!data.category && data.categoryId) {
      try {
        const cat = await Category.findById(data.categoryId);
        data.category = cat ? cat.name : 'Unknown';
      } catch (err) {
        console.warn('⚠️ Could not find category for ID:', data.categoryId);
        data.category = 'Unknown';
      }
    }

    // Check if user has access to this branch
    if (!req.user.groupId.permissions.includes('admin') && !req.user.branches.includes(data.branchId)) {
      return res.status(403).json({ error: 'Access denied. You do not have permission to access this branch.' });
    }

    // Create sale using fixed data
    const sale = await Sale.create(data);
    console.log('✅ Sale created successfully:', sale._id);

    // Populate branch & category references before sending response
    const populatedSale = await Sale.findById(sale._id)
      .populate('branchId', 'name')
      .populate('categoryId', 'name');

    res.status(201).json(populatedSale);
  } catch (error) {
    console.error('❌ Error creating sale:', error.message);
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/sales/:id', authenticate, async (req, res) => {
  console.log('✏️ PUT /api/sales/:id - Updating sale', req.params.id, req.body);
  try {
    // Check if user has access to this branch
    if (!req.user.groupId.permissions.includes('admin') && !req.user.branches.includes(req.body.branchId)) {
      return res.status(403).json({ error: 'Access denied. You do not have permission to access this branch.' });
    }

    const updated = await Sale.findByIdAndUpdate(req.params.id, req.body, { new: true })
      .populate('branchId', 'name')
      .populate('categoryId', 'name');
    
    if (!updated) {
      return res.status(404).json({ error: 'Sale not found' });
    }
    
    console.log('✅ Sale updated:', updated._id);
    res.json(updated);
  } catch (error) {
    console.error('❌ Error updating sale:', error.message);
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/sales/:id', authenticate, async (req, res) => {
  console.log('🗑️ DELETE /api/sales/:id - Deleting sale', req.params.id);
  try {
    // Check if user has access to this sale's branch
    const sale = await Sale.findById(req.params.id);
    if (!sale) {
      return res.status(404).json({ error: 'Sale not found' });
    }
    
    if (!req.user.groupId.permissions.includes('admin') && !req.user.branches.includes(sale.branchId)) {
      return res.status(403).json({ error: 'Access denied. You do not have permission to access this branch.' });
    }

    const deleted = await Sale.findByIdAndDelete(req.params.id);
    console.log('✅ Sale deleted:', deleted._id);
    res.json({ ok: true });
  } catch (error) {
    console.error('❌ Error deleting sale:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Admin-protected actions
app.post('/api/admin/delete', async (req, res) => {
  try {
    const { resource, id, password } = req.body || {};
    const expected = String(process.env.ADMIN_PASSWORD || '');
    const provided = String(password || '');
    
    if (!expected) {
      console.error('🔐 Admin password not configured on server');
      return res.status(500).json({ error: 'Admin password not configured on server' });
    }
    
    if (provided.trim() !== expected.trim()) {
      console.warn('🔒 Admin auth failed: provided.length=%d expected.length=%d', provided.length, expected.length);
      return res.status(403).json({ error: 'Invalid admin password' });
    }

    if (!resource || !id) {
      return res.status(400).json({ error: 'resource and id are required' });
    }

    let deleted = null;
    if (resource === 'sales') {
      deleted = await Sale.findByIdAndDelete(id);
    } else if (resource === 'branches') {
      deleted = await Branch.findByIdAndDelete(id);
      await Sale.deleteMany({ branchId: id });
      await User.updateMany(
        { branches: id },
        { $pull: { branches: id } }
      );
    } else if (resource === 'categories') {
      deleted = await Category.findByIdAndDelete(id);
    } else if (resource === 'groups') {
      deleted = await Group.findByIdAndDelete(id);
      await User.updateMany(
        { groupId: id },
        { $unset: { groupId: 1 } }
      );
    } else if (resource === 'users') {
      deleted = await User.findByIdAndDelete(id);
    } else {
      return res.status(400).json({ error: 'Unknown resource type' });
    }

    if (!deleted) {
      return res.status(404).json({ error: 'Record not found' });
    }
    
    return res.json({ ok: true });
  } catch (error) {
    console.error('❌ Admin delete error:', error.message);
    return res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/update', async (req, res) => {
  try {
    const { resource, id, payload, password } = req.body || {};
    const expected = String(process.env.ADMIN_PASSWORD || '');
    const provided = String(password || '');
    
    if (!expected) {
      console.error('🔐 Admin password not configured on server');
      return res.status(500).json({ error: 'Admin password not configured on server' });
    }
    
    if (provided.trim() !== expected.trim()) {
      console.warn('🔒 Admin auth failed (update): provided.length=%d expected.length=%d', provided.length, expected.length);
      return res.status(403).json({ error: 'Invalid admin password' });
    }

    if (!resource || !id || !payload) {
      return res.status(400).json({ error: 'resource, id and payload are required' });
    }

    let updated = null;
    if (resource === 'sales') {
      updated = await Sale.findByIdAndUpdate(id, payload, { new: true })
        .populate('branchId', 'name')
        .populate('categoryId', 'name');
    } else if (resource === 'branches') {
      updated = await Branch.findByIdAndUpdate(id, payload, { new: true });
    } else if (resource === 'categories') {
      updated = await Category.findByIdAndUpdate(id, payload, { new: true });
    } else if (resource === 'groups') {
      updated = await Group.findByIdAndUpdate(id, payload, { new: true });
    } else if (resource === 'users') {
      // Hash password if provided
      if (payload.password) {
        const salt = await bcrypt.genSalt(10);
        payload.password = await bcrypt.hash(payload.password, salt);
      }
      updated = await User.findByIdAndUpdate(id, payload, { new: true })
        .populate('groupId', 'name permissions');
    } else {
      return res.status(400).json({ error: 'Unknown resource type' });
    }

    if (!updated) {
      return res.status(404).json({ error: 'Record not found' });
    }
    
    return res.json(updated);
  } catch (error) {
    console.error('❌ Admin update error:', error.message);
    return res.status(500).json({ error: error.message });
  }
});

// Seed default data - FIXED to ensure admin group and user are created correctly
async function seedDefaultData() {
  console.log('🌱 Starting database seeding...');
  
  try {
    // Seed branches
    const branchCount = await Branch.estimatedDocumentCount();
    console.log(`📊 Current branch count: ${branchCount}`);
    
    if (branchCount === 0) {
      console.log('🌿 Seeding default branches...');
      const defaultBranches = [
        { name: 'D WATSON PWD', address: '' },
        { name: 'D WATSON F6', address: '' },
        { name: 'D WATSON GUJJAR KHAN', address: '' },
        { name: 'D WATSON CHANDNI CHOWK', address: '' },
        { name: 'D WATSON ATTOCK', address: '' },
        { name: 'D WATSON GHORI TOWN', address: '' },
        { name: 'D WATSON G 15', address: '' }
      ];
      await Branch.insertMany(defaultBranches);
      console.log('✅ Seeded 7 default branches');
    } else {
      console.log('⏭️ Branches already exist, skipping branch seeding');
    }

    // Seed categories
    const categoryCount = await Category.estimatedDocumentCount();
    console.log(`📊 Current category count: ${categoryCount}`);
    
    if (categoryCount === 0) {
      console.log('🏷️ Seeding default categories...');
      const defaultCategories = [
        { name: 'MEDICINE NEUTRA', description: 'Neutral medicine category', color: 'primary' },
        { name: 'MEDICINE AIMS', description: 'AIMS medicine category', color: 'success' },
        { name: 'COSTMAIES', description: 'Costmaies category', color: 'info' }
      ];
      await Category.insertMany(defaultCategories);
      console.log('✅ Seeded 3 default categories');
    } else {
      console.log('⏭️ Categories already exist, skipping category seeding');
    }
    
    // Seed groups - FIXED to ensure admin permissions are set correctly
    const groupCount = await Group.estimatedDocumentCount();
    console.log(`📊 Current group count: ${groupCount}`);
    
    if (groupCount === 0) {
      console.log('👥 Seeding default groups...');
      const defaultGroups = [
        {
          name: 'Admin',
          description: 'System administrators with full access',
          permissions: ['admin', 'dashboard', 'categories', 'sales', 'reports', 'branches', 'groups', 'users', 'settings'],
          isDefault: true
        },
        {
          name: 'Sales',
          description: 'Sales staff with access to sales entry and reports',
          permissions: ['dashboard', 'sales', 'reports'],
          isDefault: true
        },
        {
          name: 'Manager',
          description: 'Branch managers with access to sales, reports and branches',
          permissions: ['dashboard', 'sales', 'reports', 'branches'],
          isDefault: true
        }
      ];
      await Group.insertMany(defaultGroups);
      console.log('✅ Seeded 3 default groups');
      
      // Verify admin group was created correctly
      const adminGroup = await Group.findOne({ name: 'Admin' });
      if (adminGroup) {
        console.log('✅ Admin group created successfully with permissions:', adminGroup.permissions);
      } else {
        console.error('❌ Admin group not found after creation');
      }
    } else {
      console.log('⏭️ Groups already exist, skipping group seeding');
      
      // Check if admin group exists and has correct permissions
      const adminGroup = await Group.findOne({ name: 'Admin' });
      if (adminGroup) {
        console.log('✅ Admin group found with permissions:', adminGroup.permissions);
        
        // Ensure admin group has admin permission
        if (!adminGroup.permissions.includes('admin')) {
          console.log('⚠️ Admin group missing admin permission, updating...');
          adminGroup.permissions.push('admin');
          await adminGroup.save();
          console.log('✅ Admin group updated with admin permission');
        }
      } else {
        console.error('❌ Admin group not found');
      }
    }
    
    // Seed admin user - FIXED to ensure it references the admin group
    const userCount = await User.estimatedDocumentCount();
    console.log(`📊 Current user count: ${userCount}`);
    
    if (userCount === 0) {
      console.log('👤 Seeding default admin user...');
      
      // Find the admin group
      const adminGroup = await Group.findOne({ name: 'Admin' });
      if (!adminGroup) {
        console.error('❌ Admin group not found, cannot create admin user');
        return;
      }
      
      console.log('🔑 Admin group found:', adminGroup.name, 'with permissions:', adminGroup.permissions);
      
      // Get all branches
      const allBranches = await Branch.find();
      if (allBranches.length === 0) {
        console.error('❌ No branches found, cannot create admin user');
        return;
      }
      
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash('admin123', salt);
      
      const adminUser = new User({
        username: 'admin',
        fullName: 'System Administrator',
        email: 'admin@dwatson.com',
        password: hashedPassword,
        groupId: adminGroup._id,
        branches: allBranches.map(b => b._id)
      });
      
      await adminUser.save();
      console.log('✅ Seeded default admin user (username: admin, password: admin123)');
      console.log('🔑 Admin user group ID:', adminUser.groupId);
      
      // Verify admin user was created correctly
      const createdUser = await User.findById(adminUser._id).populate('groupId');
      if (createdUser) {
        console.log('✅ Admin user created successfully with permissions:', createdUser.groupId.permissions);
      } else {
        console.error('❌ Admin user not found after creation');
      }
    } else {
      console.log('⏭️ Users already exist, skipping user seeding');
      
      // Check if admin user exists and has correct group
      const adminUser = await User.findOne({ username: 'admin' }).populate('groupId');
      if (adminUser) {
        console.log('✅ Admin user found with group:', adminUser.groupId.name);
        console.log('✅ Admin user permissions:', adminUser.groupId.permissions);
        
        // Ensure admin user has admin permission
        if (!adminUser.groupId.permissions.includes('admin')) {
          console.log('⚠️ Admin user group missing admin permission, updating...');
          adminUser.groupId.permissions.push('admin');
          await adminUser.groupId.save();
          console.log('✅ Admin user group updated with admin permission');
        }
      } else {
        console.error('❌ Admin user not found');
      }
    }
    
    console.log('🎉 Database seeding completed!');
  } catch (error) {
    console.error('❌ Seed error:', error.message);
  }
}

// Serve static frontend
const clientDir = path.resolve(__dirname, '..');
app.use('/', express.static(clientDir));
console.log('📁 Serving static files from:', clientDir);

// Start server
mongoose.connection.once('open', () => {
  console.log('🔗 MongoDB connection opened, starting seeding process...');
  seedDefaultData();
  
  app.listen(port, () => {
    console.log('🎉 ==========================================');
    console.log('🚀 D.Watson Pharmacy Server Started Successfully!');
    console.log('🎉 ==========================================');
    console.log(`🌐 Server listening on port: ${port}`);
    console.log(`🏠 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🗄️ MongoDB URI: ${mongoUri.replace(/\/\/.*@/, '//***:***@')}`);
    console.log(`⏰ Start time: ${new Date().toISOString()}`);
    console.log('🎉 ==========================================');
    console.log('✅ All systems ready! API endpoints active.');
    console.log('🏥 Health check: GET /api/health');
    console.log('🔐 Authentication: POST /api/auth/login');
    console.log('📋 Branches: GET /api/branches');
    console.log('🏷️ Categories: GET /api/categories');
    console.log('👥 Groups: GET /api/groups');
    console.log('👤 Users: GET /api/users');
    console.log('💰 Sales: GET /api/sales');
    console.log('⚙️ Settings: GET /api/settings');
    console.log('🔍 Debug: GET /api/debug/user');
    console.log('🔧 Fix Admin: POST /api/fix-admin');
    console.log('🆕 Create New Admin: POST /api/create-new-admin');
    console.log('🎉 ==========================================');
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    res.status(404).json({ error: 'API endpoint not found', path: req.path });
  } else {
    // For non-API routes, serve the frontend
    res.sendFile(path.join(clientDir, 'index.html'));
  }
});


