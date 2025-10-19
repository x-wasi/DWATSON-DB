import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import morgan from 'morgan';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

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

const SaleSchema = new mongoose.Schema(
  {
    branchId: { type: mongoose.Schema.Types.ObjectId, ref: 'Branch', required: true },
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
    total: Number,
    costTotal: Number,
    profit: Number,
    category: String
  },
  { timestamps: true }
);

const Branch = mongoose.model('Branch', BranchSchema);
const Sale = mongoose.model('Sale', SaleSchema);
// Categories
const CategorySchema = new mongoose.Schema(
  {
    name: { type: String, required: true, unique: true },
    description: { type: String, default: '' },
    color: { type: String, default: 'primary' }
  },
  { timestamps: true }
);
const Category = mongoose.model('Category', CategorySchema);
// Settings (singleton)
const SettingsSchema = new mongoose.Schema(
  {
    companyName: { type: String, default: '' },
    currency: { type: String, default: 'PKR' },
    dateFormat: { type: String, default: 'DD/MM/YYYY' },
    itemsPerPage: { type: Number, default: 10 },
    defaultCostPercent: { type: Number, default: 70 }
  },
  { timestamps: true }
);
const Settings = mongoose.model('Settings', SettingsSchema);

// Health
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

// Settings API
app.get('/api/settings', async (req, res) => {
  let settings = await Settings.findOne();
  if (!settings) {
    settings = await Settings.create({});
  }
  // Always return JSON for API consumers (frontend expects JSON).
  // Some clients may accept HTML, but API endpoints should consistently return JSON.
  res.json(settings);
});

app.put('/api/settings', async (req, res) => {
  try {
    const update = {
      companyName: req.body.companyName ?? '',
      currency: req.body.currency ?? 'PKR',
      dateFormat: req.body.dateFormat ?? 'DD/MM/YYYY',
      itemsPerPage: Number(req.body.itemsPerPage ?? 10),
      defaultCostPercent: req.body.defaultCostPercent !== undefined ? Number(req.body.defaultCostPercent) : undefined
    };
    // Remove undefined to avoid overwriting with undefined
    Object.keys(update).forEach((k) => update[k] === undefined && delete update[k]);
    const settings = await Settings.findOneAndUpdate({}, update, { new: true, upsert: true });
    res.json(settings);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
//=============================================================
app.post("/api/admin/delete", async (req, res) => {
  try {
    const { collection, id, password } = req.body;

    // 1️⃣ Check password
    if (password !== process.env.ADMIN_PASSWORD) {
      return res.status(401).json({ success: false, message: "Invalid admin password" });
    }

    // 2️⃣ Select the right model
    const models = { Branch, Sale, Category };
    const Model = models[collection];
    if (!Model) {
      return res.status(400).json({ success: false, message: "Invalid collection name" });
    }

    // 3️⃣ Delete document
    await Model.findByIdAndDelete(id);
    res.json({ success: true, message: `${collection} deleted successfully` });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});







//======================================================
// Branches CRUD
app.get('/api/branches', async (req, res) => {
  console.log('📋 GET /api/branches - Fetching all branches');
  try {
    const branches = await Branch.find().sort({ createdAt: -1 });
    console.log(`✅ Found ${branches.length} branches`);
    // Always return JSON for API endpoints - ignore Accept header
    const wantsHtml = false;
    if (wantsHtml) {
    const rows = branches
      .map(
        (b) => `
          <tr>
            <td>${b._id}</td>
            <td>${b.name}</td>
            <td>${b.address || ''}</td>
            <td>${b.phone || ''}</td>
            <td>${b.email || ''}</td>
          </tr>`
      )
      .join('');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Branches</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style> body{padding:20px} table{background:#fff} </style>
</head>
<body>
  <div class="container">
    <h1 class="mb-4">Branches</h1>
    <table class="table table-striped table-bordered">
      <thead><tr><th>_id</th><th>Name</th><th>Address</th><th>Phone</th><th>Email</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <a href="/" class="btn btn-secondary">Back to App</a>
  </div>
</body>
</html>`);
    } else {
      res.json(branches);
    }
  } catch (e) {
    console.error('❌ Error fetching branches:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/branches', async (req, res) => {
  console.log('➕ POST /api/branches - Creating new branch:', req.body);
  try {
    const branch = await Branch.create(req.body);
    console.log('✅ Branch created successfully:', branch._id);
    res.status(201).json(branch);
  } catch (e) {
    console.error('❌ Error creating branch:', e.message);
    res.status(400).json({ error: e.message });
  }
});

app.put('/api/branches/:id', async (req, res) => {
  try {
    const updated = await Branch.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updated);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.delete('/api/branches/:id', async (req, res) => {
  try {
    await Branch.findByIdAndDelete(req.params.id);
    await Sale.deleteMany({ branchId: req.params.id });
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Categories CRUD
app.get('/api/categories', async (req, res) => {
  console.log('🏷️ GET /api/categories - Fetching all categories');
  try {
    const categories = await Category.find().sort({ createdAt: -1 });
    console.log(`✅ Found ${categories.length} categories`);
    // Always return JSON for API endpoints - ensure we return an array
    const wantsHtml = false;
    if (wantsHtml) {
    const rows = categories
      .map(
        (c) => `
          <tr>
            <td>${c._id}</td>
            <td>${c.name}</td>
            <td>${c.description || ''}</td>
          </tr>`
      )
      .join('');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Categories</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style> body{padding:20px} table{background:#fff} </style>
</head>
<body>
  <div class="container">
    <h1 class="mb-4">Categories</h1>
    <table class="table table-striped table-bordered">
      <thead><tr><th>_id</th><th>Name</th><th>Description</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <a href="/" class="btn btn-secondary">Back to App</a>
  </div>
</body>
</html>`);
    } else {
      // Ensure an array is always returned
      res.json(Array.isArray(categories) ? categories : (categories ? [categories] : []));
    }
  } catch (e) {
    console.error('❌ Error fetching categories:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/categories', async (req, res) => {
  console.log('➕ POST /api/categories - Creating new category:', req.body);
  try {
    const category = await Category.create(req.body);
    console.log('✅ Category created successfully:', category._id);
    res.status(201).json(category);
  } catch (e) {
    console.error('❌ Error creating category:', e.message);
    res.status(400).json({ error: e.message });
  }
});

app.put('/api/categories/:id', async (req, res) => {
  try {
    const updated = await Category.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(updated);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.delete('/api/categories/:id', async (req, res) => {
  try {
    await Category.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Sales basic endpoints (optional starter)
app.get('/api/sales', async (req, res) => {
  console.log('💰 GET /api/sales - Fetching sales with filters:', req.query);
  try {
    const filter = {};
  if (req.query.branchId && req.query.branchId !== 'undefined' && req.query.branchId.trim() !== '') filter.branchId = req.query.branchId;
    if (req.query.from || req.query.to) {
      filter.date = {};
      if (req.query.from) filter.date.$gte = new Date(req.query.from);
      if (req.query.to) filter.date.$lte = new Date(req.query.to);
    }
    const sales = await Sale.find(filter).sort({ date: -1 }).populate('branchId', 'name');
    console.log(`✅ Found ${sales.length} sales records`);
    // Always return JSON for API endpoints - ignore Accept header
    const wantsHtml = false;
    if (wantsHtml) {
    const rows = sales
      .map(
        (s) => `
          <tr>
            <td>${s._id}</td>
            <td>${s.date ? new Date(s.date).toISOString().slice(0,10) : ''}</td>
            <td>${s.branchId && s.branchId.name ? s.branchId.name : s.branchId}</td>
            <td>${(s.total ?? 0).toLocaleString()}</td>
            <td>${(s.costTotal ?? 0).toLocaleString()}</td>
            <td>${(s.profit ?? 0).toLocaleString()}</td>
            <td>${s.category || ''}</td>
          </tr>`
      )
      .join('');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Sales</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style> body{padding:20px} table{background:#fff} </style>
</head>
<body>
  <div class="container">
    <h1 class="mb-4">Sales</h1>
    <table class="table table-striped table-bordered">
      <thead><tr><th>_id</th><th>Date</th><th>Branch</th><th>Total</th><th>Cost</th><th>Profit</th><th>Category</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <a href="/" class="btn btn-secondary">Back to App</a>
  </div>
</body>
</html>`);
    } else {
      res.json(sales);
    }
  } catch (e) {
    console.error('❌ Error fetching sales:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/sales', async (req, res) => {
  console.log('➕ POST /api/sales - Creating new sale:', req.body);
  try {
    const sale = await Sale.create(req.body);
    console.log('✅ Sale created successfully:', sale._id);
    res.status(201).json(sale);
  } catch (e) {
    console.error('❌ Error creating sale:', e.message);
    res.status(400).json({ error: e.message });
  }
});

// Update a sale
app.put('/api/sales/:id', async (req, res) => {
  console.log('✏️ PUT /api/sales/:id - Updating sale', req.params.id, req.body);
  try {
    const updated = await Sale.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updated) return res.status(404).json({ error: 'Sale not found' });
    console.log('✅ Sale updated:', updated._id);
    res.json(updated);
  } catch (e) {
    console.error('❌ Error updating sale:', e.message);
    res.status(400).json({ error: e.message });
  }
});

// Delete a sale
app.delete('/api/sales/:id', async (req, res) => {
  console.log('🗑️ DELETE /api/sales/:id - Deleting sale', req.params.id);
  try {
    const deleted = await Sale.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Sale not found' });
    console.log('✅ Sale deleted:', deleted._id);
    res.json({ ok: true });
  } catch (e) {
    console.error('❌ Error deleting sale:', e.message);
    res.status(400).json({ error: e.message });
  }
});

// Admin-protected actions (verify ADMIN_PASSWORD from .env)
app.post('/api/admin/delete', async (req, res) => {
  try {
    const { resource, id, password } = req.body || {};
    const expected = String(process.env.ADMIN_PASSWORD || '');
    const provided = String(password || '');
    if (!expected) {
      console.error('🔐 Admin password not configured on server (process.env.ADMIN_PASSWORD empty)');
      return res.status(500).json({ error: 'Admin password not configured on server' });
    }
    // Trim both sides to avoid accidental whitespace mismatch
    if (provided.trim() !== expected.trim()) {
      console.warn('🔒 Admin auth failed: provided.length=%d expected.length=%d', provided.length, expected.length);
      // Do not reveal password content in logs
      return res.status(403).json({ error: 'Invalid admin password' });
    }

    if (!resource || !id) return res.status(400).json({ error: 'resource and id are required' });

    let deleted = null;
    if (resource === 'sales') {
      deleted = await Sale.findByIdAndDelete(id);
    } else if (resource === 'branches') {
      deleted = await Branch.findByIdAndDelete(id);
      // also remove sales belonging to the branch for consistency
      await Sale.deleteMany({ branchId: id });
    } else if (resource === 'categories') {
      deleted = await Category.findByIdAndDelete(id);
      // Note: we do not delete sales when removing a category. Sales keep their category text.
    } else {
      return res.status(400).json({ error: 'Unknown resource type' });
    }

    if (!deleted) return res.status(404).json({ error: 'Record not found' });
    return res.json({ ok: true });
  } catch (e) {
    console.error('❌ Admin delete error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// Admin-protected update endpoint
app.post('/api/admin/update', async (req, res) => {
  try {
    const { resource, id, payload, password } = req.body || {};
    const expected = String(process.env.ADMIN_PASSWORD || '');
    const provided = String(password || '');
    if (!expected) {
      console.error('🔐 Admin password not configured on server (process.env.ADMIN_PASSWORD empty)');
      return res.status(500).json({ error: 'Admin password not configured on server' });
    }
    if (provided.trim() !== expected.trim()) {
      console.warn('🔒 Admin auth failed (update): provided.length=%d expected.length=%d', provided.length, expected.length);
      return res.status(403).json({ error: 'Invalid admin password' });
    }

    if (!resource || !id || !payload) return res.status(400).json({ error: 'resource, id and payload are required' });

    let updated = null;
    if (resource === 'sales') {
      updated = await Sale.findByIdAndUpdate(id, payload, { new: true });
    } else if (resource === 'branches') {
      updated = await Branch.findByIdAndUpdate(id, payload, { new: true });
    } else if (resource === 'categories') {
      updated = await Category.findByIdAndUpdate(id, payload, { new: true });
    } else {
      return res.status(400).json({ error: 'Unknown resource type' });
    }

    if (!updated) return res.status(404).json({ error: 'Record not found' });
    return res.json(updated);
  } catch (e) {
    console.error('❌ Admin update error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// Temporary debug endpoint to check ADMIN_PASSWORD equality/length (local debugging only)
app.post('/api/admin/check', (req, res) => {
  try {
    const provided = String((req.body && req.body.password) || '');
    const expected = String(process.env.ADMIN_PASSWORD || '');
    const match = provided.trim() === expected.trim();
    // Return non-sensitive diagnostics: lengths and boolean match
    return res.json({ ok: match, providedLength: provided.length, expectedLength: expected.length });
  } catch (e) {
    console.error('Admin check error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Seed default branches and categories on first run (idempotent)
async function seedDefaultData() {
  console.log('🌱 Starting database seeding...');
  
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
  
  console.log('🎉 Database seeding completed!');
}

mongoose.connection.once('open', () => {
  console.log('🔗 MongoDB connection opened, starting seeding process...');
  seedDefaultData().catch((e) => {
    console.error('❌ Seed error:', e.message);
    console.error('🔍 Full error:', e);
  });
});

// Catch-all for API routes that don't exist
app.get('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found', path: req.path });
});

// Serve static frontend (index.html) from project root - MUST be after ALL API routes
const clientDir = path.resolve(__dirname, '..');
app.use('/', express.static(clientDir));
console.log('📁 Serving static files from:', clientDir);

// Start server
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
  console.log('📋 Branches: GET /api/branches');
  console.log('🏷️ Categories: GET /api/categories');
  console.log('💰 Sales: GET /api/sales');
  console.log('🎉 ==========================================');
});






// import express from 'express';
// import mongoose from 'mongoose';
// import cors from 'cors';
// import morgan from 'morgan';
// import dotenv from 'dotenv';
// import path from 'path';
// import { fileURLToPath } from 'url';

// dotenv.config();

// const app = express();
// const port = process.env.PORT || 4000;
// const mongoUri = process.env.MONGODB_URI || process.env.MONGO_URL || 'mongodb+srv://onlydevsx_db_user:aN0cWgqkOWo4rhiD@cluster0.jfuzynl.mongodb.net/sales_dashboard?retryWrites=true&w=majority&appName=Cluster0';
// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

// app.use(cors());
// app.use(express.json({ limit: '1mb' }));
// app.use(morgan('dev'));

// // Serve static frontend (index.html) from project root
// const clientDir = path.resolve(__dirname, '..');
// app.use('/', express.static(clientDir));

// // Mongo connection (✅ added clear logs)
// console.log('🟡 Attempting to connect to MongoDB...');
// console.log('🔗 Using URI:', mongoUri.includes('@') ? 'Atlas Cluster' : 'Local MongoDB');

// mongoose
//   .connect(mongoUri, { autoIndex: true })
//   .then(() => {
//     console.log('✅ MongoDB connected successfully!');
//   })
//   .catch((err) => {
//     console.error('❌ MongoDB connection error:', err.message);
//     process.exit(1);
//   });

// // Schemas/Models
// const BranchSchema = new mongoose.Schema(
//   {
//     name: { type: String, required: true },
//     address: { type: String, default: '' },
//     phone: { type: String, default: '' },
//     email: { type: String, default: '' }
//   },
//   { timestamps: true }
// );

// const SaleSchema = new mongoose.Schema(
//   {
//     branchId: { type: mongoose.Schema.Types.ObjectId, ref: 'Branch', required: true },
//     date: { type: Date, required: true },
//     items: [
//       {
//         sku: String,
//         name: String,
//         quantity: Number,
//         unitPrice: Number,
//         cost: Number
//       }
//     ],
//     total: Number,
//     costTotal: Number,
//     profit: Number,
//     category: String
//   },
//   { timestamps: true }
// );

// const Branch = mongoose.model('Branch', BranchSchema);
// const Sale = mongoose.model('Sale', SaleSchema);

// // Settings (singleton)
// const SettingsSchema = new mongoose.Schema(
//   {
//     companyName: { type: String, default: '' },
//     currency: { type: String, default: 'PKR' },
//     dateFormat: { type: String, default: 'DD/MM/YYYY' },
//     itemsPerPage: { type: Number, default: 10 },
//     defaultCostPercent: { type: Number, default: 70 }
//   },
//   { timestamps: true }
// );
// const Settings = mongoose.model('Settings', SettingsSchema);

// // Health
// app.get('/api/health', (req, res) => {
//   res.json({ ok: true });
// });

// // Settings API
// app.get('/api/settings', async (req, res) => {
//   let settings = await Settings.findOne();
//   if (!settings) {
//     settings = await Settings.create({});
//   }
//   const wantsHtml = req.accepts(['html', 'json']) === 'html';
//   if (wantsHtml) {
//     res.send(`<!DOCTYPE html>
// <html lang="en">
// <head>
//   <meta charset="UTF-8" />
//   <meta name="viewport" content="width=device-width, initial-scale=1.0" />
//   <title>Settings</title>
//   <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
//   <style> body{padding:20px} table{background:#fff} </style>
// </head>
// <body>
//   <div class="container">
//     <h1 class="mb-4">Settings</h1>
//     <table class="table table-striped table-bordered w-auto">
//       <tbody>
//         <tr><th scope="row">Company Name</th><td>${settings.companyName || ''}</td></tr>
//         <tr><th scope="row">Currency</th><td>${settings.currency || ''}</td></tr>
//         <tr><th scope="row">Date Format</th><td>${settings.dateFormat || ''}</td></tr>
//         <tr><th scope="row">Items Per Page</th><td>${Number(settings.itemsPerPage || 10)}</td></tr>
//         <tr><th scope="row">Default Cost %</th><td>${Number(settings.defaultCostPercent ?? 70)}%</td></tr>
//       </tbody>
//     </table>
//     <a href="/" class="btn btn-secondary">Back to App</a>
//   </div>
// </body>
// </html>`);
//   } else {
//     res.json(settings);
//   }
// });

// app.put('/api/settings', async (req, res) => {
//   try {
//     const update = {
//       companyName: req.body.companyName ?? '',
//       currency: req.body.currency ?? 'PKR',
//       dateFormat: req.body.dateFormat ?? 'DD/MM/YYYY',
//       itemsPerPage: Number(req.body.itemsPerPage ?? 10),
//       defaultCostPercent: req.body.defaultCostPercent !== undefined ? Number(req.body.defaultCostPercent) : undefined
//     };
//     Object.keys(update).forEach((k) => update[k] === undefined && delete update[k]);
//     const settings = await Settings.findOneAndUpdate({}, update, { new: true, upsert: true });
//     res.json(settings);
//   } catch (e) {
//     res.status(400).json({ error: e.message });
//   }
// });

// // Branches CRUD
// app.get('/api/branches', async (req, res) => {
//   const branches = await Branch.find().sort({ createdAt: -1 });
//   res.json(branches);
// });

// app.post('/api/branches', async (req, res) => {
//   try {
//     const branch = await Branch.create(req.body);
//     res.status(201).json(branch);
//   } catch (e) {
//     res.status(400).json({ error: e.message });
//   }
// });

// app.put('/api/branches/:id', async (req, res) => {
//   try {
//     const updated = await Branch.findByIdAndUpdate(req.params.id, req.body, { new: true });
//     res.json(updated);
//   } catch (e) {
//     res.status(400).json({ error: e.message });
//   }
// });

// app.delete('/api/branches/:id', async (req, res) => {
//   try {
//     await Branch.findByIdAndDelete(req.params.id);
//     await Sale.deleteMany({ branchId: req.params.id });
//     res.json({ ok: true });
//   } catch (e) {
//     res.status(400).json({ error: e.message });
//   }
// });

// // Sales endpoints
// app.get('/api/sales', async (req, res) => {
//   const filter = {};
//   if (req.query.branchId) filter.branchId = req.query.branchId;
//   if (req.query.from || req.query.to) {
//     filter.date = {};
//     if (req.query.from) filter.date.$gte = new Date(req.query.from);
//     if (req.query.to) filter.date.$lte = new Date(req.query.to);
//   }
//   const sales = await Sale.find(filter).sort({ date: -1 }).populate('branchId', 'name');
//   res.json(sales);
// });

// app.post('/api/sales', async (req, res) => {
//   try {
//     const sale = await Sale.create(req.body);
//     res.status(201).json(sale);
//   } catch (e) {
//     res.status(400).json({ error: e.message });
//   }
// });

// app.listen(port, () => {
//   console.log(`🚀 Server listening on port ${port}`);
// });






// // import express from 'express';
// // import mongoose from 'mongoose';
// // import cors from 'cors';
// // import morgan from 'morgan';
// // import dotenv from 'dotenv';
// // import path from 'path';
// // import { fileURLToPath } from 'url';

// // dotenv.config();

// // const app = express();
// // const port = process.env.PORT || 4000;
// // const mongoUri = process.env.MONGODB_URI || process.env.MONGO_URL || 'mongodb+srv://onlydevsx_db_user:aN0cWgqkOWo4rhiD@cluster0.jfuzynl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
// // const __filename = fileURLToPath(import.meta.url);
// // const __dirname = path.dirname(__filename);

// // app.use(cors());
// // app.use(express.json({ limit: '1mb' }));
// // app.use(morgan('dev'));

// // // Serve static frontend (index.html) from project root
// // const clientDir = path.resolve(__dirname, '..');
// // app.use('/', express.static(clientDir));

// // // Mongo connection
// // mongoose
// //   .connect(mongoUri, { autoIndex: true })
// //   .then(() => console.log('MongoDB connected'))
// //   .catch((err) => {
// //     console.error('MongoDB connection error:', err.message);
// //     process.exit(1);
// //   });

// // // Schemas/Models
// // const BranchSchema = new mongoose.Schema(
// //   {
// //     name: { type: String, required: true },
// //     address: { type: String, default: '' },
// //     phone: { type: String, default: '' },
// //     email: { type: String, default: '' }
// //   },
// //   { timestamps: true }
// // );

// // const SaleSchema = new mongoose.Schema(
// //   {
// //     branchId: { type: mongoose.Schema.Types.ObjectId, ref: 'Branch', required: true },
// //     date: { type: Date, required: true },
// //     items: [
// //       {
// //         sku: String,
// //         name: String,
// //         quantity: Number,
// //         unitPrice: Number,
// //         cost: Number
// //       }
// //     ],
// //     total: Number,
// //     costTotal: Number,
// //     profit: Number,
// //     category: String
// //   },
// //   { timestamps: true }
// // );

// // const Branch = mongoose.model('Branch', BranchSchema);
// // const Sale = mongoose.model('Sale', SaleSchema);
// // // Settings (singleton)
// // const SettingsSchema = new mongoose.Schema(
// //   {
// //     companyName: { type: String, default: '' },
// //     currency: { type: String, default: 'PKR' },
// //     dateFormat: { type: String, default: 'DD/MM/YYYY' },
// //     itemsPerPage: { type: Number, default: 10 },
// //     defaultCostPercent: { type: Number, default: 70 }
// //   },
// //   { timestamps: true }
// // );
// // const Settings = mongoose.model('Settings', SettingsSchema);

// // // Health
// // app.get('/api/health', (req, res) => {
// //   res.json({ ok: true });
// // });

// // // Settings API
// // app.get('/api/settings', async (req, res) => {
// //   let settings = await Settings.findOne();
// //   if (!settings) {
// //     settings = await Settings.create({});
// //   }
// //   const wantsHtml = req.accepts(['html', 'json']) === 'html';
// //   if (wantsHtml) {
// //     res.send(`<!DOCTYPE html>
// // <html lang="en">
// // <head>
// //   <meta charset="UTF-8" />
// //   <meta name="viewport" content="width=device-width, initial-scale=1.0" />
// //   <title>Settings</title>
// //   <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
// //   <style> body{padding:20px} table{background:#fff} </style>
// // </head>
// // <body>
// //   <div class="container">
// //     <h1 class="mb-4">Settings</h1>
// //     <table class="table table-striped table-bordered w-auto">
// //       <tbody>
// //         <tr><th scope="row">Company Name</th><td>${settings.companyName || ''}</td></tr>
// //         <tr><th scope="row">Currency</th><td>${settings.currency || ''}</td></tr>
// //         <tr><th scope="row">Date Format</th><td>${settings.dateFormat || ''}</td></tr>
// //         <tr><th scope="row">Items Per Page</th><td>${Number(settings.itemsPerPage || 10)}</td></tr>
// //         <tr><th scope="row">Default Cost %</th><td>${Number(settings.defaultCostPercent ?? 70)}%</td></tr>
// //       </tbody>
// //     </table>
// //     <a href="/" class="btn btn-secondary">Back to App</a>
// //   </div>
// // </body>
// // </html>`);
// //   } else {
// //     res.json(settings);
// //   }
// // });

// // app.put('/api/settings', async (req, res) => {
// //   try {
// //     const update = {
// //       companyName: req.body.companyName ?? '',
// //       currency: req.body.currency ?? 'PKR',
// //       dateFormat: req.body.dateFormat ?? 'DD/MM/YYYY',
// //       itemsPerPage: Number(req.body.itemsPerPage ?? 10),
// //       defaultCostPercent: req.body.defaultCostPercent !== undefined ? Number(req.body.defaultCostPercent) : undefined
// //     };
// //     // Remove undefined to avoid overwriting with undefined
// //     Object.keys(update).forEach((k) => update[k] === undefined && delete update[k]);
// //     const settings = await Settings.findOneAndUpdate({}, update, { new: true, upsert: true });
// //     res.json(settings);
// //   } catch (e) {
// //     res.status(400).json({ error: e.message });
// //   }
// // });

// // // Branches CRUD
// // app.get('/api/branches', async (req, res) => {
// //   const branches = await Branch.find().sort({ createdAt: -1 });
// //   const wantsHtml = req.accepts(['html', 'json']) === 'html';
// //   if (wantsHtml) {
// //     const rows = branches
// //       .map(
// //         (b) => `
// //           <tr>
// //             <td>${b._id}</td>
// //             <td>${b.name}</td>
// //             <td>${b.address || ''}</td>
// //             <td>${b.phone || ''}</td>
// //             <td>${b.email || ''}</td>
// //           </tr>`
// //       )
// //       .join('');
// //     res.send(`<!DOCTYPE html>
// // <html lang="en">
// // <head>
// //   <meta charset="UTF-8" />
// //   <meta name="viewport" content="width=device-width, initial-scale=1.0" />
// //   <title>Branches</title>
// //   <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
// //   <style> body{padding:20px} table{background:#fff} </style>
// // </head>
// // <body>
// //   <div class="container">
// //     <h1 class="mb-4">Branches</h1>
// //     <table class="table table-striped table-bordered">
// //       <thead><tr><th>_id</th><th>Name</th><th>Address</th><th>Phone</th><th>Email</th></tr></thead>
// //       <tbody>${rows}</tbody>
// //     </table>
// //     <a href="/" class="btn btn-secondary">Back to App</a>
// //   </div>
// // </body>
// // </html>`);
// //   } else {
// //     res.json(branches);
// //   }
// // });

// // app.post('/api/branches', async (req, res) => {
// //   try {
// //     const branch = await Branch.create(req.body);
// //     res.status(201).json(branch);
// //   } catch (e) {
// //     res.status(400).json({ error: e.message });
// //   }
// // });

// // app.put('/api/branches/:id', async (req, res) => {
// //   try {
// //     const updated = await Branch.findByIdAndUpdate(req.params.id, req.body, { new: true });
// //     res.json(updated);
// //   } catch (e) {
// //     res.status(400).json({ error: e.message });
// //   }
// // });

// // app.delete('/api/branches/:id', async (req, res) => {
// //   try {
// //     await Branch.findByIdAndDelete(req.params.id);
// //     await Sale.deleteMany({ branchId: req.params.id });
// //     res.json({ ok: true });
// //   } catch (e) {
// //     res.status(400).json({ error: e.message });
// //   }
// // });

// // // Sales basic endpoints (optional starter)
// // app.get('/api/sales', async (req, res) => {
// //   const filter = {};
// //   if (req.query.branchId) filter.branchId = req.query.branchId;
// //   if (req.query.from || req.query.to) {
// //     filter.date = {};
// //     if (req.query.from) filter.date.$gte = new Date(req.query.from);
// //     if (req.query.to) filter.date.$lte = new Date(req.query.to);
// //   }
// //   const sales = await Sale.find(filter).sort({ date: -1 }).populate('branchId', 'name');
// //   const wantsHtml = req.accepts(['html', 'json']) === 'html';
// //   if (wantsHtml) {
// //     const rows = sales
// //       .map(
// //         (s) => `
// //           <tr>
// //             <td>${s._id}</td>
// //             <td>${s.date ? new Date(s.date).toISOString().slice(0,10) : ''}</td>
// //             <td>${s.branchId && s.branchId.name ? s.branchId.name : s.branchId}</td>
// //             <td>${(s.total ?? 0).toLocaleString()}</td>
// //             <td>${(s.costTotal ?? 0).toLocaleString()}</td>
// //             <td>${(s.profit ?? 0).toLocaleString()}</td>
// //             <td>${s.category || ''}</td>
// //           </tr>`
// //       )
// //       .join('');
// //     res.send(`<!DOCTYPE html>
// // <html lang="en">
// // <head>
// //   <meta charset="UTF-8" />
// //   <meta name="viewport" content="width=device-width, initial-scale=1.0" />
// //   <title>Sales</title>
// //   <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
// //   <style> body{padding:20px} table{background:#fff} </style>
// // </head>
// // <body>
// //   <div class="container">
// //     <h1 class="mb-4">Sales</h1>
// //     <table class="table table-striped table-bordered">
// //       <thead><tr><th>_id</th><th>Date</th><th>Branch</th><th>Total</th><th>Cost</th><th>Profit</th><th>Category</th></tr></thead>
// //       <tbody>${rows}</tbody>
// //     </table>
// //     <a href="/" class="btn btn-secondary">Back to App</a>
// //   </div>
// // </body>
// // </html>`);
// //   } else {
// //     res.json(sales);
// //   }
// // });

// // app.post('/api/sales', async (req, res) => {
// //   try {
// //     const sale = await Sale.create(req.body);
// //     res.status(201).json(sale);
// //   } catch (e) {
// //     res.status(400).json({ error: e.message });
// //   }
// // });

// // app.listen(port, () => {
// //   console.log(`Server listening on http://localhost:${port}`);
// // });








