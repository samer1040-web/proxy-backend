require('dotenv').config(); 
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet'); // تمت الإضافة
const crypto = require('crypto'); // لتوليد كلمات مرور عشوائية
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1); 

// 1. إضافة ترويسات الأمان (Helmet)
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10kb' })); // منع إرسال بيانات ضخمة تستنزف الخادم
app.use(express.static('public'));

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// 2. تأمين مفتاح JWT
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("FATAL SECURITY ERROR: JWT_SECRET is missing or too short. Server shutting down.");
  process.exit(1);
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many requests from this IP, please try again later.' }
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user; 
    next();
  });
};

// 3. مسار التسجيل (محمي ضد المدخلات الضارة وكشف الحسابات)
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { email, password, username } = req.body;
    
    if (!email || !password) return res.status(400).json({ error: 'Please enter email and password' });

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ error: 'Invalid email format' });

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({ error: 'Password must be between 8 and 72 characters' });
    }

    if (username && username.length > 20) {
      return res.status(400).json({ error: 'Username is too long' });
    }

    const { data: existingUser } = await supabase.from('users').select('email').eq('email', email).single();
    
    // منع كشف الحسابات: رسالة عامة بدلاً من "User already exists"
    if (existingUser) return res.status(400).json({ error: 'Registration failed. Please try logging in.' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const { error } = await supabase.from('users').insert([{ 
      email, password: hashedPassword, username: username || email.split('@')[0], balance: 0 
    }]);

    if (error) throw error;
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error("Register Error:", error.message);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// 4. مسار الدخول (جلب الحقول المطلوبة فقط + تحقق أساسي)
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) return res.status(400).json({ error: 'Please enter email and password' });

    // نجلب فقط الحقول التي نحتاجها بدلاً من select('*')
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, username, balance, password')
      .eq('email', email)
      .single();

    if (error || !user) return res.status(400).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1d' });

    res.json({ 
      message: 'Login successful', 
      token,
      user: { id: user.id, email: user.email, username: user.username || user.email.split('@')[0], balance: user.balance || 0 }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error during login' });
  }
});

// 5. مسار شراء الباقة (محمي ضد الخصم المزدوج + كلمة مرور عشوائية)
app.post('/api/buy-proxy', authenticateToken, async (req, res) => {
  try {
    const { plan } = req.body;
    const userId = req.user.id; 

    const planPrices = {
      '300MB': 0.25,
      '600MB': 0.50,
      '1000MB': 1.00 // تم إصلاحها لتطابق الواجهة
    };
    
    const price = planPrices[plan];
    if (!price) return res.status(400).json({ error: 'Invalid plan' });

    const { data: user, error } = await supabase.from('users').select('balance').eq('id', userId).single();
    if (error || !user) return res.status(404).json({ error: 'User not found' });

    if (user.balance < price) return res.status(400).json({ error: 'Insufficient balance' });

    const { data: updatedUser, error: updateError } = await supabase
      .from('users')
      .update({ balance: user.balance - price })
      .eq('id', userId)
      .gte('balance', price) 
      .select('balance');

    if (updateError || !updatedUser || updatedUser.length === 0) {
      return res.status(400).json({ error: 'Insufficient balance or concurrent transaction' });
    }

    const newBalance = updatedUser[0].balance;

    // 6. توليد كلمة مرور عشوائية للبروكسي بدلاً من الثابتة
    const randomPassword = crypto.randomBytes(8).toString('hex');

    const mockProxy = {
      host: 'us-residential.hproxy.net', port: 8000,
      username: `user_${userId}_sess_${Math.floor(Math.random() * 10000)}`, 
      password: randomPassword, 
      dataLimit: plan
    };

    res.json({ message: 'Purchase successful', newBalance, proxy: mockProxy });
  } catch (error) {
    res.status(500).json({ error: 'Server error during purchase' });
  }
});

app.post('/api/change-password', authenticateToken, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.id;

    if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Please provide old and new password' });

    if (newPassword.length < 8 || newPassword.length > 72) {
      return res.status(400).json({ error: 'New password must be between 8 and 72 characters' });
    }

    const { data: user, error } = await supabase.from('users').select('password').eq('id', userId).single();
    if (error || !user) return res.status(404).json({ error: 'User not found' });

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Incorrect old password' });

    const salt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(newPassword, salt);

    await supabase.from('users').update({ password: hashedNewPassword }).eq('id', userId);

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error("Change Password Error:", error.message);
    res.status(500).json({ error: 'Server error during password change' });
  }
});

// مسار البروكسيات المجانية (محمي بدون حد أقصى كما طلبت)
app.get('/api/proxies', authenticateToken, async (req, res) => {
  try {
    const response = await axios.get('https://proxmint.com/api/free-proxies?protocol=socks5&anonymity=elite&countryCode=us&limit=100');
    const rows = response.data.rows || [];
    const bestProxies = rows.sort((a, b) => a.latencyMs - b.latencyMs).slice(0, 10).map(p => ({
      ip: p.ip, port: p.port, country: 'United States', latency: p.latencyMs
    }));
    res.json({ proxies: bestProxies });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch proxies', proxies: [] });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));