require('dotenv').config(); // قراءة ملف .env السري
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// إعداد الاتصال بقاعدة بيانات Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

const JWT_SECRET = 'ProxyNova_Super_Secret_Key_2024'; // مفتاح التشفير

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many requests from this IP, please try again later.' }
});

// ---------------------------------------------------------
// مسار التسجيل (Register) - متصل بـ Supabase
// ---------------------------------------------------------
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Please enter email and password' });

    // 1. التحقق إذا كان المستخدم موجوداً مسبقاً في قاعدة البيانات
    const { data: existingUser } = await supabase
      .from('users')
      .select('email')
      .eq('email', email)
      .single();

    if (existingUser) return res.status(400).json({ error: 'User already exists' });

    // 2. تشفير كلمة المرور
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 3. حفظ المستخدم الجديد في قاعدة البيانات
    const { error } = await supabase
      .from('users')
      .insert([{ 
        email: email, 
        password: hashedPassword, 
        balance: 0 
      }]);

    if (error) throw error;

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error("Register Error:", error.message);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// ---------------------------------------------------------
// مسار تسجيل الدخول (Login) - متصل بـ Supabase
// ---------------------------------------------------------
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Please enter email and password' });

    // 1. جلب المستخدم من قاعدة البيانات
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) return res.status(400).json({ error: 'Invalid credentials' });

    // 2. التحقق من كلمة المرور
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    // 3. إنشاء التوكن
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1d' });

    // 4. إرسال التوكن وبيانات المستخدم (مع الرصيد)
    res.json({ 
      message: 'Login successful', 
      token: token,
      user: { id: user.id, email: user.email, balance: user.balance || 0 }
    });
  } catch (error) {
    console.error("Login Error:", error.message);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// ---------------------------------------------------------
// مسار جلب البروكسيات المجانية (كما هو تماماً - لم نلمسه)
// ---------------------------------------------------------
app.get('/api/proxies', async (req, res) => {
  try {
    const response = await axios.get('https://proxmint.com/api/free-proxies?protocol=socks5&anonymity=elite&countryCode=us&limit=100');
    const rows = response.data.rows || [];

    const bestProxies = rows
      .sort((a, b) => a.latencyMs - b.latencyMs)
      .slice(0, 10)
      .map(p => ({
        ip: p.ip,
        port: p.port,
        country: 'United States',
        latency: p.latencyMs
      }));

    res.json({ proxies: bestProxies });
  } catch (error) {
    console.error("Fetch error:", error.message);
    res.status(500).json({ error: 'Failed to fetch proxies', proxies: [] });
  }
});

// ---------------------------------------------------------
// تشغيل الخادم
// ---------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});