require('dotenv').config(); 
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { OAuth2Client } = require('google-auth-library');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.set('trust proxy', 1); 

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public'));

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("FATAL SECURITY ERROR: JWT_SECRET is missing or too short. Server shutting down.");
  process.exit(1);
}

const GOOGLE_CLIENT_ID = '572901406239-ft74dvvuomeimdndcu3bqnrhnvmr63ur.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

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

app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const { email, password, username } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Please enter email and password' });
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).json({ error: 'Invalid email format' });
    if (password.length < 1 || password.length > 72) return res.status(400).json({ error: 'Password is invalid' });
    if (username && username.length > 20) return res.status(400).json({ error: 'Username is too long' });

    const { data: existingUser } = await supabase.from('users').select('email').eq('email', email).single();
    if (existingUser) return res.status(400).json({ error: 'Registration failed. Please try logging in.' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const { error } = await supabase.from('users').insert([{ email, password: hashedPassword, username: username || email.split('@')[0], balance: 0 }]);

    if (error) throw error;
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error("Register Error:", error.message);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Please enter email and password' });
    const { data: user, error } = await supabase.from('users').select('id, email, username, balance, password').eq('email', email).single();
    if (error || !user || !user.password) return res.status(400).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ message: 'Login successful', token, user: { id: user.id, email: user.email, username: user.username || user.email.split('@')[0], balance: user.balance || 0 } });
  } catch (error) {
    res.status(500).json({ error: 'Server error during login' });
  }
});

app.post('/api/auth/google', authLimiter, async (req, res) => {
  try {
    const { idToken } = req.body;
    const ticket = await googleClient.verifyIdToken({ idToken: idToken, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const { email, name } = payload;
    let { data: user } = await supabase.from('users').select('*').eq('email', email).single();
    if (!user) {
      const { data: newUser, error } = await supabase.from('users').insert([{ email, password: '', username: name || email.split('@')[0], balance: 0 }]).select().single();
      if (error) throw error;
      user = newUser;
    }
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ message: 'Google Login successful', token, user: { id: user.id, email: user.email, username: user.username, balance: user.balance || 0 } });
  } catch (error) {
    console.error("Google Auth Error:", error.message);
    res.status(401).json({ error: 'Google authentication failed' });
  }
});

app.post('/api/buy-proxy', authenticateToken, async (req, res) => {
  try {
    const { plan } = req.body;
    const userId = req.user.id; 
    const { data, error } = await supabase.rpc('purchase_plan', { p_user_id: userId, p_plan_id: plan });
    if (error) {
      if (error.message.includes('insufficient_balance')) return res.status(400).json({ error: 'Insufficient balance' });
      if (error.message.includes('invalid_plan')) return res.status(400).json({ error: 'Invalid plan' });
      return res.status(500).json({ error: 'Server error during purchase' });
    }
    const { data: userData } = await supabase.from('users').select('balance').eq('id', userId).single();
    const session = Array.isArray(data) ? data[0] : data;
    res.json({ message: 'Purchase successful', newBalance: userData.balance, proxy: { host: session.host, port: session.port, username: session.proxy_username, password: session.proxy_password, dataLimit: session.plan_id } });
  } catch (error) {
    res.status(500).json({ error: 'Server error during purchase' });
  }
});

app.post('/api/change-password', authenticateToken, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.id;
    if (!newPassword || newPassword.length > 72) return res.status(400).json({ error: 'Invalid password' });
    const { data: user, error } = await supabase.from('users').select('password').eq('id', userId).single();
    if (error || !user) return res.status(404).json({ error: 'User not found' });
    if (user.password) {
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Incorrect old password' });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(newPassword, salt);
    await supabase.from('users').update({ password: hashedNewPassword }).eq('id', userId);
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Server error during password change' });
  }
});

app.get('/api/proxies', authenticateToken, async (req, res) => {
  try {
    const response = await axios.get('https://proxmint.com/api/free-proxies?protocol=socks5&anonymity=elite&countryCode=us&limit=100');
    const rows = response.data.rows || [];
    const bestProxies = rows.sort((a, b) => a.latencyMs - b.latencyMs).slice(0, 10).map(p => ({ ip: p.ip, port: p.port, country: 'United States', latency: p.latencyMs }));
    res.json({ proxies: bestProxies });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch proxies', proxies: [] });
  }
});

// ==========================================
// 🚀 مسار التحقق من FaucetPay
// ==========================================
app.post('/api/verify-faucetpay', authenticateToken, async (req, res) => {
  const { txId, amount } = req.body;
  const userId = req.user.id;

  if (!txId || !amount) return res.status(400).json({ error: 'Missing transaction ID or amount' });

  try {
    // 1. التحقق من عدم استخدام رقم العملية مسبقاً في قاعدة البيانات
    const { data: existingTx } = await supabase.from('transactions').select('id').eq('txid', txId).single();
    if (existingTx) return res.status(400).json({ error: 'Transaction ID already used' });

    // 2. الاتصال بـ FaucetPay API للتحقق من العملية
    // ملاحظة: يعتمد FaucetPay على التحقق عبر الـ IPN أو API. هنا نستخدم API التحقق.
    const FAUCETPAY_API_KEY = process.env.FAUCETPAY_API_KEY;
    if (!FAUCETPAY_API_KEY) {
        return res.status(500).json({ error: 'FaucetPay API Key is missing in server config' });
    }

    // استدعاء واجهة FaucetPay (كمثال، قد تحتاج لتعديل الرابط حسب توثيقهم الرسمي)
    // في الغالب، التحقق يتم عبر الـ IPN. لكن إذا كان لديهم endpoint للتحقق من TxID:
    const response = await axios.get(`https://faucetpay.io/api/v1/checktransaction`, {
      params: {
        api_key: FAUCETPAY_API_KEY,
        txid: txId
      }
    });

    // التحقق من نجاح الاستجابة والمبلغ
    if (!response.data || response.data.status !== 200 || parseFloat(response.data.amount) < parseFloat(amount)) {
       return res.status(400).json({ error: 'Transaction not found or invalid amount' });
    }

    // 3. تحديث رصيد المستخدم
    const { data: userData, error: userError } = await supabase.from('users').select('balance').eq('id', userId).single();
    if (userError) throw userError;

    const newBalance = (userData.balance || 0) + parseFloat(amount);
    const { error: updateError } = await supabase.from('users').update({ balance: newBalance }).eq('id', userId);
    if (updateError) throw updateError;

    // 4. تسجيل العملية
    await supabase.from('transactions').insert([{ user_id: userId, amount: parseFloat(amount), txid: txId, type: 'faucetpay_topup', status: 'completed' }]);

    res.json({ message: 'Payment verified successfully', newBalance: newBalance });

  } catch (error) {
    console.error("FaucetPay Verification Error:", error.message);
    res.status(500).json({ error: 'Server error during payment verification' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));