const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(cors());

app.get('/api/proxies', async (req, res) => {
  try {
    // جلب المزيد من البروكسيات لضمان وجود عدد كافٍ بعد الفلترة
    const response = await axios.get('https://proxmint.com/api/free-proxies?protocol=socks5&anonymity=elite&limit=200');
    
    const rows = response.data.rows || [];
    
    // فلترة البروكسيات: أمريكا فقط + جودة من متوسطة إلى عالية
    const filteredProxies = rows.filter(p => {
      const isUS = p.countryCode?.toLowerCase() === 'us' || p.countryName === 'United States';
      const isGoodSpeed = p.latencyMs >= 100 && p.latencyMs <= 1500; // سرعة جيدة (أقل من 1.5 ثانية)
      const isGoodRisk = p.uptimePct >= 80; // استقرار عالي (فوق 80%)
      return isUS && isGoodSpeed && isGoodRisk;
    });

    // ترتيب البروكسيات حسب التقييم (الأفضل أولاً) والأخذ أفضل 20
    const bestProxies = filteredProxies
      .sort((a, b) => b.score - a.score)
      .slice(0, 20)
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});