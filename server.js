const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(cors());

app.get('/api/proxies', async (req, res) => {
  try {
    // جلب أفضل البروكسيات من Proxmint
    const response = await axios.get('https://proxmint.com/api/free-proxies?protocol=socks5&anonymity=elite&sort=score&limit=50');
    
    const rows = response.data.rows || [];
    
    // ترتيبها حسب التقييم والأخذ أفضل 20
    const bestProxies = rows
      .sort((a, b) => b.score - a.score)
      .slice(0, 20)
      .map(p => ({
        ip: p.ip,
        port: p.port,
        country: p.countryName || p.countryCode || 'Unknown',
        latency: p.latencyMs || 999
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