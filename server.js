const express = require('express');
const axios = require('axios');
const cors = require('cors');

const app = express();
app.use(cors());

app.get('/api/proxies', async (req, res) => {
  try {
    // جلب البروكسيات الأمريكية مباشرة من Proxmint
    const response = await axios.get('https://proxmint.com/api/free-proxies?protocol=socks5&anonymity=elite&countryCode=us&limit=100');
    const rows = response.data.rows || [];

    // ترتيبها حسب السرعة (الأقل هو الأسرع) وأخذ أفضل 10
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});