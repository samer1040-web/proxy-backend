const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { SocksProxyAgent } = require('socks-proxy-agent');

const app = express();
app.use(cors());

// دالة لجلب البروكسيات من مصدر ProxyScrape
async function fetchFromProxyScrape() {
  try {
    const res = await axios.get('https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/countries/us/socks5/data.json');
    return res.data.map(p => ({ ...p, source: 'proxyscrape' }));
  } catch (e) {
    console.error('ProxyScrape failed:', e.message);
    return [];
  }
}

// دالة لجلب البروكسيات من مصدر Proxmint
async function fetchFromProxmint() {
  try {
    const res = await axios.get('https://proxmint.com/api/free-proxies?protocol=socks5&anonymity=elite&countryCode=us&limit=150');
    return (res.data.rows || []).map(p => ({ ...p, source: 'proxmint' }));
  } catch (e) {
    console.error('Proxmint failed:', e.message);
    return [];
  }
}

app.get('/api/proxies', async (req, res) => {
  try {
    // جلب البيانات من المصدرين في نفس الوقت
    const [scrapeProxies, mintProxies] = await Promise.all([
      fetchFromProxyScrape(),
      fetchFromProxmint()
    ]);

    // دمج البروكسيات وإزالة التكرار
    const allProxies = [...scrapeProxies, ...mintProxies];
    const uniqueProxies = Array.from(
      new Map(allProxies.map(p => [`${p.ip}:${p.port}`, p])).values()
    );

    // ترتيب مبدئي حسب التقييم (إن وجد) والأخذ أفضل 35 للاختبار
    const topCandidates = uniqueProxies
      .sort((a, b) => (b.score || 0) - (a.score || 0))
      .slice(0, 35);

    // اختبار السرعة الحقيقي لكل بروكسي
    const speedTest = async (p) => {
      const agent = new SocksProxyAgent(`socks://${p.ip}:${p.port}`);
      const start = Date.now();
      try {
        await axios.get('https://api.ipify.org', { 
          httpAgent: agent, 
          httpsAgent: agent, 
          timeout: 5000 
        });
        return { ...p, actualLatency: Date.now() - start };
      } catch (err) {
        return null;
      }
    };

    const testedProxies = await Promise.all(topCandidates.map(p => speedTest(p)));

    // اختيار أسرع 10 بروكسيات فقط
    const fastProxies = testedProxies
      .filter(p => p !== null)
      .sort((a, b) => a.actualLatency - b.actualLatency)
      .slice(0, 10)
      .map(p => ({
        ip: p.ip,
        port: p.port,
        country: 'United States',
        latency: p.actualLatency
      }));

    res.json({ proxies: fastProxies });
  } catch (error) {
    console.error("Fetch error:", error.message);
    res.status(500).json({ error: 'Failed to fetch proxies', proxies: [] });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});