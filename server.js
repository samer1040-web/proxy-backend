const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { SocksProxyAgent } = require('socks-proxy-agent'); // مكتبة فحص السرعة

const app = express();
app.use(cors());

app.get('/api/proxies', async (req, res) => {
  try {
    // جلب كمية كبيرة من البروكسيات
    const response = await axios.get('https://proxmint.com/api/free-proxies?protocol=socks5&anonymity=elite&limit=300');
    const rows = response.data.rows || [];
    
    // فلترة أولية: أمريكا فقط
    const usProxies = rows.filter(p => {
      const isUS = p.countryCode?.toLowerCase() === 'us' || p.countryName === 'United States';
      return isUS && p.uptimePct >= 60; 
    });

    // أخذ أفضل 25 بروكسي حسب تقييم الموقع لاختبارهم
    const topCandidates = usProxies.sort((a, b) => b.score - a.score).slice(0, 25);

    // اختبار السرعة الفعلي لكل بروكسي
    const speedTest = async (p) => {
      const agent = new SocksProxyAgent(`socks://${p.ip}:${p.port}`);
      const start = Date.now();
      try {
        // طلب ملف صغير جداً لقياس سرعة الاستجابة الحقيقية
        await axios.get('http://www.gstatic.com/generate_204', { 
          httpAgent: agent, 
          httpsAgent: agent, 
          timeout: 4000 // إذا تأخر أكثر من 4 ثواني، نعتبره بطيئاً
        });
        return { ...p, actualLatency: Date.now() - start };
      } catch (err) {
        return null; // البروكسي فشل في الاختبار
      }
    };

    // تشغيل الاختبار للجميع في نفس الوقت
    const testedProxies = await Promise.all(topCandidates.map(p => speedTest(p)));

    // تصفية البروكسيات التي فشلت، وترتيبها حسب السرعة الفعلية
    const fastProxies = testedProxies
      .filter(p => p !== null)
      .sort((a, b) => a.actualLatency - b.actualLatency)
      .slice(0, 10) // نرسل أسرع 10 بروكسيات فقط
      .map(p => ({
        ip: p.ip,
        port: p.port,
        country: 'United States',
        latency: p.actualLatency // نعرض السرعة الحقيقية
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