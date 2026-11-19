export default async (req, context) => {
  const now = Math.floor(Date.now() / 1000);
  const sixHoursAgo = now - 21600;
  const urlhausKey = process.env.URLHAUS_AUTH_KEY || "";

  const sources = {
    cisaKev: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ransomwareVictims: "https://api.ransomware.live/v2/recentvictims",
    iodaOutages: `https://api.ioda.inetintel.cc.gatech.edu/v2/outages/alerts?from=${sixHoursAgo}&until=${now}`,
    feodoC2: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
    gdeltGeo: "https://api.gdeltproject.org/api/v2/doc/doc?query=(geopolitical%20crisis%20OR%20military%20conflict%20OR%20critical%20infrastructure)&mode=ArtList&maxrecords=10&format=json",
    gdeltEnergy: "https://api.gdeltproject.org/api/v2/doc/doc?query=(power%20grid%20outage%20OR%20energy%20infrastructure%20attack%20OR%20pipeline%20disruption)&mode=ArtList&maxrecords=8&format=json"
  };

  const fetchJson = async (url, extraHeaders = {}) => {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 8000);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: {
          "User-Agent": "OSINT-SOC-Dashboard/1.0",
          ...extraHeaders
        }
      });
      clearTimeout(id);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      clearTimeout(id);
      return { error: e.message };
    }
  };

  const urlhausPromise = urlhausKey
    ? fetchJson("https://urlhaus-api.abuse.ch/v1/urls/recent/limit/15/", {
        "Auth-Key": urlhausKey
      })
    : Promise.resolve({ urls: [] });

  const [kev, victims, outages, c2, geo, energy, urlhausData] = await Promise.all([
    fetchJson(sources.cisaKev),
    fetchJson(sources.ransomwareVictims),
    fetchJson(sources.iodaOutages),
    fetchJson(sources.feodoC2),
    fetchJson(sources.gdeltGeo),
    fetchJson(sources.gdeltEnergy),
    urlhausPromise
  ]);

  const recentKev = Array.isArray(kev?.vulnerabilities)
    ? kev.vulnerabilities.slice(-10).reverse()
    : [];

  const recentVictims = Array.isArray(victims) ? victims.slice(0, 15) : [];
  const sectorCounts = {};
  const groupCounts = {};
  recentVictims.forEach(v => {
    const sec = v.activity || "Non classificato";
    const grp = v.group_name || "Sconosciuto";
    sectorCounts[sec] = (sectorCounts[sec] || 0) + 1;
    groupCounts[grp] = (groupCounts[grp] || 0) + 1;
  });

  const activeOutages = Array.isArray(outages?.data)
    ? outages.data.slice(0, 10)
    : [];

  const activeC2 = Array.isArray(c2) ? c2.slice(0, 12) : [];

  const recentMalwareUrls = Array.isArray(urlhausData?.urls)
    ? urlhausData.urls.slice(0, 10).map(u => ({
        url: u.url,
        host: u.host,
        status: u.url_status,
        threat: u.threat,
        dateAdded: u.date_added,
        reference: u.urlhaus_reference,
        tags: Array.isArray(u.tags) ? u.tags.slice(0, 3) : []
      }))
    : [];

  const payload = {
    timestamp: new Date().toISOString(),
    cve: recentKev,
    ransomware: {
      victims: recentVictims.slice(0, 8),
      sectors: Object.entries(sectorCounts).sort((a, b) => b[1] - a[1]).slice(0, 6),
      groups: Object.entries(groupCounts).sort((a, b) => b[1] - a[1]).slice(0, 6)
    },
    outages: activeOutages,
    c2: activeC2,
    geopolitics: geo?.articles || [],
    energy: energy?.articles || [],
    urlhaus: recentMalwareUrls
  };

  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, s-maxage=60, stale-while-revalidate=30"
    }
  });
};
