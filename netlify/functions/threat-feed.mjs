export default async (req, context) => {
  const now = Math.floor(Date.now() / 1000);
  const sixHoursAgo = now - 21600;

  const sources = {
    cisaKev: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ransomwareVictims: "https://api.ransomware.live/v2/recentvictims",
    iodaOutages: `https://api.ioda.inetintel.cc.gatech.edu/v2/outages/alerts?from=${sixHoursAgo}&until=${now}`,
    feodoC2: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
    gdeltGeo: "https://api.gdeltproject.org/api/v2/doc/doc?query=(geopolitical%20crisis%20OR%20military%20conflict%20OR%20critical%20infrastructure)&mode=ArtList&maxrecords=10&format=json",
    gdeltEnergy: "https://api.gdeltproject.org/api/v2/doc/doc?query=(power%20grid%20outage%20OR%20energy%20infrastructure%20attack%20OR%20pipeline%20disruption)&mode=ArtList&maxrecords=8&format=json"
  };

  const fetchJson = async (url) => {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 8000);
    try {
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { "User-Agent": "OSINT-SOC-Dashboard/1.0" }
      });
      clearTimeout(id);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      clearTimeout(id);
      return { error: e.message };
    }
  };

  const [kev, victims, outages, c2, geo, energy] = await Promise.all([
    fetchJson(sources.cisaKev),
    fetchJson(sources.ransomwareVictims),
    fetchJson(sources.iodaOutages),
    fetchJson(sources.feodoC2),
    fetchJson(sources.gdeltGeo),
    fetchJson(sources.gdeltEnergy)
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
    energy: energy?.articles || []
  };

  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, s-maxage=60, stale-while-revalidate=30"
    }
  });
};
