# Global OSINT & Cyber Threat Intelligence Monitor

Dashboard OSINT e Cyber Threat Intelligence pronta per il deploy su Netlify con aggiornamento automatico ogni 60 secondi tramite Netlify Functions ed Edge Caching.

## Fonti Integrate
- **CVE Sfruttate Attivamente:** CISA KEV (Known Exploited Vulnerabilities)
- **URL Distribuzione Malware:** abuse.ch URLhaus API (tramite `URLHAUS_AUTH_KEY`)
- **Server C2 & Botnet:** abuse.ch Feodo Tracker
- **Gang Ransomware & Settori Colpiti:** Ransomware.live API v2
- **Outage di Rete & Anomalie BGP:** IODA (Georgia Tech / CAIDA)
- **Geopolitica & Infrastrutture Energetiche:** GDELT Project 2.0 API

## Configurazione Variabili d'Ambiente su Netlify
1. Vai su **Site configuration -> Environment variables**.
2. Aggiungi `URLHAUS_AUTH_KEY` con la tua chiave personale abuse.ch.
3. Avvia un nuovo deploy per rendere effettiva la variabile.
