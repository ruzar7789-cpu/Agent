cat <<EOF > app.py
import streamlit as st
import socket
import requests
import whois
import ssl
import re
from pam_core import MaintenanceEngine

st.set_page_config(page_title="AGENT-CORE: REAL-TIME SUITE", layout="wide")
engine = MaintenanceEngine()

# Taktický kybernetický design
st.markdown("""
<style>
    .stApp { background-color: #020202; color: #00FF66; font-family: 'Courier New', monospace; }
    .card { border: 1px solid #00FF66; padding: 15px; margin: 10px 0px; background: #0a0a0a; border-radius: 4px; }
    h1, h2, h3 { color: #00FF66; text-shadow: 0 0 5px #00FF66; }
    .stButton>button { background: #000; color: #00FF66; border: 1px solid #00FF66; width: 100%; font-weight: bold; }
    .stButton>button:hover { background: #00FF66; color: #000; }
    .stProgress > div > div > div > div { background-color: #00FF66; }
</style>
""", unsafe_allow_html=True)

st.title("🕶️ AGENT-CORE: REAL-TIME INTELLIGENCE SUITE")

# GLOBÁLNÍ PANEL
st.markdown("### 🎯 GLOBÁLNÍ ZAMĚŘENÍ CÍLE")
target = st.text_input("Zadej doménu ke kompletní analýze:", "seznam.cz")

st.markdown("---")

# 10 plně funkčních, ostrých analytických záložen
tabs = st.tabs([
    "🎯 OSINT & IDENTITY", 
    "🛡️ SSL/TLS AUDIT", 
    "🔍 PORT & BANNERS", 
    "⚡ THREAT MATRIX", 
    "🦅 ELITE RECON", 
    "🩻 APP ARMOR", 
    "🌐 WAF DETECTOR",
    "🔗 SUPPLY CHAIN",
    "🧠 LIVE EXPLOITABILITY AUDIT",
    "📊 LOGS"
])

# Pomocná funkce pro vyčištění domény
def get_clean_target(t):
    return t.replace("https://", "").replace("http://", "").split("/")[0]

clean_target = get_clean_target(target)

# --- TAB 1: WHOIS ---
with tabs[0]:
    st.subheader("OSINT: Identity & Ownership")
    if st.button("ANALYZOVAT IDENTITU"):
        if not target: st.error("[-] Zadej cíl.")
        else:
            with st.spinner("[*] Těžím data z registrů..."):
                try:
                    w = whois.whois(clean_target)
                    st.json(w)
                    engine.log_operation("WHOIS", "SUCCESS", f"Identita {clean_target}", "HIGH")
                except Exception as e: st.error(f"Selhalo: {e}")

# --- TAB 2: SSL/TLS ---
with tabs[1]:
    st.subheader("TLS/SSL Forensic Handshake")
    if st.button("PROVĚŘIT CERTIFIKÁT"):
        with st.spinner("[*] Navazuji handshake..."):
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=clean_target) as s:
                    s.settimeout(4)
                    s.connect((clean_target, 443))
                    cert = s.getpeercert()
                    st.write(f"🔒 **Vystavitel:** {cert.get('issuer')}")
                    st.write(f"📅 **Expirace:** {cert.get('notAfter')}")
                    engine.log_operation("SSL", "SUCCESS", f"Audit TLS {clean_target}", "MEDIUM")
            except Exception as e: st.error(f"Handshake selhal: {e}")

# --- TAB 3: BANNER GRABBING ---
with tabs[2]:
    st.subheader("Banner Grabbing (Fingerprinting)")
    if st.button("OTISKOVAT SERVER"):
        with st.spinner("[*] Zachytávám surový otisk..."):
            try:
                s = socket.socket()
                s.settimeout(4)
                s.connect((clean_target, 80))
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                st.code(s.recv(1024).decode(errors='ignore'))
                engine.log_operation("FINGERPRINT", "SUCCESS", f"Otisk {clean_target}", "MEDIUM")
            except Exception as e: st.error(f"Selhalo: {e}")

# --- TAB 4: THREAT MATRIX ---
with tabs[3]:
    st.subheader("Cyber Threat Matrix & Security Score")
    if st.button("SPUSTIT ANALÝZU RIZIK"):
        with st.spinner("[*] Skenuji perimetr..."):
            ports = {22: "SSH", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT"}
            open_p = []
            score = 15
            for p, srv in ports.items():
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.0)
                    if s.connect_ex((clean_target, p)) == 0:
                        open_p.append(p)
                        score += 25
                    s.close()
                except: pass
            st.session_state['open_ports_detected'] = open_p
            st.write(f"### Celkový Risk Index: {score}%")
            st.progress(min(score / 100, 1.0))
            engine.log_operation("THREAT_MATRIX", "SUCCESS", f"Score {clean_target}: {score}%", "HIGH")

# --- TAB 5: ELITE RECON ---
with tabs[4]:
    st.subheader("🦅 Elite Passive Reconnaissance")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("AUDIT EMAILOVÉ OBRANY"):
            try:
                res = requests.get(f"https://cloudflare-dns.com/dns-query?name={clean_target}&type=TXT", headers={"Accept": "application/dns-json"}, timeout=5).json()
                spf, dmarc = False, False
                if "Answer" in res:
                    for ans in res["Answer"]:
                        if "v=spf1" in ans["data"]: spf = True
                        if "v=DMARC1" in ans["data"]: dmarc = True
                st.session_state['spf_status'] = spf
                st.session_state['dmarc_status'] = dmarc
                st.write(f"SPF: {'✅ OK' if spf else '❌ CHYBÍ'}")
                st.write(f"DMARC: {'✅ OK' if dmarc else '❌ CHYBÍ'}")
            except Exception as e: st.error(str(e))
    with col2:
        if st.button("VYSTLAČIT CT LOGY"):
            try:
                subdomains = set([item["name_value"].strip().lower() for item in requests.get(f"https://crt.sh/?q=%.{clean_target}&output=json", timeout=10).json() if "*" not in item["name_value"]])
                st.write(f"Nalezeno {len(subdomains)} subdomén. Prvních 10:")
                st.code("\n".join(list(subdomains)[:10]))
            except Exception as e: st.error(str(e))

# --- TAB 6: APP ARMOR ---
with tabs[5]:
    st.subheader("🩻 HTTP Application Armor")
    if st.button("PROVĚŘIT APLIKAČNÍ PANCÍŘ"):
        try:
            h = requests.head(f"https://{clean_target}", allow_redirects=True, timeout=5).headers
            st.session_state['missing_nosniff'] = not any(k.lower() == 'x-content-type-options' for k in h)
            st.json(dict(h))
        except Exception as e: st.error(str(e))

# --- TAB 7: WAF DETECTOR ---
with tabs[6]:
    st.subheader("🌐 WAF & CDN Shield Detector")
    if st.button("DETEKTOVAT WAF"):
        try:
            srv = requests.head(f"https://{clean_target}", timeout=5).headers.get("Server", "").lower()
            if "cloudflare" in srv: st.warning("Detekován Cloudflare WAF")
            else: st.success("Přímé spojení bez známého WAF")
        except Exception as e: st.error(str(e))

# --- TAB 8: SUPPLY CHAIN ---
with tabs[7]:
    st.subheader("🔗 Supply Chain & Third-Party Assets")
    if st.button("SKENOVAT EXTERNÍ ZÁVISLOSTI"):
        try:
            scripts = re.findall(r'src=["\'](https?://[^"\']+)["\']', requests.get(f"https://{clean_target}", timeout=5).text)
            ext = [s for s in scripts if clean_target not in s]
            st.write(f"Nalezeno {len(ext)} externích skriptů.")
            for s in ext[:5]: st.code(s)
        except Exception as e: st.error(str(e))

# --- TAB 9: OSTRÝ AUDIT EXPLOITABILITY (Živé dotazy) ---
with tabs[8]:
    st.subheader("🧠 Live Exploitability Audit (Real-Time Verification)")
    st.markdown("Tento modul provádí přímé síťové ověření zranitelností a testuje reakce serveru na nestandardní požadavky.")
    
    if st.button("SPUSTIT OSTRÝ AUDIT ZRANITELNOSTÍ"):
        with st.spinner(f"[*] Provádím aktivní analýzu na {clean_target}..."):
            
            # 1. TEST EXPOZICE CITLIVÝCH SOUBORŮ (Live HTTP probe)
            st.write("### 📂 1. Live Asset Exposure Verification")
            sensitive_paths = ["/.git/HEAD", "/.env", "/robots.txt", "/wp-admin/"]
            for path in sensitive_paths:
                try:
                    url = f"https://{clean_target}{path}"
                    res = requests.get(url, timeout=3, allow_redirects=False, headers={"User-Agent": "Mozilla/5.0"})
                    if res.status_code == 200:
                        st.error(f"🔴 EXPOZICE: Cesta {path} vrátila stav 200 OK! Soubor nebo adresář je přístupný.")
                    elif res.status_code in [401, 403]:
                        st.warning(f"🟡 RESTRIKCE: Cesta {path} existuje, ale přístup je zakázán ({res.status_code}).")
                    else:
                        st.success(f"🟢 BEZPEČNÉ: Cesta {path} vrátila stav {res.status_code} (Nedostupné).")
                except Exception as e:
                    st.caption(f"Chyba při kontrole {path}: {e}")
            
            # 2. AUDIT METOD SERVERU (HTTP Method Verb Tampering)
            st.write("### 🛠️ 2. HTTP Methods Validation")
            try:
                # Odeslání nestandardní / zakázané metody OPTIONS a TRACE
                res_options = requests.options(f"https://{clean_target}", timeout=3)
                allowed_methods = res_options.headers.get("Allow", res_options.headers.get("Access-Control-Allow-Methods", "Neznámé"))
                st.info(f"Podporované/Povolené metody serveru: `{allowed_methods}`")
                
                res_trace = requests.request("TRACE", f"https://{clean_target}", timeout=3)
                if res_trace.status_code == 200 and "TRACE" in res_trace.text:
                    st.error("🔴 ZRANITELNOST: Server podporuje metodu TRACE (Riziko Cross-Site Tracking / XST)!")
                else:
                    st.success("🟢 BEZPEČNÉ: Metoda TRACE je korektně zakázána nebo ignorována.")
            except Exception as e:
                st.caption(f"Chyba při validaci HTTP metod: {e}")

            # 3. KONTROLA STRUKTURY CORS (Cross-Origin Resource Sharing)
            st.write("### 🌐 3. CORS Configuration Probe")
            try:
                # Podvržení neplatného Origin pro test špatné konfigurace
                spoofed_headers = {"Origin": "https://evil-attacker.com"}
                res_cors = requests.get(f"https://{clean_target}", headers=spoofed_headers, timeout=3)
                cors_header = res_cors.headers.get("Access-Control-Allow-Origin", "")
                
                if cors_header == "*" or "evil-attacker.com" in cors_header:
                    st.error(f"🔴 ZRANITELNOST: Detekována nebezpečná CORS konfigurace! Server akceptuje libovolný původ: `{cors_header}`")
                else:
                    st.success(f"🟢 BEZPEČNÉ: CORS hlavičky jsou rigidní nebo chybí (výchozí bezpečný stav). Server nepropouští cizí domény.")
            except Exception as e:
                st.caption(f"Chyba při probe CORS: {e}")

            engine.log_operation("LIVE_AUDIT", "SUCCESS", f"Ostrý audit dokončen pro {clean_target}", "CRITICAL")

# --- TAB 10: LOGS ---
with tabs[9]:
    st.write("### Žurnál operací")
    for row in engine.get_history():
        st.write(f"[{row[4]}] {row[0]} -> {row[1]}")
EOF
