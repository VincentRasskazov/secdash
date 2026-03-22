// --- UTILITIES ---
function sanitizeTarget(input) { return input.trim().replace(/^https?:\/\//, '').split('/')[0]; }

function logToConsole(message, type = "info") {
    const resultsDiv = document.getElementById('reconResults');
    let color = "text-slate-300";
    if (type === "success") color = "text-green-400";
    if (type === "warning") color = "text-yellow-400";
    if (type === "error") color = "text-red-400";
    if (type === "header") color = "text-blue-400 font-bold bg-blue-900/20 px-1 rounded mt-2 inline-block shadow border border-blue-900";
    if (type === "highlight") color = "text-fuchsia-400 font-bold";
    
    resultsDiv.innerHTML += `<span class='${color}'>${message}</span>\n`;
    resultsDiv.scrollTop = resultsDiv.scrollHeight;
}

function exportReport() {
    const resultsDiv = document.getElementById('reconResults');
    let textContent = resultsDiv.innerHTML.replace(/<br\s*[\/]?>/gi, "\n").replace(/<[^>]+>/g, "");
    if (textContent.includes("System online")) return alert("Run a scan first.");
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([textContent], { type: 'text/plain' }));
    a.download = `SecDash_V6_${document.getElementById('targetInput').value}.txt`;
    a.click();
}

// --- V6 RECON LOGIC ---
async function runRecon() {
    let rawTarget = document.getElementById('targetInput').value;
    const resultsDiv = document.getElementById('reconResults');
    if (!rawTarget) return resultsDiv.innerHTML = "<span class='text-red-400'>[!] Target required.</span>";

    const target = sanitizeTarget(rawTarget);
    document.getElementById('targetInput').value = target; 
    resultsDiv.innerHTML = "";
    logToConsole(`[INIT] Engaging Target: ${target}\n`, "header");

    let ip = target; let isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);

    // 1. DNS & TXT
    if (!isIp) {
        logToConsole("[*] NetworkCalc: DNS Resolution & TXT...", "highlight");
        try {
            const dnsRes = await fetch(`https://networkcalc.com/api/dns/lookup/${target}`);
            const dnsData = await dnsRes.json();
            if (dnsData.records && dnsData.records.A) {
                ip = dnsData.records.A[0].address; logToConsole(`[+] IPv4: ${ip}`, "success");
            }
            if (dnsData.records && dnsData.records.TXT) {
                const spf = dnsData.records.TXT.map(t=>t.replace(/['"]/g, '')).find(t=>t.includes('v=spf1'));
                if (spf) logToConsole(`[+] SPF Record: ${spf}`, "success");
                else logToConsole(`[-] No SPF Record found (Spoof spoof?)`, "warning");
            }
        } catch (e) { logToConsole(`[-] DNS failed.`, "warning"); }
    }

    // 2. WHOIS DATA (NEW)
    if (!isIp) {
        logToConsole("\n[*] NetworkCalc: WHOIS Data...", "highlight");
        try {
            const whoRes = await fetch(`https://networkcalc.com/api/whois/${target}`);
            const whoData = await whoRes.json();
            if (whoData.status === "OK" && whoData.whois) {
                logToConsole(`[+] Registrar: ${whoData.whois.registrar || 'Unknown'}`, "success");
                logToConsole(`[+] Created: ${whoData.whois.creation_date || 'Unknown'}`, "success");
            } else logToConsole(`[-] WHOIS data hidden.`, "info");
        } catch (e) { logToConsole(`[-] WHOIS failed.`, "warning"); }
    }

    // 3. SSL/TLS CERT (NEW)
    if (!isIp) {
        logToConsole("\n[*] NetworkCalc: SSL/TLS Analyzer...", "highlight");
        try {
            const sslRes = await fetch(`https://networkcalc.com/api/security/certificate/${target}`);
            const sslData = await sslRes.json();
            if (sslData.status === "OK" && sslData.certificate) {
                logToConsole(`[+] Issuer: ${sslData.certificate.issuer.organization || sslData.certificate.issuer.common_name}`, "success");
                logToConsole(`[+] Expires: ${sslData.certificate.valid_to}`, "success");
                if (sslData.certificate.subject_alt_names) {
                    logToConsole(`[+] SANs (Alt Names): ${sslData.certificate.subject_alt_names.slice(0,3).join(', ')}${sslData.certificate.subject_alt_names.length>3?'...':''}`, "success");
                }
            } else logToConsole(`[-] No SSL cert data found.`, "warning");
        } catch (e) { logToConsole(`[-] SSL fetch failed.`, "warning"); }
    }

    // 4. WAYBACK MACHINE (NEW)
    if (!isIp) {
        logToConsole("\n[*] Archive.org: Wayback Machine Probe...", "highlight");
        try {
            // Use CDX API to get 3 random snapshots to prove it's archived without crashing browser
            const wbRes = await fetch(`https://web.archive.org/cdx/search/cdx?url=${target}/*&output=json&collapse=urlkey&limit=3`);
            const wbData = await wbRes.json();
            if (wbData && wbData.length > 1) { // Index 0 is header row
                logToConsole(`[+] Domain is archived! Found historical endpoints:`, "success");
                wbData.slice(1).forEach(row => logToConsole(`    -> ${row[2]}`));
            } else logToConsole(`[-] No archive snapshots found.`, "info");
        } catch (e) { logToConsole(`[-] Wayback Machine blocked by CORS.`, "warning"); }
    }

    // 5. SHODAN PORTS
    logToConsole("\n[*] Shodan: Port & Vuln Scan...", "highlight");
    try {
        const shodanRes = await fetch(`https://internetdb.shodan.io/${ip}`);
        if (shodanRes.status !== 404) {
            const data = await shodanRes.json();
            logToConsole(`[+] Open Ports: ${data.ports ? data.ports.join(', ') : 'None'}`, "success");
            if (data.vulns && data.vulns.length > 0) logToConsole(`[!] CVEs: ${data.vulns.join(', ')}`, "error");
        } else logToConsole(`[-] IP not in Shodan DB.`, "warning");
    } catch (e) { logToConsole(`[-] Shodan failed.`, "warning"); }

    // 6. HEADERS
    if (!isIp) {
        logToConsole("\n[*] HackerTarget: Security Headers...", "highlight");
        try {
            const headerRes = await fetch(`https://api.hackertarget.com/httpheaders/?q=${target}`);
            const headerText = await headerRes.text();
            if (!headerText.includes("error")) {
                let notable = [];
                headerText.split('\n').forEach(line => {
                    let l = line.toLowerCase();
                    if (l.startsWith('server:') || l.startsWith('x-powered-by:') || l.startsWith('strict-transport-security:') || l.startsWith('access-control-')) notable.push(line.trim());
                });
                if (notable.length > 0) notable.forEach(n => logToConsole(`[+] ${n}`, "success"));
            }
        } catch (e) { logToConsole(`[-] Header pull failed.`, "warning"); }
    }
    logToConsole(`\n[====== RECON COMPLETE ======]\n`, "header");
}

// --- V6 PAYLOAD ARSENAL ---
const payloads = {
    // 💥 GOD MODE V3 (Now includes PostMessage & Framework states)
    godMode: `(async function(){ console.clear(); console.log('%c[+] SECDASH GOD MODE V3 ENGAGED', 'color:#ef4444; font-size:20px; font-weight:bold;'); console.groupCollapsed('%c1. Tech Stack Profiler', 'color:#a855f7; font-weight:bold;'); const tech={React:!!window.React, Vue:!!window.__VUE__, Angular:!!window.angular, NextJS:!!window.__NEXT_DATA__, NuxtJS:!!window.__NUXT__, WordPress:!!document.querySelector('link[href*="wp-content"]'), jQuery:!!window.jQuery}; console.table(tech); console.groupEnd(); console.groupCollapsed('%c2. Storage & Auth Tokens', 'color:#3b82f6; font-weight:bold;'); console.log('Cookies:', document.cookie); console.log('LocalStorage:', {...localStorage}); console.log('SessionStorage:', {...sessionStorage}); const findJWT=obj=>Object.entries(obj).filter(([k,v])=>typeof v==='string'&&v.match(/^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$/)); console.log('JWTs Found:', [...findJWT(localStorage), ...findJWT(sessionStorage)]); console.groupEnd(); console.groupCollapsed('%c3. DOM Secrets & Endpoints', 'color:#10b981; font-weight:bold;'); const html=document.documentElement.innerHTML; console.log('API Endpoints:', [...new Set(html.match(/(https?:\\/\\/[^"']+|\\/[a-zA-Z0-9_\\-\\/]+\\.json|\\/api\\/[a-zA-Z0-9_\\-\\/]+)/gi))]); console.log('API Keys/Secrets:', html.match(/(api_key|apikey|secret|token|password)["\\s:=]+["']?([a-zA-Z0-9\\-_]{16,})["']?/gi)); console.log('Internal IPs:', html.match(/(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[0-1])\\.\\d{1,3}\\.\\d{1,3})/g)); console.groupEnd(); console.groupCollapsed('%c4. Vulnerability Sinks', 'color:#f59e0b; font-weight:bold;'); console.log('DOM XSS Sinks:', Array.from(document.scripts).filter(s=>s.innerHTML.includes('innerHTML')||s.innerHTML.includes('eval('))); console.groupEnd(); console.log('%c[+] Initiating Background PostMessage Listener...', 'color:#f59e0b;'); window.addEventListener('message', function(e){ console.log('%c[PostMessage Intercept]', 'color:#ef4444; font-weight:bold;', {Origin: e.origin, Data: e.data}); }); console.log('%c[✓] Initial Scan Complete. PostMessage listener is active.', 'color:#10b981; font-weight:bold;'); })();`,

    // New Payloads
    postMessage: `window.addEventListener('message', function(e){ console.log('%c[PostMessage Intercept]', 'color:#ef4444; font-weight:bold; background:#fff; padding:2px;', {Origin: e.origin, Data: e.data, Source: e.source}); }); console.log('Listening for cross-origin messages...');`,
    internalIPs: `const html = document.documentElement.innerHTML; const ips = html.match(/(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[0-1])\\.\\d{1,3}\\.\\d{1,3})/g); console.log('Potential Internal IPs found:', [...new Set(ips)]);`,
    reduxState: `console.log('--- React/Redux State Dump ---'); console.log('__NEXT_DATA__:', window.__NEXT_DATA__); console.log('__REDUX_STATE__:', window.__REDUX_STATE__); console.log('__INITIAL_STATE__:', window.__INITIAL_STATE__); console.log('__NUXT__:', window.__NUXT__);`,
    lsPoison: `console.log('Poisoning LocalStorage...'); Object.keys(localStorage).forEach(k => { localStorage.setItem(k, 'SECDASH_POISON_TEST_"\'><img src=x onerror=alert(1)>'); }); console.log('Done. Reload the page and check for alerts or broken layouts.');`,

    // Existing / Upgraded
    techProfiler: `(function(){ console.log('%c[+] Client-Side Tech Profiler', 'color:#6366f1; font-weight:bold;'); const p={React:!!window.React||!!document.querySelector('[data-reactroot]'), Vue:!!window.Vue||!!window.__VUE__, Angular:!!window.angular, NextJS:!!window.__NEXT_DATA__, NuxtJS:!!window.__NUXT__, WordPress:!!document.querySelector('link[href*="wp-content"]'), Shopify:!!window.Shopify, jQuery:!!window.jQuery}; console.table(Object.fromEntries(Object.entries(p).filter(([k,v])=>v))); })();`,
    indexedDB: `(async function(){ const dbs = await indexedDB.databases(); if(dbs.length===0) return console.log('No IndexedDB found.'); for(let dbInfo of dbs){ const req = indexedDB.open(dbInfo.name, dbInfo.version); req.onsuccess = (e) => { const db = e.target.result; console.group('DB:', db.name); Array.from(db.objectStoreNames).forEach(s => { const tx = db.transaction(s, 'readonly'); tx.objectStore(s).getAll().onsuccess = (res) => console.log(s, res.target.result); }); setTimeout(()=>console.groupEnd(), 500); }; } })();`,
    subdomains: `const dom = document.documentElement.innerHTML; const subs = dom.match(/[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/g); console.log('Subdomains in DOM:', [...new Set(subs)].filter(s => s.endsWith(location.hostname.split('.').slice(-2).join('.'))));`,
    apiEndpoints: `const html = document.documentElement.innerHTML; console.log('API Endpoints:', [...new Set(html.match(/(https?:\\/\\/[^"']+|\\/[a-zA-Z0-9_\\-\\/]+\\.json|\\/api\\/[a-zA-Z0-9_\\-\\/]+)/gi))]);`,
    storage: `console.log('LocalStorage:', {...localStorage}); console.log('SessionStorage:', {...sessionStorage});`,
    cookies: `let c=document.cookie.split(';');console.table(c.map(x=>{let y=x.split('=');return{Name:y[0].trim(),Value:y[1]}}));`,
    jwtHunter: `const findJWT = (obj) => Object.entries(obj).filter(([k, v]) => typeof v === 'string' && v.match(/^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$/)); console.log('JWTs:', [...findJWT(localStorage), ...findJWT(sessionStorage)]);`,
    xssSinks: `const scripts = Array.from(document.scripts).filter(s => s.innerHTML.includes('innerHTML') || s.innerHTML.includes('eval(')); console.log('DOM Sinks:', scripts);`,
    sensitiveData: `const html = document.documentElement.innerHTML; console.log('Emails:', [...new Set(html.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\\.[a-zA-Z0-9_-]+)/gi))]); console.log('Keys:', html.match(/(api_key|apikey|secret|token)["\\s:=]+["']?([a-zA-Z0-9\\-_]{16,})["']?/gi));`,
    prototypePollution: `let testObj = {}; Object.prototype.polluted = "yes"; if(testObj.polluted === "yes") console.log("[!] VULNERABLE to Prototype Pollution."); else console.log("[-] SECURE."); delete Object.prototype.polluted;`,
    xhrHook: `(function() { const origOpen = XMLHttpRequest.prototype.open; XMLHttpRequest.prototype.open = function() { console.log('%c[XHR]', 'color: #f59e0b', arguments[1]); return origOpen.apply(this, arguments); }; const origFetch = window.fetch; window.fetch = async function(...args) { console.log('%c[Fetch]', 'color: #10b981', args[0]); return origFetch.apply(this, args); }; console.log('Network traffic hooked.'); })();`,
    wsMonitor: `(function(){ const OrigWS = window.WebSocket; window.WebSocket = function(url, protocols) { console.log('%c[WS Connected]', 'color: #8b5cf6', url); const ws = new OrigWS(url, protocols); ws.addEventListener('message', e => console.log('%c[WS In]', 'color: #a78bfa', e.data)); const origSend = ws.send; ws.send = function(data) { console.log('%c[WS Out]', 'color: #c4b5fd', data); return origSend.apply(this, arguments); }; return ws; }; console.log('WebSockets hooked.'); })();`,
    enableRightClick: `document.addEventListener('contextmenu', e => e.stopPropagation(), true); document.addEventListener('copy', e => e.stopPropagation(), true); document.addEventListener('selectstart', e => e.stopPropagation(), true); console.log('Right-click protections bypassed.');`
};

function copyPayload(type) {
    const code = payloads[type] || `console.error("Payload not found.");`;
    navigator.clipboard.writeText(code).then(() => {
        const toast = document.getElementById('copyToast');
        toast.classList.remove('hidden');
        setTimeout(() => toast.classList.add('hidden'), 2000);
    });
}
