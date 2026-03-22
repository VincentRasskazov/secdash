// --- UTILITIES ---
function sanitizeTarget(input) { return input.trim().replace(/^https?:\/\//, '').split('/')[0]; }

function logToConsole(message, type = "info") {
    const resultsDiv = document.getElementById('reconResults');
    let color = "text-slate-300";
    if (type === "success") color = "text-green-400";
    if (type === "warning") color = "text-yellow-400";
    if (type === "error") color = "text-red-400";
    if (type === "header") color = "text-blue-400 font-bold bg-blue-900/20 px-1 rounded mt-2 inline-block";
    if (type === "highlight") color = "text-fuchsia-400 font-bold";
    
    resultsDiv.innerHTML += `<span class='${color}'>${message}</span>\n`;
    resultsDiv.scrollTop = resultsDiv.scrollHeight;
}

function exportReport() {
    const resultsDiv = document.getElementById('reconResults');
    let textContent = resultsDiv.innerHTML.replace(/<br\s*[\/]?>/gi, "\n").replace(/<[^>]+>/g, "");
    if (textContent.includes("System idle")) return alert("Run a scan first.");
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([textContent], { type: 'text/plain' }));
    a.download = `SecDash_Report_${document.getElementById('targetInput').value || "target"}.txt`;
    a.click();
}

// --- RECON LOGIC (Upgraded) ---
async function runRecon() {
    let rawTarget = document.getElementById('targetInput').value;
    const resultsDiv = document.getElementById('reconResults');
    if (!rawTarget) return resultsDiv.innerHTML = "<span class='text-red-400'>[!] Target required.</span>";

    const target = sanitizeTarget(rawTarget);
    document.getElementById('targetInput').value = target; 
    resultsDiv.innerHTML = "";
    logToConsole(`[INIT] Engaging Target: ${target}\n`, "header");

    let ip = target; let isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);

    // 1. DNS RESOLUTION & TXT RECORDS (SPF/DMARC)
    if (!isIp) {
        logToConsole("[*] Querying DNS (NetworkCalc)...", "highlight");
        try {
            const dnsRes = await fetch(`https://networkcalc.com/api/dns/lookup/${target}`);
            const dnsData = await dnsRes.json();
            if (dnsData.records && dnsData.records.A) {
                ip = dnsData.records.A[0].address; logToConsole(`[+] IPv4: ${ip}`, "success");
            }
            // Check for SPF / DMARC in TXT records
            if (dnsData.records && dnsData.records.TXT) {
                const txtRecs = dnsData.records.TXT.map(t => t.replace(/['"]/g, ''));
                const spf = txtRecs.find(t => t.includes('v=spf1'));
                if (spf) logToConsole(`[+] SPF Record: ${spf}`, "success");
                else logToConsole(`[-] No SPF Record found (Spoofing possible?)`, "warning");
            } else logToConsole(`[-] No TXT Records found.`, "warning");
        } catch (e) { logToConsole(`[-] DNS failed: ${e.message}`, "warning"); }
    }

    // 2. GEOLOCATION
    logToConsole("\n[*] Geolocation (FreeIPAPI)...", "highlight");
    try {
        const geoRes = await fetch(`https://freeipapi.com/api/json/${ip}`);
        const geoData = await geoRes.json();
        if (geoData.countryName) logToConsole(`[+] ${geoData.cityName || 'Unknown'}, ${geoData.countryName} (ISP: ${geoData.isp})`, "success");
    } catch (e) { logToConsole(`[-] Geo failed.`, "warning"); }

    // 3. SUBDOMAINS
    if (!isIp) {
        logToConsole("\n[*] Subdomain Enumeration (HackerTarget)...", "highlight");
        try {
            const subRes = await fetch(`https://api.hackertarget.com/hostsearch/?q=${target}`);
            const subText = await subRes.text();
            if (!subText.includes("error")) {
                const subs = subText.split('\n').filter(Boolean);
                logToConsole(`[+] Found ${subs.length} subdomains. Top 5:`, "success");
                subs.slice(0, 5).forEach(s => logToConsole(`    -> ${s.split(',')[0]}`));
            }
        } catch (e) { logToConsole(`[-] Subdomain scan failed.`, "warning"); }
    }

    // 4. SHODAN PORTS & CVES
    logToConsole("\n[*] Shodan InternetDB...", "highlight");
    try {
        const shodanRes = await fetch(`https://internetdb.shodan.io/${ip}`);
        if (shodanRes.status !== 404) {
            const data = await shodanRes.json();
            logToConsole(`[+] Open Ports: ${data.ports ? data.ports.join(', ') : 'None'}`, "success");
            if (data.vulns && data.vulns.length > 0) logToConsole(`[!] CVEs: ${data.vulns.join(', ')}`, "error");
            else logToConsole(`[-] No CVEs mapped.`, "info");
        } else logToConsole(`[-] IP not in Shodan DB.`, "warning");
    } catch (e) { logToConsole(`[-] Shodan query failed.`, "warning"); }

    // 5. SECURITY HEADERS
    if (!isIp) {
        logToConsole("\n[*] Security Headers (HackerTarget)...", "highlight");
        try {
            const headerRes = await fetch(`https://api.hackertarget.com/httpheaders/?q=${target}`);
            const headerText = await headerRes.text();
            if (!headerText.includes("error")) {
                let notable = [];
                headerText.split('\n').forEach(line => {
                    let l = line.toLowerCase();
                    if (l.startsWith('server:') || l.startsWith('x-powered-by:') || l.startsWith('strict-transport-security:')) notable.push(line.trim());
                });
                if (notable.length > 0) notable.forEach(n => logToConsole(`[+] ${n}`, "success"));
                else logToConsole(`[-] No notable headers.`, "info");
            }
        } catch (e) { logToConsole(`[-] Header pull failed.`, "warning"); }
    }
    logToConsole(`\n[====== RECON COMPLETE ======]\n`, "header");
}

// --- PAYLOAD ARSENAL ---
const payloads = {
    // 💥 GOD MODE V2 (Massive compilation)
    godMode: `(async function(){ console.clear(); console.log('%c[+] SECDASH GOD MODE V2 ENGAGED', 'color:#ef4444; font-size:20px; font-weight:bold; text-shadow: 0 0 10px red;'); console.groupCollapsed('%c1. Tech Stack Profiler', 'color:#a855f7; font-weight:bold;'); const tech={React:!!window.React||!!document.querySelector('[data-reactroot], [data-reactid]'), Vue:!!window.Vue||!!window.__VUE__, Angular:!!window.angular||!!document.querySelector('[ng-version]'), NextJS:!!window.__NEXT_DATA__, NuxtJS:!!window.__NUXT__, WordPress:!!document.querySelector('link[href*="wp-content"]'), Shopify:!!window.Shopify, jQuery:!!window.jQuery}; console.table(tech); console.groupEnd(); console.groupCollapsed('%c2. Storage & Auth Tokens', 'color:#3b82f6; font-weight:bold;'); console.log('Cookies:', document.cookie); console.log('LocalStorage:', {...localStorage}); console.log('SessionStorage:', {...sessionStorage}); const findJWT=obj=>Object.entries(obj).filter(([k,v])=>typeof v==='string'&&v.match(/^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$/)); console.log('JWTs Found:', [...findJWT(localStorage), ...findJWT(sessionStorage)]); console.groupEnd(); console.groupCollapsed('%c3. DOM Secrets & Endpoints', 'color:#10b981; font-weight:bold;'); const html=document.documentElement.innerHTML; console.log('API Endpoints:', [...new Set(html.match(/(https?:\\/\\/[^"']+|\\/[a-zA-Z0-9_\\-\\/]+\\.json|\\/api\\/[a-zA-Z0-9_\\-\\/]+)/gi))]); console.log('API Keys/Secrets:', html.match(/(api_key|apikey|secret|token|password)["\\s:=]+["']?([a-zA-Z0-9\\-_]{16,})["']?/gi)); console.log('Hidden Inputs:', Array.from(document.querySelectorAll('input[type="hidden"]')).map(i=>({name:i.name, value:i.value}))); console.groupEnd(); console.groupCollapsed('%c4. Vulnerability Sinks', 'color:#f59e0b; font-weight:bold;'); console.log('DOM XSS Sinks:', Array.from(document.scripts).filter(s=>s.innerHTML.includes('innerHTML')||s.innerHTML.includes('eval('))); console.log('External Links (Target Blank?):', Array.from(document.links).filter(a=>!a.href.includes(location.hostname)).map(a=>a.href)); console.groupEnd(); console.log('%c[✓] Scan Complete.', 'color:#10b981; font-weight:bold;'); })();`,

    // WAPPALYZER CLONE
    techProfiler: `(function(){ console.log('%c[+] Client-Side Tech Profiler', 'color:#6366f1; font-weight:bold; font-size:14px;'); const p={}; p['React'] = !!window.React || !!document.querySelector('[data-reactroot], [data-reactid]'); p['Vue.js'] = !!window.Vue || !!window.__VUE__; p['Angular'] = !!window.angular || !!document.querySelector('[ng-app], [ng-version]'); p['Next.js'] = !!window.__NEXT_DATA__; p['Nuxt.js'] = !!window.__NUXT__; p['Gatsby'] = !!document.querySelector('#___gatsby'); p['WordPress'] = !!document.querySelector('link[href*="wp-content"], link[href*="wp-includes"]'); p['Shopify'] = !!window.Shopify; p['Magento'] = !!window.Mage; p['jQuery'] = !!window.jQuery; p['Google Analytics'] = !!window.ga || !!window.gtag || !!window._gaq; p['Stripe'] = !!window.Stripe; console.table(Object.fromEntries(Object.entries(p).filter(([k,v])=>v))); })();`,

    // INDEXEDDB DUMPER
    indexedDB: `(async function(){ console.log('%c[+] Dumping IndexedDB Databases', 'color:#10b981; font-weight:bold;'); const dbs = await indexedDB.databases(); if(dbs.length===0){ console.log('[-] No IndexedDB databases found.'); return; } for(let dbInfo of dbs){ const req = indexedDB.open(dbInfo.name, dbInfo.version); req.onsuccess = (e) => { const db = e.target.result; console.group('Database:', db.name); Array.from(db.objectStoreNames).forEach(storeName => { const tx = db.transaction(storeName, 'readonly'); const store = tx.objectStore(storeName); const getAll = store.getAll(); getAll.onsuccess = () => console.log('Store ['+storeName+']:', getAll.result); }); setTimeout(()=>console.groupEnd(), 500); }; } })();`,

    // CLICKJACKING TESTER
    clickjacking: `(function(){ document.body.innerHTML = '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#000;z-index:9999;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#0f0;font-family:monospace;"><h2>Clickjacking Test</h2><p>If the site loads in the frame below, it is VULNERABLE to Clickjacking (Missing X-Frame-Options/CSP).</p><iframe src="'+location.href+'" style="width:80%;height:70%;border:5px solid red;background:#fff;"></iframe><button onclick="location.reload()" style="margin-top:20px;padding:10px;background:#f00;color:#fff;cursor:pointer;">Close Test</button></div>'; })();`,

    // Standard Payloads
    subdomains: `const dom = document.documentElement.innerHTML; const subs = dom.match(/[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/g); const uniqueSubs = [...new Set(subs)].filter(s => s.endsWith(location.hostname.split('.').slice(-2).join('.'))); console.log('Subdomains in DOM:', uniqueSubs);`,
    apiEndpoints: `const html = document.documentElement.innerHTML; const endpoints = html.match(/(https?:\\/\\/[^"']+|\\/[a-zA-Z0-9_\\-\\/]+\\.json|\\/api\\/[a-zA-Z0-9_\\-\\/]+)/gi); console.log('Potential API Endpoints:', [...new Set(endpoints)]);`,
    comments: `var iterator = document.createNodeIterator(document, NodeFilter.SHOW_COMMENT, () => NodeFilter.FILTER_ACCEPT); var curNode; while (curNode = iterator.nextNode()) { console.log(curNode.nodeValue); }`,
    cookies: `let c=document.cookie.split(';');console.table(c.map(x=>{let y=x.split('=');return{Name:y[0].trim(),Value:y[1]}}));`,
    storage: `console.log('--- LocalStorage ---'); console.table({...localStorage}); console.log('--- SessionStorage ---'); console.table({...sessionStorage});`,
    jwtHunter: `const findJWT = (obj) => Object.entries(obj).filter(([k, v]) => typeof v === 'string' && v.match(/^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$/)); console.log('JWTs in LocalStorage:', findJWT(localStorage)); console.log('JWTs in SessionStorage:', findJWT(sessionStorage));`,
    xssSinks: `const scripts = document.querySelectorAll('script'); let sinks = []; scripts.forEach(s => { if(s.innerHTML.includes('innerHTML') || s.innerHTML.includes('eval(') || s.innerHTML.includes('document.write')) sinks.push(s.src || 'Inline Script'); }); console.log('Potential DOM XSS Sinks:', sinks);`,
    sensitiveData: `const html = document.documentElement.innerHTML; console.log('Emails:', [...new Set(html.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\\.[a-zA-Z0-9_-]+)/gi))]); console.log('Keys:', html.match(/(api_key|apikey|secret|token)["\\s:=]+["']?([a-zA-Z0-9\\-_]{16,})["']?/gi));`,
    prototypePollution: `let testObj = {}; Object.prototype.polluted = "yes"; if(testObj.polluted === "yes") console.log("[!] VULNERABLE: Object.prototype is mutable."); else console.log("[-] SECURE: Object.prototype locked."); delete Object.prototype.polluted;`,
    xhrHook: `(function() { const origOpen = XMLHttpRequest.prototype.open; XMLHttpRequest.prototype.open = function() { console.log('%c[XHR]', 'color: #f59e0b', arguments[1]); return origOpen.apply(this, arguments); }; const origFetch = window.fetch; window.fetch = async function(...args) { console.log('%c[Fetch]', 'color: #10b981', args[0]); return origFetch.apply(this, args); }; console.log('Network traffic hooked.'); })();`,
    wsMonitor: `(function(){ const OrigWS = window.WebSocket; window.WebSocket = function(url, protocols) { console.log('%c[WS Connected]', 'color: #8b5cf6', url); const ws = new OrigWS(url, protocols); ws.addEventListener('message', e => console.log('%c[WS In]', 'color: #a78bfa', e.data)); const origSend = ws.send; ws.send = function(data) { console.log('%c[WS Out]', 'color: #c4b5fd', data); return origSend.apply(this, arguments); }; return ws; }; console.log('WebSockets hooked.'); })();`,
    hiddenInputs: `document.querySelectorAll('input[type="hidden"]').forEach(i => { i.type = 'text'; i.style.border = '2px solid red'; console.log('Revealed:', i.name, '=', i.value); });`,
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
