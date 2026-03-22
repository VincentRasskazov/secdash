// --- UTILITIES ---
function sanitizeTarget(input) {
    let clean = input.trim().replace(/^https?:\/\//, '').split('/')[0];
    return clean;
}

function logToConsole(message, type = "info") {
    const resultsDiv = document.getElementById('reconResults');
    let color = "text-slate-300";
    if (type === "success") color = "text-green-400";
    if (type === "warning") color = "text-yellow-400";
    if (type === "error") color = "text-red-400";
    if (type === "header") color = "text-blue-400 font-bold";
    
    resultsDiv.innerHTML += `<span class='${color}'>${message}</span>\n`;
    resultsDiv.scrollTop = resultsDiv.scrollHeight;
}

function exportReport() {
    const resultsDiv = document.getElementById('reconResults');
    const target = document.getElementById('targetInput').value || "report";
    
    // Strip HTML tags for clean text output
    let textContent = resultsDiv.innerHTML.replace(/<br\s*[\/]?>/gi, "\n").replace(/<[^>]+>/g, "");
    if (textContent.includes("System idle")) {
        alert("Run a scan first before exporting.");
        return;
    }

    const blob = new Blob([textContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SecDash_Report_${target}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// --- RECON LOGIC (Unchanged from v3, proven stable) ---
async function runRecon() {
    let rawTarget = document.getElementById('targetInput').value;
    const resultsDiv = document.getElementById('reconResults');
    if (!rawTarget) return resultsDiv.innerHTML = "<span class='text-red-400'>[!] Error: Target required.</span>";

    const target = sanitizeTarget(rawTarget);
    document.getElementById('targetInput').value = target; 
    resultsDiv.innerHTML = "";
    logToConsole(`[INIT] Engaging target: ${target}\n`, "header");

    let ip = target; let isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);

    // 1. RESOLVE DNS
    if (!isIp) {
        logToConsole("[*] Resolving DNS via NetworkCalc...");
        try {
            const dnsRes = await fetch(`https://networkcalc.com/api/dns/lookup/${target}`);
            const dnsData = await dnsRes.json();
            if (dnsData.status === "OK" && dnsData.records && dnsData.records.A) {
                ip = dnsData.records.A[0].address; logToConsole(`[+] Resolved IPv4: ${ip}\n`, "success");
            } else throw new Error("No A records found.");
        } catch (e) { logToConsole(`[-] DNS failed: ${e.message}\n`, "warning"); }
    }

    // 2. GEOLOCATION
    logToConsole("[*] Fetching Geolocation Data...");
    try {
        const geoRes = await fetch(`https://freeipapi.com/api/json/${ip}`);
        const geoData = await geoRes.json();
        if (geoData.countryName) logToConsole(`[+] Location: ${geoData.cityName || 'Unknown'}, ${geoData.countryName} (ISP: ${geoData.isp || 'N/A'})\n`, "success");
    } catch (e) { logToConsole(`[-] Geolocation fetch failed.\n`, "warning"); }

    // 3. SUBDOMAINS
    if (!isIp) {
        logToConsole("[*] Enumerating Subdomains...");
        try {
            const subRes = await fetch(`https://api.hackertarget.com/hostsearch/?q=${target}`);
            const subText = await subRes.text();
            if (!subText.includes("error")) {
                const subs = subText.split('\n').filter(line => line.trim() !== '');
                logToConsole(`[+] Found ${subs.length} subdomains. Displaying Top 5:`, "success");
                subs.slice(0, 5).forEach(s => logToConsole(`    -> ${s.split(',')[0]}`)); logToConsole("\n");
            }
        } catch (e) { logToConsole(`[-] Subdomain scan blocked.\n`, "warning"); }
    }

    // 4. SHODAN
    logToConsole("[*] Querying Shodan InternetDB...");
    try {
        const shodanRes = await fetch(`https://internetdb.shodan.io/${ip}`);
        if (shodanRes.status !== 404) {
            const data = await shodanRes.json();
            logToConsole(`[+] Open Ports: ${data.ports && data.ports.length > 0 ? data.ports.join(', ') : 'None'}`, "success");
            if (data.vulns && data.vulns.length > 0) logToConsole(`[!] Known CVEs: ${data.vulns.join(', ')}\n`, "error");
            else logToConsole(`[-] No direct CVEs mapped in InternetDB.\n`, "info");
        }
    } catch (e) { logToConsole(`[-] Shodan query failed.\n`, "warning"); }

    // 5. HEADERS
    if (!isIp) {
        logToConsole("[*] Pulling HTTP Security Headers...");
        try {
            const headerRes = await fetch(`https://api.hackertarget.com/httpheaders/?q=${target}`);
            const headerText = await headerRes.text();
            if (!headerText.includes("error")) {
                let notable = [];
                headerText.split('\n').forEach(line => {
                    let l = line.toLowerCase();
                    if (l.startsWith('server:') || l.startsWith('x-powered-by:') || l.startsWith('strict-transport-security:')) notable.push(line.trim());
                });
                if (notable.length > 0) logToConsole(`[+] Notable Headers:\n    ${notable.join('\n    ')}\n`, "success");
            }
        } catch (e) { logToConsole(`[-] Header pull failed.\n`, "warning"); }
    }
    logToConsole("[DONE] Reconnaissance complete.", "header");
}

// --- MASSIVE PAYLOAD DICTIONARY ---
const payloads = {
    // 🔥 THE ALL-IN-ONE GOD MODE 🔥
    godMode: `(function(){ console.clear(); console.log('%c[+] SecDash God Mode Engaged', 'color: #10b981; font-size: 18px; font-weight: bold;'); console.groupCollapsed('%c1. Storage & State', 'color: #60a5fa; font-weight: bold;'); console.log('Cookies:', document.cookie); console.log('LocalStorage:', { ...localStorage }); console.log('SessionStorage:', { ...sessionStorage }); console.groupEnd(); console.groupCollapsed('%c2. DOM Secrets & Inputs', 'color: #60a5fa; font-weight: bold;'); document.querySelectorAll('input[type="hidden"]').forEach(i => console.log('Hidden Input:', i.name, '=', i.value)); const comments = []; const iter = document.createNodeIterator(document, NodeFilter.SHOW_COMMENT, null); let node; while(node = iter.nextNode()) comments.push(node.nodeValue); console.log('HTML Comments:', comments); console.groupEnd(); console.groupCollapsed('%c3. XSS Sinks & Links', 'color: #60a5fa; font-weight: bold;'); const scripts = Array.from(document.scripts).filter(s => s.innerHTML.includes('innerHTML') || s.innerHTML.includes('eval(')); console.log('Potential DOM Sinks:', scripts); const external = Array.from(document.links).map(a=>a.href).filter(h=>!h.includes(location.hostname)); console.log('External Links:', [...new Set(external)]); console.groupEnd(); console.groupCollapsed('%c4. Sensitive Data Search', 'color: #60a5fa; font-weight: bold;'); const html = document.documentElement.innerHTML; console.log('Emails:', [...new Set(html.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\\.[a-zA-Z0-9_-]+)/gi))]); console.log('Keys/Tokens:', html.match(/(api_key|apikey|secret|token)["\\s:=]+["']?([a-zA-Z0-9\\-_]{16,})["']?/gi)); console.groupEnd(); console.log('%c[✓] Scan Complete. Expand groups above to view data.', 'color: #10b981;'); })();`,

    // Network Hooking
    xhrHook: `(function() { const origOpen = XMLHttpRequest.prototype.open; XMLHttpRequest.prototype.open = function() { console.log('%c[XHR Intercept]', 'color: #f59e0b', arguments[1]); this.addEventListener('load', function() { console.log('Response from', arguments[1], this.responseText.substring(0, 200) + '...'); }); return origOpen.apply(this, arguments); }; const origFetch = window.fetch; window.fetch = async function(...args) { console.log('%c[Fetch Intercept]', 'color: #10b981', args[0]); return origFetch.apply(this, args); }; console.log('Network traffic is now being logged to the console.'); })();`,
    wsMonitor: `(function(){ const OrigWS = window.WebSocket; window.WebSocket = function(url, protocols) { console.log('%c[WebSocket Created]', 'color: #8b5cf6', url); const ws = new OrigWS(url, protocols); ws.addEventListener('message', e => console.log('%c[WS Message In]', 'color: #a78bfa', e.data)); const origSend = ws.send; ws.send = function(data) { console.log('%c[WS Message Out]', 'color: #c4b5fd', data); return origSend.apply(this, arguments); }; return ws; }; console.log('WebSocket connections are now being monitored.'); })();`,
    frameworkDetect: `console.table({ React: !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__, Vue: !!window.__VUE__, Angular: !!window.ng, Svelte: !!window.__svelte });`,

    // Info Gathering
    subdomains: `const dom = document.documentElement.innerHTML; const subs = dom.match(/[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/g); const uniqueSubs = [...new Set(subs)].filter(s => s.endsWith(location.hostname.split('.').slice(-2).join('.'))); console.log('Subdomains in DOM:', uniqueSubs);`,
    apiEndpoints: `const html = document.documentElement.innerHTML; const endpoints = html.match(/(https?:\\/\\/[^"']+|\\/[a-zA-Z0-9_\\-\\/]+\\.json|\\/api\\/[a-zA-Z0-9_\\-\\/]+)/gi); console.log('Potential API Endpoints:', [...new Set(endpoints)]);`,
    comments: `var iterator = document.createNodeIterator(document, NodeFilter.SHOW_COMMENT, () => NodeFilter.FILTER_ACCEPT); var curNode; while (curNode = iterator.nextNode()) { console.log(curNode.nodeValue); }`,
    externalLinks: `const links = Array.from(document.links).map(a => a.href).filter(href => !href.includes(location.hostname)); console.table([...new Set(links)]);`,
    
    // State & Auth
    cookies: `let c=document.cookie.split(';');console.table(c.map(x=>{let y=x.split('=');return{Name:y[0].trim(),Value:y[1]}}));`,
    storage: `console.log('--- LocalStorage ---'); console.table(Object.entries(localStorage)); console.log('--- SessionStorage ---'); console.table(Object.entries(sessionStorage));`,
    jwtHunter: `const findJWT = (obj) => Object.entries(obj).filter(([k, v]) => typeof v === 'string' && v.match(/^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$/)); console.log('JWTs in LocalStorage:', findJWT(localStorage)); console.log('JWTs in SessionStorage:', findJWT(sessionStorage));`,
    globalConfigs: `const suspicious = ['config', 'env', 'settings', 'api', 'auth', 'token', 'user']; const found = Object.keys(window).filter(k => suspicious.some(s => k.toLowerCase().includes(s))); console.log('Potential Global Configs:', found); found.forEach(f => console.log(f, window[f]));`,
    
    // Vulnerabilities
    xssSinks: `const scripts = document.querySelectorAll('script'); let sinks = []; scripts.forEach(s => { if(s.innerHTML.includes('innerHTML') || s.innerHTML.includes('eval(') || s.innerHTML.includes('document.write')) sinks.push(s.src || 'Inline Script'); }); console.log('Potential DOM XSS Sinks:', sinks);`,
    openRedirects: `const urls = Array.from(document.querySelectorAll('a')).map(a => a.href).filter(h => h.includes('url=') || h.includes('redirect=') || h.includes('next=') || h.includes('return=')); console.log('Potential Open Redirects:', [...new Set(urls)]);`,
    prototypePollution: `let testObj = {}; console.log("Checking Prototype..."); Object.prototype.polluted = "yes"; if(testObj.polluted === "yes") { console.log("[!] VULNERABLE: Object.prototype is mutable."); } else { console.log("[-] SECURE: Object.prototype locked."); } delete Object.prototype.polluted;`,
    
    // Evasion & UI
    hiddenInputs: `document.querySelectorAll('input[type="hidden"]').forEach(i => { i.type = 'text'; i.style.border = '2px solid red'; console.log('Revealed:', i.name, '=', i.value); });`,
    enableRightClick: `document.addEventListener('contextmenu', e => e.stopPropagation(), true); document.addEventListener('copy', e => e.stopPropagation(), true); document.addEventListener('selectstart', e => e.stopPropagation(), true); console.log('Right-click and copy protections bypassed.');`,
    disableCSS: `for (let s of document.styleSheets) { try { s.disabled = true; } catch(e){} } console.log('All CSS Disabled. Layout revealed.');`,
    highlightClickables: `document.querySelectorAll('a, button, [onclick]').forEach(el => { el.style.border = '2px solid lime'; el.style.backgroundColor = 'rgba(0, 255, 0, 0.2)'; }); console.log('All clickable elements highlighted.');`
};

function copyPayload(type) {
    const code = payloads[type] || `console.error("Payload not found.");`;
    navigator.clipboard.writeText(code).then(() => {
        const toast = document.getElementById('copyToast');
        toast.classList.remove('hidden');
        setTimeout(() => toast.classList.add('hidden'), 2000);
    });
}
