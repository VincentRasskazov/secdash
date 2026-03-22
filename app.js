// --- UTILITIES ---
function sanitizeTarget(input) {
    let clean = input.trim();
    clean = clean.replace(/^https?:\/\//, '');
    clean = clean.split('/')[0];
    return clean;
}

function logToConsole(message, type = "info") {
    const resultsDiv = document.getElementById('reconResults');
    let color = "text-slate-300";
    if (type === "success") color = "text-emerald-400";
    if (type === "warning") color = "text-yellow-400";
    if (type === "error") color = "text-red-400";
    
    resultsDiv.innerHTML += `<span class='${color}'>${message}</span>\n`;
    resultsDiv.scrollTop = resultsDiv.scrollHeight;
}

// --- RECON LOGIC ---
async function runRecon() {
    let rawTarget = document.getElementById('targetInput').value;
    const resultsDiv = document.getElementById('reconResults');
    
    if (!rawTarget) {
        resultsDiv.innerHTML = "<span class='text-red-400'>Error: Target required.</span>";
        return;
    }

    const target = sanitizeTarget(rawTarget);
    document.getElementById('targetInput').value = target; 
    
    resultsDiv.innerHTML = "";
    logToConsole(`[*] Initializing scan for: ${target}\n`, "info");

    try {
        let ip = target;
        let isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);

        // 1. Resolve DNS via Cloudflare (More reliable for strict browsers)
        if (!isIp) {
            logToConsole("[*] Resolving DNS via Cloudflare DoH...");
            try {
                const dnsRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${target}&type=A`, {
                    headers: { 'Accept': 'application/dns-json' }
                });
                const dnsData = await dnsRes.json();
                
                if (dnsData.Answer && dnsData.Answer.length > 0) {
                    ip = dnsData.Answer[0].data;
                    logToConsole(`[+] Resolved IP: ${ip}\n`, "success");
                } else {
                    throw new Error("No A records found.");
                }
            } catch (e) {
                logToConsole(`[-] Cloudflare DNS failed: ${e.message}`, "warning");
                return; // Stop if we can't get an IP
            }
        }

        // 2. Fetch HTTP Headers (Via HackerTarget Public API)
        if (!isIp) {
            logToConsole("[*] Pulling HTTP Security Headers...");
            try {
                const headerRes = await fetch(`https://api.hackertarget.com/httpheaders/?q=${target}`);
                const headerText = await headerRes.text();
                if (headerText.includes("error")) {
                    logToConsole("[-] Header check failed or rate limited.\n", "warning");
                } else {
                    // Truncate to keep it clean
                    const cleanHeaders = headerText.split('\n').filter(line => line.trim() !== '').slice(0, 10).join('\n');
                    logToConsole(`[+] Headers retrieved:\n${cleanHeaders}\n`, "success");
                }
            } catch (e) {
                logToConsole(`[-] Header pull failed: CORS or network error.\n`, "warning");
            }
        }

        // 3. Query Shodan InternetDB
        logToConsole("[*] Querying Shodan InternetDB for open ports and CVEs...");
        try {
            const shodanRes = await fetch(`https://internetdb.shodan.io/${ip}`);
            
            if (shodanRes.status === 404) {
                logToConsole("[-] No data found in Shodan InternetDB for this IP.\n", "warning");
            } else {
                const data = await shodanRes.json();
                logToConsole(`[+] Open Ports: ${data.ports && data.ports.length > 0 ? data.ports.join(', ') : 'None'}`, "success");
                
                if (data.cpes && data.cpes.length > 0) {
                    logToConsole(`[+] Tech Stack (CPEs): ${data.cpes.slice(0, 5).join(', ')}`, "info");
                }
                
                if (data.vulns && data.vulns.length > 0) {
                    logToConsole(`[!] Known CVEs mapped to IP: ${data.vulns.join(', ')}\n`, "error");
                } else {
                    logToConsole(`[-] No direct CVEs mapped to this IP in InternetDB.\n`, "info");
                }
            }
        } catch (e) {
            logToConsole(`[-] Shodan query failed: ${e.message}\n`, "error");
        }

        logToConsole("[*] Reconnaissance complete.", "info");

    } catch (error) {
        logToConsole(`[!] Fatal Error: ${error.message}`, "error");
    }
}

// --- PAYLOAD GENERATOR LOGIC ---
const payloads = {
    // State & Auth
    cookies: `let c=document.cookie.split(';');console.table(c.map(x=>{let y=x.split('=');return{Name:y[0].trim(),Value:y[1]}}));`,
    storage: `console.log('--- LocalStorage ---'); console.table(Object.entries(localStorage)); console.log('--- SessionStorage ---'); console.table(Object.entries(sessionStorage));`,
    jwtHunter: `const findJWT = (obj) => Object.entries(obj).filter(([k, v]) => typeof v === 'string' && v.match(/^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$/)); console.log('JWTs in LocalStorage:', findJWT(localStorage)); console.log('JWTs in SessionStorage:', findJWT(sessionStorage)); console.log('Check cookies manually for HttpOnly JWTs.');`,
    globalConfigs: `const suspicious = ['config', 'env', 'settings', 'api', 'auth', 'token']; const found = Object.keys(window).filter(k => suspicious.some(s => k.toLowerCase().includes(s))); console.log('Potential Global Configs:', found); found.forEach(f => console.log(f, window[f]));`,
    
    // DOM Inspection
    hiddenInputs: `document.querySelectorAll('input[type="hidden"]').forEach(i => { i.type = 'text'; i.style.border = '2px solid red'; console.log('Revealed:', i.name, '=', i.value); });`,
    forms: `console.table(Array.from(document.forms).map(f=>({Action:f.action, Method:f.method, Inputs:f.elements.length})));`,
    comments: `var iterator = document.createNodeIterator(document, NodeFilter.SHOW_COMMENT, () => NodeFilter.FILTER_ACCEPT); var curNode; while (curNode = iterator.nextNode()) { console.log(curNode.nodeValue); }`,
    apiEndpoints: `const html = document.documentElement.innerHTML; const endpoints = html.match(/(https?:\\/\\/[^"']+|\\/[a-zA-Z0-9_\\-\\/]+\\.json|\\/api\\/[a-zA-Z0-9_\\-\\/]+)/gi); console.log('Potential API Endpoints:', [...new Set(endpoints)]);`,
    
    // Scanners
    xssSinks: `const scripts = document.querySelectorAll('script'); let sinks = []; scripts.forEach(s => { if(s.innerHTML.includes('innerHTML') || s.innerHTML.includes('eval(')) sinks.push(s.src || 'Inline Script'); }); console.log('Potential DOM XSS Sinks:', sinks);`,
    sensitiveData: `const html = document.documentElement.innerHTML; const emails = html.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\\.[a-zA-Z0-9_-]+)/gi); const keys = html.match(/(api_key|apikey|secret|token)["\\s:=]+["']?([a-zA-Z0-9\\-_]{16,})["']?/gi); console.log('Emails found:', [...new Set(emails)]); console.log('Potential Keys found:', keys);`,
    prototypePollution: `let testObj = {}; console.log("Checking Prototype Pollution..."); Object.prototype.polluted = "yes"; if(testObj.polluted === "yes") { console.log("VULNERABLE: Object.prototype is mutable."); } else { console.log("SECURE: Object.prototype is locked."); } delete Object.prototype.polluted;`
};

function copyPayload(type) {
    // Fallback error message if the key doesn't match
    const code = payloads[type] || `console.error("SecDash Error: Payload '${type}' not found in app.js dict.");`;
    
    navigator.clipboard.writeText(code).then(() => {
        const toast = document.getElementById('copyToast');
        toast.classList.remove('hidden');
        setTimeout(() => toast.classList.add('hidden'), 2000);
    }).catch(err => {
        console.error("Failed to copy text: ", err);
    });
}
