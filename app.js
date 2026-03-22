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
    if (type === "success") color = "text-green-400";
    if (type === "warning") color = "text-yellow-400";
    if (type === "error") color = "text-red-400";
    if (type === "header") color = "text-blue-400 font-bold";
    
    resultsDiv.innerHTML += `<span class='${color}'>${message}</span>\n`;
    resultsDiv.scrollTop = resultsDiv.scrollHeight;
}

// --- RECON LOGIC ---
async function runRecon() {
    let rawTarget = document.getElementById('targetInput').value;
    const resultsDiv = document.getElementById('reconResults');
    
    if (!rawTarget) {
        resultsDiv.innerHTML = "<span class='text-red-400'>[!] Error: Target required.</span>";
        return;
    }

    const target = sanitizeTarget(rawTarget);
    document.getElementById('targetInput').value = target; 
    
    resultsDiv.innerHTML = "";
    logToConsole(`[INIT] Engaging target: ${target}\n`, "header");

    let ip = target;
    let isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);

    // 1. RESOLVE DNS (Using NetworkCalc - rarely blocked by adblockers)
    if (!isIp) {
        logToConsole("[*] Resolving DNS via NetworkCalc...");
        try {
            const dnsRes = await fetch(`https://networkcalc.com/api/dns/lookup/${target}`);
            const dnsData = await dnsRes.json();
            
            if (dnsData.status === "OK" && dnsData.records && dnsData.records.A) {
                ip = dnsData.records.A[0].address;
                logToConsole(`[+] Resolved IPv4: ${ip}\n`, "success");
            } else {
                throw new Error("No A records found.");
            }
        } catch (e) {
            logToConsole(`[-] DNS failed (Check your extensions): ${e.message}\n`, "warning");
        }
    }

    // 2. IP GEOLOCATION (FreeIPAPI)
    logToConsole("[*] Fetching Geolocation Data...");
    try {
        const geoRes = await fetch(`https://freeipapi.com/api/json/${ip}`);
        const geoData = await geoRes.json();
        if (geoData.countryName) {
            logToConsole(`[+] Location: ${geoData.cityName || 'Unknown'}, ${geoData.countryName}`, "success");
            logToConsole(`[+] ASN/ISP: ${geoData.isp || 'N/A'}\n`, "success");
        }
    } catch (e) {
        logToConsole(`[-] Geolocation fetch failed.\n`, "warning");
    }

    // 3. SUBDOMAIN ENUMERATION (HackerTarget)
    if (!isIp) {
        logToConsole("[*] Enumerating Subdomains...");
        try {
            const subRes = await fetch(`https://api.hackertarget.com/hostsearch/?q=${target}`);
            const subText = await subRes.text();
            if (subText.includes("error") || subText.includes("API count exceeded")) {
                logToConsole("[-] Subdomain API rate limited.\n", "warning");
            } else {
                const subs = subText.split('\n').filter(line => line.trim() !== '');
                logToConsole(`[+] Found ${subs.length} subdomains. Displaying Top 10:`, "success");
                subs.slice(0, 10).forEach(s => logToConsole(`    -> ${s.split(',')[0]}`));
                logToConsole("\n");
            }
        } catch (e) {
            logToConsole(`[-] Subdomain scan blocked by CORS/Network.\n`, "warning");
        }
    }

    // 4. SHODAN INTERNETDB (Open Ports & Vulns)
    logToConsole("[*] Querying Shodan InternetDB for ports and CVEs...");
    try {
        const shodanRes = await fetch(`https://internetdb.shodan.io/${ip}`);
        
        if (shodanRes.status === 404) {
            logToConsole("[-] Target IP not indexed by Shodan InternetDB.\n", "warning");
        } else {
            const data = await shodanRes.json();
            logToConsole(`[+] Open Ports: ${data.ports && data.ports.length > 0 ? data.ports.join(', ') : 'None'}`, "success");
            
            if (data.cpes && data.cpes.length > 0) {
                logToConsole(`[+] Fingerprints: ${data.cpes.slice(0, 5).join(', ')}`, "success");
            }
            
            if (data.vulns && data.vulns.length > 0) {
                logToConsole(`[!] Known CVEs on IP: ${data.vulns.join(', ')}\n`, "error");
            } else {
                logToConsole(`[-] No direct CVEs mapped in InternetDB.\n`, "info");
            }
        }
    } catch (e) {
        logToConsole(`[-] Shodan query failed: ${e.message}\n`, "warning");
    }

    // 5. SECURITY HEADERS (HackerTarget)
    if (!isIp) {
        logToConsole("[*] Pulling HTTP Security Headers...");
        try {
            const headerRes = await fetch(`https://api.hackertarget.com/httpheaders/?q=${target}`);
            const headerText = await headerRes.text();
            if (headerText.includes("error") || headerText.includes("API count exceeded")) {
                logToConsole("[-] Header check rate limited.\n", "warning");
            } else {
                const lines = headerText.split('\n');
                let interestingHeaders = [];
                lines.forEach(line => {
                    const l = line.toLowerCase();
                    if (l.startsWith('server:') || l.startsWith('x-powered-by:') || l.startsWith('content-security-policy:') || l.startsWith('strict-transport-security:')) {
                        interestingHeaders.push(line.trim());
                    }
                });
                if (interestingHeaders.length > 0) {
                    logToConsole(`[+] Notable Headers:\n    ${interestingHeaders.join('\n    ')}\n`, "success");
                } else {
                    logToConsole(`[-] No notable security headers detected.\n`, "info");
                }
            }
        } catch (e) {
            logToConsole(`[-] Header pull failed.\n`, "warning");
        }
    }

    logToConsole("[DONE] Reconnaissance complete.", "header");
}

// --- PAYLOAD GENERATOR LOGIC ---
const payloads = {
    // Info Gathering
    subdomains: `const dom = document.documentElement.innerHTML; const subs = dom.match(/[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/g); const uniqueSubs = [...new Set(subs)].filter(s => s.endsWith(location.hostname.split('.').slice(-2).join('.'))); console.log('Subdomains in DOM:', uniqueSubs);`,
    apiEndpoints: `const html = document.documentElement.innerHTML; const endpoints = html.match(/(https?:\\/\\/[^"']+|\\/[a-zA-Z0-9_\\-\\/]+\\.json|\\/api\\/[a-zA-Z0-9_\\-\\/]+)/gi); console.log('Potential API Endpoints:', [...new Set(endpoints)]);`,
    comments: `var iterator = document.createNodeIterator(document, NodeFilter.SHOW_COMMENT, () => NodeFilter.FILTER_ACCEPT); var curNode; while (curNode = iterator.nextNode()) { console.log(curNode.nodeValue); }`,
    externalLinks: `const links = Array.from(document.links).map(a => a.href).filter(href => !href.includes(location.hostname)); console.table([...new Set(links)]);`,
    forms: `console.table(Array.from(document.forms).map(f=>({Action:f.action, Method:f.method, Inputs:f.elements.length})));`,
    
    // State & Auth
    cookies: `let c=document.cookie.split(';');console.table(c.map(x=>{let y=x.split('=');return{Name:y[0].trim(),Value:y[1]}}));`,
    storage: `console.log('--- LocalStorage ---'); console.table(Object.entries(localStorage)); console.log('--- SessionStorage ---'); console.table(Object.entries(sessionStorage));`,
    jwtHunter: `const findJWT = (obj) => Object.entries(obj).filter(([k, v]) => typeof v === 'string' && v.match(/^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+$/)); console.log('JWTs in LocalStorage:', findJWT(localStorage)); console.log('JWTs in SessionStorage:', findJWT(sessionStorage));`,
    globalConfigs: `const suspicious = ['config', 'env', 'settings', 'api', 'auth', 'token', 'user']; const found = Object.keys(window).filter(k => suspicious.some(s => k.toLowerCase().includes(s))); console.log('Potential Global Configs:', found); found.forEach(f => console.log(f, window[f]));`,
    
    // Vulnerabilities
    xssSinks: `const scripts = document.querySelectorAll('script'); let sinks = []; scripts.forEach(s => { if(s.innerHTML.includes('innerHTML') || s.innerHTML.includes('eval(') || s.innerHTML.includes('document.write')) sinks.push(s.src || 'Inline Script'); }); console.log('Potential DOM XSS Sinks:', sinks);`,
    openRedirects: `const urls = Array.from(document.querySelectorAll('a')).map(a => a.href).filter(h => h.includes('url=') || h.includes('redirect=') || h.includes('next=') || h.includes('return=')); console.log('Potential Open Redirects:', [...new Set(urls)]);`,
    sensitiveData: `const html = document.documentElement.innerHTML; const emails = html.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\\.[a-zA-Z0-9_-]+)/gi); const keys = html.match(/(api_key|apikey|secret|token)["\\s:=]+["']?([a-zA-Z0-9\\-_]{16,})["']?/gi); console.log('Emails found:', [...new Set(emails)]); console.log('Potential Keys found:', keys);`,
    prototypePollution: `let testObj = {}; console.log("Checking Prototype..."); Object.prototype.polluted = "yes"; if(testObj.polluted === "yes") { console.log("[!] VULNERABLE: Object.prototype is mutable."); } else { console.log("[-] SECURE: Object.prototype locked."); } delete Object.prototype.polluted;`,
    
    // Evasion & UI
    hiddenInputs: `document.querySelectorAll('input[type="hidden"]').forEach(i => { i.type = 'text'; i.style.border = '2px solid red'; console.log('Revealed:', i.name, '=', i.value); });`,
    enableRightClick: `document.addEventListener('contextmenu', e => e.stopPropagation(), true); document.addEventListener('copy', e => e.stopPropagation(), true); document.addEventListener('selectstart', e => e.stopPropagation(), true); console.log('Right-click and copy protections bypassed.');`,
    disableCSS: `for (let s of document.styleSheets) { s.disabled = true; } console.log('All CSS Disabled. Layout revealed.');`,
    highlightClickables: `document.querySelectorAll('a, button, [onclick]').forEach(el => { el.style.border = '2px solid lime'; el.style.backgroundColor = 'rgba(0, 255, 0, 0.2)'; }); console.log('All clickable elements highlighted.');`
};

function copyPayload(type) {
    const code = payloads[type] || `console.error("Payload not found.");`;
    
    navigator.clipboard.writeText(code).then(() => {
        const toast = document.getElementById('copyToast');
        toast.classList.remove('hidden');
        setTimeout(() => toast.classList.add('hidden'), 2000);
    }).catch(err => {
        console.error("Copy failed: ", err);
    });
}
