// --- UTILITIES ---
function sanitizeTarget(input) {
    // Strips http, https, paths, and trailing slashes to ensure a clean domain or IP
    let clean = input.trim();
    clean = clean.replace(/^https?:\/\//, '');
    clean = clean.split('/')[0];
    return clean;
}

// --- RECON LOGIC ---
async function runRecon() {
    let rawTarget = document.getElementById('targetInput').value;
    const resultsDiv = document.getElementById('reconResults');
    
    if (!rawTarget) {
        resultsDiv.innerHTML = "<span class='text-red-400'>Error: Please enter a target.</span>";
        return;
    }

    const target = sanitizeTarget(rawTarget);
    document.getElementById('targetInput').value = target; // Update UI with cleaned target
    
    resultsDiv.innerHTML = `Starting recon on: <span class='text-emerald-400'>${target}</span><br><br>`;

    try {
        let ip = target;
        let isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);

        // 1. Resolve DNS if it is a domain
        if (!isIp) {
            resultsDiv.innerHTML += "[*] Resolving DNS via Google DoH...<br>";
            const dnsRes = await fetch(`https://dns.google/resolve?name=${target}&type=A`);
            const dnsData = await dnsRes.json();
            
            if (dnsData.Answer && dnsData.Answer.length > 0) {
                ip = dnsData.Answer[0].data;
                resultsDiv.innerHTML += `[+] Resolved IP: <span class='text-emerald-400'>${ip}</span><br><br>`;
            } else {
                throw new Error("Could not resolve domain. Check spelling or network.");
            }
        }

        // 2. Fetch IP Geolocation (Free API, CORS friendly)
        resultsDiv.innerHTML += "[*] Fetching Geolocation...<br>";
        try {
            const geoRes = await fetch(`https://freeipapi.com/api/json/${ip}`);
            const geoData = await geoRes.json();
            if (geoData.countryName) {
                resultsDiv.innerHTML += `[+] Location: ${geoData.cityName || 'Unknown'}, ${geoData.countryName} (ISP: ${geoData.isp || 'N/A'})<br><br>`;
            }
        } catch (e) {
            resultsDiv.innerHTML += "<span class='text-yellow-400'>[-] Geolocation fetch failed.</span><br><br>";
        }

        // 3. Query Shodan InternetDB
        resultsDiv.innerHTML += "[*] Querying Shodan InternetDB...<br>";
        const shodanRes = await fetch(`https://internetdb.shodan.io/${ip}`);
        
        if (shodanRes.status === 404) {
            resultsDiv.innerHTML += "<span class='text-yellow-400'>[-] No data found in Shodan InternetDB for this IP.</span>";
            return;
        }

        const data = await shodanRes.json();
        
        let output = `[+] <b>Hostnames:</b> ${data.hostnames && data.hostnames.length > 0 ? data.hostnames.join(', ') : 'None'}<br>`;
        output += `[+] <b>Open Ports:</b> <span class='text-emerald-400'>${data.ports && data.ports.length > 0 ? data.ports.join(', ') : 'None'}</span><br>`;
        
        if (data.cpes && data.cpes.length > 0) {
            output += `[+] <b>Detected Tech (CPEs):</b><br><ul class='list-disc pl-5 text-xs text-slate-400'>`;
            data.cpes.slice(0, 10).forEach(cpe => output += `<li>${cpe}</li>`);
            output += `</ul>`;
        }
        
        if (data.vulns && data.vulns.length > 0) {
            output += `[!] <b>Known CVEs:</b> <span class='text-red-400'>${data.vulns.join(', ')}</span><br>`;
        } else {
            output += `[-] <b>Known CVEs:</b> None mapped in InternetDB.<br>`;
        }

        resultsDiv.innerHTML += output;

    } catch (error) {
        resultsDiv.innerHTML += `<br><span class='text-red-400'>[!] Error: ${error.message}</span>`;
    }
}

// --- PAYLOAD GENERATOR LOGIC ---
// Formatted tightly so they copy-paste cleanly into the console
const payloads = {
    // DOM & Inputs
    hiddenInputs: `document.querySelectorAll('input[type="hidden"]').forEach(i => { i.type = 'text'; i.style.border = '2px solid red'; console.log('Revealed:', i.name, '=', i.value); });`,
    forms: `console.table(Array.from(document.forms).map(f=>({Action:f.action, Method:f.method, Inputs:f.elements.length})));`,
    comments: `var iterator = document.createNodeIterator(document, NodeFilter.SHOW_COMMENT, () => NodeFilter.FILTER_ACCEPT); var curNode; while (curNode = iterator.nextNode()) { console.log(curNode.nodeValue); }`,
    externalLinks: `const links = Array.from(document.links).map(a => a.href).filter(href => !href.includes(location.hostname)); console.table([...new Set(links)]);`,
    
    // Storage
    cookies: `let c=document.cookie.split(';');console.table(c.map(x=>{let y=x.split('=');return{Name:y[0].trim(),Value:y[1]}}));`,
    localStorage: `console.table(Object.entries(localStorage).map(([k, v]) => ({ Key: k, Value: v })));`,
    sessionStorage: `console.table(Object.entries(sessionStorage).map(([k, v]) => ({ Key: k, Value: v })));`,
    
    // Vulnerability Scanning
    xssSinks: `const scripts = document.querySelectorAll('script'); let sinks = []; scripts.forEach(s => { if(s.innerHTML.includes('innerHTML') || s.innerHTML.includes('eval(')) sinks.push(s.src || 'Inline Script'); }); console.log('Potential DOM XSS Sinks:', sinks);`,
    sensitiveData: `const html = document.documentElement.innerHTML; const emails = html.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\\.[a-zA-Z0-9_-]+)/gi); const keys = html.match(/(api_key|apikey|secret|token)["\\s:=]+["']?([a-zA-Z0-9\\-_]{16,})["']?/gi); console.log('Emails found:', [...new Set(emails)]); console.log('Potential Keys found:', keys);`
};

function copyPayload(type) {
    const code = payloads[type];
    navigator.clipboard.writeText(code).then(() => {
        const toast = document.getElementById('copyToast');
        toast.classList.remove('hidden');
        setTimeout(() => toast.classList.add('hidden'), 2000);
    });
}
