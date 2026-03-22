// --- RECON LOGIC ---
async function runRecon() {
    const target = document.getElementById('targetInput').value.trim();
    const resultsDiv = document.getElementById('reconResults');
    
    if (!target) {
        resultsDiv.innerHTML = "<span class='text-red-400'>Error: Please enter a target domain or IP.</span>";
        return;
    }

    resultsDiv.innerHTML = "Querying DNS...<br>";

    try {
        // Step 1: Resolve Domain to IP using Google DNS over HTTPS (CORS friendly)
        let ip = target;
        // Basic check if it's already an IP
        if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target)) {
            const dnsRes = await fetch(`https://dns.google/resolve?name=${target}&type=A`);
            const dnsData = await dnsRes.json();
            if (dnsData.Answer && dnsData.Answer.length > 0) {
                ip = dnsData.Answer[0].data;
                resultsDiv.innerHTML += `Resolved to IP: <span class='text-emerald-400'>${ip}</span><br>Querying Shodan InternetDB...<br><br>`;
            } else {
                throw new Error("Could not resolve domain.");
            }
        }

        // Step 2: Query Shodan InternetDB (Free, CORS friendly, No Auth)
        const shodanRes = await fetch(`https://internetdb.shodan.io/${ip}`);
        
        if (shodanRes.status === 404) {
            resultsDiv.innerHTML += "<span class='text-yellow-400'>No data found in Shodan InternetDB for this IP.</span>";
            return;
        }

        const data = await shodanRes.json();
        
        // Step 3: Format and display results
        let output = `<b>Hostnames:</b> ${data.hostnames.join(', ') || 'None'}<br>`;
        output += `<b>Open Ports:</b> <span class='text-emerald-400'>${data.ports.join(', ') || 'None'}</span><br>`;
        
        if (data.cpes && data.cpes.length > 0) {
            output += `<b>Detected Tech (CPEs):</b><br><ul class='list-disc pl-5 text-xs text-slate-400'>`;
            data.cpes.slice(0, 10).forEach(cpe => output += `<li>${cpe}</li>`);
            output += `</ul>`;
        }
        
        if (data.vulns && data.vulns.length > 0) {
            output += `<b>Known CVEs:</b> <span class='text-red-400'>${data.vulns.join(', ')}</span><br>`;
        } else {
            output += `<b>Known CVEs:</b> None directly mapped to this IP in InternetDB.<br>`;
        }

        resultsDiv.innerHTML += output;

    } catch (error) {
        resultsDiv.innerHTML += `<br><span class='text-red-400'>Error: ${error.message}</span>`;
    }
}

// --- PAYLOAD GENERATOR LOGIC ---
const payloads = {
    cookie: `let c=document.cookie.split(';');console.table(c.map(x=>{let y=x.split('=');return{Name:y[0].trim(),Value:y[1],Note:'Verify HttpOnly/Secure in Network Tab'}}));`,
    
    forms: `console.table(Array.from(document.forms).map(f=>({Action:f.action, Method:f.method, Inputs:f.elements.length})));`,
    
    hidden: `document.querySelectorAll('input[type="hidden"]').forEach(i => { i.type = 'text'; i.style.border = '2px solid red'; console.log('Revealed Hidden Input:', i.name, '=', i.value); });`
};

function copyPayload(type) {
    const code = payloads[type];
    navigator.clipboard.writeText(code).then(() => {
        const toast = document.getElementById('copyToast');
        toast.style.display = 'block';
        setTimeout(() => toast.style.display = 'none', 2000);
    });
}
