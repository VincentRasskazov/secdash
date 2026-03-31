"use strict";

const STORAGE_KEY = "secdash.session.v1";
const RECON_TIMEOUT_MS = 15000;
const MAX_LOG_LINES = 350;
const PERSIST_DEBOUNCE_MS = 250;
const DEFAULT_FILTER = "All";
const IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;

const dom = {
    targetInput: document.getElementById("targetInput"),
    runReconBtn: document.getElementById("runReconBtn"),
    clearSessionBtn: document.getElementById("clearSessionBtn"),
    exportReportBtn: document.getElementById("exportReportBtn"),
    workspaceTabs: document.getElementById("workspaceTabs"),
    workspaceLayout: document.getElementById("workspaceLayout"),
    reconSection: document.getElementById("reconSection"),
    activeSection: document.getElementById("activeSection"),
    reportSection: document.getElementById("reportSection"),
    reconStats: document.getElementById("reconStats"),
    reconToolGrid: document.getElementById("reconToolGrid"),
    clearReconLogBtn: document.getElementById("clearReconLogBtn"),
    reconOutput: document.getElementById("reconOutput"),
    activeCategoryFilters: document.getElementById("activeCategoryFilters"),
    activeSearchInput: document.getElementById("activeSearchInput"),
    compactModeToggle: document.getElementById("compactModeToggle"),
    activeShowMoreBtn: document.getElementById("activeShowMoreBtn"),
    activeToolCount: document.getElementById("activeToolCount"),
    activeToolGrid: document.getElementById("activeToolGrid"),
    commandBundle: document.getElementById("commandBundle"),
    copyBundleBtn: document.getElementById("copyBundleBtn"),
    copySummaryBtn: document.getElementById("copySummaryBtn"),
    copyDetailedReportBtn: document.getElementById("copyDetailedReportBtn"),
    scanSummaryStats: document.getElementById("scanSummaryStats"),
    scanSummaryNarrative: document.getElementById("scanSummaryNarrative"),
    scanReportPreview: document.getElementById("scanReportPreview"),
    findingForm: document.getElementById("findingForm"),
    findingTitle: document.getElementById("findingTitle"),
    findingSeverity: document.getElementById("findingSeverity"),
    findingEvidence: document.getElementById("findingEvidence"),
    findingNotes: document.getElementById("findingNotes"),
    clearFindingsBtn: document.getElementById("clearFindingsBtn"),
    findingsList: document.getElementById("findingsList"),
    toast: document.getElementById("toast")
};

if (Object.values(dom).some((node) => !node)) {
    throw new Error("SecDash initialization failed: required DOM nodes are missing.");
}

const reconModules = [
    {
        id: "dns-profile",
        mode: "Passive",
        name: "DNS Profile",
        description: "Collect A/AAAA/MX/TXT records and baseline email security posture.",
        coverage: "Infrastructure visibility and spoofing controls",
        run: runDnsProfile
    },
    {
        id: "whois-profile",
        mode: "Passive",
        name: "WHOIS Snapshot",
        description: "Identify registrar, registration timeline, and ownership metadata.",
        coverage: "Asset ownership and domain lifecycle",
        run: runWhoisProfile
    },
    {
        id: "tls-profile",
        mode: "Passive",
        name: "TLS Certificate Review",
        description: "Inspect issuer, expiry window, SAN list, and cryptographic metadata.",
        coverage: "Transport security hygiene",
        run: runTlsProfile
    },
    {
        id: "subdomain-intel",
        mode: "Passive",
        name: "Subdomain Intelligence",
        description: "Aggregate likely subdomains from public certificate and DNS sources.",
        coverage: "Attack surface expansion",
        run: runSubdomainIntel
    },
    {
        id: "historical-surface",
        mode: "Passive",
        name: "Historical Surface",
        description: "Sample archived endpoints from Wayback snapshots for legacy exposure.",
        coverage: "Hidden and deprecated routes",
        run: runHistoricalSurface
    },
    {
        id: "robots-sitemap",
        mode: "Low Impact",
        name: "Robots and Sitemap Discovery",
        description: "Read robots.txt and sitemap references to identify hidden or sensitive crawl paths.",
        coverage: "Application route intelligence",
        run: runRobotsAndSitemap
    },
    {
        id: "security-txt",
        mode: "Low Impact",
        name: "security.txt Presence",
        description: "Check coordinated disclosure metadata and contact channels exposed by the target.",
        coverage: "Disclosure readiness and response hygiene",
        run: runSecurityTxtPresence
    },
    {
        id: "port-exposure",
        mode: "Passive",
        name: "Port and CVE Exposure",
        description: "Query Shodan InternetDB for open ports and known vulnerability tags.",
        coverage: "External service exposure",
        run: runPortExposure
    },
    {
        id: "header-posture",
        mode: "Passive",
        name: "HTTP Header Posture",
        description: "Review security header adoption and server fingerprint leakage.",
        coverage: "Response hardening",
        run: runHeaderPosture
    },
    {
        id: "dns-policy",
        mode: "Passive",
        name: "DNS Policy Signals",
        description: "Check CAA, NS, MX, and DNSKEY records for policy completeness.",
        coverage: "Certificate and DNS resilience",
        run: runDnsPolicySignals
    }
];

const activeTools = [
    {
        id: "xss-reflection",
        category: "Input Validation",
        title: "Reflected XSS Echo Probe",
        description: "Send encoded script payloads through reflected parameters and inspect response contexts.",
        checklist: [
            "Probe search, error, and preview endpoints.",
            "Test element text, attribute, and script contexts separately.",
            "Capture request + response evidence with execution proof."
        ],
        command: "curl -isk \"{{ORIGIN}}/search?q=%3Csvg%20onload%3Dalert(document.domain)%3E\""
    },
    {
        id: "sqli-sanity",
        category: "Input Validation",
        title: "SQL Injection Sanity Check",
        description: "Validate server-side query handling for quote breaking and boolean logic patterns.",
        checklist: [
            "Compare baseline and injected response lengths/status.",
            "Test both query params and JSON body fields.",
            "Track DB errors and timing anomalies."
        ],
        command: "curl -isk \"{{ORIGIN}}/api/items?id=1%27%20OR%20%271%27%3D%271\""
    },
    {
        id: "open-redirect",
        category: "Input Validation",
        title: "Open Redirect Validation",
        description: "Verify redirect parameter enforcement and destination allowlisting.",
        checklist: [
            "Use absolute, protocol-relative, and encoded external URLs.",
            "Check response Location header and status code.",
            "Confirm if redirect happens before authentication checks."
        ],
        command: "curl -isk \"{{ORIGIN}}/redirect?next=https%3A%2F%2Fexample.org\""
    },
    {
        id: "session-cookie-review",
        category: "Authentication and Session",
        title: "Session Cookie Flag Review",
        description: "Inspect cookie security attributes and scope boundaries.",
        checklist: [
            "Check HttpOnly, Secure, and SameSite flags.",
            "Confirm cookies are scoped to the smallest valid path/domain.",
            "Re-test after login/logout and privilege changes."
        ],
        command: "curl -isk \"{{ORIGIN}}\" | grep -i \"set-cookie\""
    },
    {
        id: "jwt-claims-review",
        category: "Authentication and Session",
        title: "JWT Claims and Algorithm Review",
        description: "Decode tokens and verify strict algorithm and claim validation on protected endpoints.",
        checklist: [
            "Validate exp, nbf, aud, and iss checks on server side.",
            "Test tampered claims and signature mismatch handling.",
            "Look for acceptance of unsigned or downgraded algorithms."
        ],
        command: "echo \"<jwt-token>\" | awk -F. '{print $1\"\\n\"$2}' | tr '_-' '/+' | base64 -d 2>/dev/null"
    },
    {
        id: "mfa-bypass",
        category: "Authentication and Session",
        title: "MFA Step Enforcement Check",
        description: "Ensure second-factor completion is required before sensitive routes are accessible.",
        checklist: [
            "Capture login flow requests before and after MFA.",
            "Replay post-auth calls without second-factor completion.",
            "Validate server-side state, not only frontend route guards."
        ],
        command: "curl -isk \"{{ORIGIN}}/account/security\" -H \"Authorization: Bearer <primary-auth-token>\""
    },
    {
        id: "idor-horizontal",
        category: "Authorization",
        title: "Horizontal IDOR Sequence",
        description: "Iterate resource identifiers to test tenant and user boundary enforcement.",
        checklist: [
            "Use low-privilege credentials for baseline.",
            "Cycle predictable IDs and UUID variants.",
            "Confirm denied responses do not leak sensitive metadata."
        ],
        command: "for id in 1001 1002 1003; do curl -isk \"{{ORIGIN}}/api/orders/$id\" -H \"Authorization: Bearer <token>\"; done"
    },
    {
        id: "vertical-access",
        category: "Authorization",
        title: "Vertical Privilege Check",
        description: "Verify non-admin accounts cannot reach admin API and UI actions.",
        checklist: [
            "Call admin endpoints directly with low-priv tokens.",
            "Check hidden UI actions by invoking APIs manually.",
            "Validate server responses and audit logs."
        ],
        command: "curl -isk \"{{ORIGIN}}/api/admin/users\" -H \"Authorization: Bearer <low-priv-token>\""
    },
    {
        id: "graphql-introspection",
        category: "API Security",
        title: "GraphQL Introspection Check",
        description: "Assess schema exposure and resolver access control through introspection queries.",
        checklist: [
            "Test introspection in production configuration.",
            "Review mutation paths for privilege abuse.",
            "Check field-level authorization behavior."
        ],
        command: "curl -isk \"{{ORIGIN}}/graphql\" -H \"Content-Type: application/json\" --data '{\"query\":\"{__schema{types{name}}}\"}'"
    },
    {
        id: "mass-assignment",
        category: "API Security",
        title: "Mass Assignment Probe",
        description: "Attempt to set sensitive model fields that should be server-protected.",
        checklist: [
            "Include privilege and ownership fields in payload.",
            "Compare accepted fields against API docs/schema.",
            "Verify persistence after refresh and re-authentication."
        ],
        command: "curl -isk -X PATCH \"{{ORIGIN}}/api/profile\" -H \"Content-Type: application/json\" -H \"Authorization: Bearer <token>\" --data '{\"displayName\":\"test\",\"isAdmin\":true}'"
    },
    {
        id: "cors-trust",
        category: "API Security",
        title: "CORS Trust Boundary Test",
        description: "Validate Origin validation and credential handling across API routes.",
        checklist: [
            "Send hostile Origin headers from untrusted domains.",
            "Check Access-Control-Allow-Origin reflection behavior.",
            "Verify credentialed cross-origin requests are rejected."
        ],
        command: "curl -isk -X OPTIONS \"{{ORIGIN}}/api/me\" -H \"Origin: https://attacker.example\" -H \"Access-Control-Request-Method: GET\""
    },
    {
        id: "ssrf-reachability",
        category: "API Security",
        title: "SSRF Reachability Probe",
        description: "Test backend URL fetchers for internal network and metadata service exposure.",
        checklist: [
            "Probe URL preview/import endpoints that fetch remote resources.",
            "Test localhost, RFC1918 ranges, and cloud metadata endpoints.",
            "Validate egress allowlisting and protocol restrictions."
        ],
        command: "curl -isk -X POST \"{{ORIGIN}}/api/fetch\" -H \"Content-Type: application/json\" -H \"Authorization: Bearer <token>\" --data '{\"url\":\"http://169.254.169.254/latest/meta-data/\"}'"
    },
    {
        id: "csrf-origin-check",
        category: "Authentication and Session",
        title: "CSRF Origin Enforcement",
        description: "Verify state-changing routes enforce anti-CSRF protections and strict origin checks.",
        checklist: [
            "Send authenticated POST without CSRF token.",
            "Manipulate Origin and Referer headers.",
            "Validate SameSite and token rotation behavior."
        ],
        command: "curl -isk -X POST \"{{ORIGIN}}/api/profile/email\" -H \"Cookie: session=<session-cookie>\" -H \"Origin: https://attacker.example\" --data 'email=evil@example.org'"
    },
    {
        id: "host-header-poisoning",
        category: "Input Validation",
        title: "Host Header Poisoning",
        description: "Check trust assumptions around Host and X-Forwarded-Host usage in absolute URL generation.",
        checklist: [
            "Send malicious Host and X-Forwarded-Host combinations.",
            "Inspect redirects, password reset links, and emails.",
            "Verify reverse proxy and app routing consistency."
        ],
        command: "curl -isk \"{{ORIGIN}}/password/forgot\" -H \"Host: attacker.example\" -H \"X-Forwarded-Host: attacker.example\""
    },
    {
        id: "cache-poisoning",
        category: "Client-Side",
        title: "Cache Poisoning Heuristic",
        description: "Evaluate cache key variance and header trust to surface poisoning opportunities.",
        checklist: [
            "Inject unkeyed headers and compare cache behavior.",
            "Observe cache-control, age, and vary headers.",
            "Verify personalized pages are never cached publicly."
        ],
        command: "curl -isk \"{{ORIGIN}}/\" -H \"X-Forwarded-Host: poison.example\" -H \"X-Original-URL: /admin\""
    },
    {
        id: "rate-limit-login",
        category: "Rate Limiting",
        title: "Login Rate-Limit Verification",
        description: "Burst authentication attempts to confirm lockout/throttling controls.",
        checklist: [
            "Track HTTP status transitions and retry-after headers.",
            "Test per-IP and per-account throttling dimensions.",
            "Validate reset windows and abuse resistance."
        ],
        command: "for i in $(seq 1 25); do curl -sk -o /dev/null -w \"%{http_code}\\n\" -X POST \"{{ORIGIN}}/login\" -d \"username=test&password=wrong-$i\"; done"
    },
    {
        id: "race-coupon",
        category: "Rate Limiting",
        title: "Race Condition Coupon Redeem",
        description: "Launch parallel redemption attempts to expose non-atomic business logic.",
        checklist: [
            "Use parallel requests with identical coupon/token.",
            "Monitor duplicate success states and balance drift.",
            "Confirm transactional rollback behavior."
        ],
        command: "seq 1 20 | xargs -I{} -P 20 curl -sk -X POST \"{{ORIGIN}}/api/redeem\" -H \"Content-Type: application/json\" --data '{\"coupon\":\"WELCOME100\"}' -o /dev/null -w \"{}:%{http_code}\\n\""
    },
    {
        id: "file-upload",
        category: "File Upload",
        title: "File Upload Validation",
        description: "Check extension/MIME validation and post-upload execution surfaces.",
        checklist: [
            "Upload mismatched extension and MIME combinations.",
            "Verify server-side content inspection and storage path.",
            "Attempt retrieval to assess content-type and execution behavior."
        ],
        command: "curl -isk -X POST \"{{ORIGIN}}/upload\" -H \"Authorization: Bearer <token>\" -F 'file=@proof.png;type=image/png'"
    },
    {
        id: "path-traversal",
        category: "File Upload",
        title: "Path Traversal Retrieval Probe",
        description: "Test file download/export endpoints for directory traversal handling.",
        checklist: [
            "Try encoded and double-encoded traversal payloads.",
            "Confirm canonical path enforcement on server side.",
            "Check error responses for filesystem leakage."
        ],
        command: "curl -isk \"{{ORIGIN}}/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd\""
    },
    {
        id: "business-discount",
        category: "Business Logic",
        title: "Discount and Cart Logic Abuse",
        description: "Evaluate duplicate discounting, negative quantity, and pricing trust assumptions.",
        checklist: [
            "Attempt stacked coupon combinations and replay.",
            "Send client-controlled price or quantity fields.",
            "Validate server-side recomputation before checkout."
        ],
        command: "curl -isk -X POST \"{{ORIGIN}}/api/cart/checkout\" -H \"Content-Type: application/json\" -H \"Authorization: Bearer <token>\" --data '{\"items\":[{\"sku\":\"A1\",\"qty\":-1,\"price\":0.01}],\"coupon\":\"WELCOME100\"}'"
    },
    {
        id: "password-reset",
        category: "Business Logic",
        title: "Password Reset Flow Abuse",
        description: "Test reset token entropy, expiration, replay, and account enumeration risk.",
        checklist: [
            "Observe response differences for existing vs non-existing users.",
            "Replay reset tokens after successful use.",
            "Verify token invalidation after password change."
        ],
        command: "curl -isk \"{{ORIGIN}}/reset?token=000000\""
    },
    {
        id: "dom-sink-scan",
        category: "Client-Side",
        title: "DOM Sink Inventory",
        description: "Enumerate dangerous client-side sink patterns during runtime.",
        checklist: [
            "Scan inline scripts and dynamic script creation paths.",
            "Trace user-controlled data into sink APIs.",
            "Capture stack traces when possible."
        ],
        command: "(() => {\n  const sinks = [\"innerHTML\", \"outerHTML\", \"insertAdjacentHTML\", \"eval(\", \"Function(\", \"setTimeout(\", \"setInterval(\"];\n  const scriptText = Array.from(document.scripts).map((s) => s.textContent || \"\").join(\"\\n\");\n  const found = sinks.filter((sink) => scriptText.includes(sink));\n  console.table(found.map((sink) => ({ sink })));\n})();"
    },
    {
        id: "websocket-auth",
        category: "Client-Side",
        title: "WebSocket Authorization Check",
        description: "Inspect authentication requirements and message-level authorization for WS channels.",
        checklist: [
            "Open socket without auth context and compare behavior.",
            "Replay privileged actions over existing channels.",
            "Verify server-side permission checks per message type."
        ],
        command: "(() => {\n  const ws = new WebSocket(\"wss://{{TARGET}}/ws\");\n  ws.onopen = () => console.log(\"Socket opened\");\n  ws.onmessage = (event) => console.log(\"WS message\", event.data);\n  ws.onerror = (event) => console.log(\"WS error\", event);\n})();"
    }
];

const activeToolIdSet = new Set(activeTools.map((tool) => tool.id));

const state = {
    target: "",
    targetOrigin: "",
    reconLogs: [],
    reconStatus: createDefaultReconStatus(),
    findings: [],
    selectedToolIds: [],
    activeFilter: DEFAULT_FILTER,
    activeQuery: "",
    compactMode: true,
    activeDisplayLimit: 10,
    activePane: "reconSection",
    scanSummary: null,
    isReconRunning: false
};

let persistTimerId = 0;

initializeApp();

function initializeApp() {
    hydrateState();
    bindStaticEvents();
    renderAll();
}

function bindStaticEvents() {
    dom.runReconBtn.addEventListener("click", handleRunFullRecon);
    dom.clearSessionBtn.addEventListener("click", handleClearSession);
    dom.exportReportBtn.addEventListener("click", handleExportReport);
    dom.clearReconLogBtn.addEventListener("click", handleClearReconLog);
    dom.copyBundleBtn.addEventListener("click", handleCopyBundle);
    dom.copySummaryBtn.addEventListener("click", handleCopySummary);
    dom.copyDetailedReportBtn.addEventListener("click", handleCopyDetailedReport);
    dom.findingForm.addEventListener("submit", handleFindingSubmit);
    dom.clearFindingsBtn.addEventListener("click", handleClearFindings);

    dom.workspaceTabs.addEventListener("click", handleWorkspaceTabClick);
    dom.reconToolGrid.addEventListener("click", handleReconToolGridClick);
    dom.activeToolGrid.addEventListener("click", handleActiveToolGridClick);
    dom.activeToolGrid.addEventListener("change", handleActiveToolGridChange);
    dom.activeShowMoreBtn.addEventListener("click", handleActiveShowMore);

    dom.activeSearchInput.addEventListener("input", () => {
        state.activeQuery = dom.activeSearchInput.value.trim();
        state.activeDisplayLimit = 10;
        renderActiveTools();
        persistStateDebounced();
    });

    dom.compactModeToggle.addEventListener("change", () => {
        state.compactMode = dom.compactModeToggle.checked;
        renderActiveTools();
        persistState();
    });

    dom.targetInput.addEventListener("change", () => {
        const normalized = normalizeTargetInput(dom.targetInput.value);
        if (!normalized.ok) {
            return;
        }
        state.target = normalized.hostname;
        state.targetOrigin = normalized.origin;
        dom.targetInput.value = normalized.hostname;
        persistState();
        renderReconStats();
    });
}

function renderAll() {
    dom.targetInput.value = state.target;
    dom.activeSearchInput.value = state.activeQuery;
    dom.compactModeToggle.checked = state.compactMode;
    renderWorkspacePane();
    renderReconStats();
    renderReconTools();
    renderReconOutput();
    renderActiveFilters();
    renderActiveTools();
    renderCommandBundle();
    renderScanSummary();
    updateDetailedReportPreview();
    renderFindings();
    updateReconControls();
}

function renderWorkspacePane() {
    const paneIds = ["reconSection", "activeSection", "reportSection"];
    if (!paneIds.includes(state.activePane)) {
        state.activePane = "reconSection";
    }

    paneIds.forEach((paneId) => {
        const node = dom[paneId];
        if (!node) {
            return;
        }
        const isActive = paneId === state.activePane;
        node.classList.toggle("pane-hidden", !isActive);
    });

    dom.workspaceLayout.classList.add("single-pane");

    dom.workspaceTabs.querySelectorAll("[data-pane]").forEach((button) => {
        const paneId = button.getAttribute("data-pane");
        button.classList.toggle("active", paneId === state.activePane);
    });
}

function handleWorkspaceTabClick(event) {
    const button = event.target.closest("[data-pane]");
    if (!button || !dom.workspaceTabs.contains(button)) {
        return;
    }

    const paneId = button.getAttribute("data-pane");
    if (!paneId || paneId === state.activePane) {
        return;
    }

    state.activePane = paneId;
    renderWorkspacePane();
    persistStateDebounced();
}

function handleActiveShowMore() {
    state.activeDisplayLimit = Math.min(80, state.activeDisplayLimit + 10);
    renderActiveTools();
    persistStateDebounced();
}

async function handleCopyDetailedReport() {
    const report = buildMarkdownReport();
    const copied = await copyText(report);
    showToast(copied ? "Detailed report copied." : "Clipboard copy failed.", copied ? "success" : "error");
}

function updateDetailedReportPreview() {
    dom.scanReportPreview.value = buildMarkdownReport();
}

function createDefaultReconStatus() {
    return reconModules.reduce((accumulator, module) => {
        accumulator[module.id] = {
            status: "idle",
            lastRun: "",
            durationMs: 0,
            error: ""
        };
        return accumulator;
    }, {});
}

function hydrateState() {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
        return;
    }

    try {
        const saved = JSON.parse(raw);

        if (typeof saved.target === "string") {
            state.target = saved.target;
        }

        if (typeof saved.targetOrigin === "string") {
            state.targetOrigin = saved.targetOrigin;
        }

        if (Array.isArray(saved.reconLogs)) {
            state.reconLogs = saved.reconLogs
                .filter((entry) => entry && typeof entry.message === "string")
                .slice(-MAX_LOG_LINES);
        }

        if (saved.reconStatus && typeof saved.reconStatus === "object") {
            const defaults = createDefaultReconStatus();
            for (const module of reconModules) {
                const candidate = saved.reconStatus[module.id] || {};
                defaults[module.id] = {
                    status: isValidReconState(candidate.status) ? candidate.status : "idle",
                    lastRun: typeof candidate.lastRun === "string" ? candidate.lastRun : "",
                    durationMs: Number.isFinite(candidate.durationMs) ? candidate.durationMs : 0,
                    error: typeof candidate.error === "string" ? candidate.error : ""
                };
            }
            state.reconStatus = defaults;
        }

        if (Array.isArray(saved.findings)) {
            state.findings = saved.findings
                .filter((finding) => finding && typeof finding.title === "string")
                .slice(0, 300);
        }

        if (Array.isArray(saved.selectedToolIds)) {
            state.selectedToolIds = saved.selectedToolIds.filter((id) => activeToolIdSet.has(id));
        }

        if (typeof saved.activeFilter === "string") {
            state.activeFilter = saved.activeFilter;
        }

        if (typeof saved.activeQuery === "string") {
            state.activeQuery = saved.activeQuery;
        }

        if (typeof saved.compactMode === "boolean") {
            state.compactMode = saved.compactMode;
        }

        if (Number.isFinite(saved.activeDisplayLimit)) {
            state.activeDisplayLimit = Math.max(10, Math.min(80, Number(saved.activeDisplayLimit)));
        }

        if (typeof saved.activePane === "string") {
            state.activePane = saved.activePane;
        }

        if (saved.scanSummary && typeof saved.scanSummary === "object") {
            state.scanSummary = saved.scanSummary;
        }
    } catch (error) {
        console.warn("Failed to restore persisted session:", error);
    }

    if (!state.scanSummary && (state.reconLogs.length || state.findings.length)) {
        state.scanSummary = buildScanSummary();
    }
}

function persistState() {
    const snapshot = {
        target: state.target,
        targetOrigin: state.targetOrigin,
        reconLogs: state.reconLogs,
        reconStatus: state.reconStatus,
        findings: state.findings,
        selectedToolIds: state.selectedToolIds,
        activeFilter: state.activeFilter,
        activeQuery: state.activeQuery,
        compactMode: state.compactMode,
        activeDisplayLimit: state.activeDisplayLimit,
        activePane: state.activePane,
        scanSummary: state.scanSummary
    };

    localStorage.setItem(STORAGE_KEY, JSON.stringify(snapshot));
}

function persistStateDebounced() {
    window.clearTimeout(persistTimerId);
    persistTimerId = window.setTimeout(() => {
        persistState();
        persistTimerId = 0;
    }, PERSIST_DEBOUNCE_MS);
}

function isValidReconState(status) {
    return status === "idle" || status === "running" || status === "success" || status === "error";
}

function normalizeTargetInput(rawValue) {
    const raw = rawValue.trim();
    if (!raw) {
        return { ok: false, error: "Target is required." };
    }

    const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    let parsed;
    try {
        parsed = new URL(withProtocol);
    } catch {
        return { ok: false, error: "Target is not a valid URL or hostname." };
    }

    if (!parsed.hostname) {
        return { ok: false, error: "Hostname could not be parsed from target." };
    }

    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
    const host = parsed.host.toLowerCase();
    const origin = `${parsed.protocol}//${host}`;

    return {
        ok: true,
        hostname,
        host,
        origin,
        isIp: IPV4_PATTERN.test(hostname)
    };
}

function getTargetForRecon() {
    const candidate = dom.targetInput.value || state.target;
    const normalized = normalizeTargetInput(candidate);

    if (!normalized.ok) {
        showToast(normalized.error, "error");
        return null;
    }

    state.target = normalized.hostname;
    state.targetOrigin = normalized.origin;
    dom.targetInput.value = normalized.hostname;
    persistState();
    renderReconStats();

    return normalized;
}

async function handleRunFullRecon() {
    if (state.isReconRunning) {
        return;
    }

    const target = getTargetForRecon();
    if (!target) {
        return;
    }

    state.isReconRunning = true;
    updateReconControls();
    appendReconLog("detail", `Starting full reconnaissance against ${target.hostname}.`);

    const shared = { cache: {} };
    let successCount = 0;

    try {
        for (const module of reconModules) {
            const success = await executeReconModule(module, target, shared);
            if (success) {
                successCount += 1;
            }
        }

        appendReconLog("success", `Recon suite completed: ${successCount}/${reconModules.length} modules succeeded.`);
        refreshScanSummary();
        showToast(`Recon complete (${successCount}/${reconModules.length}).`, "success");
    } finally {
        state.isReconRunning = false;
        updateReconControls();
        renderReconTools();
        renderReconStats();
        persistState();
    }
}

async function executeReconModule(module, target, shared) {
    updateModuleStatus(module.id, {
        status: "running",
        error: "",
        durationMs: 0,
        lastRun: new Date().toISOString()
    });
    renderReconTools();
    renderReconStats();

    const startedAt = Date.now();

    try {
        await module.run({
            target,
            cache: shared.cache,
            log: (level, message) => {
                appendReconLog(level, `${module.name}: ${message}`);
            },
            fetchJson: fetchJson,
            fetchText: fetchText
        });

        const durationMs = Date.now() - startedAt;
        updateModuleStatus(module.id, {
            status: "success",
            error: "",
            durationMs,
            lastRun: new Date().toISOString()
        });
        appendReconLog("success", `${module.name}: completed in ${durationMs} ms.`);
        return true;
    } catch (error) {
        const durationMs = Date.now() - startedAt;
        const message = error instanceof Error ? error.message : String(error);
        updateModuleStatus(module.id, {
            status: "error",
            error: message,
            durationMs,
            lastRun: new Date().toISOString()
        });
        appendReconLog("error", `${module.name}: failed - ${message}`);
        return false;
    } finally {
        renderReconTools();
        renderReconStats();
        persistState();
    }
}

function updateModuleStatus(moduleId, patch) {
    const current = state.reconStatus[moduleId] || {
        status: "idle",
        lastRun: "",
        durationMs: 0,
        error: ""
    };

    state.reconStatus[moduleId] = {
        ...current,
        ...patch
    };
}

function renderReconTools() {
    const cards = reconModules.map((module) => {
        const status = state.reconStatus[module.id] || {};
        const statusLabel = getReconStatusLabel(status.status);
        const statusClass = getReconStatusClass(status.status);
        const lastRun = status.lastRun ? `Last run: ${formatDateTime(status.lastRun)}` : "Never run";
        const duration = status.durationMs > 0 ? `${status.durationMs} ms` : "-";

        return `
            <article class="tool-card">
                <div class="tool-meta">
                    <span class="tool-tag">${escapeHtml(module.mode)}</span>
                    <p class="tool-status ${statusClass}">${escapeHtml(statusLabel)}</p>
                </div>
                <h3>${escapeHtml(module.name)}</h3>
                <p>${escapeHtml(module.description)}</p>
                <p class="tool-status">Coverage: ${escapeHtml(module.coverage)}</p>
                <p class="tool-status">${escapeHtml(lastRun)} | Duration: ${escapeHtml(duration)}</p>
                ${status.error ? `<p class="tool-status status-error">${escapeHtml(status.error)}</p>` : ""}
                <div class="tool-actions">
                    <button type="button" data-run-module="${escapeAttr(module.id)}" ${state.isReconRunning ? "disabled" : ""}>Run Module</button>
                </div>
            </article>
        `;
    });

    dom.reconToolGrid.innerHTML = cards.join("");
}

async function handleReconToolGridClick(event) {
    const button = event.target.closest("[data-run-module]");
    if (!button || !dom.reconToolGrid.contains(button)) {
        return;
    }

    if (state.isReconRunning) {
        return;
    }

    const target = getTargetForRecon();
    if (!target) {
        return;
    }

    const moduleId = button.getAttribute("data-run-module");
    const module = reconModules.find((entry) => entry.id === moduleId);
    if (!module) {
        return;
    }

    state.isReconRunning = true;
    updateReconControls();
    appendReconLog("detail", `Starting module: ${module.name}.`);
    try {
        await executeReconModule(module, target, { cache: {} });
        refreshScanSummary();
    } finally {
        state.isReconRunning = false;
        updateReconControls();
        renderReconTools();
        persistState();
    }
}

function renderReconStats() {
    const statuses = Object.values(state.reconStatus);
    const completed = statuses.filter((item) => item.status !== "idle").length;
    const success = statuses.filter((item) => item.status === "success").length;
    const errors = statuses.filter((item) => item.status === "error").length;

    const chips = [
        `<span class="stat-chip">Target: ${escapeHtml(state.target || "not set")}</span>`,
        `<span class="stat-chip">Modules run: ${completed}/${reconModules.length}</span>`,
        `<span class="stat-chip">Succeeded: ${success}</span>`,
        `<span class="stat-chip">Issues: ${errors}</span>`,
        `<span class="stat-chip">Findings: ${state.findings.length}</span>`
    ];

    if (state.scanSummary && (state.scanSummary.moduleRunCount > 0 || state.findings.length > 0)) {
        chips.push(`<span class="stat-chip">Risk: ${escapeHtml(state.scanSummary.riskTier)} (${state.scanSummary.score}/100)</span>`);
    }

    dom.reconStats.innerHTML = chips.join("");
}

function getReconStatusLabel(status) {
    if (status === "running") {
        return "Running";
    }
    if (status === "success") {
        return "Success";
    }
    if (status === "error") {
        return "Issue";
    }
    return "Idle";
}

function getReconStatusClass(status) {
    if (status === "running") {
        return "status-running";
    }
    if (status === "success") {
        return "status-success";
    }
    if (status === "error") {
        return "status-error";
    }
    return "";
}

function appendReconLog(level, message) {
    const validLevel = level === "success" || level === "warn" || level === "error" ? level : "detail";

    const entry = {
        level: validLevel,
        message,
        timestamp: new Date().toISOString()
    };

    state.reconLogs.push(entry);
    let requiresFullRender = false;

    if (state.reconLogs.length > MAX_LOG_LINES) {
        state.reconLogs = state.reconLogs.slice(-MAX_LOG_LINES);
        requiresFullRender = true;
    }

    if (requiresFullRender) {
        renderReconOutput();
    } else {
        appendReconOutputLine(entry);
    }

    persistStateDebounced();
}

function renderReconOutput() {
    if (!state.reconLogs.length) {
        dom.reconOutput.innerHTML = "<p class=\"log-line detail\">[system] Recon output will appear here.</p>";
        dom.reconOutput.dataset.empty = "1";
        return;
    }

    dom.reconOutput.dataset.empty = "0";
    const fragment = document.createDocumentFragment();
    state.reconLogs.forEach((entry) => {
        fragment.appendChild(createReconLogElement(entry));
    });
    dom.reconOutput.replaceChildren(fragment);

    dom.reconOutput.scrollTop = dom.reconOutput.scrollHeight;
}

function appendReconOutputLine(entry) {
    if (dom.reconOutput.dataset.empty === "1") {
        dom.reconOutput.innerHTML = "";
    }

    dom.reconOutput.dataset.empty = "0";
    dom.reconOutput.appendChild(createReconLogElement(entry));
    dom.reconOutput.scrollTop = dom.reconOutput.scrollHeight;
}

function createReconLogElement(entry) {
    const className = entry.level === "warn" ? "warn" : entry.level;
    const line = document.createElement("p");
    line.className = `log-line ${className}`;
    line.textContent = `[${formatTime(entry.timestamp)}] ${entry.message}`;
    return line;
}

function updateReconControls() {
    dom.runReconBtn.disabled = state.isReconRunning;
    dom.runReconBtn.textContent = state.isReconRunning ? "Recon Running..." : "Run Full Recon";
}

function handleClearReconLog() {
    state.reconLogs = [];
    renderReconOutput();
    refreshScanSummary();
    persistState();
    showToast("Recon output cleared.", "success");
}

function renderActiveFilters() {
    const categories = [DEFAULT_FILTER, ...new Set(activeTools.map((tool) => tool.category))];

    if (!categories.includes(state.activeFilter)) {
        state.activeFilter = DEFAULT_FILTER;
    }

    dom.activeCategoryFilters.innerHTML = categories
        .map((category) => {
            const active = category === state.activeFilter ? "active" : "";
            return `<button type=\"button\" class=\"chip-filter ${active}\" data-filter=\"${escapeAttr(category)}\">${escapeHtml(category)}</button>`;
        })
        .join("");

    dom.activeCategoryFilters.querySelectorAll("[data-filter]").forEach((button) => {
        button.addEventListener("click", () => {
            const category = button.getAttribute("data-filter") || DEFAULT_FILTER;
            state.activeFilter = category;
            state.activeDisplayLimit = 10;
            persistState();
            renderActiveFilters();
            renderActiveTools();
        });
    });
}

function renderActiveTools() {
    const query = state.activeQuery.trim().toLowerCase();
    const visibleTools = activeTools.filter((tool) => {
        const categoryMatch = state.activeFilter === DEFAULT_FILTER || tool.category === state.activeFilter;
        if (!categoryMatch) {
            return false;
        }

        if (!query) {
            return true;
        }

        const haystack = [tool.title, tool.category, tool.description, tool.checklist.join(" ")]
            .join(" ")
            .toLowerCase();
        return haystack.includes(query);
    });

    const pagedTools = visibleTools.slice(0, state.activeDisplayLimit);
    dom.activeToolCount.textContent = `${pagedTools.length}/${visibleTools.length} visible | ${state.selectedToolIds.length} bundled`;

    const hasMore = visibleTools.length > pagedTools.length;
    dom.activeShowMoreBtn.hidden = !hasMore;
    dom.activeShowMoreBtn.disabled = !hasMore;
    dom.activeShowMoreBtn.textContent = hasMore
        ? `Show More (${visibleTools.length - pagedTools.length} remaining)`
        : "Show More";

    if (!visibleTools.length) {
        dom.activeToolGrid.innerHTML = "<article class=\"tool-card\"><p class=\"tool-status\">No tools match the current filter or search query.</p></article>";
        return;
    }

    dom.activeToolGrid.innerHTML = pagedTools
        .map((tool) => {
            const selected = state.selectedToolIds.includes(tool.id);
            const command = materializeCommand(tool);
            const checklist = tool.checklist.map((item) => `<li>${escapeHtml(item)}</li>`).join("");

            return `
                <article class="tool-card ${state.compactMode ? "compact" : ""}">
                    <div class="tool-meta">
                        <span class="tool-tag">${escapeHtml(tool.category)}</span>
                        <div class="tool-meta-actions">
                            <button type="button" class="ghost tiny" data-tool-copy="${escapeAttr(tool.id)}">Copy</button>
                            <label class="tool-check">
                                <input type="checkbox" data-tool-select="${escapeAttr(tool.id)}" ${selected ? "checked" : ""}>
                                Bundle
                            </label>
                        </div>
                    </div>
                    <h3>${escapeHtml(tool.title)}</h3>
                    <p class="tool-short">${escapeHtml(tool.description)}</p>
                    <div class="tool-expanded">
                        <ul class="tool-checklist">${checklist}</ul>
                        <pre class="command-box">${escapeHtml(command)}</pre>
                    </div>
                </article>
            `;
        })
        .join("");
}

async function handleActiveToolGridClick(event) {
    const button = event.target.closest("[data-tool-copy]");
    if (!button || !dom.activeToolGrid.contains(button)) {
        return;
    }

    const toolId = button.getAttribute("data-tool-copy");
    const tool = activeTools.find((entry) => entry.id === toolId);
    if (!tool) {
        return;
    }

    const copied = await copyText(materializeCommand(tool));
    showToast(copied ? `${tool.title} copied.` : "Clipboard copy failed.", copied ? "success" : "error");
}

function handleActiveToolGridChange(event) {
    const checkbox = event.target.closest("[data-tool-select]");
    if (!checkbox || !dom.activeToolGrid.contains(checkbox)) {
        return;
    }

    const toolId = checkbox.getAttribute("data-tool-select");
    if (!toolId) {
        return;
    }

    if (checkbox.checked) {
        if (!state.selectedToolIds.includes(toolId)) {
            state.selectedToolIds.push(toolId);
        }
    } else {
        state.selectedToolIds = state.selectedToolIds.filter((id) => id !== toolId);
    }

    persistState();
    renderCommandBundle();
    renderReconStats();
    renderActiveTools();
}

function materializeCommand(tool) {
    const target = state.target || "example.com";
    const origin = state.targetOrigin || `https://${target}`;

    return tool.command
        .replaceAll("{{TARGET}}", target)
        .replaceAll("{{ORIGIN}}", origin);
}

function renderCommandBundle() {
    const selectedTools = activeTools.filter((tool) => state.selectedToolIds.includes(tool.id));

    if (!selectedTools.length) {
        dom.commandBundle.value = "# Select active testing tools to build your runbook bundle.";
        return;
    }

    const blocks = selectedTools.map((tool, index) => {
        return [
            `# ${index + 1}. ${tool.title}`,
            `# Category: ${tool.category}`,
            materializeCommand(tool)
        ].join("\n");
    });

    dom.commandBundle.value = blocks.join("\n\n");
}

async function handleCopyBundle() {
    const text = dom.commandBundle.value.trim();
    if (!text || text.includes("Select active testing tools")) {
        showToast("Choose at least one active tool first.", "error");
        return;
    }

    const copied = await copyText(text);
    showToast(copied ? "Command bundle copied." : "Clipboard copy failed.", copied ? "success" : "error");
}

function handleFindingSubmit(event) {
    event.preventDefault();

    const title = dom.findingTitle.value.trim();
    const severity = dom.findingSeverity.value;
    const evidence = dom.findingEvidence.value.trim();
    const notes = dom.findingNotes.value.trim();

    if (!title) {
        showToast("Finding title is required.", "error");
        return;
    }

    const finding = {
        id: generateId(),
        title,
        severity: normalizeSeverity(severity),
        evidence,
        notes,
        createdAt: new Date().toISOString()
    };

    state.findings.unshift(finding);
    persistState();
    renderFindings();
    renderReconStats();
    refreshScanSummary();

    dom.findingTitle.value = "";
    dom.findingEvidence.value = "";
    dom.findingNotes.value = "";

    showToast("Finding added to report queue.", "success");
}

function renderFindings() {
    if (!state.findings.length) {
        dom.findingsList.innerHTML = "<article class=\"finding-card\"><p class=\"tool-status\">No findings recorded yet. Add reproducible evidence while you test.</p></article>";
        return;
    }

    dom.findingsList.innerHTML = state.findings
        .map((finding) => {
            const severityClass = `sev-${finding.severity}`;
            const evidenceLine = finding.evidence
                ? `<p class="tool-status">Evidence: <a href="${escapeAttr(finding.evidence)}" target="_blank" rel="noreferrer">${escapeHtml(finding.evidence)}</a></p>`
                : "<p class=\"tool-status\">Evidence: n/a</p>";

            return `
                <article class="finding-card">
                    <div class="finding-head">
                        <div>
                            <strong>${escapeHtml(finding.title)}</strong>
                            <p class="tool-status">Logged: ${escapeHtml(formatDateTime(finding.createdAt))}</p>
                        </div>
                        <span class="severity ${escapeAttr(severityClass)}">${escapeHtml(finding.severity)}</span>
                    </div>
                    ${evidenceLine}
                    <p>${escapeHtml(finding.notes || "No notes provided.")}</p>
                    <div class="tool-actions">
                        <button type="button" class="ghost tiny" data-remove-finding="${escapeAttr(finding.id)}">Remove</button>
                    </div>
                </article>
            `;
        })
        .join("");

    dom.findingsList.querySelectorAll("[data-remove-finding]").forEach((button) => {
        button.addEventListener("click", () => {
            const id = button.getAttribute("data-remove-finding");
            state.findings = state.findings.filter((finding) => finding.id !== id);
            persistState();
            renderFindings();
            renderReconStats();
            refreshScanSummary();
        });
    });
}

function handleClearFindings() {
    if (!state.findings.length) {
        return;
    }

    const confirmed = window.confirm("Clear all recorded findings?");
    if (!confirmed) {
        return;
    }

    state.findings = [];
    persistState();
    renderFindings();
    renderReconStats();
    refreshScanSummary();
    showToast("All findings cleared.", "success");
}

function handleClearSession() {
    const confirmed = window.confirm("Clear target, recon logs, selected tools, and findings?");
    if (!confirmed) {
        return;
    }

    state.target = "";
    state.targetOrigin = "";
    state.reconLogs = [];
    state.reconStatus = createDefaultReconStatus();
    state.findings = [];
    state.selectedToolIds = [];
    state.activeFilter = DEFAULT_FILTER;
    state.activeQuery = "";
    state.activeDisplayLimit = 10;
    state.activePane = "reconSection";
    state.scanSummary = null;
    state.isReconRunning = false;

    persistState();
    renderAll();
    showToast("Session cleared.", "success");
}

function handleExportReport() {
    const markdown = buildMarkdownReport();
    const targetPart = sanitizeFileNamePart(state.target || "target");
    const datePart = new Date().toISOString().slice(0, 10);
    const fileName = `secdash-report-${targetPart}-${datePart}.md`;

    downloadTextFile(fileName, markdown, "text/markdown;charset=utf-8");
    showToast("Markdown report exported.", "success");
}

function refreshScanSummary() {
    state.scanSummary = buildScanSummary();
    renderScanSummary();
    updateDetailedReportPreview();
    renderReconStats();
    persistStateDebounced();
}

function buildScanSummary() {
    const statuses = reconModules.map((module) => {
        const status = state.reconStatus[module.id] || {};
        return {
            id: module.id,
            name: module.name,
            status: status.status || "idle",
            durationMs: status.durationMs || 0,
            error: status.error || ""
        };
    });

    const logCounts = state.reconLogs.reduce(
        (accumulator, entry) => {
            const level = entry.level === "warn" ? "warn" : entry.level;
            if (level in accumulator) {
                accumulator[level] += 1;
            }
            return accumulator;
        },
        { success: 0, warn: 0, error: 0, detail: 0 }
    );

    const moduleRunCount = statuses.filter((entry) => entry.status !== "idle").length;
    const moduleSuccessCount = statuses.filter((entry) => entry.status === "success").length;
    const moduleErrorCount = statuses.filter((entry) => entry.status === "error").length;

    const severityCounts = collectSeverityCounts(state.findings);
    const penalty =
        (moduleErrorCount * 8) +
        (logCounts.error * 4) +
        (logCounts.warn * 1) +
        (severityCounts.critical * 20) +
        (severityCounts.high * 12) +
        (severityCounts.medium * 7) +
        (severityCounts.low * 3) +
        (severityCounts.info * 1);

    const score = Math.max(0, 100 - Math.min(95, penalty));
    const riskTier = getRiskTier(score);
    const notableObservations = state.reconLogs
        .filter((entry) => /(missing|exposed|cve|failed|not detected|policy|warning)/i.test(entry.message))
        .slice(-8)
        .map((entry) => entry.message);

    const highlights = [];
    if (!moduleRunCount) {
        highlights.push("Recon modules have not run yet. Start a scan to generate target-specific insights.");
    } else {
        highlights.push(`${moduleSuccessCount}/${reconModules.length} recon modules completed successfully.`);
    }

    if (moduleErrorCount) {
        highlights.push(`${moduleErrorCount} module(s) returned execution issues and should be manually verified.`);
    }

    if (logCounts.warn || logCounts.error) {
        highlights.push(`${logCounts.warn} warning log(s) and ${logCounts.error} error log(s) were observed.`);
    }

    if (severityCounts.critical || severityCounts.high) {
        highlights.push(`High-priority findings: ${severityCounts.critical} critical and ${severityCounts.high} high.`);
    } else if (state.findings.length) {
        highlights.push(`Findings recorded: ${state.findings.length}, currently below high severity.`);
    } else {
        highlights.push("No analyst findings have been recorded yet.");
    }

    const recommendations = [
        "Validate all recon module issues manually where browser restrictions may have affected results.",
        "Prioritize remediation for exposed headers, CVEs, and missing email or certificate policies.",
        "Convert selected active testing tools into a runbook and attach evidence to each finding.",
        "Re-run this scan after changes and compare score and log deltas to verify hardening progress."
    ];

    const durationEntries = statuses.filter((entry) => entry.durationMs > 0);
    const averageDuration = durationEntries.length
        ? Math.round(durationEntries.reduce((total, entry) => total + entry.durationMs, 0) / durationEntries.length)
        : 0;

    return {
        generatedAt: new Date().toISOString(),
        target: state.target || "not set",
        score,
        riskTier,
        moduleRunCount,
        moduleSuccessCount,
        moduleErrorCount,
        averageDuration,
        logCounts,
        severityCounts,
        highlights,
        recommendations,
        notableObservations,
        moduleStatuses: statuses
    };
}

function collectSeverityCounts(findings) {
    return findings.reduce(
        (accumulator, finding) => {
            const severity = normalizeSeverity(finding.severity);
            accumulator[severity] += 1;
            return accumulator;
        },
        { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    );
}

function getRiskTier(score) {
    if (score >= 85) {
        return "Low";
    }
    if (score >= 70) {
        return "Moderate";
    }
    if (score >= 50) {
        return "Elevated";
    }
    return "High";
}

function renderScanSummary() {
    const summary = isValidSummary(state.scanSummary) ? state.scanSummary : buildScanSummary();
    const hasScanData = summary.moduleRunCount > 0 || state.reconLogs.length > 0 || state.findings.length > 0;

    if (!hasScanData) {
        dom.scanSummaryStats.innerHTML = `<span class="stat-chip">Scan status: waiting for first run</span>`;
        dom.scanSummaryNarrative.innerHTML = [
            "<p>Run a reconnaissance scan to generate an automated executive summary, risk score, and prioritized next steps.</p>",
            "<p>After scanning, this panel will include highlights, notable observations, and recommendations.</p>"
        ].join("");
        dom.copySummaryBtn.disabled = true;
        return;
    }

    dom.copySummaryBtn.disabled = false;
    dom.scanSummaryStats.innerHTML = [
        `<span class="stat-chip">Risk Score: ${summary.score}/100</span>`,
        `<span class="stat-chip">Risk Tier: ${escapeHtml(summary.riskTier)}</span>`,
        `<span class="stat-chip">Module Success: ${summary.moduleSuccessCount}/${reconModules.length}</span>`,
        `<span class="stat-chip">Warnings: ${summary.logCounts.warn}</span>`,
        `<span class="stat-chip">Errors: ${summary.logCounts.error}</span>`,
        `<span class="stat-chip">Findings: ${state.findings.length}</span>`
    ].join("");

    const highlights = summary.highlights.map((item) => `<li>${escapeHtml(item)}</li>`).join("");
    const recommendations = summary.recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join("");

    dom.scanSummaryNarrative.innerHTML = [
        `<p><strong>Assessment Snapshot:</strong> ${escapeHtml(summary.target)} currently rates <strong>${summary.score}/100</strong> (${escapeHtml(summary.riskTier)} risk).</p>`,
        `<ul class="summary-list">${highlights}</ul>`,
        `<p><strong>Recommended Next Steps:</strong></p>`,
        `<ul class="summary-list">${recommendations}</ul>`
    ].join("");
}

async function handleCopySummary() {
    const summary = isValidSummary(state.scanSummary) ? state.scanSummary : buildScanSummary();
    const text = buildSummaryText(summary);
    const copied = await copyText(text);
    showToast(copied ? "Scan summary copied." : "Clipboard copy failed.", copied ? "success" : "error");
}

function buildSummaryText(summary) {
    const lines = [
        "SecDash Automated Scan Summary",
        `Target: ${summary.target}`,
        `Generated: ${summary.generatedAt}`,
        `Risk Score: ${summary.score}/100 (${summary.riskTier})`,
        `Modules Succeeded: ${summary.moduleSuccessCount}/${reconModules.length}`,
        `Warnings: ${summary.logCounts.warn} | Errors: ${summary.logCounts.error}`,
        `Findings: critical=${summary.severityCounts.critical}, high=${summary.severityCounts.high}, medium=${summary.severityCounts.medium}, low=${summary.severityCounts.low}, info=${summary.severityCounts.info}`,
        "",
        "Highlights:"
    ];

    summary.highlights.forEach((item) => lines.push(`- ${item}`));
    lines.push("", "Recommendations:");
    summary.recommendations.forEach((item) => lines.push(`- ${item}`));
    return lines.join("\n");
}

function buildMarkdownReport() {
    const generated = new Date().toISOString();
    const summary = isValidSummary(state.scanSummary) ? state.scanSummary : buildScanSummary();
    const statuses = reconModules.map((module) => {
        const status = state.reconStatus[module.id] || {};
        return {
            name: module.name,
            status: status.status || "idle",
            lastRun: status.lastRun ? formatDateTime(status.lastRun) : "-",
            duration: status.durationMs ? `${status.durationMs} ms` : "-",
            issue: status.error || ""
        };
    });

    const statusTable = statuses
        .map((row) => `| ${escapeMarkdown(row.name)} | ${escapeMarkdown(row.status)} | ${escapeMarkdown(row.lastRun)} | ${escapeMarkdown(row.duration)} | ${escapeMarkdown(row.issue || "-")} |`)
        .join("\n");

    const reconLogSection = state.reconLogs.length
        ? state.reconLogs
            .slice(-250)
            .map((entry) => `[${formatTime(entry.timestamp)}] [${entry.level.toUpperCase()}] ${entry.message}`)
            .join("\n")
        : "No recon logs captured.";

    const selectedTools = activeTools.filter((tool) => state.selectedToolIds.includes(tool.id));
    const toolSection = selectedTools.length
        ? selectedTools
            .map((tool, index) => {
                const checklist = tool.checklist.map((item) => `- [ ] ${escapeMarkdown(item)}`).join("\n");
                return [
                    `### ${index + 1}. ${escapeMarkdown(tool.title)}`,
                    `- Category: ${escapeMarkdown(tool.category)}`,
                    checklist,
                    "",
                    "```bash",
                    materializeCommand(tool),
                    "```"
                ].join("\n");
            })
            .join("\n\n")
        : "No active testing tools selected.";

    const findingsSection = state.findings.length
        ? state.findings
            .map((finding, index) => {
                return [
                    `### ${index + 1}. ${escapeMarkdown(finding.title)}`,
                    `- Severity: ${escapeMarkdown(finding.severity.toUpperCase())}`,
                    `- Logged: ${escapeMarkdown(formatDateTime(finding.createdAt))}`,
                    `- Evidence: ${escapeMarkdown(finding.evidence || "n/a")}`,
                    "",
                    finding.notes ? escapeMarkdown(finding.notes) : "_No notes provided._"
                ].join("\n");
            })
            .join("\n\n")
        : "No findings recorded.";

    const summaryHighlights = summary.highlights.length
        ? summary.highlights.map((item) => `- ${escapeMarkdown(item)}`).join("\n")
        : "- No highlights available.";

    const summaryRecommendations = summary.recommendations.length
        ? summary.recommendations.map((item) => `- ${escapeMarkdown(item)}`).join("\n")
        : "- No recommendations available.";

    const notableSection = summary.notableObservations.length
        ? summary.notableObservations.map((item) => `- ${escapeMarkdown(item)}`).join("\n")
        : "- No notable log observations captured.";

    return [
        "# SecDash Assessment Report",
        "",
        `Generated: ${generated}`,
        `Target: ${state.target || "not set"}`,
        `Automated Risk Score: ${summary.score}/100 (${summary.riskTier})`,
        "",
        "## Scope and Authorization",
        "This report is intended only for authorized ethical security testing engagements.",
        "",
        "## Executive Summary",
        `- Risk score: ${summary.score}/100`,
        `- Risk tier: ${summary.riskTier}`,
        `- Recon modules completed: ${summary.moduleSuccessCount}/${reconModules.length}`,
        `- Recon warnings/errors: ${summary.logCounts.warn}/${summary.logCounts.error}`,
        `- Findings recorded: ${state.findings.length}`,
        `- Average module duration: ${summary.averageDuration} ms`,
        "",
        "### Highlights",
        summaryHighlights,
        "",
        "### Notable Observations",
        notableSection,
        "",
        "## Reconnaissance Summary",
        `- Modules configured: ${reconModules.length}`,
        `- Findings recorded: ${state.findings.length}`,
        `- Active tool commands selected: ${selectedTools.length}`,
        "",
        "| Module | Status | Last Run | Duration | Issue |",
        "| --- | --- | --- | --- | --- |",
        statusTable,
        "",
        "## Reconnaissance Logs",
        "```text",
        reconLogSection,
        "```",
        "",
        "## Active Testing Runbook",
        toolSection,
        "",
        "## Findings",
        findingsSection,
        "",
        "## Recommendations",
        summaryRecommendations,
        "",
        "## Retest Checklist",
        "- [ ] Re-run full recon and compare module outcomes.",
        "- [ ] Re-validate all previously exploitable paths with fixed builds.",
        "- [ ] Confirm logging and monitoring alerts trigger for malicious patterns.",
        "- [ ] Attach new evidence proving closure for each finding."
    ].join("\n");
}

function isValidSummary(candidate) {
    return Boolean(
        candidate &&
        typeof candidate === "object" &&
        typeof candidate.score === "number" &&
        Array.isArray(candidate.highlights) &&
        Array.isArray(candidate.recommendations)
    );
}

function showToast(message, type) {
    dom.toast.textContent = message;
    dom.toast.className = `toast show ${type === "error" ? "error" : "success"}`;

    window.clearTimeout(showToast.timeoutId);
    showToast.timeoutId = window.setTimeout(() => {
        dom.toast.className = "toast";
    }, 2200);
}

async function copyText(value) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        try {
            await navigator.clipboard.writeText(value);
            return true;
        } catch {
            return false;
        }
    }

    const helper = document.createElement("textarea");
    helper.value = value;
    helper.setAttribute("readonly", "readonly");
    helper.style.position = "absolute";
    helper.style.left = "-9999px";
    document.body.appendChild(helper);
    helper.select();

    const copied = document.execCommand("copy");
    document.body.removeChild(helper);
    return copied;
}

function downloadTextFile(fileName, content, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

function generateId() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
        return window.crypto.randomUUID();
    }
    return `finding-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function normalizeSeverity(value) {
    const normalized = String(value || "").toLowerCase();
    if (["critical", "high", "medium", "low", "info"].includes(normalized)) {
        return normalized;
    }
    return "medium";
}

function formatTime(iso) {
    try {
        return new Date(iso).toLocaleTimeString();
    } catch {
        return "--:--:--";
    }
}

function formatDateTime(iso) {
    try {
        return new Date(iso).toLocaleString();
    } catch {
        return "n/a";
    }
}

function sanitizeFileNamePart(value) {
    return value
        .toLowerCase()
        .replace(/[^a-z0-9.-]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 64) || "target";
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}

function escapeAttr(value) {
    return escapeHtml(value).replaceAll("`", "&#96;");
}

function escapeMarkdown(value) {
    return String(value)
        .replaceAll("|", "\\|")
        .replaceAll("`", "\\`");
}

async function fetchWithTimeout(url, options, timeoutMs) {
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, {
            ...options,
            signal: controller.signal
        });
    } finally {
        window.clearTimeout(timeoutId);
    }
}

async function fetchJson(url) {
    const response = await fetchWithTimeout(url, {}, RECON_TIMEOUT_MS);
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    return response.json();
}

async function fetchText(url) {
    const response = await fetchWithTimeout(url, {}, RECON_TIMEOUT_MS);
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    return response.text();
}

function extractRecordValues(records, key) {
    if (!Array.isArray(records)) {
        return [];
    }

    return records
        .map((entry) => {
            if (entry && typeof entry === "object" && key in entry) {
                return entry[key];
            }
            return entry;
        })
        .map((item) => String(item || "").trim())
        .filter(Boolean);
}

function extractDnsAnswers(payload) {
    if (!payload || !Array.isArray(payload.Answer)) {
        return [];
    }

    return payload.Answer.map((answer) => String(answer.data || "").replace(/^\"|\"$/g, "").trim()).filter(Boolean);
}

async function resolvePrimaryIp(context) {
    if (context.target.isIp) {
        return context.target.hostname;
    }

    if (context.cache.primaryIp) {
        return context.cache.primaryIp;
    }

    const dnsPayload = await context.fetchJson(`https://networkcalc.com/api/dns/lookup/${encodeURIComponent(context.target.hostname)}`);
    const ipList = extractRecordValues(dnsPayload.records ? dnsPayload.records.A : [], "address");

    if (!ipList.length) {
        throw new Error("Unable to resolve IPv4 address for target.");
    }

    context.cache.primaryIp = ipList[0];
    return context.cache.primaryIp;
}

async function runDnsProfile(context) {
    if (context.target.isIp) {
        context.cache.primaryIp = context.target.hostname;
        context.log("warn", "Target is an IP address, domain DNS records skipped.");
        return;
    }

    const payload = await context.fetchJson(`https://networkcalc.com/api/dns/lookup/${encodeURIComponent(context.target.hostname)}`);
    const records = payload.records || {};

    const ipv4 = extractRecordValues(records.A, "address");
    const ipv6 = extractRecordValues(records.AAAA, "address");
    const mx = extractRecordValues(records.MX, "exchange");
    const txt = extractRecordValues(records.TXT, "value");

    if (ipv4.length) {
        context.cache.primaryIp = ipv4[0];
        context.log("success", `A records: ${ipv4.join(", ")}`);
    } else {
        context.log("warn", "No A records returned.");
    }

    if (ipv6.length) {
        context.log("detail", `AAAA records: ${ipv6.join(", ")}`);
    }

    if (mx.length) {
        context.log("success", `MX records: ${mx.join(", ")}`);
    } else {
        context.log("warn", "No MX records observed.");
    }

    const spf = txt.find((entry) => entry.toLowerCase().includes("v=spf1"));
    context.log(spf ? "success" : "warn", spf ? `SPF policy: ${spf}` : "SPF policy not detected.");

    const dmarcPayload = await context.fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(`_dmarc.${context.target.hostname}`)}&type=TXT`);
    const dmarc = extractDnsAnswers(dmarcPayload).find((entry) => entry.toLowerCase().includes("v=dmarc1"));
    context.log(dmarc ? "success" : "warn", dmarc ? `DMARC policy: ${dmarc}` : "DMARC policy not detected.");
}

async function runWhoisProfile(context) {
    if (context.target.isIp) {
        context.log("warn", "WHOIS profile is focused on domain targets.");
        return;
    }

    const payload = await context.fetchJson(`https://networkcalc.com/api/whois/${encodeURIComponent(context.target.hostname)}`);
    if (payload.status !== "OK" || !payload.whois) {
        context.log("warn", "WHOIS data unavailable or redacted.");
        return;
    }

    const whois = payload.whois;
    context.log("success", `Registrar: ${whois.registrar || "Unknown"}`);
    context.log("detail", `Created: ${whois.creation_date || "Unknown"}`);
    context.log("detail", `Expires: ${whois.expiration_date || whois.registry_expiry_date || "Unknown"}`);

    if (Array.isArray(whois.name_servers) && whois.name_servers.length) {
        context.log("detail", `Name servers: ${whois.name_servers.slice(0, 6).join(", ")}`);
    }
}

async function runTlsProfile(context) {
    if (context.target.isIp) {
        context.log("warn", "TLS certificate lookup expects a domain target.");
        return;
    }

    const payload = await context.fetchJson(`https://networkcalc.com/api/security/certificate/${encodeURIComponent(context.target.hostname)}`);
    if (payload.status !== "OK" || !payload.certificate) {
        context.log("warn", "Certificate details not available from source.");
        return;
    }

    const certificate = payload.certificate;
    const issuer = certificate.issuer
        ? certificate.issuer.organization || certificate.issuer.common_name || "Unknown issuer"
        : "Unknown issuer";
    context.log("success", `Issuer: ${issuer}`);
    context.log("detail", `Validity: ${certificate.valid_from || "?"} -> ${certificate.valid_to || "?"}`);

    if (certificate.signature_algorithm) {
        context.log("detail", `Signature algorithm: ${certificate.signature_algorithm}`);
    }

    if (Array.isArray(certificate.subject_alt_names) && certificate.subject_alt_names.length) {
        const sample = certificate.subject_alt_names.slice(0, 8);
        context.log("detail", `SAN sample: ${sample.join(", ")}`);
    }
}

async function runSubdomainIntel(context) {
    if (context.target.isIp) {
        context.log("warn", "Subdomain intelligence is not applicable to direct IP targets.");
        return;
    }

    const domain = context.target.hostname;
    const discovered = new Set();

    try {
        const text = await context.fetchText(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`);
        if (!/error/i.test(text)) {
            text.split("\n").forEach((line) => {
                const host = line.split(",")[0];
                if (host && host.endsWith(domain)) {
                    discovered.add(host.trim().toLowerCase());
                }
            });
        } else {
            context.log("warn", "Hostsearch source returned an error response.");
        }
    } catch {
        context.log("warn", "Hostsearch source is unreachable from this browser session.");
    }

    try {
        const certRows = await context.fetchJson(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`);
        if (Array.isArray(certRows)) {
            certRows.slice(0, 120).forEach((row) => {
                const names = String(row.name_value || "").split("\n");
                names.forEach((name) => {
                    const normalized = name.trim().replace(/^\*\./, "").toLowerCase();
                    if (normalized.endsWith(domain)) {
                        discovered.add(normalized);
                    }
                });
            });
        }
    } catch {
        context.log("warn", "Certificate transparency source blocked or unavailable.");
    }

    if (!discovered.size) {
        context.log("warn", "No subdomain hints collected from configured sources.");
        return;
    }

    const sample = Array.from(discovered).sort().slice(0, 12);
    context.log("success", `Subdomain candidates discovered: ${discovered.size}`);
    context.log("detail", `Sample: ${sample.join(", ")}`);
}

async function runHistoricalSurface(context) {
    if (context.target.isIp) {
        context.log("warn", "Historical archive scan is intended for domain targets.");
        return;
    }

    const payload = await context.fetchJson(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(context.target.hostname)}/*&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit=30`);

    if (!Array.isArray(payload) || payload.length <= 1) {
        context.log("warn", "No archived endpoints returned in sample window.");
        return;
    }

    const rows = payload.slice(1);
    context.log("success", `Archived endpoints sampled: ${rows.length}`);

    rows.slice(0, 8).forEach((row) => {
        const timestamp = row[0] || "unknown-time";
        const endpoint = row[1] || "unknown-endpoint";
        const status = row[2] || "unknown-status";
        context.log("detail", `${timestamp} | ${status} | ${endpoint}`);
    });
}

async function runRobotsAndSitemap(context) {
    if (context.target.isIp) {
        context.log("warn", "Robots and sitemap discovery expects a domain target.");
        return;
    }

    const robotsUrl = `${context.target.origin}/robots.txt`;
    try {
        const response = await fetchWithTimeout(robotsUrl, {}, RECON_TIMEOUT_MS);
        if (response.status === 404) {
            context.log("warn", "robots.txt not found.");
            return;
        }

        if (!response.ok) {
            context.log("warn", `robots.txt probe returned HTTP ${response.status}.`);
            return;
        }

        const text = await response.text();
        const lines = text.split("\n").map((line) => line.trim());
        const disallow = lines
            .filter((line) => /^disallow:/i.test(line))
            .map((line) => line.replace(/^disallow:\s*/i, "").trim())
            .filter(Boolean);
        const sitemaps = lines
            .filter((line) => /^sitemap:/i.test(line))
            .map((line) => line.replace(/^sitemap:\s*/i, "").trim())
            .filter(Boolean);

        context.log("success", `robots.txt reachable (${robotsUrl}).`);
        context.log(disallow.length ? "warn" : "detail", disallow.length ? `Disallow entries sample: ${disallow.slice(0, 8).join(", ")}` : "No Disallow entries parsed.");
        context.log(sitemaps.length ? "success" : "warn", sitemaps.length ? `Sitemap references: ${sitemaps.join(", ")}` : "No sitemap entries in robots.txt.");
    } catch {
        context.log("warn", "robots.txt check blocked by browser policy or network restrictions.");
    }
}

async function runSecurityTxtPresence(context) {
    if (context.target.isIp) {
        context.log("warn", "security.txt checks are intended for domain targets.");
        return;
    }

    const candidates = [
        `${context.target.origin}/.well-known/security.txt`,
        `${context.target.origin}/security.txt`
    ];

    let fileText = "";
    let matchedUrl = "";

    for (const url of candidates) {
        try {
            const response = await fetchWithTimeout(url, {}, RECON_TIMEOUT_MS);
            if (response.ok) {
                fileText = await response.text();
                matchedUrl = url;
                break;
            }
        } catch {
            continue;
        }
    }

    if (!fileText) {
        context.log("warn", "security.txt not detected on common locations.");
        return;
    }

    const lines = fileText.split("\n").map((line) => line.trim()).filter(Boolean);
    const contact = lines.find((line) => /^contact:/i.test(line));
    const policy = lines.find((line) => /^policy:/i.test(line));
    const expires = lines.find((line) => /^expires:/i.test(line));

    context.log("success", `security.txt discovered at ${matchedUrl}`);
    context.log(contact ? "success" : "warn", contact ? `Contact channel: ${contact.replace(/^contact:\s*/i, "")}` : "No Contact field found.");
    context.log(policy ? "detail" : "warn", policy ? `Policy URL: ${policy.replace(/^policy:\s*/i, "")}` : "No Policy field found.");
    context.log(expires ? "detail" : "warn", expires ? `Disclosure metadata expires: ${expires.replace(/^expires:\s*/i, "")}` : "No Expires field found.");
}

async function runPortExposure(context) {
    const ip = await resolvePrimaryIp(context);
    context.log("detail", `Using IP ${ip} for InternetDB lookup.`);

    const response = await fetchWithTimeout(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {}, RECON_TIMEOUT_MS);
    if (response.status === 404) {
        context.log("warn", "Host is not currently indexed by Shodan InternetDB.");
        return;
    }

    if (!response.ok) {
        throw new Error(`InternetDB request failed (HTTP ${response.status})`);
    }

    const payload = await response.json();
    const ports = Array.isArray(payload.ports) ? payload.ports : [];
    const vulns = Array.isArray(payload.vulns) ? payload.vulns : [];

    context.log(ports.length ? "success" : "warn", ports.length ? `Open ports: ${ports.join(", ")}` : "No open ports listed.");
    context.log(vulns.length ? "error" : "detail", vulns.length ? `Known CVEs: ${vulns.join(", ")}` : "No CVE entries from InternetDB.");
}

async function runHeaderPosture(context) {
    if (context.target.isIp) {
        context.log("warn", "Header posture module expects domain targets.");
        return;
    }

    const text = await context.fetchText(`https://api.hackertarget.com/httpheaders/?q=${encodeURIComponent(context.target.hostname)}`);
    if (/error/i.test(text)) {
        context.log("warn", "Header source returned an error response.");
        return;
    }

    const parsed = parseHeaderMap(text);
    const required = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy"
    ];

    required.forEach((name) => {
        if (parsed[name]) {
            context.log("success", `${name}: present`);
        } else {
            context.log("warn", `${name}: missing`);
        }
    });

    if (parsed.server) {
        context.log("warn", `Server header exposed: ${parsed.server}`);
    }
    if (parsed["x-powered-by"]) {
        context.log("warn", `X-Powered-By exposed: ${parsed["x-powered-by"]}`);
    }
}

async function runDnsPolicySignals(context) {
    if (context.target.isIp) {
        context.log("warn", "DNS policy module expects a domain target.");
        return;
    }

    const domain = context.target.hostname;

    const [mxPayload, nsPayload, caaPayload, dnskeyPayload] = await Promise.all([
        safeDnsResolve(context, domain, "MX"),
        safeDnsResolve(context, domain, "NS"),
        safeDnsResolve(context, domain, "CAA"),
        safeDnsResolve(context, domain, "DNSKEY")
    ]);

    const mx = extractDnsAnswers(mxPayload);
    const ns = extractDnsAnswers(nsPayload);
    const caa = extractDnsAnswers(caaPayload);
    const dnskey = extractDnsAnswers(dnskeyPayload);

    context.log(mx.length ? "success" : "warn", mx.length ? `MX answers: ${mx.join(", ")}` : "No MX answers found.");
    context.log(ns.length ? "success" : "warn", ns.length ? `NS answers: ${ns.join(", ")}` : "No NS answers found.");
    context.log(caa.length ? "success" : "warn", caa.length ? `CAA policy: ${caa.join(" | ")}` : "CAA records not found.");
    context.log(dnskey.length ? "success" : "warn", dnskey.length ? "DNSKEY records present (DNSSEC likely configured)." : "DNSKEY records absent in resolver output.");
}

async function safeDnsResolve(context, name, type) {
    try {
        return await context.fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`);
    } catch {
        return null;
    }
}

function parseHeaderMap(rawText) {
    const headers = {};
    rawText.split("\n").forEach((line) => {
        const separator = line.indexOf(":");
        if (separator <= 0) {
            return;
        }
        const key = line.slice(0, separator).trim().toLowerCase();
        const value = line.slice(separator + 1).trim();
        if (key && value) {
            headers[key] = value;
        }
    });
    return headers;
}
