# SecDash

SecDash is a static, browser-based dashboard for authorized web application security testing.

It is designed for readability and operational flow:

- Passive reconnaissance modules to map exposure quickly.
- Active testing toolcards organized by category.
- Search and compact mode to reduce visual clutter.
- Tabbed workspace to focus one section at a time.
- Incremental tool rendering with Show More for smoother browsing.
- Findings tracking with severity and evidence.
- Automated scan summary with risk score and recommendations.
- One-click markdown report export with executive summary.

No backend is required.

## Ethical Use

Use this project only for targets where you have explicit written permission.

- Respect scope boundaries and legal constraints.
- Avoid destructive testing unless it is approved.
- Treat this dashboard as an assistant, not a replacement for analyst judgment.

## What Is Included

### Reconnaissance Section

The recon panel supports full-run execution and per-module execution with status tracking, durations, and a live log console.

Current module coverage:

1. DNS Profile
2. WHOIS Snapshot
3. TLS Certificate Review
4. Subdomain Intelligence
5. Historical Surface (Wayback sample)
6. Robots and Sitemap Discovery
7. security.txt Presence
8. Port and CVE Exposure (Shodan InternetDB)
9. HTTP Header Posture
10. DNS Policy Signals (MX/NS/CAA/DNSKEY)

### Active Testing Section

The active testing panel provides categorized tools with:

- Objective-oriented descriptions
- Analyst checklists
- Command templates with target substitution
- Per-tool copy action
- Multi-tool runbook bundle builder

Categories currently include:

1. Input Validation
2. Authentication and Session
3. Authorization
4. API Security
5. Rate Limiting
6. File Upload
7. Business Logic
8. Client-Side

Additional tool coverage includes SSRF checks, CSRF origin validation, host-header poisoning tests, and cache-poisoning heuristics.

### Findings and Reporting Section

The reporting panel allows you to:

1. Add findings with severity, evidence URL, and notes
2. Track findings in-session
3. Generate an automated post-scan summary including:
	- risk score and risk tier
	- highlight list
	- notable observations from recon logs
	- prioritized recommendations
4. Export a markdown report including:
	- executive summary and score snapshot
	- recon status summary
	- recon logs
	- selected active testing runbook commands
	- findings and recommendations

## Project Structure

- `index.html`: UI layout, styles, and section structure
- `app.js`: app state, recon engine, active tool registry, findings manager, report exporter
- `LICENSE`: MIT license

## Run Locally

No build step is required.

1. Clone the repository.
2. Open `index.html` in a browser.

Optional: host with GitHub Pages from the `main` branch.

## Usage Workflow

1. Enter a target domain or URL.
2. Run full recon or execute individual recon modules.
3. Review module status and the recon console output.
4. Filter active testing tools by category and select tools for a command bundle.
5. Record findings as evidence is gathered.
6. Export markdown report for disclosure or internal tracking.

## Architecture Notes

`app.js` is organized around registries and render functions to avoid monolithic logic:

- Recon modules are defined in a single module registry.
- Active testing tools are defined in a single tool registry.
- Rendering is segmented by section (recon, active tools, findings, report bundle).
- Session state persists via `localStorage`.

This keeps the code readable and makes adding new modules predictable.

## Extending SecDash

### Add a New Recon Module

1. Add a new object to the `reconModules` array in `app.js`.
2. Implement the module runner function.
3. Use the shared context helpers (`fetchJson`, `fetchText`, `log`, cache).

### Add a New Active Testing Tool

1. Add a new object to the `activeTools` array in `app.js`.
2. Provide `category`, `title`, `description`, `checklist`, and `command`.
3. Use `{{TARGET}}` and `{{ORIGIN}}` placeholders where useful.

## Known Limitations

- Browser CORS policy can block some third-party API responses depending on provider changes.
- Public API availability can vary and may enforce request limits.
- Command templates are generic and must be adapted to target-specific routes and parameters.

## License

This project is licensed under the MIT License. See `LICENSE`.
