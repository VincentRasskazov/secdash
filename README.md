# SecDash v6.0 (Terminal Velocity)

**Made with AI.** SecDash is a 100% static, client-side reconnaissance and injection workbench designed for bug bounty hunters and security analysts. It operates entirely without a backend, utilizing open APIs for passive external OSINT and generating advanced JavaScript payloads for direct DevTools injection to perform in-situ application analysis.

## Core Features

* **Automated OSINT Engine:** Chains public APIs (NetworkCalc, HackerTarget, Shodan) to gather DNS records, WHOIS data, SSL/TLS certificates, open ports, CVEs, and historical Wayback Machine endpoints without touching the target's origin server.
* **DevTools Payload Arsenal:** A massive clipboard library of advanced client-side scripts. Paste these into the target's DevTools Console (F12) to bypass CORS and extract IndexedDB data, hook `fetch()`/`WebSocket` traffic, sniff `postMessage` events, and hunt for DOM XSS sinks.
* **God Mode V3:** A single-click payload that generates a comprehensive client-side audit report directly in the target's console.

## Deployment

Zero build steps. Zero dependencies.

1. Clone or fork this repository.
2. Enable GitHub Pages in your repository settings (point to the `main` branch).
3. Access your live instance. (Alternatively, just open `index.html` locally in your browser).

## Usage Guide

1. Enter your target domain (e.g., `example.com`) and click **ENGAGE**.
2. Review the automated infrastructure data in the left terminal.
3. Select a payload from the right-hand arsenal and click **Copy**.
4. Open a new tab, navigate to the target web application, open Developer Tools (F12), and paste the payload into the Console.

## Disclaimer

**Authorized Use Only.** SecDash is built for educational purposes and authorized security research. Do not use this tool against infrastructure or applications you do not have explicit, written permission to test. The developers assume no liability for misuse.

## License

This project is licensed under the MIT License.

Copyright (c) 2026 

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
