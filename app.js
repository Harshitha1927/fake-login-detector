/**
 * Fake Login Page Detector - Client Application Logic
 * Interactive UI, Scanning Radar Animation, Gauge Rendering, and Local Storage History.
 */

// Local Storage Key
const STORAGE_KEY = 'phishsentry_scan_history_v1';

// DOM Elements
const scanForm = document.getElementById('scanForm');
const urlInput = document.getElementById('urlInput');
const btnScan = document.getElementById('btnScan');
const btnClear = document.getElementById('btnClear');
const scanningOverlay = document.getElementById('scanningOverlay');
const scanningLogText = document.getElementById('scanningLogText');
const scanningProgressBar = document.getElementById('scanningProgressBar');

const resultsSection = document.getElementById('results-section');
const verdictBadge = document.getElementById('verdictBadge');
const verdictIcon = document.getElementById('verdictIcon');
const verdictText = document.getElementById('verdictText');
const verdictDesc = document.getElementById('verdictDesc');
const scanTimestamp = document.getElementById('scanTimestamp');
const scannedUrlCode = document.getElementById('scannedUrlCode');

const gaugeProgress = document.getElementById('gaugeProgress');
const gaugeScoreValue = document.getElementById('gaugeScoreValue');
const gaugeRiskLabel = document.getElementById('gaugeRiskLabel');

const metricScheme = document.getElementById('metricScheme');
const metricPort = document.getElementById('metricPort');
const metricLength = document.getElementById('metricLength');
const metricSubdomains = document.getElementById('metricSubdomains');

const countCrit = document.getElementById('countCrit');
const countWarn = document.getElementById('countWarn');
const countPass = document.getElementById('countPass');

const heuristicList = document.getElementById('heuristicList');
const recommendationsList = document.getElementById('recommendationsList');
const historyTableBody = document.getElementById('historyTableBody');

// Scanning visualizer log messages
const SCAN_STEPS = [
    { text: "Resolving URL syntax and RFC 3986 tokens...", progress: 20 },
    { text: "Auditing domain authority and raw IP flags...", progress: 40 },
    { text: "Executing brand impersonation & typosquatting heuristics...", progress: 65 },
    { text: "Inspecting transport encryption & TLD abuse registry...", progress: 85 },
    { text: "Computing consolidated threat risk score...", progress: 100 }
];

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    renderHistory();
});

/**
 * Handles Form Submission
 */
async function handleScanSubmit(e) {
    if (e) e.preventDefault();
    const url = urlInput.value.trim();

    if (!url) {
        alert("Please enter a website URL to scan.");
        urlInput.focus();
        return;
    }

    startScanAnimation();

    try {
        const startTime = Date.now();
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        // Enforce minimum scanning animation time (1.2s) for realistic cybersecurity experience
        const elapsed = Date.now() - startTime;
        const remainingDelay = Math.max(0, 1200 - elapsed);

        setTimeout(() => {
            stopScanAnimation();

            if (!response.ok || !data.valid) {
                alert(data.error || "Failed to analyze URL. Please check the address format.");
                return;
            }

            displayResults(data);
            saveToHistory(data);
        }, remainingDelay);

    } catch (err) {
        stopScanAnimation();
        alert("Network or connection error. Please verify the backend server is reachable.");
        console.error(err);
    }
}

/**
 * Triggers Radar Scanning Animation
 */
let scanInterval = null;
function startScanAnimation() {
    scanningOverlay.classList.remove('hidden');
    scanningProgressBar.style.width = '0%';
    let stepIndex = 0;

    scanningLogText.textContent = SCAN_STEPS[0].text;
    scanningProgressBar.style.width = `${SCAN_STEPS[0].progress}%`;

    scanInterval = setInterval(() => {
        stepIndex++;
        if (stepIndex < SCAN_STEPS.length) {
            scanningLogText.textContent = SCAN_STEPS[stepIndex].text;
            scanningProgressBar.style.width = `${SCAN_STEPS[stepIndex].progress}%`;
        }
    }, 240);
}

function stopScanAnimation() {
    if (scanInterval) {
        clearInterval(scanInterval);
        scanInterval = null;
    }
    scanningOverlay.classList.add('hidden');
}

/**
 * Displays Audit Results in UI
 */
function displayResults(data) {
    resultsSection.classList.remove('hidden');

    // Update Verdict Badge & Colors
    verdictBadge.className = 'verdict-badge';
    if (data.verdict_badge === 'danger') {
        verdictBadge.classList.add('badge-danger');
        verdictIcon.textContent = '🚨';
    } else if (data.verdict_badge === 'warning') {
        verdictBadge.classList.add('badge-warning');
        verdictIcon.textContent = '⚠️';
    } else {
        verdictBadge.classList.add('badge-safe');
        verdictIcon.textContent = '🛡️';
    }

    verdictText.textContent = data.verdict;
    verdictDesc.textContent = data.verdict_desc;
    scanTimestamp.textContent = data.timestamp || new Date().toLocaleTimeString();
    scannedUrlCode.textContent = data.url;

    // Technical Metrics
    metricScheme.textContent = data.extracted_info.scheme;
    metricPort.textContent = data.extracted_info.port;
    metricLength.textContent = `${data.extracted_info.url_length} chars`;
    metricSubdomains.textContent = data.extracted_info.subdomain_count;

    // Summary counts
    countCrit.textContent = data.summary.critical_flags;
    countWarn.textContent = data.summary.warning_flags;
    countPass.textContent = data.summary.passed_checks;

    // Animate Circular Risk Gauge
    animateGauge(data.risk_score);

    // Render Heuristic Matrix Rows
    renderHeuristics(data.checks);

    // Render Actionable Recommendations
    renderRecommendations(data.recommendations);

    // Smooth scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/**
 * Animates the SVG Gauge & Score Counter
 */
function animateGauge(score) {
    // Circle circumference for r=85 is 2 * PI * 85 ≈ 534
    const maxOffset = 534;
    const progressOffset = maxOffset - (score / 100) * maxOffset;

    gaugeProgress.style.strokeDashoffset = progressOffset;

    let strokeColor = 'var(--color-safe)';
    let riskText = 'SAFE';

    if (score >= 61) {
        strokeColor = 'var(--color-danger)';
        riskText = 'HIGH RISK';
    } else if (score >= 26) {
        strokeColor = 'var(--color-warn)';
        riskText = 'MODERATE';
    }

    gaugeProgress.style.stroke = strokeColor;
    gaugeRiskLabel.textContent = riskText;
    gaugeRiskLabel.style.color = strokeColor;

    // Countup animation for number
    let current = 0;
    const duration = 800;
    const stepTime = Math.max(10, Math.floor(duration / (score || 1)));

    const counter = setInterval(() => {
        if (current >= score) {
            gaugeScoreValue.textContent = score;
            clearInterval(counter);
        } else {
            current += 1;
            gaugeScoreValue.textContent = current;
        }
    }, stepTime);
}

/**
 * Renders the 14 Heuristic Matrix Cards
 */
function renderHeuristics(checks) {
    heuristicList.innerHTML = '';

    checks.forEach((chk, index) => {
        const item = document.createElement('div');
        item.className = 'heuristic-item';
        item.onclick = () => item.classList.toggle('expanded');

        let iconChar = '✓';
        let iconClass = 'icon-safe';
        let statusClass = 'status-SAFE';
        let statusLabel = 'PASSED';

        if (chk.status === 'CRITICAL') {
            iconChar = '!';
            iconClass = 'icon-crit';
            statusClass = 'status-CRITICAL';
            statusLabel = 'CRITICAL RISK';
        } else if (chk.status === 'WARNING') {
            iconChar = '▲';
            iconClass = 'icon-warn';
            statusClass = 'status-WARNING';
            statusLabel = 'WARNING';
        }

        item.innerHTML = `
            <div class="heuristic-header">
                <div class="heuristic-left">
                    <div class="status-badge-icon ${iconClass}">${iconChar}</div>
                    <div class="heuristic-title-box">
                        <span class="heuristic-title">${chk.name}</span>
                        <span class="heuristic-category">${chk.category}</span>
                    </div>
                </div>
                <div class="heuristic-right">
                    <span class="heuristic-status-text ${statusClass}">${statusLabel}</span>
                    <span class="chevron-icon">
                        <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </span>
                </div>
            </div>
            <div class="heuristic-details">
                <div class="detail-point"><strong>Finding:</strong> ${chk.details}</div>
                <div class="detail-point"><strong>Cybersecurity Impact:</strong> ${chk.reason}</div>
            </div>
        `;

        heuristicList.appendChild(item);
    });
}

/**
 * Renders Actionable Recommendations
 */
function renderRecommendations(recs) {
    recommendationsList.innerHTML = '';
    recs.forEach(rec => {
        const div = document.createElement('div');
        div.className = 'rec-item';
        div.innerHTML = `
            <span class="rec-item-icon">⚡</span>
            <span>${rec}</span>
        `;
        recommendationsList.appendChild(div);
    });
}

/**
 * Loads Quick Demo Sample URLs
 */
function loadSample(url) {
    urlInput.value = url;
    handleScanSubmit();
}

/**
 * Clears URL Input and Hides Results
 */
function clearInput() {
    urlInput.value = '';
    resultsSection.classList.add('hidden');
    urlInput.focus();
}

/**
 * Copies Target URL to Clipboard
 */
function copyAnalyzedUrl() {
    const text = scannedUrlCode.textContent;
    navigator.clipboard.writeText(text).then(() => {
        alert("Analyzed URL copied to clipboard!");
    }).catch(err => {
        console.error("Failed to copy URL:", err);
    });
}

/**
 * Scan History LocalStorage Management
 */
function getHistory() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        return raw ? JSON.parse(raw) : [];
    } catch (e) {
        return [];
    }
}

function saveToHistory(data) {
    const history = getHistory();
    const item = {
        id: Date.now(),
        timestamp: data.timestamp || new Date().toLocaleTimeString(),
        url: data.url,
        score: data.risk_score,
        verdict: data.verdict,
        badge: data.verdict_badge
    };

    // Keep up to 10 latest scans, avoiding immediate consecutive duplicates
    const filtered = history.filter(h => h.url !== item.url);
    filtered.unshift(item);
    const trimmed = filtered.slice(0, 10);

    localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
    renderHistory();
}

function renderHistory() {
    const history = getHistory();
    historyTableBody.innerHTML = '';

    if (history.length === 0) {
        historyTableBody.innerHTML = `
            <tr id="emptyHistoryRow">
                <td colspan="5" class="empty-state">No scans recorded yet. Enter a website URL to begin analysis.</td>
            </tr>
        `;
        return;
    }

    history.forEach(item => {
        const tr = document.createElement('tr');
        let badgeClass = 'badge-pass';
        if (item.badge === 'danger') badgeClass = 'badge-crit';
        else if (item.badge === 'warning') badgeClass = 'badge-warn';

        tr.innerHTML = `
            <td>${item.timestamp}</td>
            <td><span class="history-url" title="${item.url}">${item.url}</span></td>
            <td><strong>${item.score}/100</strong></td>
            <td><span class="badge-mini ${badgeClass}">${item.verdict}</span></td>
            <td>
                <button class="btn-rescan" onclick="loadSample('${item.url}')">Re-Scan</button>
            </td>
        `;
        historyTableBody.appendChild(tr);
    });
}

function clearHistory() {
    if (confirm("Are you sure you want to clear your local scan history?")) {
        localStorage.removeItem(STORAGE_KEY);
        renderHistory();
    }
}
