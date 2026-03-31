import { DashboardData, DiagramData, ThreatModelData } from './types.js';

export class DashboardTemplate {
    public render(data: DashboardData): string {
        const dataJson = JSON.stringify(data);

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SRT // ${this.escapeHtml(data.meta.projectName)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <style>
${this.getStyles()}
    </style>
</head>
<body>
    <div class="noise"></div>
    <div class="scanlines"></div>

    <div class="app">
        <header class="header">
            <div class="header-glow"></div>
            <div class="header-content">
                <div class="logo">
                    <div class="logo-mark">
                        <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M16 2L4 8v8c0 7.73 5.12 14.95 12 16 6.88-1.05 12-8.27 12-16V8L16 2z" stroke="currentColor" stroke-width="1.5" fill="none"/>
                            <path d="M16 6L8 10v6c0 5.1 3.41 9.87 8 10.67 4.59-.8 8-5.57 8-10.67v-6L16 6z" stroke="currentColor" stroke-width="1" opacity="0.5"/>
                            <circle cx="16" cy="14" r="3" fill="currentColor"/>
                        </svg>
                    </div>
                    <div class="logo-text">
                        <span class="logo-prefix">SRT://</span>
                        <span class="logo-project">${this.escapeHtml(data.meta.projectName)}</span>
                    </div>
                </div>
                <div class="header-meta">
                    <div class="meta-item">
                        <span class="meta-label">SCAN_TIME</span>
                        <span class="meta-value">${this.formatDate(data.meta.scanDate)}</span>
                    </div>
                    <div class="meta-divider"></div>
                    <div class="meta-item status-indicator ${(data.summary.open + data.summary.reopened) > 0 ? 'has-issues' : 'clear'}">
                        <span class="status-dot"></span>
                        <span class="meta-value">${(data.summary.open + data.summary.reopened) > 0 ? 'ISSUES_DETECTED' : 'ALL_CLEAR'}</span>
                    </div>
                </div>
            </div>
        </header>

        <main class="main">
            <div class="dashboard-grid${data.showAll ? '' : ' dashboard-grid-single'}">
                <section class="metrics-panel" style="--delay: 0">
                    <div class="panel-header">
                        <span class="panel-title">// METRICS</span>
                        <span class="panel-decorator"></span>
                    </div>
                    <div class="metrics-grid${data.showAll ? '' : ' metrics-grid-compact'}">
                        <div class="metric metric-total">
                            <div class="metric-value" data-value="${data.summary.total}">${data.summary.total}</div>
                            <div class="metric-bar"></div>
                            <div class="metric-label">TOTAL</div>
                        </div>
                        ${data.showAll ? `<div class="metric metric-blocking">
                            <div class="metric-value" data-value="${data.summary.blocking}">${data.summary.blocking}</div>
                            <div class="metric-bar"></div>
                            <div class="metric-label">BLOCKING</div>
                        </div>` : ''}
                        <div class="metric metric-critical">
                            <div class="metric-value" data-value="${data.summary.open + data.summary.reopened}">${data.summary.open + data.summary.reopened}</div>
                            <div class="metric-bar"></div>
                            <div class="metric-label">OPEN</div>
                        </div>
                        <div class="metric metric-resolved">
                            <div class="metric-value" data-value="${data.summary.resolved}">${data.summary.resolved}</div>
                            <div class="metric-bar"></div>
                            <div class="metric-label">FIXED</div>
                        </div>
                        <div class="metric metric-suppressed">
                            <div class="metric-value" data-value="${data.summary.suppressed}">${data.summary.suppressed}</div>
                            <div class="metric-bar"></div>
                            <div class="metric-label">SUPPRESSED</div>
                        </div>
                    </div>
                </section>

                ${data.showAll ? `<section class="severity-panel" style="--delay: 1">
                    <div class="panel-header">
                        <span class="panel-title">// SEVERITY_DISTRIBUTION</span>
                    </div>
                    ${this.renderSeverityBars(data)}
                </section>` : ''}
            </div>

            <nav class="nav-tabs" style="--delay: 2">
                ${data.projectSummary ? `<button class="nav-tab active" data-tab="summary">
                    <span class="tab-label">SUMMARY</span>
                </button>` : ''}
                <button class="nav-tab${data.projectSummary ? '' : ' active'}" data-tab="issues">
                    <span class="tab-label">ISSUES</span>
                    <span class="tab-count">${data.issues.filter(i => !i.isCustomResource).length}</span>
                </button>
                ${data.threatModels.length > 0 ? `<button class="nav-tab" data-tab="threats">
                    <span class="tab-label">THREAT MODELS</span>
                    <span class="tab-count">${data.threatModels.length}</span>
                </button>` : ''}
                ${data.diagrams.length > 0 ? `<button class="nav-tab" data-tab="diagrams">
                    <span class="tab-label">DIAGRAMS</span>
                    <span class="tab-count">${data.diagrams.length}</span>
                </button>` : ''}
                ${data.bom && data.bom.length > 0 ? `<button class="nav-tab" data-tab="bom">
                    <span class="tab-label">DEPENDENCIES</span>
                    <span class="tab-count">${data.bom.length}</span>
                </button>` : ''}
            </nav>

            <div class="content-panel" style="--delay: 3">
                ${data.projectSummary ? `<div class="tab-pane active" id="summary">
                    ${this.renderSummaryPanel(data.projectSummary)}
                </div>` : ''}
                <div class="tab-pane${data.projectSummary ? '' : ' active'}" id="issues">
                    ${this.renderIssuesPanel(data)}
                </div>
                ${data.threatModels.length > 0 ? `<div class="tab-pane" id="threats">
                    <div class="threats-content">${this.renderThreatModels(data.threatModels)}</div>
                </div>` : ''}
                ${data.diagrams.length > 0 ? `<div class="tab-pane" id="diagrams">
                    <div class="diagrams-content">${this.renderDiagrams(data.diagrams)}</div>
                </div>` : ''}
                ${data.bom && data.bom.length > 0 ? `<div class="tab-pane" id="bom">
                    ${this.renderBomPanel(data)}
                </div>` : ''}
            </div>
        </main>

        <footer class="footer">
            <div class="footer-line"></div>
            <div class="footer-content">
                <span class="footer-text">SRT v${data.meta.toolVersion}</span>
                <span class="footer-separator">•</span>
                <span class="footer-text">GENERATED ${this.formatDate(data.meta.generatedAt)}</span>
            </div>
        </footer>
    </div>

    <script type="application/json" id="dashboard-data">${dataJson}</script>
    <script>
${this.getScripts()}
    </script>
</body>
</html>`;
    }

    private getStyles(): string {
        return `
@keyframes fadeInUp {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
}

@keyframes glowPulse {
    0%, 100% { opacity: 0.5; }
    50% { opacity: 1; }
}

@keyframes scanline {
    0% { transform: translateY(-100%); }
    100% { transform: translateY(100vh); }
}

@keyframes typeIn {
    from { width: 0; }
    to { width: 100%; }
}

@keyframes blink {
    0%, 50% { opacity: 1; }
    51%, 100% { opacity: 0; }
}

@keyframes barGrow {
    from { transform: scaleX(0); }
    to { transform: scaleX(1); }
}

:root {
    --font-mono: 'JetBrains Mono', 'SF Mono', 'Fira Code', monospace;
    --font-display: 'Space Grotesk', system-ui, sans-serif;

    --bg-deep: #05080a;
    --bg-primary: #0a0e12;
    --bg-elevated: #0f1419;
    --bg-surface: #151c24;
    --bg-hover: #1a232d;

    --border-subtle: rgba(56, 189, 248, 0.08);
    --border-default: rgba(56, 189, 248, 0.15);
    --border-accent: rgba(56, 189, 248, 0.3);

    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --text-accent: #38bdf8;

    --cyan: #22d3ee;
    --cyan-glow: rgba(34, 211, 238, 0.4);
    --blue: #38bdf8;
    --blue-glow: rgba(56, 189, 248, 0.3);

    --critical: #f43f5e;
    --critical-bg: rgba(244, 63, 94, 0.1);
    --critical-glow: rgba(244, 63, 94, 0.4);

    --warning: #fb923c;
    --warning-bg: rgba(251, 146, 60, 0.1);
    --warning-glow: rgba(251, 146, 60, 0.4);

    --info: #38bdf8;
    --info-bg: rgba(56, 189, 248, 0.1);

    --success: #4ade80;
    --success-bg: rgba(74, 222, 128, 0.1);
    --success-glow: rgba(74, 222, 128, 0.4);

    --suppressed: #64748b;
    --suppressed-bg: rgba(100, 116, 139, 0.1);
}

*, *::before, *::after {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

html {
    font-size: 15px;
}

body {
    font-family: var(--font-mono);
    background: var(--bg-deep);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
    overflow-x: hidden;
}

/* Noise & Scanline Effects */
.noise {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    pointer-events: none;
    z-index: 1000;
    opacity: 0.03;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E");
}

.scanlines {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    pointer-events: none;
    z-index: 999;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0, 0, 0, 0.1) 2px,
        rgba(0, 0, 0, 0.1) 4px
    );
    opacity: 0.4;
}

.app {
    position: relative;
    z-index: 1;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

/* Header */
.header {
    position: sticky;
    top: 0;
    z-index: 100;
    background: var(--bg-primary);
    border-bottom: 1px solid var(--border-default);
    padding: 0;
    overflow: hidden;
}

.header-glow {
    position: absolute;
    top: 0;
    left: 50%;
    transform: translateX(-50%);
    width: 60%;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--cyan), transparent);
    animation: glowPulse 3s ease-in-out infinite;
}

.header-content {
    max-width: 1600px;
    margin: 0 auto;
    padding: 1.25rem 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logo {
    display: flex;
    align-items: center;
    gap: 1rem;
}

.logo-mark {
    width: 36px;
    height: 36px;
    color: var(--cyan);
    filter: drop-shadow(0 0 8px var(--cyan-glow));
}

.logo-text {
    display: flex;
    align-items: baseline;
    gap: 0.25rem;
}

.logo-prefix {
    font-family: var(--font-mono);
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--text-muted);
}

.logo-project {
    font-family: var(--font-display);
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--text-primary);
    letter-spacing: -0.02em;
}

.header-meta {
    display: flex;
    align-items: center;
    gap: 1.5rem;
}

.meta-item {
    display: flex;
    flex-direction: column;
    gap: 0.125rem;
}

.meta-label {
    font-size: 0.65rem;
    font-weight: 500;
    color: var(--text-muted);
    letter-spacing: 0.1em;
}

.meta-value {
    font-size: 0.8rem;
    color: var(--text-secondary);
}

.meta-divider {
    width: 1px;
    height: 32px;
    background: var(--border-default);
}

.status-indicator {
    flex-direction: row;
    align-items: center;
    gap: 0.5rem;
    padding: 0.375rem 0.75rem;
    border-radius: 4px;
    background: var(--success-bg);
    border: 1px solid rgba(74, 222, 128, 0.2);
}

.status-indicator.has-issues {
    background: var(--critical-bg);
    border-color: rgba(244, 63, 94, 0.2);
}

.status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--success);
    box-shadow: 0 0 8px var(--success-glow);
    animation: glowPulse 2s ease-in-out infinite;
}

.status-indicator.has-issues .status-dot {
    background: var(--critical);
    box-shadow: 0 0 8px var(--critical-glow);
}

.status-indicator .meta-value {
    color: var(--success);
    font-weight: 500;
    font-size: 0.7rem;
    letter-spacing: 0.05em;
}

.status-indicator.has-issues .meta-value {
    color: var(--critical);
}

/* Main Content */
.main {
    flex: 1;
    max-width: 1600px;
    margin: 0 auto;
    padding: 2rem;
    width: 100%;
}

/* Dashboard Grid */
.dashboard-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1.5rem;
    margin-bottom: 2rem;
}

.dashboard-grid-single {
    grid-template-columns: 1fr;
}

/* Panels */
.metrics-panel,
.severity-panel,
.content-panel {
    background: var(--bg-primary);
    border: 1px solid var(--border-default);
    border-radius: 8px;
    overflow: hidden;
    animation: fadeInUp 0.6s ease-out backwards;
    animation-delay: calc(var(--delay, 0) * 0.1s);
}

.panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 1.25rem;
    border-bottom: 1px solid var(--border-subtle);
    background: var(--bg-elevated);
}

.panel-title {
    font-size: 0.7rem;
    font-weight: 600;
    color: var(--text-accent);
    letter-spacing: 0.1em;
}

.panel-decorator {
    width: 40px;
    height: 2px;
    background: linear-gradient(90deg, var(--cyan), transparent);
}

/* Metrics */
.metrics-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 0;
}

.metrics-grid-compact {
    grid-template-columns: repeat(4, 1fr);
}

.metric {
    padding: 1.5rem 1.25rem;
    text-align: center;
    position: relative;
    border-right: 1px solid var(--border-subtle);
}

.metric:last-child {
    border-right: none;
}

.metric-value {
    font-family: var(--font-display);
    font-size: 2.5rem;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 0.75rem;
    color: var(--text-primary);
}

.metric-total .metric-value {
    color: var(--cyan);
    text-shadow: 0 0 30px var(--cyan-glow);
}

.metric-blocking .metric-value {
    color: var(--warning);
    text-shadow: 0 0 30px var(--warning-glow);
}

.metric-critical .metric-value {
    color: var(--critical);
    text-shadow: 0 0 30px var(--critical-glow);
}

.metric-warning .metric-value {
    color: var(--warning);
    text-shadow: 0 0 30px var(--warning-glow);
}

.metric-resolved .metric-value {
    color: var(--success);
    text-shadow: 0 0 30px var(--success-glow);
}

.metric-suppressed .metric-value {
    color: var(--suppressed);
}

.metric-bar {
    width: 100%;
    height: 2px;
    background: var(--border-subtle);
    margin-bottom: 0.75rem;
    position: relative;
    overflow: hidden;
}

.metric-bar::after {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    height: 100%;
    width: 100%;
    transform-origin: left;
    animation: barGrow 1s ease-out forwards;
    animation-delay: 0.3s;
    transform: scaleX(0);
}

.metric-total .metric-bar::after { background: var(--cyan); }
.metric-blocking .metric-bar::after { background: var(--warning); }
.metric-critical .metric-bar::after { background: var(--critical); }
.metric-warning .metric-bar::after { background: var(--warning); }
.metric-resolved .metric-bar::after { background: var(--success); }
.metric-suppressed .metric-bar::after { background: var(--suppressed); }

.metric-label {
    font-size: 0.65rem;
    font-weight: 600;
    color: var(--text-muted);
    letter-spacing: 0.15em;
}

/* Severity Bars */
.severity-bars {
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.severity-row {
    display: grid;
    grid-template-columns: 80px 1fr 50px;
    align-items: center;
    gap: 1rem;
}

.severity-label {
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.1em;
}

.severity-label.high { color: var(--critical); }
.severity-label.medium { color: var(--warning); }
.severity-label.low { color: var(--info); }

.severity-track {
    height: 8px;
    background: var(--bg-surface);
    border-radius: 4px;
    overflow: hidden;
    position: relative;
}

.severity-fill {
    height: 100%;
    border-radius: 4px;
    transform-origin: left;
    animation: barGrow 1s ease-out forwards;
    animation-delay: 0.5s;
    transform: scaleX(0);
}

.severity-fill.high { background: linear-gradient(90deg, var(--critical), rgba(244, 63, 94, 0.5)); }
.severity-fill.medium { background: linear-gradient(90deg, var(--warning), rgba(251, 146, 60, 0.5)); }
.severity-fill.low { background: linear-gradient(90deg, var(--info), rgba(56, 189, 248, 0.5)); }

.severity-count {
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--text-secondary);
    text-align: right;
    font-family: var(--font-display);
}

/* Navigation Tabs */
.nav-tabs {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--border-subtle);
    animation: fadeInUp 0.6s ease-out backwards;
    animation-delay: calc(var(--delay, 0) * 0.1s);
}

.nav-tab {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.625rem 1rem;
    background: transparent;
    border: 1px solid var(--border-subtle);
    border-radius: 4px;
    color: var(--text-secondary);
    font-family: var(--font-mono);
    font-size: 0.75rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
}

.nav-tab:hover {
    background: var(--bg-elevated);
    border-color: var(--border-default);
    color: var(--text-primary);
}

.nav-tab.active {
    background: var(--bg-surface);
    border-color: var(--cyan);
    color: var(--cyan);
    box-shadow: 0 0 20px rgba(34, 211, 238, 0.1);
}

.tab-key {
    color: var(--text-muted);
    font-size: 0.65rem;
}

.nav-tab.active .tab-key {
    color: var(--cyan);
    opacity: 0.7;
}

.tab-label {
    letter-spacing: 0.05em;
}

.tab-count {
    padding: 0.125rem 0.5rem;
    background: var(--bg-hover);
    border-radius: 3px;
    font-size: 0.7rem;
    color: var(--text-muted);
}

.nav-tab.active .tab-count {
    background: rgba(34, 211, 238, 0.15);
    color: var(--cyan);
}

/* Content Panel */
.content-panel {
    animation: fadeInUp 0.6s ease-out backwards;
    animation-delay: calc(var(--delay, 0) * 0.1s);
}

.tab-pane {
    display: none;
    padding: 1.5rem;
}

.tab-pane.active {
    display: block;
    animation: fadeInUp 0.4s ease-out;
}

/* Filters */
.filters {
    display: flex;
    gap: 1rem;
    margin-bottom: 1.25rem;
    padding-bottom: 1.25rem;
    border-bottom: 1px solid var(--border-subtle);
}

.filter-group {
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.filter-label {
    font-size: 0.65rem;
    font-weight: 600;
    color: var(--text-muted);
    letter-spacing: 0.1em;
}

.filter-select {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 4px;
    padding: 0.5rem 0.875rem;
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 0.75rem;
    cursor: pointer;
    transition: all 0.2s ease;
    min-width: 120px;
}

.filter-select option {
    background: var(--bg-surface);
    color: var(--text-primary);
}

.filter-select:hover {
    border-color: var(--border-accent);
}

.filter-select:focus {
    outline: none;
    border-color: var(--cyan);
    box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.1);
}

/* Issues Table */
.table-container {
    border: 1px solid var(--border-subtle);
    border-radius: 6px;
    overflow: hidden;
}

.data-table {
    width: 100%;
    border-collapse: collapse;
}

.data-table th {
    text-align: left;
    padding: 0.875rem 1rem;
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-muted);
    background: var(--bg-elevated);
    border-bottom: 1px solid var(--border-default);
    cursor: pointer;
    user-select: none;
    transition: color 0.2s ease;
    white-space: nowrap;
}

.data-table th:hover {
    color: var(--text-accent);
}

.data-table th.sorted::after {
    content: ' ▼';
    font-size: 0.5rem;
}

.data-table th.sorted.desc::after {
    content: ' ▲';
}

.data-table td {
    padding: 0.875rem 1rem;
    border-bottom: 1px solid var(--border-subtle);
    font-size: 0.8rem;
    vertical-align: top;
}

.data-table tbody tr {
    transition: background 0.15s ease;
}

.data-table tbody tr:hover {
    background: var(--bg-hover);
}

.data-table tbody tr:last-child td {
    border-bottom: none;
}

/* Badges */
.badge {
    display: inline-flex;
    align-items: center;
    padding: 0.25rem 0.625rem;
    border-radius: 3px;
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.badge-high {
    background: var(--critical-bg);
    color: var(--critical);
    border: 1px solid rgba(244, 63, 94, 0.25);
}

.badge-medium {
    background: var(--warning-bg);
    color: var(--warning);
    border: 1px solid rgba(251, 146, 60, 0.25);
}

.badge-low {
    background: var(--info-bg);
    color: var(--info);
    border: 1px solid rgba(56, 189, 248, 0.25);
}

.badge-open {
    background: var(--critical-bg);
    color: var(--critical);
}

.badge-reopened {
    background: var(--warning-bg);
    color: var(--warning);
}

.badge-fixed {
    background: var(--success-bg);
    color: var(--success);
}

.badge-suppressed {
    background: var(--suppressed-bg);
    color: var(--suppressed);
}

.badge-source {
    background: var(--bg-surface);
    color: var(--text-secondary);
    border: 1px solid var(--border-subtle);
}

/* Issue Location */
.issue-location {
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--text-secondary);
    word-break: break-all;
}

.issue-line {
    color: var(--cyan);
    font-weight: 600;
}

/* Issue Description */
.issue-desc {
    color: var(--text-primary);
    line-height: 1.5;
}

.issue-fix {
    margin-top: 0.5rem;
    padding-top: 0.5rem;
    border-top: 1px dashed var(--border-subtle);
    font-size: 0.75rem;
    color: var(--text-muted);
}

.issue-fix::before {
    content: '→ ';
    color: var(--success);
}

.issue-suppression {
    margin-top: 0.5rem;
    padding-top: 0.5rem;
    border-top: 1px dashed var(--border-subtle);
    font-size: 0.75rem;
    color: var(--suppressed);
}

.issue-suppression::before {
    content: '// ';
    font-family: var(--font-mono);
    color: var(--suppressed);
    opacity: 0.7;
}

/* Empty State */
.empty-state {
    text-align: center;
    padding: 4rem 2rem;
}

.empty-icon {
    font-size: 3rem;
    margin-bottom: 1rem;
    opacity: 0.3;
}

.empty-title {
    font-family: var(--font-display);
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--text-secondary);
    margin-bottom: 0.5rem;
}

.empty-text {
    font-size: 0.8rem;
    color: var(--text-muted);
}

/* Pagination */
.pagination {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem;
    border-top: 1px solid var(--border-subtle);
    background: var(--bg-elevated);
}

.pagination-info {
    font-size: 0.75rem;
    color: var(--text-muted);
}

.pagination-controls {
    display: flex;
    align-items: center;
    gap: 0.75rem;
}

.pagination-btn {
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 4px;
    padding: 0.5rem 0.875rem;
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 0.75rem;
    cursor: pointer;
    transition: all 0.2s ease;
}

.pagination-btn:hover:not(:disabled) {
    border-color: var(--cyan);
    color: var(--cyan);
}

.pagination-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
}

.page-indicator {
    font-size: 0.75rem;
    color: var(--text-secondary);
}

.pagination-top {
    border-top: none;
    border-bottom: 1px solid var(--border-subtle);
    border-radius: 6px 6px 0 0;
}

.pagination-top:empty {
    display: none;
}

/* Summary Content */
.summary-content {
    padding: 2rem;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 200px;
}

.summary-text {
    font-family: var(--font-display);
    font-size: 1.1rem;
    line-height: 1.8;
    color: var(--text-primary);
    max-width: 800px;
    text-align: center;
}

/* Markdown Content */
.markdown-content {
    line-height: 1.8;
    color: var(--text-secondary);
}

.markdown-content h1,
.markdown-content h2,
.markdown-content h3 {
    font-family: var(--font-display);
    color: var(--text-primary);
    margin: 2rem 0 1rem;
    font-weight: 600;
}

.markdown-content h1 { font-size: 1.5rem; }
.markdown-content h2 { font-size: 1.25rem; color: var(--text-accent); }
.markdown-content h3 { font-size: 1.1rem; }

.markdown-content p { margin-bottom: 1rem; }

.markdown-content ul,
.markdown-content ol {
    margin-bottom: 1rem;
    padding-left: 1.5rem;
}

.markdown-content li { margin-bottom: 0.375rem; }

.markdown-content code {
    background: var(--bg-surface);
    padding: 0.125rem 0.375rem;
    border-radius: 3px;
    font-size: 0.85em;
    color: var(--cyan);
}

.markdown-content pre {
    background: var(--bg-surface);
    padding: 1rem;
    border-radius: 6px;
    overflow-x: auto;
    margin-bottom: 1rem;
    border: 1px solid var(--border-subtle);
}

.markdown-content pre code {
    background: none;
    padding: 0;
    color: var(--text-primary);
}

.markdown-content table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 1rem;
}

.markdown-content th,
.markdown-content td {
    padding: 0.75rem;
    border: 1px solid var(--border-subtle);
    text-align: left;
}

.markdown-content th {
    background: var(--bg-elevated);
    font-weight: 600;
    color: var(--text-primary);
}

/* Collapsible Sections */
.collapsible-section {
    margin-bottom: 0.5rem;
    border: 1px solid var(--border-subtle);
    border-radius: 6px;
    overflow: hidden;
}

.collapsible-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    width: 100%;
    padding: 1rem 1.25rem;
    background: var(--bg-elevated);
    border: none;
    cursor: pointer;
    text-align: left;
    transition: all 0.2s ease;
}

.collapsible-header:hover {
    background: var(--bg-surface);
}

.collapsible-icon {
    font-size: 0.7rem;
    color: var(--text-muted);
    transition: transform 0.2s ease;
}

.collapsible-section.expanded .collapsible-icon {
    transform: rotate(90deg);
}

.collapsible-title {
    font-family: var(--font-display);
    font-size: 1rem;
    font-weight: 600;
    color: var(--text-accent);
}

.collapsible-content {
    display: none;
    padding: 1.25rem;
    border-top: 1px solid var(--border-subtle);
    background: var(--bg-primary);
}

.collapsible-section.expanded .collapsible-content {
    display: block;
}

/* Threat Models */
.threats-content {
    padding: 0;
}

/* Diagrams */
.diagrams-content {
    padding: 0;
}

.mermaid {
    background: var(--bg-surface);
    padding: 1.5rem;
    border-radius: 6px;
    border: 1px solid var(--border-subtle);
    overflow-x: auto;
    white-space: pre-wrap;
    font-family: var(--font-mono);
    font-size: 0.85rem;
}

.mermaid svg {
    max-width: 100%;
    height: auto;
}

/* BOM Search */
.bom-search {
    margin-bottom: 1.25rem;
}

.search-input {
    width: 100%;
    max-width: 400px;
    background: var(--bg-surface);
    border: 1px solid var(--border-default);
    border-radius: 4px;
    padding: 0.625rem 1rem;
    color: var(--text-primary);
    font-family: var(--font-mono);
    font-size: 0.8rem;
    transition: all 0.2s ease;
}

.search-input::placeholder {
    color: var(--text-muted);
}

.search-input:focus {
    outline: none;
    border-color: var(--cyan);
    box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.1);
}

/* Footer */
.footer {
    margin-top: auto;
    padding: 1.5rem 2rem;
    position: relative;
}

.footer-line {
    position: absolute;
    top: 0;
    left: 2rem;
    right: 2rem;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--border-default), transparent);
}

.footer-content {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 1rem;
}

.footer-text {
    font-size: 0.65rem;
    color: var(--text-muted);
    letter-spacing: 0.1em;
}

.footer-separator {
    color: var(--border-default);
}

/* Responsive */
@media (max-width: 1024px) {
    .dashboard-grid {
        grid-template-columns: 1fr;
    }

    .metrics-grid {
        grid-template-columns: repeat(2, 1fr);
    }

    .metric {
        border-bottom: 1px solid var(--border-subtle);
    }

    .metric:nth-child(2) {
        border-right: none;
    }

    .metric:nth-child(3),
    .metric:nth-child(4) {
        border-bottom: none;
    }
}

@media (max-width: 768px) {
    html { font-size: 14px; }

    .header-content {
        flex-direction: column;
        gap: 1rem;
        text-align: center;
    }

    .header-meta {
        flex-wrap: wrap;
        justify-content: center;
    }

    .main { padding: 1rem; }

    .nav-tabs {
        flex-wrap: wrap;
    }

    .filters {
        flex-direction: column;
        align-items: stretch;
    }

    .filter-select {
        width: 100%;
    }
}
`;
    }

    private getScripts(): string {
        return `
// Data & State
const dashboardData = JSON.parse(document.getElementById('dashboard-data').textContent);
let currentFilters = { priority: 'all', status: 'all', source: 'all' };
let currentSort = { column: null, desc: false };
let currentPage = 1;
const PAGE_SIZE = 100;

// Tab Navigation
document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
        const targetId = tab.dataset.tab;

        document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

        tab.classList.add('active');
        document.getElementById(targetId)?.classList.add('active');
    });
});

// Keyboard shortcuts for tabs
document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;

    const tabs = document.querySelectorAll('.nav-tab');
    const num = parseInt(e.key);
    if (num >= 1 && num <= tabs.length) {
        tabs[num - 1].click();
    }
});

// Filtering
const priorityOrder = { high: 0, medium: 1, low: 2 };
const statusOrder = { reopened: 0, open: 1, fixed: 2, suppressed: 3 };

function filterIssues(resetPage = true) {
    if (resetPage) currentPage = 1;

    const issues = dashboardData.issues.filter(issue => {
        if (issue.isCustomResource) return false;
        if (currentFilters.priority !== 'all' && (issue.priority?.toLowerCase() || '') !== currentFilters.priority) return false;
        if (currentFilters.status !== 'all') {
            const status = (issue.status?.toLowerCase() || 'open');
            if (status !== currentFilters.status) return false;
        }
        if (currentFilters.source !== 'all' && issue.source !== currentFilters.source) return false;
        return true;
    });

    if (currentSort.column) {
        issues.sort((a, b) => {
            let aVal = a[currentSort.column] || '';
            let bVal = b[currentSort.column] || '';
            if (typeof aVal === 'string') aVal = aVal.toLowerCase();
            if (typeof bVal === 'string') bVal = bVal.toLowerCase();
            if (aVal < bVal) return currentSort.desc ? 1 : -1;
            if (aVal > bVal) return currentSort.desc ? -1 : 1;
            return 0;
        });
    } else {
        // Default sort: priority (high first), then status (open first)
        issues.sort((a, b) => {
            const aPriority = priorityOrder[(a.priority || 'low').toLowerCase()] ?? 3;
            const bPriority = priorityOrder[(b.priority || 'low').toLowerCase()] ?? 3;
            if (aPriority !== bPriority) return aPriority - bPriority;

            const aStatus = statusOrder[(a.status || 'open').toLowerCase()] ?? 3;
            const bStatus = statusOrder[(b.status || 'open').toLowerCase()] ?? 3;
            return aStatus - bStatus;
        });
    }

    renderIssuesTable(issues);
}

function renderIssuesTable(issues) {
    const tbody = document.getElementById('issues-tbody');
    if (!tbody) return;

    const totalPages = Math.ceil(issues.length / PAGE_SIZE);
    const startIdx = (currentPage - 1) * PAGE_SIZE;
    const endIdx = Math.min(startIdx + PAGE_SIZE, issues.length);
    const pageIssues = issues.slice(startIdx, endIdx);

    if (issues.length === 0) {
        tbody.innerHTML = \`<tr><td colspan="6">
            <div class="empty-state">
                <div class="empty-icon">◇</div>
                <div class="empty-title">No matching issues</div>
                <div class="empty-text">Try adjusting your filters</div>
            </div>
        </td></tr>\`;
        renderPagination(0, 0, 0);
        return;
    }

    tbody.innerHTML = pageIssues.map(issue => {
        const priority = (issue.priority || 'low').toLowerCase();
        const status = (issue.status || 'open').toLowerCase();
        return \`
            <tr>
                <td><span class="badge badge-\${priority}">\${priority.toUpperCase()}</span></td>
                <td><span class="badge badge-\${status}">\${status.toUpperCase()}</span></td>
                <td><span class="badge badge-source">\${escapeHtml(issue.source || 'Unknown')}</span></td>
                <td>
                    <div class="issue-desc">\${escapeHtml(issue.issue || '')}</div>
                    \${issue.fix ? \`<div class="issue-fix">\${escapeHtml(issue.fix)}</div>\` : ''}
                    \${status === 'suppressed' && issue.suppressionReason ? \`<div class="issue-suppression">\${escapeHtml(issue.suppressionReason)}</div>\` : ''}
                </td>
                <td>
                    <div class="issue-location">\${escapeHtml(issue.path || '')}\${issue.line ? \`<span class="issue-line">:\${issue.line}</span>\` : ''}</div>
                </td>
                <td><span class="resource-name">\${escapeHtml(issue.resourceName || '')}</span></td>
            </tr>
        \`;
    }).join('');

    renderPagination(issues.length, startIdx + 1, endIdx, totalPages);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Pagination
function renderPagination(total, start, end, totalPages) {
    let paginationBottom = document.getElementById('issues-pagination');
    if (!paginationBottom) {
        const tableContainer = document.querySelector('#issues .table-container');
        if (tableContainer) {
            paginationBottom = document.createElement('div');
            paginationBottom.id = 'issues-pagination';
            paginationBottom.className = 'pagination';
            tableContainer.appendChild(paginationBottom);
        }
    }

    const paginationTop = document.getElementById('issues-pagination-top');
    const paginationHtml = total <= PAGE_SIZE ? '' : \`
        <span class="pagination-info">Showing \${start}-\${end} of \${total} issues</span>
        <div class="pagination-controls">
            <button class="pagination-btn" onclick="goToPage(\${currentPage - 1})" \${currentPage === 1 ? 'disabled' : ''}>← Prev</button>
            <span class="page-indicator">Page \${currentPage} of \${totalPages}</span>
            <button class="pagination-btn" onclick="goToPage(\${currentPage + 1})" \${currentPage === totalPages ? 'disabled' : ''}>Next →</button>
        </div>
    \`;

    if (paginationBottom) paginationBottom.innerHTML = paginationHtml;
    if (paginationTop) paginationTop.innerHTML = paginationHtml;
}

function goToPage(page) {
    currentPage = page;
    filterIssues(false);
    document.querySelector('#issues .filters')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Filter handlers
document.querySelectorAll('.filter-select').forEach(select => {
    select.addEventListener('change', (e) => {
        currentFilters[e.target.dataset.filter] = e.target.value;
        filterIssues();
    });
});

// Initialize pagination on page load
filterIssues(false);

// Table sorting
document.querySelectorAll('.data-table th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
        const column = th.dataset.sort;
        if (currentSort.column === column) {
            currentSort.desc = !currentSort.desc;
        } else {
            currentSort.column = column;
            currentSort.desc = false;
        }

        document.querySelectorAll('.data-table th').forEach(h => {
            h.classList.remove('sorted', 'desc');
        });
        th.classList.add('sorted');
        if (currentSort.desc) th.classList.add('desc');

        filterIssues();
    });
});

// BOM Search
const bomSearch = document.getElementById('bom-search');
if (bomSearch) {
    bomSearch.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const rows = document.querySelectorAll('#bom-tbody tr');
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(query) ? '' : 'none';
        });
    });
}

// Collapsible sections
document.querySelectorAll('.collapsible-header').forEach(header => {
    header.addEventListener('click', () => {
        const section = header.parentElement;
        const isExpanded = section.classList.contains('expanded');
        section.classList.toggle('expanded');
        header.setAttribute('aria-expanded', !isExpanded);
    });
});

// Initialize Mermaid
document.addEventListener('DOMContentLoaded', async () => {
    if (typeof mermaid !== 'undefined') {
        mermaid.initialize({
            startOnLoad: false,
            theme: 'dark',
            securityLevel: 'loose',
            suppressErrors: true,
            themeVariables: {
                darkMode: true,
                background: '#0a0e12',
                primaryColor: '#22d3ee',
                primaryTextColor: '#e2e8f0',
                primaryBorderColor: '#38bdf8',
                lineColor: '#64748b',
                secondaryColor: '#151c24',
                tertiaryColor: '#1a232d'
            }
        });

        // Render each diagram individually with error handling
        const diagrams = document.querySelectorAll('.mermaid');
        for (let i = 0; i < diagrams.length; i++) {
            const element = diagrams[i];
            const code = element.textContent || '';
            try {
                const { svg } = await mermaid.render('mermaid-' + i, code);
                element.innerHTML = svg;
            } catch (err) {
                console.error('Mermaid render error:', err);
                element.innerHTML = '<div style="color: var(--warning); padding: 1rem;">Diagram rendering failed. Raw code:</div><pre style="color: var(--text-muted); font-size: 0.75rem; white-space: pre-wrap;">' + escapeHtml(code) + '</pre>';
            }
        }
    }
});
`;
    }

    private renderSeverityBars(data: DashboardData): string {
        const { high, medium, low } = data.summary.byPriority;
        const total = high + medium + low;

        if (total === 0) {
            return `<div class="severity-bars">
                <div class="empty-state">
                    <div class="empty-icon">✔</div>
                    <div class="empty-title">No issues detected</div>
                </div>
            </div>`;
        }

        const maxCount = Math.max(high, medium, low, 1);

        return `
            <div class="severity-bars">
                <div class="severity-row">
                    <span class="severity-label high">HIGH</span>
                    <div class="severity-track">
                        <div class="severity-fill high" style="width: ${(high / maxCount) * 100}%"></div>
                    </div>
                    <span class="severity-count">${high}</span>
                </div>
                <div class="severity-row">
                    <span class="severity-label medium">MEDIUM</span>
                    <div class="severity-track">
                        <div class="severity-fill medium" style="width: ${(medium / maxCount) * 100}%"></div>
                    </div>
                    <span class="severity-count">${medium}</span>
                </div>
                <div class="severity-row">
                    <span class="severity-label low">LOW</span>
                    <div class="severity-track">
                        <div class="severity-fill low" style="width: ${(low / maxCount) * 100}%"></div>
                    </div>
                    <span class="severity-count">${low}</span>
                </div>
            </div>
        `;
    }

    private renderIssuesPanel(data: DashboardData): string {
        const sources = Object.keys(data.summary.bySource);

        return `
            <div class="filters">
                ${data.showAll ? `<div class="filter-group">
                    <label class="filter-label">PRIORITY</label>
                    <select class="filter-select" data-filter="priority">
                        <option value="all">All</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                </div>` : ''}
                <div class="filter-group">
                    <label class="filter-label">STATUS</label>
                    <select class="filter-select" data-filter="status">
                        <option value="all">All</option>
                        <option value="open">Open</option>
                        <option value="reopened">Reopened</option>
                        <option value="fixed">Fixed</option>
                        <option value="suppressed">Suppressed</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label class="filter-label">SOURCE</label>
                    <select class="filter-select" data-filter="source">
                        <option value="all">All</option>
                        ${sources.map(s => `<option value="${this.escapeHtml(s)}">${this.escapeHtml(s)}</option>`).join('')}
                    </select>
                </div>
            </div>
            <div id="issues-pagination-top" class="pagination pagination-top"></div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th data-sort="priority" style="width: 90px;">Priority</th>
                            <th data-sort="status" style="width: 90px;">Status</th>
                            <th data-sort="source" style="width: 100px;">Source</th>
                            <th>Issue</th>
                            <th data-sort="path" style="width: 25%;">Location</th>
                            <th data-sort="resourceName" style="width: 150px;">Resource</th>
                        </tr>
                    </thead>
                    <tbody id="issues-tbody">
                        ${this.renderIssueRows(data.issues)}
                    </tbody>
                </table>
            </div>
        `;
    }

    private renderIssueRows(issues: any[]): string {
        const priorityOrder: Record<string, number> = { high: 0, medium: 1, low: 2 };
        const statusOrder: Record<string, number> = { reopened: 0, open: 1, fixed: 2, suppressed: 3 };

        const filteredIssues = issues
            .filter(i => !i.isCustomResource)
            .sort((a, b) => {
                const aPriority = priorityOrder[(a.priority || 'low').toLowerCase()] ?? 3;
                const bPriority = priorityOrder[(b.priority || 'low').toLowerCase()] ?? 3;
                if (aPriority !== bPriority) return aPriority - bPriority;

                const aStatus = statusOrder[(a.status || 'open').toLowerCase()] ?? 3;
                const bStatus = statusOrder[(b.status || 'open').toLowerCase()] ?? 3;
                return aStatus - bStatus;
            });

        if (filteredIssues.length === 0) {
            return `<tr><td colspan="6">
                <div class="empty-state">
                    <div class="empty-icon">◇</div>
                    <div class="empty-title">No issues found</div>
                    <div class="empty-text">Your project passed all security checks</div>
                </div>
            </td></tr>`;
        }

        const PAGE_SIZE = 100;
        const initialPage = filteredIssues.slice(0, PAGE_SIZE);

        return initialPage.map(issue => {
            const priority = (issue.priority || 'low').toLowerCase();
            const status = (issue.status || 'open').toLowerCase();

            return `
                <tr>
                    <td><span class="badge badge-${priority}">${priority.toUpperCase()}</span></td>
                    <td><span class="badge badge-${status}">${status.toUpperCase()}</span></td>
                    <td><span class="badge badge-source">${this.escapeHtml(issue.source || 'Unknown')}</span></td>
                    <td>
                        <div class="issue-desc">${this.escapeHtml(issue.issue || '')}</div>
                        ${issue.fix ? `<div class="issue-fix">${this.escapeHtml(issue.fix)}</div>` : ''}
                        ${status === 'suppressed' && issue.suppressionReason ? `<div class="issue-suppression">${this.escapeHtml(issue.suppressionReason)}</div>` : ''}
                    </td>
                    <td>
                        <div class="issue-location">${this.escapeHtml(issue.path || '')}${issue.line ? `<span class="issue-line">:${issue.line}</span>` : ''}</div>
                    </td>
                    <td><span class="resource-name">${this.escapeHtml(issue.resourceName || '')}</span></td>
                </tr>
            `;
        }).join('');
    }

    private renderBomPanel(data: DashboardData): string {
        if (!data.bom || data.bom.length === 0) {
            return `<div class="empty-state">
                <div class="empty-icon">◇</div>
                <div class="empty-title">No dependencies found</div>
            </div>`;
        }

        return `
            <div class="bom-search">
                <input type="text" id="bom-search" class="search-input" placeholder="Search dependencies...">
            </div>
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th style="width: 100px;">Type</th>
                            <th style="width: 25%;">Name</th>
                            <th style="width: 100px;">Version</th>
                            <th style="width: 120px;">License</th>
                            <th>Path</th>
                        </tr>
                    </thead>
                    <tbody id="bom-tbody">
                        ${data.bom.map(pkg => `
                            <tr>
                                <td><span class="badge badge-source">${this.escapeHtml(pkg.type)}</span></td>
                                <td>${this.escapeHtml(pkg.name)}</td>
                                <td><code>${this.escapeHtml(pkg.version)}</code></td>
                                <td>${this.escapeHtml(pkg.license) || '—'}</td>
                                <td class="issue-location">${this.escapeHtml(pkg.path)}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    private renderSummaryPanel(summary: string): string {
        return `
            <div class="summary-content">
                <div class="summary-text">${this.escapeHtml(summary)}</div>
            </div>
        `;
    }

    private renderMarkdown(content: string): string {
        return content
            .replace(/^### (.*$)/gim, '<h3>$1</h3>')
            .replace(/^## (.*$)/gim, '<h2>$1</h2>')
            .replace(/^# (.*$)/gim, '<h1>$1</h1>')
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(.*?)\*/g, '<em>$1</em>')
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            .replace(/^\s*[-*]\s+(.*)$/gim, '<li>$1</li>')
            .replace(/(<li>.*<\/li>)\n(?!<li>)/g, '<ul>$1</ul>')
            .replace(/\n\n/g, '</p><p>')
            .replace(/^(?!<[hulo])/gm, '<p>')
            .replace(/(?<![>])$/gm, '</p>')
            .replace(/<p><\/p>/g, '')
            .replace(/<p>(<[hulo])/g, '$1')
            .replace(/(<\/[hulo][^>]*>)<\/p>/g, '$1');
    }

    private renderThreatModels(threatModels: ThreatModelData[]): string {
        return threatModels.map((model, index) => `
            <div class="collapsible-section">
                <button class="collapsible-header" aria-expanded="false">
                    <span class="collapsible-icon">▶</span>
                    <span class="collapsible-title">${this.escapeHtml(model.stackName)}</span>
                </button>
                <div class="collapsible-content">
                    <div class="markdown-content">${this.renderMarkdown(model.content)}</div>
                </div>
            </div>
        `).join('');
    }

    private renderDiagrams(diagrams: DiagramData[]): string {
        return diagrams.map((diagram, index) => `
            <div class="collapsible-section" data-diagram-index="${index}">
                <button class="collapsible-header" aria-expanded="false">
                    <span class="collapsible-icon">▶</span>
                    <span class="collapsible-title">${this.escapeHtml(diagram.stackName)}</span>
                </button>
                <div class="collapsible-content">
                    <pre class="mermaid">${diagram.content}</pre>
                </div>
            </div>
        `).join('');
    }

    private formatDate(dateStr: string): string {
        const date = new Date(dateStr);
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            hour12: false
        }).toUpperCase().replace(',', '');
    }

    private escapeHtml(text: string): string {
        if (!text) return '';
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
}
