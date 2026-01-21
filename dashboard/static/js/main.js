// TwinSanity Recon V2 - Dashboard JavaScript

// ===== UI SCHEDULER - Prevents UI freezing during heavy operations =====
class UIScheduler {
    constructor() {
        this.queue = [];
        this.isProcessing = false;
    }

    // Add task to queue and process in batches
    schedule(task) {
        this.queue.push(task);
        if (!this.isProcessing) {
            this.processQueue();
        }
    }

    // Process queue using requestAnimationFrame for smooth UI
    processQueue() {
        if (this.queue.length === 0) {
            this.isProcessing = false;
            return;
        }

        this.isProcessing = true;
        requestAnimationFrame(() => {
            const startTime = performance.now();
            // Process tasks for max 8ms per frame (leaves time for rendering)
            while (this.queue.length > 0 && performance.now() - startTime < 8) {
                const task = this.queue.shift();
                try {
                    task();
                } catch (e) {
                    console.error('UIScheduler task error:', e);
                }
            }
            // Continue processing remaining tasks
            if (this.queue.length > 0) {
                setTimeout(() => this.processQueue(), 0);
            } else {
                this.isProcessing = false;
            }
        });
    }

    // Clear pending tasks
    clear() {
        this.queue = [];
        this.isProcessing = false;
    }
}

// Global UI scheduler instance
const uiScheduler = new UIScheduler();

// ===== AUTHENTICATION HELPERS =====
async function handleLogout() {
    try {
        const response = await fetch('/api/auth/logout', { method: 'POST' });
        if (response.ok) {
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Logout failed:', error);
        // Force redirect anyway
        window.location.href = '/login';
    }
}

// Handle 401 responses globally - redirect to login
function handleAuthError(response) {
    if (response.status === 401) {
        window.location.href = '/login';
        return true;
    }
    return false;
}


// ===== TOAST NOTIFICATION SYSTEM =====
class ToastManager {
    constructor() {
        this.container = null;
        this.init();
    }

    init() {
        this.container = document.createElement('div');
        this.container.className = 'toast-container';
        document.body.appendChild(this.container);
    }

    show(type, title, message, duration = 4000) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        const icons = {
            success: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>',
            error: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
            warning: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
            info: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
        };

        toast.innerHTML = `
            <div class="toast-icon">${icons[type]}</div>
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                ${message ? `<div class="toast-message">${message}</div>` : ''}
            </div>
            <button class="toast-close">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
            <div class="toast-progress"></div>
        `;

        const closeBtn = toast.querySelector('.toast-close');
        closeBtn.addEventListener('click', () => this.dismiss(toast));

        this.container.appendChild(toast);

        if (duration > 0) {
            setTimeout(() => this.dismiss(toast), duration);
        }

        return toast;
    }

    dismiss(toast) {
        if (!toast || !toast.parentNode) return;
        toast.classList.add('hiding');
        setTimeout(() => {
            if (toast.parentNode) toast.remove();
        }, 300);
    }

    success(title, message) { return this.show('success', title, message); }
    error(title, message) { return this.show('error', title, message); }
    warning(title, message) { return this.show('warning', title, message); }
    info(title, message) { return this.show('info', title, message); }
}

// Global toast instance
const toast = new ToastManager();

// ===== REAL-TIME UPDATE MANAGER =====
class RealTimeManager {
    constructor() {
        this.updateInterval = null;
        this.lastUpdate = Date.now();
    }

    startPolling(scanId, callback, intervalMs = 2000) {
        this.stopPolling();
        this.updateInterval = setInterval(async () => {
            try {
                const response = await fetch(`/api/scans/${scanId}/status`);
                if (response.ok) {
                    const status = await response.json();
                    callback(status);
                    this.lastUpdate = Date.now();
                }
            } catch (error) {
                console.error('Polling error:', error);
            }
        }, intervalMs);
    }

    stopPolling() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
            this.updateInterval = null;
        }
    }
}

const realTimeManager = new RealTimeManager();

class TwinSanityDashboard {
    constructor() {
        this.ws = null;
        this.currentScanId = null;
        this.scanData = null;
        this.charts = {};
        this.allCVEs = [];
        this.isScanning = false;
        this.aiReport = null;  // V1-style AI analysis report

        this.elements = {
            scanForm: document.getElementById('scanForm'),
            domainInput: document.getElementById('domainInput'),
            btnScan: document.getElementById('btnScan'),
            btnNew: document.getElementById('btnNew'),
            btnRescan: document.getElementById('btnRescan'),
            btnDelete: document.getElementById('btnDelete'),
            btnVisibility: document.getElementById('btnVisibility'),
            sessionSelect: document.getElementById('sessionSelect'),
            statusText: document.getElementById('statusText'),
            progressText: document.getElementById('progressText'),
            progressFill: document.getElementById('progressFill'),
            emptyState: document.getElementById('emptyState'),
            resultsContainer: document.getElementById('resultsContainer'),
            hostsList: document.getElementById('hostsList'),
            subdomainsList: document.getElementById('subdomainsList'),
            subdomainCount: document.getElementById('subdomainCount'),
            subdomainSearch: document.getElementById('subdomainSearch'),
            toggleSubdomains: document.getElementById('toggleSubdomains'),
            cveTable: document.getElementById('cveTable'),
            cveSearch: document.getElementById('cveSearch'),
            cveFilter: document.getElementById('cveFilter'),
            chatMessages: document.getElementById('chatMessages'),
            chatInput: document.getElementById('chatInput'),
            btnSend: document.getElementById('btnSend'),
            llmProvider: document.getElementById('llmProvider'),
            statIPs: document.getElementById('statIPs'),
            statSubs: document.getElementById('statSubs'),
            statCVEs: document.getElementById('statCVEs'),
            statCrit: document.getElementById('statCrit'),
            // Report tabs
            findingsPanel: document.getElementById('findingsPanel'),
            aiReportPanel: document.getElementById('aiReportPanel'),
            aiReportTab: document.getElementById('aiReportTab'),
            aiReportBadge: document.getElementById('aiReportBadge'),

            // CVE Explorer
            cveExplorer: document.getElementById('cveExplorer'),
            cveExplorerGrid: document.getElementById('cveExplorerGrid'),
            btnCveExplorer: document.getElementById('btnCveExplorer'),
            globalCveSearch: document.getElementById('globalCveSearch'),
            globalCveFilter: document.getElementById('globalCveFilter'),
            btnRefreshCves: document.getElementById('btnRefreshCves'),
            expTotal: document.getElementById('expTotal'),
            expCrit: document.getElementById('expCrit'),
            expHigh: document.getElementById('expHigh')
        };

        // Store all subdomains for filtering
        this.allSubdomainsData = [];

        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadScans();
        this.checkAuthStatus();
        this.loadConfigDefaults();  // Load scan defaults from config.yaml
        this.checkActiveScans();    // Check for any running scans on page load
        // WebSocket connects when a scan starts
    }

    // Check for any active (running) scans on page load
    async checkActiveScans() {
        try {
            const response = await fetch('/api/scans');
            if (!response.ok) return;

            const scans = await response.json();
            const scanList = Array.isArray(scans) ? scans : (scans.scans || []);

            // Find any scan that might still be running
            for (const scan of scanList) {
                if (scan.status === 'running' || scan.status === 'pending' || scan.status === 'scanning') {
                    console.log('Found active scan on page load:', scan.id);

                    // Set as current scan
                    this.currentScanId = scan.id;
                    this.isScanning = true;

                    // Get current progress from status API
                    await this.fetchAndUpdateScanStatus(scan.id);

                    // Connect WebSocket for real-time updates
                    this.connectWebSocket(scan.id);

                    // Select it in the dropdown
                    if (this.elements.sessionSelect) {
                        this.elements.sessionSelect.value = scan.id;
                    }

                    // Show results area and disable scan button
                    this.showResults();
                    this.disableScanButton();
                    break;
                }
            }
        } catch (error) {
            console.warn('Could not check for active scans:', error);
        }
    }

    // Fetch and update scan status from API
    async fetchAndUpdateScanStatus(scanId) {
        try {
            const response = await fetch(`/api/scans/${scanId}/status`);
            if (response.ok) {
                const status = await response.json();
                console.log('Fetched scan status:', status);

                // Update progress bar
                if (status.progress !== undefined) {
                    this.updateProgress(status.message || 'Scanning...', status.progress);
                }

                // Update connection status
                if (status.status === 'running' || status.status === 'scanning') {
                    this.updateConnectionStatus('scanning');
                } else if (status.status === 'completed' || status.status === 'complete') {
                    await this.handleScanComplete();
                }

                return status;
            }
        } catch (error) {
            console.warn('Could not fetch scan status:', error);
        }
        return null;
    }

    async loadConfigDefaults() {
        /**
         * Load scan configuration defaults from config.yaml via API.
         * This ensures UI checkboxes match the config.yaml settings.
         */
        try {
            const response = await fetch('/api/config/scan-defaults');
            if (response.ok) {
                const defaults = await response.json();
                console.log('Loaded config defaults:', defaults);

                // Apply defaults to checkbox elements - ALL scan toggles from config.yaml
                const checkboxMappings = {
                    'chkSubdomains': defaults.subdomain_discovery,
                    'chkShodan': defaults.shodan_lookup,
                    'chkCVE': defaults.cve_enrichment,
                    'chkDNS': defaults.validate_dns,
                    'chkHttpProbing': defaults.http_probing,
                    'chkNucleiScan': defaults.nuclei_scan,
                    'chkUrlHarvesting': defaults.url_harvesting,
                    'chkXssScan': defaults.xss_scan,
                    'chkApiDiscovery': defaults.api_discovery,
                    'chkAIAnalysis': defaults.ai_analysis,
                    'chkBruteForce': defaults.brute_force,
                    'chkProxy': defaults.use_proxies,
                };

                for (const [elementId, defaultValue] of Object.entries(checkboxMappings)) {
                    const el = document.getElementById(elementId);
                    if (el && typeof defaultValue === 'boolean') {
                        // FORCE UPDATE UI based on config
                        el.checked = defaultValue;
                        // Also trigger change event for any listeners
                        el.dispatchEvent(new Event('change'));
                    }
                }

                // SYNC MC toggle badges with sidebar checkboxes AFTER config is loaded
                this.syncAllMCBadges();

                console.log('Applied config.yaml defaults to UI');
            }
        } catch (error) {
            console.warn('Could not load config defaults:', error);
            // Fail silently - HTML defaults will be used
        }
    }

    // Sync all Mission Control toggle badges with their sidebar counterparts
    syncAllMCBadges() {
        const mappings = [
            { mc: 'mcSubdomains', sidebar: 'chkSubdomains' },
            { mc: 'mcShodan', sidebar: 'chkShodan' },
            { mc: 'mcAI', sidebar: 'chkAIAnalysis' }
        ];

        mappings.forEach(({ mc, sidebar }) => {
            const mcToggle = document.getElementById(mc);
            const sidebarCheckbox = document.getElementById(sidebar);

            if (mcToggle && sidebarCheckbox) {
                // Sync checkbox state
                mcToggle.checked = sidebarCheckbox.checked;

                // Update visual state of toggle badge
                const badge = mcToggle.closest('.mc-toggle-badge');
                if (badge) {
                    if (mcToggle.checked) {
                        badge.classList.add('active');
                    } else {
                        badge.classList.remove('active');
                    }
                }
            }
        });
    }

    setupEventListeners() {
        this.elements.scanForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.startScan();
        });

        this.elements.btnNew.addEventListener('click', () => this.resetUI());
        this.elements.btnRescan.addEventListener('click', () => this.rescan());

        // Delete session button
        if (this.elements.btnDelete) {
            this.elements.btnDelete.addEventListener('click', () => this.deleteCurrentScan());
        }

        if (this.elements.btnVisibility) {
            this.elements.btnVisibility.addEventListener('click', () => this.toggleVisibility());
        }

        this.elements.sessionSelect.addEventListener('change', (e) => {
            if (e.target.value) this.loadScan(e.target.value);
        });

        this.elements.cveSearch.addEventListener('input', () => this.filterCVEs());
        this.elements.cveFilter.addEventListener('change', () => this.filterCVEs());

        // Subdomain section event listeners
        if (this.elements.subdomainSearch) {
            this.elements.subdomainSearch.addEventListener('input', () => this.filterSubdomains());
        }
        if (this.elements.toggleSubdomains) {
            this.elements.toggleSubdomains.addEventListener('click', () => this.toggleSubdomainsSection());
        }

        this.elements.chatInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        this.elements.btnSend.addEventListener('click', () => this.sendMessage());

        // btnCveExplorer uses onclick attribute to match admin panel style
        if (this.elements.globalCveSearch) {
            this.elements.globalCveSearch.addEventListener('input', () => {
                // Simple debounce
                clearTimeout(this.cveSearchTimeout);
                this.cveSearchTimeout = setTimeout(() => this.loadGlobalCves(), 500);
            });
        }
        if (this.elements.globalCveFilter) {
            this.elements.globalCveFilter.addEventListener('change', () => this.loadGlobalCves());
        }
        if (this.elements.btnRefreshCves) {
            this.elements.btnRefreshCves.addEventListener('click', () => this.loadGlobalCves());
        }
    }

    async checkAuthStatus() {
        try {
            const response = await fetch('/api/auth/me');
            if (response.ok) {
                const user = await response.json();
                console.log('Auth check - User:', user.username, 'Role:', user.role);

                // Update Sidebar Profile
                const userInitial = document.getElementById('userInitial');
                const userName = document.getElementById('userName');
                const userRole = document.getElementById('userRole');

                if (userInitial) userInitial.textContent = user.username.charAt(0).toUpperCase();
                if (userName) userName.textContent = user.username;
                // Show SUPER ADMIN for primary admin, otherwise show role
                if (userRole) {
                    userRole.textContent = user.is_primary_admin ? 'SUPER ADMIN' : user.role.toUpperCase();
                }

                // Show Admin Panel if admin
                if (user.role === 'admin') {
                    const navAdmin = document.getElementById('navAdmin');
                    console.log('Admin detected, navAdmin element:', navAdmin);
                    if (navAdmin) {
                        navAdmin.classList.remove('hidden');
                        console.log('Admin nav button shown');
                    }
                }
            } else if (response.status === 401) {
                window.location.href = '/login';
            }
        } catch (error) {
            console.error('Auth check failed:', error);
        }
    }

    async deleteCurrentScan() {
        if (!this.currentScanId) {
            toast.warning('No Selection', 'Please select a scan session to delete.');
            return;
        }

        const confirmDelete = confirm(`Are you sure you want to delete this scan session?\n\nThis will permanently remove:\n• Scan results\n• Chat history\n• AI analysis report\n\nThis action cannot be undone.`);

        if (!confirmDelete) return;

        try {
            const response = await fetch(`/api/scans/${this.currentScanId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                toast.success('Deleted', 'Scan session deleted successfully.');
                this.resetUI();
                this.loadScans();  // Refresh the session list
            } else {
                const error = await response.json();
                alert(`Failed to delete scan: ${error.detail || 'Unknown error'}`);
            }
        } catch (error) {
            console.error('Delete scan error:', error);
            toast.error('Deletion Failed', error.toString());
        }
    }

    async toggleVisibility() {
        if (!this.currentScanId) return;

        const newVisibility = this.currentScanVisibility === 'public' ? 'private' : 'public';

        try {
            const response = await fetch(`/api/scans/${this.currentScanId}/visibility`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ visibility: newVisibility })
            });

            if (response.ok) {
                this.currentScanVisibility = newVisibility;
                this.updateVisibilityButton(newVisibility === 'public');
                toast.success('Visibility Updated', `Scan is now ${newVisibility}`);
                // Reload list to update icons
                this.loadScans();
            } else {
                const data = await response.json();
                toast.error('Update Failed', data.detail || 'Failed to update visibility');
            }
        } catch (error) {
            console.error('Visibility update error:', error);
            toast.error('Connection Error', 'Failed to update visibility');
        }
    }

    updateVisibilityButton(isPublic) {
        if (!this.elements.btnVisibility) return;

        const btn = this.elements.btnVisibility;
        if (isPublic) {
            btn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                    <circle cx="12" cy="12" r="3"></circle>
                </svg>
            `;
            btn.title = "Public (Visible to Guests)";
            btn.style.color = "var(--accent-cyan)";
        } else {
            btn.innerHTML = `
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                    <line x1="1" y1="1" x2="23" y2="23"></line>
                </svg>
            `;
            btn.title = "Private (Only You)";
            btn.style.color = "var(--text-muted)";
        }
    }

    connectWebSocket(scanId = null) {
        // Close existing connection if any
        if (this.ws) {
            try { this.ws.close(); } catch (e) { }
        }

        // Only connect if we have a scan ID
        if (!scanId) {
            this.updateConnectionStatus('disconnected');
            return;
        }

        this.updateConnectionStatus('connecting');

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/scan/${scanId}`;
        this.ws = new WebSocket(wsUrl);
        this.wsReconnectAttempts = 0;
        this.wsScanId = scanId;
        this.isScanning = true;

        this.ws.onopen = () => {
            console.log(`WebSocket connected for scan ${scanId}`);
            this.wsReconnectAttempts = 0;
            this.updateConnectionStatus('connected');
            // Start polling as backup for WebSocket
            this.startBackupPolling(scanId);
        };

        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleWSMessage(data);
        };

        this.ws.onclose = (event) => {
            console.log('WebSocket disconnected', event.code);
            this.updateConnectionStatus('disconnected');
            // Auto-reconnect if not a normal close and scan might still be running
            if (event.code !== 1000 && this.wsReconnectAttempts < 5 && this.isScanning) {
                this.wsReconnectAttempts++;
                console.log(`Attempting WebSocket reconnection (${this.wsReconnectAttempts}/5)...`);
                this.updateConnectionStatus('connecting');
                setTimeout(() => this.connectWebSocket(this.wsScanId), 2000 * this.wsReconnectAttempts);
            }
        };

        this.ws.onerror = (err) => {
            console.error('WebSocket error:', err);
            this.updateConnectionStatus('disconnected');
        };
    }

    // Backup polling in case WebSocket drops - polls every 2 seconds
    startBackupPolling(scanId) {
        realTimeManager.startPolling(scanId, (status) => {
            // Use polling data, especially if WebSocket is not connected
            const wsDisconnected = !this.ws || this.ws.readyState !== WebSocket.OPEN;

            if (wsDisconnected || status.status === 'completed' || status.status === 'complete') {
                if (status.progress !== undefined) {
                    this.updateProgress(status.message || 'Scanning...', status.progress);

                    // Also update connection status
                    if (status.status === 'running' || status.status === 'scanning') {
                        this.updateConnectionStatus('scanning');
                    }
                }

                if (status.status === 'complete' || status.status === 'completed') {
                    console.log('Polling detected scan completion');
                    this.handleScanComplete();
                }
            }
        }, 2000);  // Poll every 2 seconds for faster updates
    }

    stopBackupPolling() {
        realTimeManager.stopPolling();
    }

    async handleScanComplete() {
        console.log('Scan complete! Refreshing UI...');
        this.isScanning = false;
        this.stopBackupPolling();
        this.updateProgress('Scan complete! Loading results...', 100);
        this.updateConnectionStatus('connected');  // Show "Live" briefly

        // Wait a moment for database to finalize
        await new Promise(resolve => setTimeout(resolve, 1000));

        // Refresh session list first so new scan appears
        await this.loadScans();

        // Load the completed scan's results
        if (this.currentScanId) {
            await this.loadScan(this.currentScanId);
            // Explicitly reload tools findings after scan complete
            loadToolsFindings(this.currentScanId);
            // Reload AI report if analysis was enabled
            await this.loadAIReport(this.currentScanId);
        }

        this.enableChat();
        this.showResults();  // Force show results panel

        toast.success('Scan Complete', `Reconnaissance finished successfully`);

        setTimeout(() => {
            this.updateProgress('Ready', 0);
            this.updateConnectionStatus('ready');  // Reset to "Ready"
            this.enableScanButton();
        }, 2000);
    }

    updateConnectionStatus(status) {
        const statusEl = document.getElementById('connectionStatus');
        if (!statusEl) return;

        statusEl.className = `connection-status ${status}`;
        const textEl = statusEl.querySelector('.connection-text');
        const dotEl = statusEl.querySelector('.connection-dot');

        if (textEl) {
            const statusTexts = {
                'connected': '● Live',
                'connecting': '◌ Connecting...',
                'disconnected': '○ Ready',
                'ready': '○ Ready',
                'scanning': '◉ Scanning...'
            };
            textEl.textContent = statusTexts[status] || 'Ready';
        }
    }

    handleWSMessage(data) {
        console.log('WS Message:', data);

        // Force UI update on any message
        this.lastWSUpdate = Date.now();

        switch (data.type) {
            case 'status':
                this.updateProgress(data.message, data.progress || 0);
                this.updateConnectionStatus('scanning');
                break;

            case 'log':
                console.log('Scan log:', data.message);
                // Show important log messages in chat for visibility
                if (data.message && (data.message.includes('✅') || data.message.includes('Found'))) {
                    this.addMessage('ai', data.message);
                }
                break;

            case 'progress':
                this.updateProgress(data.message, data.progress || 0);
                this.updateConnectionStatus('scanning');
                break;

            case 'subdomain_found':
                this.updateProgress(`Found: ${data.subdomain}`, data.progress || 30);
                // Real-time subdomain count update
                const currentSubs = parseInt(this.elements.statSubs?.textContent || '0');
                if (this.elements.statSubs) {
                    this.animateStatValue(this.elements.statSubs, currentSubs + 1);
                }
                break;

            case 'host_scanned':
                this.updateProgress(`Scanning: ${data.hostname}`, data.progress || 60);
                if (data.host_data) {
                    this.addHostToUI(data.host_data);
                    // Update IP count in real-time
                    const currentIPs = parseInt(this.elements.statIPs?.textContent || '0');
                    this.animateStatValue(this.elements.statIPs, currentIPs + 1);
                }
                break;

            case 'ai_analysis':
                // Handle AI analysis progress messages
                this.handleAIAnalysisProgress(data);
                break;

            case 'complete':
                this.handleScanComplete();
                break;

            case 'error':
                this.isScanning = false;
                this.stopBackupPolling();
                this.updateProgress(`Error: ${data.message}`, 0);
                this.updateConnectionStatus('disconnected');
                toast.error('Scan Error', data.message);
                this.enableScanButton();
                break;
        }
    }

    handleAIAnalysisProgress(data) {
        // Show AI analysis progress in status bar
        this.updateProgress(data.message, data.progress || 0);

        // Also show in chat panel for detailed visibility
        switch (data.status) {
            case 'starting':
                this.addMessage('ai', data.message);
                toast.info('AI Analysis', 'Starting vulnerability analysis...');
                break;
            case 'processing':
                this.addMessage('ai', `${data.message}\n*Total chunks: ${data.total_chunks}*`);
                break;
            case 'chunk_processing':
                // Update progress only, don't spam chat
                break;
            case 'chunk_complete':
                // Show chunk completion in chat
                this.addMessage('ai', data.message);
                break;
            case 'tools_analysis':
                this.addMessage('ai', data.message);
                break;
            case 'tools_analysis_complete':
                this.addMessage('ai', data.message);
                // Reload report to show tools findings
                this.loadAIReport(this.currentScanId);
                break;
            case 'complete':
                this.addMessage('ai', `${data.message}\n\n📊 **Summary:**\n- IPs Analyzed: ${data.total_ips}\n- CVEs Found: ${data.total_cves}\n- Chunks Processed: ${data.chunks_processed}\n\n*Switch to **AI Report** tab to view full analysis.*`);
                // Show AI report badge
                if (this.elements.aiReportBadge) {
                    this.elements.aiReportBadge.classList.remove('hidden');
                    this.elements.aiReportBadge.textContent = 'NEW';
                }
                // Reload AI report
                this.loadAIReport(this.currentScanId);
                toast.success('AI Analysis Complete', 'View the AI Report tab for details');
                break;
        }
    }

    async startScan() {
        const domain = this.elements.domainInput.value.trim();
        if (!domain) {
            toast.warning('Missing Domain', 'Please enter a target domain');
            return;
        }

        this.disableScanButton();
        this.resetResults();
        this.showResults();
        toast.info('Scan Started', `Scanning ${domain}...`);

        // Get AI analysis checkbox state
        const aiAnalysisEnabled = document.getElementById('chkAIAnalysis')?.checked ?? false;

        // Get brute force settings
        const bruteForceEnabled = document.getElementById('chkBruteForce')?.checked ?? false;
        const wordlistSelect = document.getElementById('wordlistSelect');
        const selectedWordlist = bruteForceEnabled ? (wordlistSelect?.value || 'small') : null;

        // Get proxy settings
        const useProxies = document.getElementById('chkProxy')?.checked ?? false;

        // Get bug bounty tools settings
        const httpProbing = document.getElementById('chkHttpProbing')?.checked ?? false;
        const nucleiScan = document.getElementById('chkNucleiScan')?.checked ?? false;
        const urlHarvesting = document.getElementById('chkUrlHarvesting')?.checked ?? false;
        const xssScan = document.getElementById('chkXssScan')?.checked ?? false;
        const apiDiscovery = document.getElementById('chkApiDiscovery')?.checked ?? false;

        const config = {
            domain,
            subdomain_discovery: document.getElementById('chkSubdomains').checked,
            shodan_lookup: document.getElementById('chkShodan').checked,
            cve_enrichment: document.getElementById('chkCVE').checked,
            validate_dns: document.getElementById('chkDNS')?.checked ?? false,
            ai_analysis: aiAnalysisEnabled,  // V1-style chunk analysis
            subdomain_sources: this.getSelectedSources().subdomain_sources,
            cve_sources: this.getSelectedSources().cve_sources,
            // Brute force settings
            brute_force: bruteForceEnabled,
            wordlist: selectedWordlist,
            // Proxy settings
            use_proxies: useProxies,
            // Bug bounty tools
            http_probing: httpProbing,
            nuclei_scan: nucleiScan,
            url_harvesting: urlHarvesting,
            xss_scan: xssScan,
            api_discovery: apiDiscovery
        };

        try {
            const response = await fetch('/api/scans', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Scan failed');
            }

            const result = await response.json();
            this.currentScanId = result.scan_id;
            this.updateProgress('Scan started...', 10);

            // Connect WebSocket for real-time updates
            this.connectWebSocket(this.currentScanId);

            // Refresh session list to show new scan
            await this.loadScans();

            // Should auto-select the new scan in dropdown because loadScans usually keeps current selection or we can force it
            if (this.elements.sessionSelect) {
                // Find the option with this value and select it
                this.elements.sessionSelect.value = this.currentScanId;
            }

            // If AI analysis is enabled, show message
            if (aiAnalysisEnabled) {
                this.addMessage('ai', '🤖 AI Analysis enabled. The scan will analyze findings using **Gemini → Ollama Cloud → Local** pipeline after completion.');
            }

        } catch (error) {
            console.error('Scan error:', error);
            this.updateProgress(`Error: ${error.message}`, 0);
            toast.error('Scan Failed', error.message);
            this.enableScanButton();
        }
    }

    getSelectedSources() {
        const subdomain_sources = {};
        const cve_sources = [];

        const srcMap = {
            'src_crtsh': 'crtsh',
            'src_hackertarget': 'hackertarget',
            'src_rapiddns': 'rapiddns',
            'src_urlscan': 'urlscan',
            'src_webarchive': 'webarchive',
            'src_bufferover': 'bufferover',
            'src_certspotter': 'certspotter'
        };

        const cveMap = {
            'cve_circl': 'circl',
            'cve_shodan': 'shodan',
            'cve_nvd': 'nvd',
            'cve_virustotal': 'virustotal'
        };

        for (const [name, source] of Object.entries(srcMap)) {
            const el = document.querySelector(`input[name="${name}"]`);
            subdomain_sources[source] = el?.checked ?? true;
        }

        for (const [name, source] of Object.entries(cveMap)) {
            const el = document.querySelector(`input[name="${name}"]`);
            if (el?.checked) cve_sources.push(source);
        }

        return { subdomain_sources, cve_sources };
    }

    async loadScans() {
        try {
            const response = await fetch('/api/scans');
            const scans = await response.json();

            this.elements.sessionSelect.innerHTML = '<option value="">Select previous scan...</option>';

            // scans is an array directly
            const scanList = Array.isArray(scans) ? scans : (scans.scans || []);

            for (const scan of scanList) {
                const opt = document.createElement('option');
                opt.value = scan.id;
                const date = scan.created_at ? new Date(scan.created_at).toLocaleString() : 'Unknown';
                const domain = scan.domain || scan.config?.domain || 'Unknown';
                const visibility = scan.visibility === 'public' ? '🌐' : '🔒';
                opt.textContent = `${visibility} ${domain} - ${date}`;
                this.elements.sessionSelect.appendChild(opt);
            }
        } catch (error) {
            console.error('Failed to load scans:', error);
        }
    }

    async loadScan(scanId) {
        try {
            console.log('Loading scan:', scanId);

            // Clear previous state before loading new scan
            this.clearPreviousState();

            // Stop any existing polling/websocket for previous scan
            this.stopBackupPolling();
            if (this.ws) {
                try { this.ws.close(); this.ws = null; } catch (e) { }
            }
            this.isScanning = false;

            // Use /full endpoint which has DB fallback and loads results from file
            const response = await fetch(`/api/scans/${scanId}/full`);
            if (!response.ok) throw new Error('Failed to load scan');

            const data = await response.json();
            this.currentScanId = scanId;
            this.scanData = data.results;
            this.currentScanVisibility = data.visibility || 'private';
            const domain = data.domain || data.config?.domain || '';
            this.elements.domainInput.value = domain;

            if (this.elements.btnVisibility) {
                this.elements.btnVisibility.disabled = false;
                this.updateVisibilityButton(this.currentScanVisibility === 'public');
            }

            this.showResults();

            // Transform results to hosts format for rendering
            this.renderResultsFromData(data);

            // Load chat history from DB
            await this.loadChatHistory(scanId);
            this.enableChat();

            // Load AI analysis report if available
            await this.loadAIReport(scanId);

            // Load tools findings (HTTP probing, nuclei, XSS, API discovery)
            loadToolsFindings(scanId);

            // Check scan status and sync progress bar
            await this.syncScanProgress(scanId);

        } catch (error) {
            console.error('Load scan error:', error);
        }
    }

    // Sync scan progress when switching sessions
    async syncScanProgress(scanId) {
        try {
            const response = await fetch(`/api/scans/${scanId}/status`);
            if (!response.ok) return;

            const status = await response.json();

            // Update UI based on scan status
            if (status.status === 'running' || status.status === 'scanning') {
                this.isScanning = true;
                this.updateProgress(status.message || 'Scanning...', status.progress || 50);
                this.updateConnectionStatus('scanning');

                // Reconnect WebSocket for active scan
                this.connectWebSocket(scanId);
            } else if (status.status === 'complete' || status.status === 'completed') {
                this.isScanning = false;
                this.updateProgress('Scan complete', 100);
                this.updateConnectionStatus('ready');
                this.enableScanButton();
            } else {
                // Unknown or idle state
                this.isScanning = false;
                this.updateProgress('Ready', 0);
                this.updateConnectionStatus('ready');
                this.enableScanButton();
            }
        } catch (error) {
            console.log('Could not sync scan status:', error);
            // Default to ready state
            this.updateProgress('Ready', 0);
            this.updateConnectionStatus('ready');
        }
    }

    renderResultsFromData(data) {
        // Handle both direct results format and scan object format
        let results = data.results;

        if (!results && data.result_file) {
            // Results are in file, not in response
            console.log('Results in file:', data.result_file);
        }

        // If results is the IP-keyed object from the scan
        if (results && typeof results === 'object') {
            // Extract metadata if present
            const metadata = results._metadata || {};
            const allDiscoveredSubdomains = metadata.all_subdomains || [];

            // Transform IP-keyed results to hosts array
            const hosts = [];
            const resolvedSubdomains = new Set(); // Track subdomains that resolved to IPs

            for (const [ip, hostData] of Object.entries(results)) {
                // Skip metadata key
                if (ip === '_metadata') continue;

                // Collect subdomains from hosts array
                const hostnames = hostData.hosts || [];
                hostnames.forEach(h => resolvedSubdomains.add(h));

                // Get CVEs from both cve_details (fetched) and vulns (raw from internetdb)
                const rawVulns = hostData.internetdb?.data?.vulns || [];
                const cveDetails = hostData.cve_details || [];

                // Create a map of fetched CVE details by ID
                const fetchedCVEs = new Map();
                for (const cve of cveDetails) {
                    const cveId = cve.id || cve.cve_id;
                    if (cveId) {
                        fetchedCVEs.set(cveId, {
                            id: cveId,
                            cvss: this.extractCVSS(cve),
                            summary: cve.summary || cve.description || 'No description available',
                            references: cve.references || []
                        });
                    }
                }

                // Include all CVEs from vulns, using details if available
                const allCVEs = [];
                for (const vuln of rawVulns) {
                    const cveId = typeof vuln === 'string' ? vuln : (vuln.id || vuln.cve_id);
                    if (cveId) {
                        if (fetchedCVEs.has(cveId)) {
                            allCVEs.push(fetchedCVEs.get(cveId));
                        } else {
                            // CVE not fetched - include with minimal info
                            allCVEs.push({
                                id: cveId,
                                cvss: 0,
                                summary: 'Details not fetched - CVE detected by InternetDB',
                                references: []
                            });
                        }
                    }
                }

                // Also add any CVEs from cve_details that weren't in vulns (edge case)
                for (const [cveId, cveData] of fetchedCVEs) {
                    if (!allCVEs.find(c => c.id === cveId)) {
                        allCVEs.push(cveData);
                    }
                }

                hosts.push({
                    ip: ip,
                    hostname: hostData.hosts?.[0] || ip,
                    hostnames: hostData.hosts || [],
                    ports: hostData.internetdb?.data?.ports || [],
                    tags: hostData.internetdb?.data?.tags || [],
                    cpes: hostData.internetdb?.data?.cpes || [],
                    vulns: rawVulns,
                    totalVulns: rawVulns.length, // Track total vulnerabilities found
                    cves: allCVEs
                });
            }

            // Use all discovered subdomains from metadata if available, otherwise use resolved ones
            const subdomainsToRender = allDiscoveredSubdomains.length > 0
                ? allDiscoveredSubdomains
                : Array.from(resolvedSubdomains);

            this.renderResults({
                hosts,
                subdomains: subdomainsToRender,
                resolvedSubdomains: Array.from(resolvedSubdomains),
                metadata
            });
        }
    }

    renderResults(results) {
        if (!results) return;

        // Calculate stats
        const hosts = results.hosts || [];
        let allPorts = {};
        this.allCVEs = [];

        // Track unique CVEs and count subdomains properly
        const uniqueCVEs = new Map(); // CVE ID -> {cve data, cvss}
        let totalSubdomains = 0;

        for (const host of hosts) {
            const cves = host.cves || [];

            // Count subdomains from host data (hostnames/subdomains array)
            const hostnames = host.hostnames || host.hosts || host.subdomains || [];
            if (Array.isArray(hostnames)) {
                totalSubdomains += hostnames.length;
            } else if (host.hostname || host.subdomain) {
                totalSubdomains += 1;
            }

            for (const cve of cves) {
                const cvss = this.extractCVSS(cve);
                const cveId = cve.id || cve.cve_id || 'Unknown';

                // Track unique CVEs with proper CVSS
                if (!uniqueCVEs.has(cveId)) {
                    uniqueCVEs.set(cveId, { cvss, cve: { ...cve, cvss } });
                }

                this.allCVEs.push({
                    ...cve,
                    cvss: cvss,
                    host: host.hostname || host.ip
                });
            }

            for (const port of (host.ports || [])) {
                allPorts[port] = (allPorts[port] || 0) + 1;
            }
        }

        // Count unique CVEs by severity
        let criticalCVEs = 0;
        for (const [id, data] of uniqueCVEs) {
            if (data.cvss >= 9.0) criticalCVEs++;
        }

        // Update stats with animations - use unique CVE count and proper subdomain count
        this.animateStatValue(this.elements.statIPs, hosts.length);
        this.animateStatValue(this.elements.statSubs, results.subdomains?.length || totalSubdomains || hosts.length);
        this.animateStatValue(this.elements.statCVEs, uniqueCVEs.size); // Unique CVEs
        this.animateStatValue(this.elements.statCrit, criticalCVEs);

        // Build detailed subdomains data for rendering
        // Create a map of resolved subdomains with their data
        const resolvedMap = new Map();
        for (const host of hosts) {
            const hostnames = host.hostnames || [];
            const ip = host.ip;
            const ports = host.ports || [];
            const cves = host.cves || [];
            const vulnCount = cves.length;
            const tags = host.tags || [];

            for (const subdomain of hostnames) {
                resolvedMap.set(subdomain.toLowerCase(), {
                    name: subdomain,
                    ip: ip,
                    ports: ports,
                    vulnCount: vulnCount,
                    cves: cves,  // Store full CVE data for modal display
                    tags: tags,
                    hasData: ports.length > 0 || vulnCount > 0,
                    resolved: true
                });
            }
        }

        // Build the full subdomain list including unresolved ones
        this.allSubdomainsData = [];
        const allSubdomains = results.subdomains || [];

        for (const subdomain of allSubdomains) {
            const resolved = resolvedMap.get(subdomain.toLowerCase());
            if (resolved) {
                this.allSubdomainsData.push(resolved);
            } else {
                // Subdomain didn't resolve to an IP
                this.allSubdomainsData.push({
                    name: subdomain,
                    ip: null,
                    ports: [],
                    vulnCount: 0,
                    hasData: false,
                    resolved: false
                });
            }
        }

        // Sort subdomains: resolved with vulns first, then resolved, then unresolved
        this.allSubdomainsData.sort((a, b) => {
            // First by resolved status
            if (a.resolved !== b.resolved) return b.resolved - a.resolved;
            // Then by vuln count
            if (a.vulnCount !== b.vulnCount) return b.vulnCount - a.vulnCount;
            // Then by name
            return a.name.localeCompare(b.name);
        });

        // Render subdomains section
        this.renderSubdomains();

        // Render hosts using UI scheduler for smooth performance
        this.elements.hostsList.innerHTML = '';
        if (hosts.length > 0) {
            // Batch render hosts to prevent UI freeze
            const batchSize = 5;
            for (let i = 0; i < hosts.length; i += batchSize) {
                const batch = hosts.slice(i, i + batchSize);
                uiScheduler.schedule(() => {
                    batch.forEach(host => this.addHostToUI(host));
                });
            }
        }

        // Render CVE table
        this.renderCVETable();

        // Update charts
        this.updateCharts(hosts, allPorts);
    }

    renderSubdomains(filter = '') {
        if (!this.elements.subdomainsList) return;

        const searchTerm = filter.toLowerCase();
        const filtered = searchTerm
            ? this.allSubdomainsData.filter(s => s.name.toLowerCase().includes(searchTerm))
            : this.allSubdomainsData;

        // Update count badge
        if (this.elements.subdomainCount) {
            this.elements.subdomainCount.textContent = filtered.length;
        }

        if (filtered.length === 0) {
            this.elements.subdomainsList.innerHTML = `
                <div style="grid-column: 1/-1; text-align: center; padding: 2rem; color: var(--text-muted);">
                    ${searchTerm ? 'No subdomains match your filter' : 'No subdomains discovered'}
                </div>
            `;
            return;
        }

        this.elements.subdomainsList.innerHTML = filtered.map((sub, idx) => {
            let cardClass = 'no-data';
            if (!sub.resolved) {
                cardClass = 'unresolved';
            } else if (sub.vulnCount > 0) {
                cardClass = 'has-vulns';
            } else if (sub.hasData) {
                cardClass = 'no-vulns';
            }

            // Find the original index in allSubdomainsData
            const originalIndex = this.allSubdomainsData.indexOf(sub);

            return `
                <div class="subdomain-card ${cardClass}" onclick="dashboard.showSubdomainModal(${originalIndex})" title="Click for details">
                    <div class="subdomain-name">${this.escapeHtml(sub.name)}</div>
                    <div class="subdomain-meta">
                        ${sub.resolved && sub.ip ? `<span class="subdomain-ip">${this.escapeHtml(sub.ip)}</span>` : ''}
                        ${!sub.resolved ? `<span class="subdomain-badge unresolved">No DNS</span>` : ''}
                        ${sub.vulnCount > 0 ? `<span class="subdomain-badge vuln-count">${sub.vulnCount} CVEs</span>` : ''}
                        ${sub.ports && sub.ports.length > 0 ? `<span class="subdomain-badge port-count">${sub.ports.length} ports</span>` : ''}
                        ${sub.resolved && sub.vulnCount === 0 && sub.hasData ? `<span class="subdomain-badge clean">Clean</span>` : ''}
                    </div>
                </div>
            `;
        }).join('');
    }

    showSubdomainModal(index) {
        const subdomain = this.allSubdomainsData[index];
        if (!subdomain) return;

        const modal = document.getElementById('subdomainModal');
        if (!modal) return;

        // Set subdomain name
        document.getElementById('modalSubdomainName').textContent = subdomain.name;

        // Set host info
        document.getElementById('modalIP').textContent = subdomain.ip || 'Not resolved';
        document.getElementById('modalPorts').textContent = subdomain.ports?.length > 0
            ? subdomain.ports.join(', ')
            : 'No open ports';
        document.getElementById('modalTags').textContent = subdomain.tags?.length > 0
            ? subdomain.tags.join(', ')
            : 'None detected';

        // Get CVEs for this subdomain
        const cves = subdomain.cves || [];

        // Count severities
        let critical = 0, high = 0, medium = 0, low = 0;
        cves.forEach(cve => {
            const cvss = this.extractCVSS(cve);
            if (cvss >= 9.0) critical++;
            else if (cvss >= 7.0) high++;
            else if (cvss >= 4.0) medium++;
            else low++;
        });

        // Update severity boxes
        const summaryEl = document.getElementById('modalSeveritySummary');
        summaryEl.innerHTML = `
            <div class="severity-box critical"><span class="sev-count">${critical}</span><span class="sev-label">Critical</span></div>
            <div class="severity-box high"><span class="sev-count">${high}</span><span class="sev-label">High</span></div>
            <div class="severity-box medium"><span class="sev-count">${medium}</span><span class="sev-label">Medium</span></div>
            <div class="severity-box low"><span class="sev-count">${low}</span><span class="sev-label">Low</span></div>
        `;

        // Update CVE count
        document.getElementById('modalCVECount').textContent = cves.length;

        // Render CVE list
        this.renderModalCVEList(cves);

        // Setup search filter
        const searchInput = document.getElementById('modalCVESearch');
        if (searchInput) {
            searchInput.value = '';
            searchInput.oninput = () => this.filterModalCVEs(cves, searchInput.value);
        }

        // Show modal
        modal.classList.remove('hidden');
    }

    renderModalCVEList(cves, filter = '') {
        const listEl = document.getElementById('modalCVEList');
        if (!listEl) return;

        const searchTerm = filter.toLowerCase();
        const filtered = searchTerm
            ? cves.filter(c => c.id?.toLowerCase().includes(searchTerm) || c.summary?.toLowerCase().includes(searchTerm))
            : cves;

        if (filtered.length === 0) {
            listEl.innerHTML = `<div class="empty-cve-state">${searchTerm ? 'No CVEs match your filter' : 'No vulnerabilities found for this subdomain'}</div>`;
            return;
        }

        // Sort by severity
        const sorted = [...filtered].sort((a, b) => this.extractCVSS(b) - this.extractCVSS(a));

        listEl.innerHTML = sorted.map(cve => {
            const cvss = this.extractCVSS(cve);
            const severity = this.getSeverityClass(cvss);
            const description = cve.summary || cve.description || 'No description available';

            return `
                <div class="cve-detail-item severity-${severity}" onclick="window.open('https://nvd.nist.gov/vuln/detail/${cve.id}', '_blank')">
                    <div class="cve-item-header">
                        <span class="cve-item-id">${cve.id}</span>
                        <span class="cve-item-score ${severity}">
                            ${cvss > 0 ? cvss.toFixed(1) : 'N/A'} ${severity.toUpperCase()}
                        </span>
                    </div>
                    <div class="cve-item-description">${this.escapeHtml(description)}</div>
                    <div class="cve-item-meta">
                        ${cve.cvss_version ? `<span class="cve-meta-tag">CVSS v${cve.cvss_version}</span>` : ''}
                        ${cve.attack_vector ? `<span class="cve-meta-tag">${cve.attack_vector}</span>` : ''}
                        ${cve.published ? `<span class="cve-meta-tag">Published: ${cve.published.split('T')[0]}</span>` : ''}
                    </div>
                </div>
            `;
        }).join('');
    }

    filterModalCVEs(cves, filter) {
        this.renderModalCVEList(cves, filter);
    }

    getSeverityClass(cvss) {
        if (cvss >= 9.0) return 'critical';
        if (cvss >= 7.0) return 'high';
        if (cvss >= 4.0) return 'medium';
        return 'low';
    }

    filterSubdomains() {
        const searchTerm = this.elements.subdomainSearch?.value || '';
        this.renderSubdomains(searchTerm);
    }

    toggleSubdomainsSection() {
        const btn = this.elements.toggleSubdomains;
        const grid = this.elements.subdomainsList;
        if (btn && grid) {
            btn.classList.toggle('collapsed');
            grid.classList.toggle('collapsed');
        }
    }

    addHostToUI(host) {
        const cves = host.cves || [];
        const ports = host.ports || [];
        const totalVulns = host.totalVulns || cves.length;
        const cveCount = cves.length;

        // Count CVEs by severity
        const critCount = cves.filter(c => this.extractCVSS(c) >= 9.0).length;
        const highCount = cves.filter(c => { const cvss = this.extractCVSS(c); return cvss >= 7.0 && cvss < 9.0; }).length;
        const mediumCount = cves.filter(c => { const cvss = this.extractCVSS(c); return cvss >= 4.0 && cvss < 7.0; }).length;
        const lowCount = cves.filter(c => { const cvss = this.extractCVSS(c); return cvss > 0 && cvss < 4.0; }).length;
        const unknownCount = cves.filter(c => this.extractCVSS(c) === 0).length;

        // Sort CVEs by severity for display
        const sortedCVEs = [...cves].sort((a, b) => this.extractCVSS(b) - this.extractCVSS(a));

        const card = document.createElement('div');
        card.className = 'host-card';

        // Get hostname count for this IP
        const hostnameCount = host.hostnames?.length || 0;

        card.innerHTML = `
            <div class="host-header">
                <div class="host-info">
                    <div class="host-name">${this.escapeHtml(host.ip || 'No IP')}</div>
                    <div class="host-ip">${hostnameCount} subdomain${hostnameCount !== 1 ? 's' : ''} resolved to this IP</div>
                </div>
                <div class="host-badges">
                    ${critCount > 0 ? `<span class="badge badge-critical" title="Critical (CVSS 9+)">${critCount} CRIT</span>` : ''}
                    ${highCount > 0 ? `<span class="badge badge-high" title="High (CVSS 7-8.9)">${highCount} HIGH</span>` : ''}
                    ${mediumCount > 0 ? `<span class="badge badge-medium" title="Medium (CVSS 4-6.9)">${mediumCount} MED</span>` : ''}
                    ${lowCount > 0 ? `<span class="badge badge-low" title="Low (CVSS 0.1-3.9)">${lowCount} LOW</span>` : ''}
                    ${totalVulns > 0 ? `<span class="badge badge-cve" title="Total vulnerabilities detected">${totalVulns} Total</span>` : ''}
                    ${ports.length > 0 ? `<span class="badge badge-port">${ports.length} Ports</span>` : ''}
                    <svg class="host-toggle" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="6 9 12 15 18 9"/>
                    </svg>
                </div>
            </div>
            <div class="host-details">
                ${host.hostnames?.length > 0 ? `
                    <div class="detail-section">
                        <div class="detail-label">All Subdomains (${host.hostnames.length})</div>
                        <div class="tag-list subdomains-list">
                            ${host.hostnames.map(h => `<span class="tag hostname-tag">${this.escapeHtml(h)}</span>`).join('')}
                        </div>
                    </div>
                ` : ''}
                ${ports.length > 0 ? `
                    <div class="detail-section">
                        <div class="detail-label">Open Ports (${ports.length})</div>
                        <div class="tag-list">
                            ${ports.slice(0, 20).map(p => `<span class="tag port-tag">${p}</span>`).join('')}
                            ${ports.length > 20 ? `<span class="tag">+${ports.length - 20} more</span>` : ''}
                        </div>
                    </div>
                ` : ''}
                ${host.tags?.length > 0 ? `
                    <div class="detail-section">
                        <div class="detail-label">Technologies</div>
                        <div class="tag-list">
                            ${host.tags.map(t => `<span class="tag tech-tag">${this.escapeHtml(t)}</span>`).join('')}
                        </div>
                    </div>
                ` : ''}
                ${host.cpes?.length > 0 ? `
                    <div class="detail-section">
                        <div class="detail-label">CPE (${host.cpes.length})</div>
                        <div class="tag-list cpe-list">
                            ${host.cpes.slice(0, 8).map(c => `<span class="tag cpe-tag" title="${this.escapeHtml(c)}">${this.escapeHtml(c.split(':').slice(-2).join(':'))}</span>`).join('')}
                            ${host.cpes.length > 8 ? `<span class="tag">+${host.cpes.length - 8} more</span>` : ''}
                        </div>
                    </div>
                ` : ''}
                ${cves.length > 0 ? `
                    <div class="detail-section vulnerabilities-section">
                        <div class="detail-label">
                            Vulnerabilities (${totalVulns} total)
                            ${critCount > 0 ? `<span class="severity-count crit">${critCount} Critical</span>` : ''}
                            ${highCount > 0 ? `<span class="severity-count high">${highCount} High</span>` : ''}
                            ${mediumCount > 0 ? `<span class="severity-count medium">${mediumCount} Medium</span>` : ''}
                            ${lowCount > 0 ? `<span class="severity-count low">${lowCount} Low</span>` : ''}
                            ${unknownCount > 0 ? `<span class="severity-count unknown">${unknownCount} Unknown</span>` : ''}
                        </div>
                        <div class="cve-list-container">
                            ${sortedCVEs.slice(0, 15).map(cve => this.renderCVEItem(cve)).join('')}
                            ${cves.length > 15 ? `<div class="show-more-cves" onclick="event.stopPropagation();">+${cves.length - 15} more vulnerabilities</div>` : ''}
                        </div>
                    </div>
                ` : ''}
            </div>
        `;

        const header = card.querySelector('.host-header');
        header.addEventListener('click', () => {
            card.classList.toggle('expanded');
        });

        this.elements.hostsList.appendChild(card);
    }

    // Extract CVSS score with fallbacks - handles null/undefined values
    extractCVSS(cve) {
        if (!cve) return 0;

        // Try multiple fields in order of preference
        const candidates = [
            cve.cvss,
            cve.cvss_score,
            cve.cvss3,
            cve.cvss_v3,
            cve.baseScore,
            cve.score
        ];

        for (const val of candidates) {
            if (val !== null && val !== undefined && val !== '') {
                const parsed = parseFloat(val);
                if (!isNaN(parsed) && parsed > 0) {
                    return parsed;
                }
            }
        }

        // Check nested metrics objects
        if (cve.metrics) {
            const metricsScore = cve.metrics.cvssMetricV31?.[0]?.cvssData?.baseScore ||
                cve.metrics.cvssMetricV30?.[0]?.cvssData?.baseScore ||
                cve.metrics.cvssMetricV2?.[0]?.cvssData?.baseScore;
            if (metricsScore) return parseFloat(metricsScore);
        }

        return 0;
    }

    renderCVEItem(cve) {
        const cvss = this.extractCVSS(cve);
        let severityClass = 'cvss-low';
        let severityLabel = 'LOW';
        if (cvss >= 9.0) { severityClass = 'cvss-critical'; severityLabel = 'CRITICAL'; }
        else if (cvss >= 7.0) { severityClass = 'cvss-high'; severityLabel = 'HIGH'; }
        else if (cvss >= 4.0) { severityClass = 'cvss-medium'; severityLabel = 'MEDIUM'; }
        else if (cvss === 0) { severityClass = 'cvss-unknown'; severityLabel = 'N/A'; }

        return `
            <div class="cve-item">
                <div class="cve-header">
                    <span class="cve-id">${this.escapeHtml(cve.id || cve.cve_id || 'Unknown')}</span>
                    <span class="cvss ${severityClass}">${cvss > 0 ? cvss.toFixed(1) : severityLabel}</span>
                </div>
                <div class="cve-summary">${this.escapeHtml((cve.summary || cve.description || 'No description available').substring(0, 150))}${(cve.summary || cve.description || '').length > 150 ? '...' : ''}</div>
            </div>
        `;
    }

    renderCVETable() {
        this.elements.cveTable.innerHTML = '';

        const search = this.elements.cveSearch.value.toLowerCase();
        const severity = this.elements.cveFilter.value;

        // Deduplicate CVEs and track affected hosts with proper CVSS extraction
        const uniqueCVEs = new Map();
        for (const cve of this.allCVEs) {
            const cveId = cve.id || cve.cve_id || 'Unknown';
            const cvss = this.extractCVSS(cve);

            if (!uniqueCVEs.has(cveId)) {
                uniqueCVEs.set(cveId, {
                    ...cve,
                    cvss: cvss, // Ensure proper CVSS
                    affectedHosts: [cve.host],
                    hostCount: 1
                });
            } else {
                const existing = uniqueCVEs.get(cveId);
                if (!existing.affectedHosts.includes(cve.host)) {
                    existing.affectedHosts.push(cve.host);
                    existing.hostCount++;
                }
                // Update CVSS if we found a better value
                if (cvss > existing.cvss) {
                    existing.cvss = cvss;
                }
            }
        }

        let filtered = Array.from(uniqueCVEs.values());

        if (search) {
            filtered = filtered.filter(cve =>
                (cve.id || cve.cve_id || '').toLowerCase().includes(search) ||
                (cve.summary || cve.description || '').toLowerCase().includes(search)
            );
        }

        if (severity) {
            filtered = filtered.filter(cve => {
                const cvss = this.extractCVSS(cve);
                switch (severity) {
                    case 'critical': return cvss >= 9.0;
                    case 'high': return cvss >= 7.0 && cvss < 9.0;
                    case 'medium': return cvss >= 4.0 && cvss < 7.0;
                    case 'low': return cvss > 0 && cvss < 4.0;
                    case 'unknown': return cvss === 0;
                    default: return true;
                }
            });
        }

        // Sort by CVSS descending (CVEs with scores first, then unknown)
        filtered.sort((a, b) => {
            const cvssA = this.extractCVSS(a);
            const cvssB = this.extractCVSS(b);
            // Put CVEs with known CVSS first
            if (cvssA === 0 && cvssB > 0) return 1;
            if (cvssB === 0 && cvssA > 0) return -1;
            return cvssB - cvssA;
        });

        for (const cve of filtered.slice(0, 100)) {
            const cvss = this.extractCVSS(cve);
            let severityClass = 'cvss-low';
            let severityLabel = cvss > 0 ? cvss.toFixed(1) : 'N/A';
            if (cvss >= 9.0) severityClass = 'cvss-critical';
            else if (cvss >= 7.0) severityClass = 'cvss-high';
            else if (cvss >= 4.0) severityClass = 'cvss-medium';
            else if (cvss === 0) severityClass = 'cvss-unknown';

            // Show host count badge if multiple hosts affected
            const hostDisplay = cve.hostCount > 1
                ? `<span style="background:var(--accent-purple);color:white;padding:2px 8px;border-radius:12px;font-size:0.7rem;">${cve.hostCount} hosts</span>`
                : this.escapeHtml(cve.host || 'N/A');

            const row = document.createElement('tr');
            row.className = 'cve-row';
            row.innerHTML = `
                <td style="font-family: 'JetBrains Mono', monospace; color: var(--text-primary);">${this.escapeHtml(cve.id || cve.cve_id || 'N/A')}</td>
                <td><span class="cvss ${severityClass}">${severityLabel}</span></td>
                <td>${this.escapeHtml((cve.summary || cve.description || 'No description').substring(0, 80))}...</td>
                <td style="font-size: 0.75rem;">${hostDisplay}</td>
            `;
            // Add tooltip with all affected hosts if multiple
            if (cve.hostCount > 1 && cve.affectedHosts) {
                row.title = `Affected: ${cve.affectedHosts.slice(0, 10).join(', ')}${cve.hostCount > 10 ? '...' : ''}`;
            }
            this.elements.cveTable.appendChild(row);
        }

        if (filtered.length === 0) {
            const row = document.createElement('tr');
            row.innerHTML = `<td colspan="4" style="text-align: center; color: var(--text-muted);">No vulnerabilities found</td>`;
            this.elements.cveTable.appendChild(row);
        }
    }

    filterCVEs() {
        this.renderCVETable();
    }

    updateCharts(hosts, portCounts) {
        // Severity distribution - use unique CVEs only with proper CVSS extraction
        const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
        const seenCVEIds = new Set();

        for (const cve of this.allCVEs) {
            const cveId = cve.id || cve.cve_id || 'unknown';
            if (seenCVEIds.has(cveId)) continue;  // Skip duplicates
            seenCVEIds.add(cveId);

            const cvss = this.extractCVSS(cve);
            if (cvss >= 9.0) severityCounts.critical++;
            else if (cvss >= 7.0) severityCounts.high++;
            else if (cvss >= 4.0) severityCounts.medium++;
            else if (cvss > 0) severityCounts.low++;
            else severityCounts.unknown++;
        }

        if (this.charts.severity) this.charts.severity.destroy();

        const severityCtx = document.getElementById('severityChart').getContext('2d');

        // Include Unknown category if there are CVEs without CVSS
        const labels = ['Critical', 'High', 'Medium', 'Low'];
        const data = [severityCounts.critical, severityCounts.high, severityCounts.medium, severityCounts.low];
        const colors = ['#ff3b5c', '#ffaa00', '#eab308', '#00ff88'];

        if (severityCounts.unknown > 0) {
            labels.push('Unknown');
            data.push(severityCounts.unknown);
            colors.push('#666666');
        }

        this.charts.severity = new Chart(severityCtx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#a0a0a0', font: { size: 11 } }
                    }
                }
            }
        });

        // Top ports
        const sortedPorts = Object.entries(portCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8);

        if (this.charts.ports) this.charts.ports.destroy();

        const portsCtx = document.getElementById('portsChart').getContext('2d');
        this.charts.ports = new Chart(portsCtx, {
            type: 'bar',
            data: {
                labels: sortedPorts.map(([port]) => port),
                datasets: [{
                    data: sortedPorts.map(([, count]) => count),
                    backgroundColor: 'rgba(0, 212, 255, 0.6)',
                    borderColor: '#00d4ff',
                    borderWidth: 1,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        ticks: { color: '#666' },
                        grid: { color: 'rgba(255,255,255,0.05)' }
                    },
                    y: {
                        ticks: { color: '#a0a0a0', font: { family: 'JetBrains Mono' } },
                        grid: { display: false }
                    }
                }
            }
        });
    }

    // =========================================================================
    // AI Report Tab Functions
    // =========================================================================

    async loadAIReport(scanId) {
        try {
            // Use GET endpoint - does NOT auto-run analysis
            const response = await fetch(`/api/ai-analysis/${scanId}`);
            const data = await response.json();

            if (data.exists && data.report) {
                this.aiReport = data.report;
                this.renderAIReport(data.report);
                // Show badge if loaded
                if (this.elements.aiReportBadge) {
                    this.elements.aiReportBadge.classList.remove('hidden');
                    this.elements.aiReportBadge.textContent = '✓';
                }
            } else {
                this.aiReport = null;
                this.hideAIReport();
            }
        } catch (error) {
            console.error('Failed to load AI report:', error);
            this.aiReport = null;
            this.hideAIReport();
        }
    }

    renderAIReport(report) {
        // Show AI report content
        const emptyEl = document.getElementById('aiReportEmpty');
        const contentEl = document.getElementById('aiReportContent');
        if (emptyEl) emptyEl.classList.add('hidden');
        if (contentEl) contentEl.classList.remove('hidden');

        // Meta info
        const metaEl = document.getElementById('aiReportMeta');
        if (metaEl) {
            metaEl.textContent = `Generated: ${report.report_generated_at || 'N/A'} | IPs: ${report.total_ips_analyzed || 0} | Chunks: ${report.chunks_processed || 0}`;
        }

        // Aggregate data from chunks
        let summaries = [];
        let highRiskAssets = [];
        let keyVulns = [];
        let actions = [];

        for (const chunk of (report.llm_analysis_results || [])) {
            const analysis = chunk.analysis || {};
            if (analysis.summary && analysis.summary !== 'No summary provided.') {
                summaries.push(analysis.summary);
            }
            highRiskAssets.push(...(analysis.high_risk_assets || []));
            keyVulns.push(...(analysis.key_vulnerabilities || []));
            actions.push(...(analysis.recommended_actions || []));
        }

        // Render Executive Summary
        const summaryEl = document.getElementById('aiSummary');
        if (summaryEl) {
            summaryEl.innerHTML = summaries.length > 0
                ? summaries.map(s => `<p style="margin-bottom: 0.75rem;">${this.escapeHtml(s)}</p>`).join('')
                : '<p style="color: var(--text-muted);">No summary available.</p>';
        }

        // Render High Risk Assets
        const assetsEl = document.getElementById('aiHighRiskAssets');
        if (assetsEl) {
            if (highRiskAssets.length > 0) {
                assetsEl.innerHTML = highRiskAssets.map(a => `
                    <div style="display: flex; align-items: center; gap: 1rem; padding: 0.75rem; background: var(--bg-elevated); border-radius: 6px; margin-bottom: 0.5rem;">
                        <span class="severity-badge ${(a.severity || 'medium').toLowerCase()}" style="padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 600;">
                            ${(a.severity || 'MEDIUM').toUpperCase()}
                        </span>
                        <div style="flex: 1;">
                            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.9rem;">${this.escapeHtml(a.ip || 'N/A')}</div>
                            <div style="font-size: 0.8rem; color: var(--text-muted);">${this.escapeHtml(a.hostname || '')}</div>
                        </div>
                        <div style="font-size: 0.85rem; color: var(--text-secondary); max-width: 300px;">${this.escapeHtml(a.reason || '')}</div>
                    </div>
                `).join('');
            } else {
                assetsEl.innerHTML = '<p style="color: var(--text-muted);">No high-risk assets identified.</p>';
            }
        }

        // Render Key Vulnerabilities
        const vulnsEl = document.getElementById('aiKeyVulns');
        if (vulnsEl) {
            if (keyVulns.length > 0) {
                vulnsEl.innerHTML = keyVulns.slice(0, 20).map(v => `
                    <div style="padding: 0.75rem; background: var(--bg-elevated); border-radius: 6px; margin-bottom: 0.5rem;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                            <span style="font-family: 'JetBrains Mono', monospace; color: var(--accent-cyan);">${this.escapeHtml(v.cve || 'N/A')}</span>
                            <span style="color: ${(v.cvss_score || 0) >= 9 ? 'var(--danger)' : (v.cvss_score || 0) >= 7 ? 'var(--warning)' : 'var(--text-muted)'}; font-weight: 600;">
                                CVSS: ${v.cvss_score || 'N/A'}
                            </span>
                        </div>
                        <div style="font-size: 0.85rem; color: var(--text-secondary);">${this.escapeHtml(v.summary || '')}</div>
                        ${(v.affected_ips || []).length > 0 ? `<div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;">Affects: ${v.affected_ips.slice(0, 5).join(', ')}</div>` : ''}
                    </div>
                `).join('');
            } else {
                vulnsEl.innerHTML = '<p style="color: var(--text-muted);">No key vulnerabilities identified.</p>';
            }
        }

        // Render Recommended Actions
        const actionsEl = document.getElementById('aiActions');
        if (actionsEl) {
            if (actions.length > 0) {
                actionsEl.innerHTML = actions.map(a => `
                    <div style="display: flex; gap: 1rem; padding: 0.75rem; background: var(--bg-elevated); border-radius: 6px; margin-bottom: 0.5rem;">
                        <span class="severity-badge ${(a.priority || 'medium').toLowerCase()}" style="padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 600; min-width: 60px; text-align: center;">
                            ${(a.priority || 'MEDIUM').toUpperCase()}
                        </span>
                        <div style="flex: 1;">
                            <div style="font-size: 0.9rem; margin-bottom: 0.25rem;">${this.escapeHtml(a.action || '')}</div>
                            <div style="font-size: 0.8rem; color: var(--text-muted);">${this.escapeHtml(a.justification || '')}</div>
                        </div>
                    </div>
                `).join('');
            } else {
                actionsEl.innerHTML = '<p style="color: var(--text-muted);">No specific actions recommended.</p>';
            }
        }

        // Render All CVEs from report
        const allCves = report.all_discovered_cves || [];
        const cveCountEl = document.getElementById('aiCveCount');
        if (cveCountEl) cveCountEl.textContent = allCves.length;

        const cvesEl = document.getElementById('aiAllCves');
        if (cvesEl) {
            if (allCves.length > 0) {
                // Sort by CVSS
                const sorted = [...allCves].sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
                cvesEl.innerHTML = sorted.slice(0, 100).map(cve => `
                    <div style="display: flex; gap: 1rem; padding: 0.5rem; border-bottom: 1px solid var(--border-color);">
                        <span style="font-family: 'JetBrains Mono', monospace; color: var(--accent-cyan); min-width: 140px;">${this.escapeHtml(cve.id || 'N/A')}</span>
                        <span style="color: ${(cve.cvss || 0) >= 9 ? 'var(--danger)' : (cve.cvss || 0) >= 7 ? 'var(--warning)' : 'var(--text-muted)'}; min-width: 50px;">
                            ${cve.cvss || 'N/A'}
                        </span>
                        <span style="font-size: 0.85rem; color: var(--text-secondary); flex: 1;">${this.escapeHtml((cve.summary || '').slice(0, 150))}${(cve.summary || '').length > 150 ? '...' : ''}</span>
                        <span style="font-size: 0.75rem; color: var(--text-muted);">${(cve.affected_ips || []).length} hosts</span>
                    </div>
                `).join('');
            } else {
                cvesEl.innerHTML = '<p style="color: var(--text-muted); padding: 1rem;">No CVEs discovered.</p>';
            }
        }

        // Render Tools Findings Summary in AI Report
        this.renderToolsFindingsInAIReport(report.tools_findings || {});
    }

    renderToolsFindingsInAIReport(toolsFindings) {
        // Get or create the tools findings container in AI report
        let toolsContainer = document.getElementById('aiToolsFindings');

        if (!toolsContainer) {
            // Create the section if it doesn't exist - append after CVEs section
            const aiContent = document.getElementById('aiReportContent');
            if (aiContent) {
                const toolsSection = document.createElement('div');
                toolsSection.className = 'ai-section ai-section-tools';
                toolsSection.innerHTML = `
                    <h3 class="ai-section-title" style="color: var(--accent-cyan);">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2">
                            <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
                        </svg>
                        Security Tools Analysis
                    </h3>
                    <div id="aiToolsFindings"></div>
                `;
                aiContent.appendChild(toolsSection);
                toolsContainer = document.getElementById('aiToolsFindings');
            }
        }

        if (!toolsContainer) return;

        const nuclei = toolsFindings.nuclei_findings || { count: 0, items: [], by_severity: {} };
        const xss = toolsFindings.xss_findings || { count: 0, items: [] };
        const api = toolsFindings.api_discoveries || { count: 0, items: [] };
        const alive = toolsFindings.alive_hosts || { count: 0, sample: [] };
        const urls = toolsFindings.harvested_urls || { count: 0, with_params: 0, sample: [] };

        const totalFindings = nuclei.count + xss.count + api.count;

        if (totalFindings === 0 && alive.count === 0 && urls.count === 0) {
            toolsContainer.innerHTML = '<p style="color: var(--text-muted); padding: 1rem;">No security tool findings. Enable advanced scanning options (HTTP Probing, URL Harvesting, Nuclei, XSS) for detailed analysis.</p>';
            return;
        }

        let html = '<div class="tools-summary-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin-bottom: 20px;">';

        // Stats cards
        html += `
            <div class="tools-stat-mini" style="background: var(--bg-elevated); padding: 12px; border-radius: 8px; text-align: center;">
                <div style="font-size: 1.5rem; font-weight: 700; color: var(--accent-cyan);">${alive.count}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">Alive Hosts</div>
            </div>
            <div class="tools-stat-mini" style="background: var(--bg-elevated); padding: 12px; border-radius: 8px; text-align: center;">
                <div style="font-size: 1.5rem; font-weight: 700; color: var(--danger);">${nuclei.count}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">Nuclei Findings</div>
            </div>
            <div class="tools-stat-mini" style="background: var(--bg-elevated); padding: 12px; border-radius: 8px; text-align: center;">
                <div style="font-size: 1.5rem; font-weight: 700; color: var(--warning);">${xss.count}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">XSS Found</div>
            </div>
            <div class="tools-stat-mini" style="background: var(--bg-elevated); padding: 12px; border-radius: 8px; text-align: center;">
                <div style="font-size: 1.5rem; font-weight: 700; color: var(--accent-purple);">${api.count}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">API Endpoints</div>
            </div>
            <div class="tools-stat-mini" style="background: var(--bg-elevated); padding: 12px; border-radius: 8px; text-align: center;">
                <div style="font-size: 1.5rem; font-weight: 700; color: var(--success);">${urls.count}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">Harvested URLs</div>
            </div>
        `;
        html += '</div>';

        // Nuclei findings details
        if (nuclei.count > 0 && nuclei.items && nuclei.items.length > 0) {
            html += `<div style="margin-top: 15px;"><h4 style="color: var(--danger); margin-bottom: 10px;">🎯 Nuclei Vulnerabilities</h4>`;
            const bySev = nuclei.by_severity || {};
            if (Object.keys(bySev).length > 0) {
                html += '<div style="margin-bottom: 10px;">';
                for (const [sev, count] of Object.entries(bySev)) {
                    const color = { critical: 'var(--danger)', high: '#f5576c', medium: 'var(--warning)', low: 'var(--success)' }[sev] || 'var(--text-muted)';
                    html += `<span style="background: ${color}22; color: ${color}; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; margin-right: 8px;">${sev.toUpperCase()}: ${count}</span>`;
                }
                html += '</div>';
            }
            html += nuclei.items.slice(0, 10).map(item => `
                <div style="display: flex; align-items: center; gap: 10px; padding: 8px; background: var(--bg-elevated); border-radius: 6px; margin-bottom: 5px; font-size: 0.85rem;">
                    <span style="background: ${{ critical: 'var(--danger)', high: '#f5576c', medium: 'var(--warning)', low: 'var(--success)' }[(item.severity || 'unknown').toLowerCase()] || 'var(--text-muted)'}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.7rem; font-weight: 600;">${(item.severity || 'N/A').toUpperCase()}</span>
                    <span style="color: var(--text-primary);">${this.escapeHtml(item.name || 'Unknown')}</span>
                    <span style="color: var(--text-muted); font-size: 0.75rem; margin-left: auto;">${this.escapeHtml(item.host || '')}</span>
                </div>
            `).join('');
            if (nuclei.items.length > 10) {
                html += `<p style="color: var(--text-muted); font-size: 0.8rem; margin-top: 5px;">+${nuclei.items.length - 10} more findings...</p>`;
            }
            html += '</div>';
        }

        // XSS findings
        if (xss.count > 0 && xss.items && xss.items.length > 0) {
            html += `<div style="margin-top: 15px;"><h4 style="color: var(--warning); margin-bottom: 10px;">⚡ XSS Vulnerabilities</h4>`;
            html += xss.items.slice(0, 5).map(item => `
                <div style="padding: 8px; background: var(--bg-elevated); border-radius: 6px; margin-bottom: 5px; font-size: 0.85rem;">
                    <div style="color: var(--warning); font-weight: 600;">Parameter: ${this.escapeHtml(item.parameter || 'N/A')}</div>
                    <div style="color: var(--text-muted); font-size: 0.75rem; word-break: break-all;">${this.escapeHtml((item.url || '').slice(0, 80))}...</div>
                </div>
            `).join('');
            html += '</div>';
        }

        // API discoveries
        if (api.count > 0 && api.items && api.items.length > 0) {
            html += `<div style="margin-top: 15px;"><h4 style="color: var(--accent-purple); margin-bottom: 10px;">🔌 API Endpoints</h4>`;
            html += api.items.slice(0, 8).map(item => `
                <div style="display: flex; gap: 10px; padding: 6px 8px; background: var(--bg-elevated); border-radius: 4px; margin-bottom: 4px; font-size: 0.8rem;">
                    <span style="color: var(--accent-cyan); min-width: 60px;">${item.api_type || 'API'}</span>
                    <span style="color: var(--text-secondary); flex: 1;">${this.escapeHtml(item.path || item.url || 'N/A')}</span>
                    <span style="color: var(--text-muted);">${item.status_code || ''}</span>
                </div>
            `).join('');
            html += '</div>';
        }

        // Harvested URLs summary
        if (urls.count > 0) {
            html += `<div style="margin-top: 15px;"><h4 style="color: var(--success); margin-bottom: 10px;">🔗 Harvested URLs</h4>`;
            html += `<p style="color: var(--text-secondary); font-size: 0.85rem;">Found ${urls.count} URLs from Wayback/CommonCrawl, ${urls.with_params} with parameters (potential test targets).</p>`;
            if (urls.sample && urls.sample.length > 0) {
                // Remove truncation: show all items in a bigger scrollable box
                html += '<div style="max-height: 400px; overflow-y: auto; background: var(--bg-elevated); border-radius: 6px; padding: 8px; font-size: 0.75rem; font-family: monospace;">';
                html += urls.sample.map(url => `<div style="padding: 2px 0; color: var(--text-muted); word-break: break-all;">${this.escapeHtml(url)}</div>`).join('');
                html += '</div>';
            }
            html += '</div>';
        }

        toolsContainer.innerHTML = html;
    }

    hideAIReport() {
        const emptyEl = document.getElementById('aiReportEmpty');
        const contentEl = document.getElementById('aiReportContent');
        if (emptyEl) emptyEl.classList.remove('hidden');
        if (contentEl) contentEl.classList.add('hidden');
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
    }

    async loadChatHistory(scanId) {
        try {
            const response = await fetch(`/api/chat/history/${scanId}`);
            if (!response.ok) return;

            const messages = await response.json();

            // Clear current messages except the welcome message
            const chatContainer = this.elements.chatMessages;
            const welcomeMsg = chatContainer.querySelector('.message');
            chatContainer.innerHTML = '';
            if (welcomeMsg) chatContainer.appendChild(welcomeMsg);

            // Helper to detect JSON content
            const isJsonContent = (text) => {
                if (typeof text !== 'string') return false;
                const trimmed = text.trim();
                return trimmed.startsWith('{') || trimmed.startsWith('[') ||
                    trimmed.includes('"report_generated_at"') ||
                    trimmed.includes('"llm_analysis_results"') ||
                    trimmed.includes('"chunk_id"') ||
                    trimmed.includes('"analysis_type"');
            };

            // Add historical messages (filtering out raw JSON responses)
            for (const msg of messages) {
                const role = msg.role === 'user' ? 'user' : 'ai';
                let content = msg.content;

                // If AI message contains raw JSON, try to extract meaningful content
                if (role === 'ai' && isJsonContent(content)) {
                    try {
                        const parsed = JSON.parse(content);
                        // Try to extract summaries or meaningful text
                        if (parsed.llm_analysis_results) {
                            const summaries = parsed.llm_analysis_results
                                .map(r => r.analysis?.summary)
                                .filter(s => s && s !== 'No summary provided.');
                            if (summaries.length > 0) {
                                content = summaries.join('\n\n');
                            } else {
                                // Skip this message - it's just raw JSON with no useful summary
                                continue;
                            }
                        } else if (parsed.summary) {
                            content = parsed.summary;
                        } else if (parsed.response) {
                            content = parsed.response;
                        } else {
                            // Skip raw JSON messages
                            continue;
                        }
                    } catch (e) {
                        // If can't parse, skip if it looks like JSON
                        if (content.trim().startsWith('{') || content.trim().startsWith('[')) {
                            continue;
                        }
                    }
                }

                this.addMessage(role, content);
            }

            // Also try to load saved AI analysis
            await this.loadSavedAnalysis(scanId);
        } catch (error) {
            console.error('Failed to load chat history:', error);
        }
    }

    async loadSavedAnalysis(scanId) {
        try {
            const response = await fetch(`/api/analysis/${scanId}`);
            if (!response.ok) return;

            const data = await response.json();

            if (data.analysis) {
                // Check if we already have this analysis displayed
                const existing = Array.from(this.elements.chatMessages.querySelectorAll('.message.ai'))
                    .some(m => m.textContent.includes('Security Analysis'));

                if (!existing) {
                    let analysisText = data.analysis;

                    // Check if analysis looks like JSON (starts with { or contains JSON structure)
                    const isJsonContent = (text) => {
                        if (typeof text !== 'string') return true;
                        const trimmed = text.trim();
                        return trimmed.startsWith('{') || trimmed.startsWith('[') ||
                            trimmed.includes('"report_generated_at"') ||
                            trimmed.includes('"llm_analysis_results"') ||
                            trimmed.includes('"chunk_id"');
                    };

                    // If it's a V2 report (JSON) or looks like JSON, extract the summary
                    if (data.analysis_type === 'v2_report' || isJsonContent(data.analysis)) {
                        try {
                            const report = typeof data.analysis === 'string'
                                ? JSON.parse(data.analysis)
                                : data.analysis;

                            // Extract summaries from chunks
                            const summaries = [];
                            const highRiskAssets = [];
                            const keyVulns = [];

                            for (const chunk of (report.llm_analysis_results || [])) {
                                const analysis = chunk.analysis || {};
                                if (analysis.summary && analysis.summary !== 'No summary provided.') {
                                    summaries.push(analysis.summary);
                                }
                                // Also collect high risk assets and vulnerabilities
                                if (analysis.high_risk_assets) {
                                    highRiskAssets.push(...analysis.high_risk_assets);
                                }
                                if (analysis.key_vulnerabilities) {
                                    keyVulns.push(...analysis.key_vulnerabilities);
                                }
                            }

                            if (summaries.length > 0) {
                                analysisText = summaries.join('\n\n');

                                // Add summary of high-risk findings
                                if (highRiskAssets.length > 0) {
                                    analysisText += `\n\n**High Risk Assets:** ${highRiskAssets.length} identified`;
                                }
                                if (keyVulns.length > 0) {
                                    analysisText += `\n**Key Vulnerabilities:** ${keyVulns.length} found`;
                                }
                                analysisText += '\n\n_See the AI Analysis Report tab for detailed findings._';
                            } else {
                                analysisText = `Analysis complete. ${report.total_ips_analyzed || 0} IPs analyzed across ${report.chunks_processed || 0} chunks.\n\nSee the **AI Analysis Report** tab for detailed findings.`;
                            }
                        } catch (e) {
                            // If JSON parse fails, it might be a plain text analysis
                            console.warn('Failed to parse analysis as JSON:', e);
                            // Check if it's actually just raw JSON text that shouldn't be displayed
                            if (isJsonContent(data.analysis)) {
                                analysisText = 'Analysis complete. See the **AI Analysis Report** tab for detailed findings.';
                            }
                            // Otherwise keep the original text
                        }
                    }

                    this.addMessage('ai', `**🎯 Security Analysis (${data.provider || 'AI'})** _(saved ${new Date(data.created_at).toLocaleString()})_\n\n${analysisText}`);
                    if (this.elements.llmProvider) {
                        this.elements.llmProvider.textContent = data.provider || 'AI';
                    }
                }
            }
        } catch (error) {
            console.error('Failed to load saved analysis:', error);
        }
    }

    async sendMessage(customMessage = null) {
        const message = customMessage || this.elements.chatInput.value.trim();
        if (!message || !this.currentScanId) return;

        this.addMessage('user', message);
        if (!customMessage) {
            this.elements.chatInput.value = '';
        }
        this.elements.btnSend.disabled = true;

        // Get selected provider
        const provider = this.getSelectedProvider();

        // Build request payload
        const payload = {
            scan_id: this.currentScanId,
            message: message,
            provider: provider
        };

        // Include model selection if model selector is visible
        const modelSection = document.getElementById('providerModelSection');
        const modelSelect = document.getElementById('providerModelSelect');
        if (modelSection && modelSelect && modelSection.style.display !== 'none') {
            const selectedModel = modelSelect.value;
            if (selectedModel) {
                payload.model = selectedModel;
            }
        }

        // Show typing indicator
        const typingId = this.showTypingIndicator();

        try {
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            // Remove typing indicator
            this.removeTypingIndicator(typingId);

            const data = await response.json();
            this.addMessage('ai', data.response || data.error || 'No response');

            if (data.provider && data.provider !== 'none') {
                const status = this.llmStatus?.[provider];
                const icon = status?.icon || '🤖';
                if (this.elements.llmProvider) {
                    this.elements.llmProvider.textContent = `${icon} ${data.provider}`;
                }
            }
        } catch (error) {
            this.removeTypingIndicator(typingId);
            this.addMessage('ai', `Error: ${error.message}`);
        }

        this.elements.btnSend.disabled = false;
    }

    showTypingIndicator() {
        const id = 'typing-' + Date.now();
        const div = document.createElement('div');
        div.className = 'message ai typing-indicator';
        div.id = id;
        div.innerHTML = `
            <div class="msg-avatar">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><circle cx="12" cy="12" r="3"/></svg>
            </div>
            <div class="msg-content">
                <div class="typing-dots">
                    <span></span><span></span><span></span>
                </div>
            </div>
        `;
        this.elements.chatMessages.appendChild(div);
        this.elements.chatMessages.scrollTop = this.elements.chatMessages.scrollHeight;
        return id;
    }

    removeTypingIndicator(id) {
        const el = document.getElementById(id);
        if (el) el.remove();
    }

    addMessage(role, content) {
        const div = document.createElement('div');
        div.className = `message ${role}`;

        const avatar = role === 'ai' ?
            `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><circle cx="12" cy="12" r="3"/></svg>` :
            `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`;

        div.innerHTML = `
            <div class="msg-avatar">${avatar}</div>
            <div class="msg-content">${this.formatMessage(content)}</div>
        `;

        this.elements.chatMessages.appendChild(div);
        this.elements.chatMessages.scrollTop = this.elements.chatMessages.scrollHeight;
    }

    formatMessage(content) {
        // Enhanced markdown-like formatting for AI responses
        let formatted = this.escapeHtml(content);

        // Strip <think>...</think> tags (DeepSeek reasoning mode)
        // These should not be shown to users in the chat
        formatted = formatted.replace(/&lt;think&gt;[\s\S]*?&lt;\/think&gt;/gi, '');
        formatted = formatted.replace(/<think>[\s\S]*?<\/think>/gi, '');
        formatted = formatted.trim();

        // Code blocks (triple backticks) - process BEFORE other formatting
        formatted = formatted.replace(/```(\w+)?\n([\s\S]*?)```/g, (match, lang, code) => {
            return `<pre class="code-block ${lang || ''}" style="background: var(--bg-card); padding: 1rem; border-radius: 8px; overflow-x: auto; font-family: 'JetBrains Mono', monospace; font-size: 0.85em; margin: 0.5rem 0; border: 1px solid var(--border-subtle);"><code>${code.trim()}</code></pre>`;
        });

        // Inline code (single backticks)
        formatted = formatted.replace(/`([^`]+)`/g, '<code style="background: var(--bg-input); padding: 0.125rem 0.5rem; border-radius: 4px; font-family: JetBrains Mono, monospace; font-size: 0.85em; color: var(--accent-cyan);">$1</code>');

        // Bold (double asterisks)
        formatted = formatted.replace(/\*\*([^*]+)\*\*/g, '<strong style="color: var(--text-primary);">$1</strong>');

        // Italic (single asterisks - but not inside other tags)
        formatted = formatted.replace(/(?<![*])\*([^*\n]+)\*(?![*])/g, '<em>$1</em>');

        // Headers (# at start of line)
        formatted = formatted.replace(/^### (.+)$/gm, '<h4 style="color: var(--accent-purple); margin: 1rem 0 0.5rem 0; font-size: 1em;">$1</h4>');
        formatted = formatted.replace(/^## (.+)$/gm, '<h3 style="color: var(--accent-cyan); margin: 1rem 0 0.5rem 0; font-size: 1.1em;">$1</h3>');
        formatted = formatted.replace(/^# (.+)$/gm, '<h2 style="color: var(--accent-pink); margin: 1rem 0 0.5rem 0; font-size: 1.2em;">$1</h2>');

        // Bullet lists (- or * at start of line)
        formatted = formatted.replace(/^[\-\*] (.+)$/gm, '<li style="margin-left: 1.5rem; list-style-type: disc;">$1</li>');

        // Numbered lists
        formatted = formatted.replace(/^(\d+)\. (.+)$/gm, '<li style="margin-left: 1.5rem; list-style-type: decimal;">$2</li>');

        // CVE references - highlight them
        formatted = formatted.replace(/(CVE-\d{4}-\d{4,})/gi, '<span style="background: var(--danger); color: white; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.85em; font-weight: 600;">$1</span>');

        // URLs - make them clickable
        formatted = formatted.replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" style="color: var(--accent-cyan); text-decoration: underline;">$1</a>');

        // IP addresses - highlight
        formatted = formatted.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g, '<span style="color: var(--accent-purple); font-family: JetBrains Mono, monospace;">$1</span>');

        // Severity levels
        formatted = formatted.replace(/\b(CRITICAL|Critical)\b/gi, '<span style="background: var(--danger); color: white; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.8em; font-weight: 600;">CRITICAL</span>');
        formatted = formatted.replace(/\b(HIGH|High)\b/g, '<span style="background: #ff5722; color: white; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.8em; font-weight: 600;">HIGH</span>');
        formatted = formatted.replace(/\b(MEDIUM|Medium)\b/g, '<span style="background: var(--warning); color: #333; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.8em; font-weight: 600;">MEDIUM</span>');
        formatted = formatted.replace(/\b(LOW|Low)\b/g, '<span style="background: var(--success); color: #333; padding: 0.1rem 0.4rem; border-radius: 4px; font-size: 0.8em; font-weight: 600;">LOW</span>');

        // Line breaks (but preserve them in code blocks)
        formatted = formatted.replace(/\n/g, '<br>');

        // Fix consecutive <li> elements to be wrapped in <ul>
        formatted = formatted.replace(/(<li[^>]*>.*?<\/li>(\s*<br>)*)+/g, (match) => {
            const items = match.replace(/<br>/g, '');
            return `<ul style="margin: 0.5rem 0; padding: 0;">${items}</ul>`;
        });

        return formatted;
    }

    enableChat() {
        this.elements.chatInput.disabled = false;
        this.elements.btnSend.disabled = false;
    }

    disableChat() {
        this.elements.chatInput.disabled = true;
        this.elements.btnSend.disabled = true;
    }

    updateProgress(status, percent) {
        this.elements.statusText.textContent = status;
        this.elements.progressText.textContent = `${Math.round(percent)}%`;
        this.elements.progressFill.style.width = `${percent}%`;
    }

    showResults() {
        this.elements.emptyState.classList.add('hidden');
        this.elements.resultsContainer.classList.remove('hidden');
    }

    // Clear state when switching between scans
    clearPreviousState() {
        // Clear chat messages
        if (this.elements.chatMessages) {
            this.elements.chatMessages.innerHTML = '';
        }

        // Clear AI report
        this.aiReport = null;
        this.hideAIReport();

        // Hide AI report badge
        if (this.elements.aiReportBadge) {
            this.elements.aiReportBadge.classList.add('hidden');
        }

        // Reset to findings tab
        switchReportTab('findings');

        // Clear hosts and CVEs
        this.elements.hostsList.innerHTML = '';
        this.elements.cveTable.innerHTML = '';
        this.allCVEs = [];

        // Clear charts
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });
        this.charts = {};

        // Reset stats
        this.elements.statIPs.textContent = '0';
        this.elements.statSubs.textContent = '0';
        this.elements.statCVEs.textContent = '0';
        this.elements.statCrit.textContent = '0';

        console.log('Previous state cleared');
    }

    resetResults() {
        this.elements.hostsList.innerHTML = '';
        this.elements.cveTable.innerHTML = '';
        if (this.elements.subdomainsList) {
            this.elements.subdomainsList.innerHTML = '';
        }
        this.allCVEs = [];
        this.elements.statIPs.textContent = '0';
        this.elements.statSubs.textContent = '0';
        this.elements.statCVEs.textContent = '0';
        this.elements.statCrit.textContent = '0';
    }

    resetUI() {
        this.clearPreviousState();
        this.currentScanId = null;
        this.scanData = null;
        this.elements.domainInput.value = '';
        this.elements.sessionSelect.value = '';
        this.elements.emptyState.classList.remove('hidden');
        this.elements.resultsContainer.classList.add('hidden');
        this.resetResults();
        this.disableChat();
        this.updateProgress('Ready', 0);
    }

    async rescan() {
        const domain = this.elements.domainInput.value?.trim();
        if (!domain) return;

        // Clear cache before rescanning
        try {
            this.updateProgress('Clearing cache...', 5);
            const response = await fetch(`/api/cache/${encodeURIComponent(domain)}`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' }
            });
            if (response.ok) {
                const data = await response.json();
                console.log(`Cache cleared for ${domain}:`, data);
            }
        } catch (err) {
            console.warn('Failed to clear cache:', err);
            // Continue with scan even if cache clear fails
        }

        // Start fresh scan
        this.startScan();
    }

    disableScanButton() {
        this.elements.btnScan.disabled = true;
        this.elements.btnScan.classList.add('loading');
        this.elements.btnScan.innerHTML = `
            <svg class="spinner" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
            </svg>
            <span class="btn-text">Scanning...</span>
        `;
        // Add scanning class to progress bar
        if (this.elements.progressFill) {
            this.elements.progressFill.classList.add('scanning');
        }
    }

    enableScanButton() {
        this.elements.btnScan.disabled = false;
        this.elements.btnScan.classList.remove('loading');
        this.elements.btnScan.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <polygon points="5 3 19 12 5 21 5 3"/>
            </svg>
            <span class="btn-text">Start Scan</span>
        `;
        // Remove scanning class from progress bar
        if (this.elements.progressFill) {
            this.elements.progressFill.classList.remove('scanning');
        }
    }

    // Animate stat value changes
    animateStatValue(element, newValue) {
        const currentValue = parseInt(element.textContent) || 0;
        if (currentValue === newValue) return;

        element.classList.add('counting');
        element.textContent = newValue;

        setTimeout(() => {
            element.classList.remove('counting');
        }, 400);
    }

    // Check LLM status and display in UI
    async checkLLMStatus() {
        try {
            const response = await fetch('/api/llm/status');
            const data = await response.json();

            // New API returns { status: 'online', providers: {...} }
            // We want to store the providers object for the UI logic
            const status = data.providers || {};

            // Store status for later use
            this.llmStatus = status;

            // Update provider dropdown options with availability indicators
            const select = document.getElementById('aiProviderSelect');
            if (select) {
                const options = select.options;
                for (let i = 0; i < options.length; i++) {
                    const opt = options[i];
                    const provider = opt.value;
                    const providerStatus = status[provider];

                    if (providerStatus) {
                        const available = providerStatus.available;
                        const icon = providerStatus.icon || '';
                        const name = providerStatus.name || provider;
                        // const tag = providerStatus.free ? ' (Free)' : providerStatus.private ? ' (Private)' : '';

                        // Keep the existing text but add checkmark/cross
                        // Or reconstruction:
                        // opt.textContent = `${icon} ${name}${tag} ${available ? '✓' : '✗'}`;

                        // Let's stick to existing text logic if possible or update it
                        // The original code was: opt.textContent = `${icon} ${name}${tag} ${available ? '✓' : '✗'}`;
                        const tag = '';
                        opt.textContent = `${name} ${available ? '✓' : ''}`;

                        opt.disabled = false;  // Allow selection
                    }
                }
            }

            // Update status indicator
            this.updateProviderStatus();

            return status;
        } catch (error) {
            console.error('LLM status check failed:', error);
            return null;
        }
    }

    // Update provider status display
    updateProviderStatus() {
        const select = document.getElementById('aiProviderSelect');
        const statusDiv = document.getElementById('providerStatus');
        if (!select || !statusDiv) return;

        const provider = select.value;
        const status = this.llmStatus?.[provider];

        if (!status) {
            statusDiv.innerHTML = '<span class="status-dot checking"></span><span class="status-text">Unknown provider</span>';
            return;
        }

        const dot = statusDiv.querySelector('.status-dot');
        const text = statusDiv.querySelector('.status-text');

        if (status.available) {
            dot.className = 'status-dot connected';

            // Show model name from API response (already from config.yaml)
            let modelName = '';

            if (provider === 'local' && status.running_models?.length > 0) {
                modelName = status.running_models[0];
            } else if (status.model) {
                // Use model from server response (from config.yaml)
                modelName = status.model;
            } else if (status.models?.length > 0) {
                modelName = status.models[0];
            } else {
                modelName = 'Connected';
            }

            text.textContent = `Connected: ${modelName}`;
        } else if (status.configured === false) {
            dot.className = 'status-dot disconnected';
            text.textContent = 'API key not configured';
        } else {
            dot.className = 'status-dot disconnected';
            text.textContent = provider === 'local' ? 'Ollama not running' : 'Not available';
        }

        // Update subtitle
        if (this.elements.llmProvider) {
            this.elements.llmProvider.textContent = `${status.icon || ''} ${status.name || provider}`;
        }
    }

    // Get currently selected AI provider
    getSelectedProvider() {
        const select = document.getElementById('aiProviderSelect');
        return select ? select.value : 'local';
    }

    // List available result files for direct LLM reading
    async listAvailableFiles() {
        try {
            const response = await fetch('/api/llm/available-files');
            const data = await response.json();
            return data.files || [];
        } catch (error) {
            console.error('Failed to list files:', error);
            return [];
        }
    }

    // Send query to analyze a specific file
    async queryFile(filePath, query) {
        this.addMessage('user', `[Analyzing file: ${filePath}]\n${query}`);
        this.elements.btnSend.disabled = true;

        try {
            const response = await fetch('/api/llm/read-file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    file_path: filePath,
                    query: query
                })
            });

            const data = await response.json();

            if (data.success) {
                const summary = data.summary || {};
                let message = data.response;
                message += `\n\n---\n*📁 File: ${data.file || filePath}*`;
                message += `\n*📊 Stats: ${summary.total_ips || 0} IPs, ${summary.total_cves || 0} CVEs*`;
                this.addMessage('ai', message);
            } else {
                this.addMessage('ai', `❌ Error: ${data.error || 'Analysis failed'}\n\n*Context preview available in console.*`);
                if (data.context_preview) {
                    console.log('Context preview:', data.context_preview);
                }
            }
        } catch (error) {
            this.addMessage('ai', `Error: ${error.message}`);
        }

        this.elements.btnSend.disabled = false;
    }

    // Generate Report - just show the modal dialog
    // The actual generation is handled by window.generateReport in the inline script
    showReportModal() {
        if (window.showReportDialog) {
            window.showReportDialog();
        } else {
            alert('Report dialog not available');
        }
    }
    // ===== CVE EXPLORER METHODS =====
    async toggleCveExplorer() {
        const cveExplorer = this.elements.cveExplorer;
        const resultsContainer = this.elements.resultsContainer;
        const emptyState = this.elements.emptyState;
        const btn = this.elements.btnCveExplorer;
        const adminPanel = document.getElementById('adminPanel');

        // Toggle state
        const isHidden = cveExplorer.classList.contains('hidden');

        if (isHidden) {
            // Show Explorer
            cveExplorer.classList.remove('hidden');
            resultsContainer.classList.add('hidden');
            emptyState.classList.add('hidden');
            if (adminPanel) adminPanel.classList.add('hidden');

            // Update buttons
            document.querySelectorAll('.btn-sidebar').forEach(b => b.classList.remove('active'));
            if (btn) btn.classList.add('active');

            // Load data
            await this.loadGlobalCves();
        } else {
            // Hide Explorer (return to Scan View)
            cveExplorer.classList.add('hidden');
            if (btn) btn.classList.remove('active');

            if (this.currentScanId) {
                resultsContainer.classList.remove('hidden');
            } else {
                emptyState.classList.remove('hidden');
            }
        }
    }

    async loadGlobalCves() {
        if (!this.elements.cveExplorerGrid) return;

        const grid = this.elements.cveExplorerGrid;
        const query = this.elements.globalCveSearch ? this.elements.globalCveSearch.value : '';
        const limit = 100;

        grid.innerHTML = '<div class="empty-state-small"><span class="spin-icon">↻</span> Loading vulnerabilities...</div>';

        try {
            const url = `/api/cves?limit=${limit}&q=${encodeURIComponent(query)}`;
            const response = await fetch(url);

            if (handleAuthError(response)) return;

            if (response.ok) {
                const cves = await response.json();
                this.renderGlobalCves(cves);
            } else {
                grid.innerHTML = '<div class="empty-state-small" style="color:var(--danger)">Failed to load data</div>';
            }
        } catch (error) {
            console.error('CVE load error:', error);
            grid.innerHTML = '<div class="empty-state-small" style="color:var(--danger)">Connection error</div>';
        }
    }

    renderGlobalCves(cves) {
        const grid = this.elements.cveExplorerGrid;

        // Update Stats
        if (this.elements.expTotal) this.elements.expTotal.textContent = cves.length;
        const crit = cves.filter(c => c.cvss >= 9.0).length;
        const high = cves.filter(c => c.cvss >= 7.0 && c.cvss < 9.0).length;
        if (this.elements.expCrit) this.elements.expCrit.textContent = crit;
        if (this.elements.expHigh) this.elements.expHigh.textContent = high;

        if (cves.length === 0) {
            grid.innerHTML = '<div class="empty-state-small">No vulnerabilities found matching your criteria.</div>';
            return;
        }

        grid.innerHTML = cves.map(cve => {
            const severityClass = cve.cvss >= 9.0 ? 'critical' :
                cve.cvss >= 7.0 ? 'high' :
                    cve.cvss >= 4.0 ? 'medium' : 'low';

            // Affected host info
            const hostname = cve.hostname || cve.ip || 'Unknown';

            return `
                <div class="cve-card" onclick="window.open('https://nvd.nist.gov/vuln/detail/${cve.cve_id}', '_blank')">
                    <div class="cve-card-header">
                        <div class="cve-id">${cve.cve_id}</div>
                        <div class="badge badge-${severityClass}">CVSS ${cve.cvss}</div>
                    </div>
                    <div class="cve-summary" title="${cve.summary}">${cve.summary}</div>
                    <div class="cve-affected">
                        <span class="cve-affected-tag">${hostname}</span>
                    </div>
                    <div class="cve-footer">
                        <div class="cve-domain">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"></circle>
                                <line x1="2" y1="12" x2="22" y2="12"></line>
                                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                            </svg>
                            ${cve.domain || 'Unknown'}
                        </div>
                        <div>${new Date(cve.scan_date).toLocaleDateString()}</div>
                    </div>
                </div>
            `;
        }).join('');
    }
}

// Config toggle
function toggleConfig() {
    const content = document.getElementById('configContent');
    const button = document.querySelector('.config-toggle');
    content.classList.toggle('open');
    if (button) {
        button.classList.toggle('active');
    }
}

// Report Tab Switching
function switchReportTab(tab) {
    const findingsPanel = document.getElementById('findingsPanel');
    const aiReportPanel = document.getElementById('aiReportPanel');
    const toolsFindingsPanel = document.getElementById('toolsFindingsPanel');
    const tabs = document.querySelectorAll('.report-tab');

    // Update tab styles
    tabs.forEach(t => {
        if (t.dataset.tab === tab) {
            t.classList.add('active');
            t.style.color = 'var(--accent-cyan)';
            t.style.borderBottomColor = 'var(--accent-cyan)';
        } else {
            t.classList.remove('active');
            t.style.color = 'var(--text-muted)';
            t.style.borderBottomColor = 'transparent';
        }
    });

    // Show/hide panels
    if (findingsPanel) findingsPanel.classList.add('hidden');
    if (aiReportPanel) aiReportPanel.classList.add('hidden');
    if (toolsFindingsPanel) toolsFindingsPanel.classList.add('hidden');

    if (tab === 'findings') {
        if (findingsPanel) findingsPanel.classList.remove('hidden');
    } else if (tab === 'ai-report') {
        if (aiReportPanel) aiReportPanel.classList.remove('hidden');
        // Hide badge when viewed
        const badge = document.getElementById('aiReportBadge');
        if (badge) badge.classList.add('hidden');
    } else if (tab === 'tools-findings') {
        if (toolsFindingsPanel) toolsFindingsPanel.classList.remove('hidden');
        // Load tools findings when tab is clicked
        if (window.dashboard?.currentScanId) {
            loadToolsFindings(window.dashboard.currentScanId);
        }
        // Hide badge when viewed
        const badge = document.getElementById('toolsFindingsBadge');
        if (badge) badge.classList.add('hidden');
    }
}

// Load Tools Findings from API
async function loadToolsFindings(scanId) {
    if (!scanId) return;

    try {
        const response = await fetch(`/api/tools/all-findings/${scanId}`);
        if (!response.ok) return;

        const data = await response.json();

        const emptyDiv = document.getElementById('toolsFindingsEmpty');
        const contentDiv = document.getElementById('toolsFindingsContent');

        if (data.total_findings > 0) {
            if (emptyDiv) emptyDiv.classList.add('hidden');
            if (contentDiv) contentDiv.classList.remove('hidden');

            // Update counts
            document.getElementById('aliveHostsCount').textContent = data.alive_hosts?.count || 0;
            document.getElementById('harvestedUrlsCount').textContent = data.harvested_urls?.count || 0;
            document.getElementById('nucleiFindingsCount').textContent = data.nuclei_findings?.count || 0;
            document.getElementById('xssFindingsCount').textContent = data.xss_findings?.count || 0;
            document.getElementById('apiEndpointsCount').textContent = data.api_discoveries?.count || 0;

            // Render Alive Hosts
            const aliveHostsList = document.getElementById('aliveHostsList');
            if (aliveHostsList && data.alive_hosts?.items) {
                aliveHostsList.innerHTML = data.alive_hosts.items.map(h => `
                    <div class="finding-card">
                        <a href="${h.url}" target="_blank" class="finding-url">${h.url}</a>
                        <div class="finding-meta">
                            <span class="badge">${h.status_code || 200}</span>
                            ${h.title ? `<span class="finding-title">${h.title}</span>` : ''}
                            ${h.technologies?.length ? `<span class="tech-tags">${h.technologies.slice(0, 3).join(', ')}</span>` : ''}
                        </div>
                    </div>
                `).join('');
            }

            // Render Harvested URLs (ALL URLs in scrollable container)
            const harvestedUrlsList = document.getElementById('harvestedUrlsList');
            if (harvestedUrlsList && data.harvested_urls?.items) {
                const urlItems = data.harvested_urls.items;  // Show ALL URLs
                harvestedUrlsList.innerHTML = `
                    <div class="harvested-urls-scroll" style="max-height: 400px; overflow-y: auto;">
                        ${urlItems.map(u => `
                            <div class="finding-item" style="display: flex; gap: 8px; padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
                                <a href="${u.url}" target="_blank" class="finding-url-small" style="flex: 1; word-break: break-all; font-family: monospace; font-size: 0.85rem;">${u.url}</a>
                                <span class="badge-source" style="font-size: 0.7rem;">${u.source || ''}</span>
                                ${u.has_params ? '<span class="badge-param" style="font-size: 0.7rem;">params</span>' : ''}
                            </div>
                        `).join('')}
                    </div>
                `;
            }

            // Render Nuclei Vulnerabilities
            const nucleiFindingsList = document.getElementById('nucleiFindingsList');
            if (nucleiFindingsList && data.nuclei_findings?.items) {
                nucleiFindingsList.innerHTML = data.nuclei_findings.items.map(f => `
                    <div class="finding-item vuln-item">
                        <span class="severity-badge ${f.severity || 'medium'}">${(f.severity || 'medium').toUpperCase()}</span>
                        <span class="finding-name">${f.name || f.template_id || 'Unknown'}</span>
                        <a href="${f.host}" target="_blank" class="finding-host">${f.host}</a>
                    </div>
                `).join('');
            }

            // Render XSS Findings
            const xssFindingsList = document.getElementById('xssFindingsList');
            if (xssFindingsList && data.xss_findings?.items) {
                xssFindingsList.innerHTML = data.xss_findings.items.length > 0 ?
                    data.xss_findings.items.map(x => `
                        <div class="finding-item xss-item">
                            <span class="severity-badge high">XSS</span>
                            <span class="finding-param">Param: ${x.parameter}</span>
                            <a href="${x.url}" target="_blank" class="finding-url-small">${x.url.slice(0, 60)}...</a>
                        </div>
                    `).join('') : '<div class="no-findings">No XSS vulnerabilities found</div>';
            }

            // Render API Endpoints
            const apiEndpointsList = document.getElementById('apiEndpointsList');
            if (apiEndpointsList && data.api_discoveries?.items) {
                apiEndpointsList.innerHTML = data.api_discoveries.items.length > 0 ?
                    data.api_discoveries.items.map(a => `
                        <div class="finding-item api-item">
                            <span class="badge-status">${a.status_code || 200}</span>
                            <a href="${a.url}" target="_blank" class="finding-url-small">${a.url}</a>
                            ${a.content_type ? `<span class="content-type">${a.content_type}</span>` : ''}
                        </div>
                    `).join('') : '<div class="no-findings">No API endpoints discovered</div>';
            }

            // Update badge with total
            const badge = document.getElementById('toolsFindingsBadge');
            if (badge && data.total_findings > 0) {
                badge.textContent = data.total_findings;
                badge.classList.remove('hidden');
            }
        } else {
            if (emptyDiv) emptyDiv.classList.remove('hidden');
            if (contentDiv) contentDiv.classList.add('hidden');
        }
    } catch (err) {
        console.error('Error loading tools findings:', err);
    }
}

// Add spinner animation
const style = document.createElement('style');
style.textContent = `
    @keyframes spin {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }
    .spin { animation: spin 1s linear infinite; }
    
    /* Severity badge colors */
    .severity-badge.critical { background: var(--danger); color: white; }
    .severity-badge.high { background: #ff5722; color: white; }
    .severity-badge.medium { background: var(--warning); color: #333; }
    .severity-badge.low { background: var(--success); color: #333; }
    
    /* Hidden class */
    .hidden { display: none !important; }
    
    /* Affected hosts badge */
    .badge-affected {
        background: var(--accent-purple);
        color: white;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    
    /* LLM Status indicator */
    .llm-status {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.75rem;
        color: var(--text-muted);
    }
    .llm-status.connected { color: var(--success); }
    .llm-status.disconnected { color: var(--danger); }
`;
document.head.appendChild(style);

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new TwinSanityDashboard();
    // Check LLM status on load
    window.dashboard.checkLLMStatus();

    // Expose global functions for buttons
    // NOTE: window.generateReport and window.showReportDialog are defined in the inline script
    window.loadProxyList = loadProxyList;
    window.addSingleProxy = addSingleProxy;
    window.clearProxies = clearProxies;
    window.loadCustomWordlist = loadCustomWordlist;
    window.clearCustomWordlist = clearCustomWordlist;
    window.toggleBruteForceOptions = toggleBruteForceOptions;
    window.toggleProxyOptions = toggleProxyOptions;

    // Initialize visibility sync for state persistence across tab switches
    initVisibilitySync();

    // Initialize Mission Control and Theme
    initMissionControl();
    initThemeToggle();
});

// ========================
// MISSION CONTROL FUNCTIONS
// ========================

function initMissionControl() {
    // Sync Mission Control toggles with sidebar checkboxes
    syncMCToggles();

    // Setup Mission Control domain input
    const mcDomainInput = document.getElementById('mcDomainInput');
    const sidebarDomainInput = document.getElementById('domainInput');

    if (mcDomainInput && sidebarDomainInput) {
        // Sync domain input between Mission Control and sidebar
        mcDomainInput.addEventListener('input', () => {
            sidebarDomainInput.value = mcDomainInput.value;
        });
        sidebarDomainInput.addEventListener('input', () => {
            mcDomainInput.value = sidebarDomainInput.value;
        });

        // Allow Enter key to start scan from Mission Control
        mcDomainInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                startScanFromMC();
            }
        });
    }

    // Expose global functions
    window.startScanFromMC = startScanFromMC;
    window.toggleAdvancedOptions = toggleAdvancedOptions;
    window.toggleToolsPanel = toggleToolsPanel;
    window.syncMCToggle = syncMCToggle;
}

function syncMCToggles() {
    // Sync Mission Control toggle states with sidebar checkboxes
    const toggleMappings = [
        { mc: 'mcSubdomains', sidebar: 'chkSubdomains' },
        { mc: 'mcShodan', sidebar: 'chkShodan' },
        { mc: 'mcAI', sidebar: 'chkAIAnalysis' }
    ];

    toggleMappings.forEach(({ mc, sidebar }) => {
        const mcToggle = document.getElementById(mc);
        const sidebarCheckbox = document.getElementById(sidebar);

        if (mcToggle && sidebarCheckbox) {
            // Initial sync from sidebar to MC
            mcToggle.checked = sidebarCheckbox.checked;

            // Two-way sync
            mcToggle.addEventListener('change', () => {
                sidebarCheckbox.checked = mcToggle.checked;
                // Update visual state of toggle badge
                const badge = mcToggle.closest('.mc-toggle-badge');
                if (badge) {
                    badge.classList.toggle('active', mcToggle.checked);
                }
            });
            sidebarCheckbox.addEventListener('change', () => {
                mcToggle.checked = sidebarCheckbox.checked;
                // Update visual state of toggle badge
                const badge = mcToggle.closest('.mc-toggle-badge');
                if (badge) {
                    badge.classList.toggle('active', mcToggle.checked);
                }
            });
        }
    });
}

function syncMCToggle(mcToggleId, sidebarCheckboxId) {
    const mcToggle = document.getElementById(mcToggleId);
    const sidebarCheckbox = document.getElementById(sidebarCheckboxId);

    if (mcToggle && sidebarCheckbox) {
        sidebarCheckbox.checked = mcToggle.checked;
    }
}

function startScanFromMC() {
    const mcDomainInput = document.getElementById('mcDomainInput');
    const sidebarDomainInput = document.getElementById('domainInput');

    if (mcDomainInput && mcDomainInput.value.trim()) {
        // Sync domain to sidebar input
        if (sidebarDomainInput) {
            sidebarDomainInput.value = mcDomainInput.value;
        }

        // Use the dashboard's startScan method
        if (window.dashboard) {
            window.dashboard.startScan();
        }
    } else {
        toast.warning('Missing Domain', 'Please enter a target domain');
    }
}

function toggleAdvancedOptions() {
    const panel = document.getElementById('scanForm');
    const chevron = document.querySelector('.expand-chevron');
    const advancedSection = document.getElementById('advancedScanOptions');

    if (panel) {
        panel.classList.toggle('expanded');
        if (chevron) {
            chevron.classList.toggle('rotated');
        }
        if (advancedSection) {
            advancedSection.classList.toggle('expanded');
        }
    }
}

function toggleToolsPanel() {
    // Toggle the advanced scanner tools panel in the sidebar
    const advancedSection = document.getElementById('advancedScanOptions');
    const panel = document.getElementById('scanForm');
    const chevron = document.querySelector('.expand-chevron');

    if (panel && advancedSection) {
        // If panel is not visible, show it
        if (!panel.classList.contains('expanded')) {
            panel.classList.add('expanded');
            advancedSection.classList.add('expanded');
            if (chevron) {
                chevron.classList.add('rotated');
            }
        } else {
            // Toggle off
            panel.classList.remove('expanded');
            advancedSection.classList.remove('expanded');
            if (chevron) {
                chevron.classList.remove('rotated');
            }
        }
    }

    // Expose global function
    window.toggleToolsPanel = toggleToolsPanel;
}

// ========================
// THEME TOGGLE FUNCTIONS
// ========================

function initThemeToggle() {
    // Load saved theme preference
    const savedTheme = localStorage.getItem('twinsanity-theme') || 'dark';
    applyTheme(savedTheme);

    // Set toggle state based on saved theme
    const themeCheckbox = document.getElementById('themeToggle');
    if (themeCheckbox) {
        themeCheckbox.checked = savedTheme === 'light';
    }

    // Expose global function
    window.toggleTheme = toggleTheme;
}

function toggleTheme() {
    const themeCheckbox = document.getElementById('themeToggle');
    const newTheme = themeCheckbox?.checked ? 'light' : 'dark';
    applyTheme(newTheme);
    localStorage.setItem('twinsanity-theme', newTheme);
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);

    // Update meta theme-color for mobile browsers
    const metaTheme = document.querySelector('meta[name="theme-color"]');
    if (metaTheme) {
        metaTheme.content = theme === 'light' ? '#f1f5f9' : '#0b0f19';
    }
}

// ========================
// AI PROVIDER FUNCTIONS
// ========================

// Note: onProviderChange is defined inline in index.html with dynamic model loading
// from /api/llm/provider-models endpoint. It loads models from config.yaml.

// ========================
// PAGE VISIBILITY SYNC
// ========================

// Handle page visibility change - sync scan state when tab becomes visible
function initVisibilitySync() {
    document.addEventListener('visibilitychange', async () => {
        if (document.visibilityState === 'visible' && window.dashboard?.currentScanId) {
            console.log('Tab visible - syncing scan state...');
            await syncScanState(window.dashboard.currentScanId);
        }
    });
}

// Sync scan state from server
async function syncScanState(scanId) {
    if (!scanId) return;

    try {
        const response = await fetch(`/api/scans/${scanId}/status`);
        if (response.ok) {
            const status = await response.json();

            // Update progress bar
            if (window.dashboard) {
                if (status.progress !== undefined) {
                    window.dashboard.updateProgress(status.message || status.status, status.progress);
                }

                // If scan is complete, update UI
                if (status.status === 'complete' || status.status === 'completed') {
                    window.dashboard.isScanning = false;
                    window.dashboard.updateProgress('Scan complete!', 100);
                    window.dashboard.updateConnectionStatus('ready');
                } else if (status.status === 'running' || status.status === 'scanning') {
                    window.dashboard.isScanning = true;
                    window.dashboard.updateConnectionStatus('scanning');

                    // Reconnect WebSocket if needed
                    if (!window.dashboard.ws || window.dashboard.ws.readyState !== WebSocket.OPEN) {
                        window.dashboard.connectWebSocket(scanId);
                    }
                }
            }
        }
    } catch (error) {
        console.error('State sync error:', error);
    }
}

// ========================
// PROXY MANAGEMENT FUNCTIONS
// ========================

// Load proxy list from textarea
async function loadProxyList() {
    const proxyTextarea = document.getElementById('proxyListInput');
    if (!proxyTextarea) {
        alert('Proxy textarea not found');
        return;
    }

    const proxyText = proxyTextarea.value.trim();
    if (!proxyText) {
        alert('Please enter proxy addresses');
        return;
    }

    // Parse proxies (one per line)
    const proxies = proxyText.split('\n')
        .map(p => p.trim())
        .filter(p => p && !p.startsWith('#'));

    if (proxies.length === 0) {
        alert('No valid proxies found');
        return;
    }

    try {
        // Upload proxies as a text file
        const blob = new Blob([proxies.join('\n')], { type: 'text/plain' });
        const formData = new FormData();
        formData.append('file', blob, 'proxies.txt');

        const response = await fetch('/api/proxy/upload', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const result = await response.json();
            alert(`✅ Loaded ${result.count || proxies.length} proxies successfully!`);
            updateProxyStatus();
        } else {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || 'Failed to load proxies');
        }
    } catch (error) {
        console.error('Error loading proxies:', error);
        alert('Error loading proxies: ' + error.message);
    }
}

// Add a single proxy
async function addSingleProxy() {
    const input = document.getElementById('proxyInput');  // Fixed: was 'singleProxyInput'
    if (!input) {
        console.error('Proxy input element not found');
        return;
    }

    const proxy = input.value.trim();
    if (!proxy) {
        showProxyFeedback('⚠️ Please enter a proxy address', 'warning');
        return;
    }

    // Show loading state
    const btn = document.querySelector('[onclick="addSingleProxy()"]');
    const originalText = btn ? btn.innerHTML : '';
    if (btn) btn.innerHTML = '⏳ Adding...';

    try {
        const response = await fetch('/api/proxy/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ proxy })
        });

        if (response.ok) {
            const result = await response.json();
            input.value = '';
            showProxyFeedback(`✅ Proxy added! Total: ${result.total}`, 'success');
            updateProxyStatus();
        } else {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || 'Invalid proxy format');
        }
    } catch (error) {
        console.error('Error adding proxy:', error);
        showProxyFeedback(`❌ ${error.message}`, 'error');
    } finally {
        if (btn) btn.innerHTML = originalText;
    }
}

// Show visual feedback for proxy operations
function showProxyFeedback(message, type = 'info') {
    let feedbackEl = document.getElementById('proxyFeedback');
    if (!feedbackEl) {
        // Create feedback element if not exists
        feedbackEl = document.createElement('div');
        feedbackEl.id = 'proxyFeedback';
        feedbackEl.style.cssText = 'padding: 8px 12px; margin-top: 8px; border-radius: 6px; font-size: 0.85em; transition: opacity 0.3s;';
        const proxyOptions = document.getElementById('proxyOptions');
        if (proxyOptions) {
            proxyOptions.insertBefore(feedbackEl, proxyOptions.firstChild);
        }
    }

    // Set colors based on type
    const colors = {
        success: { bg: 'rgba(38, 222, 129, 0.15)', color: '#26de81' },
        error: { bg: 'rgba(255, 8, 68, 0.15)', color: '#ff0844' },
        warning: { bg: 'rgba(250, 130, 49, 0.15)', color: '#fa8231' },
        info: { bg: 'rgba(88, 166, 255, 0.15)', color: '#58a6ff' }
    };
    const style = colors[type] || colors.info;
    feedbackEl.style.background = style.bg;
    feedbackEl.style.color = style.color;
    feedbackEl.textContent = message;
    feedbackEl.style.display = 'block';
    feedbackEl.style.opacity = '1';

    // Auto-hide after 4 seconds
    setTimeout(() => {
        feedbackEl.style.opacity = '0';
        setTimeout(() => { feedbackEl.style.display = 'none'; }, 300);
    }, 4000);
}


// Clear all proxies
async function clearProxies() {
    if (!confirm('Are you sure you want to clear all proxies?')) {
        return;
    }

    try {
        const response = await fetch('/api/proxy/clear', {
            method: 'POST'
        });

        if (response.ok) {
            alert('✅ All proxies cleared!');
            const proxyTextarea = document.getElementById('proxyListInput');
            if (proxyTextarea) proxyTextarea.value = '';
            updateProxyStatus();
        } else {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || 'Failed to clear proxies');
        }
    } catch (error) {
        console.error('Error clearing proxies:', error);
        alert('Error clearing proxies: ' + error.message);
    }
}

// Update proxy status display
async function updateProxyStatus() {
    try {
        const response = await fetch('/api/proxy/list');
        if (response.ok) {
            const data = await response.json();
            const count = data.count || 0;
            const statusEl = document.getElementById('proxyStatus');
            if (statusEl) {
                statusEl.textContent = count > 0 ? `${count} proxies loaded` : 'No proxies';
                statusEl.style.color = count > 0 ? 'var(--success)' : 'var(--text-muted)';
            }
        }
    } catch (error) {
        console.error('Error fetching proxy status:', error);
    }
}

// ========================
// WORDLIST MANAGEMENT FUNCTIONS
// ========================

// Load custom wordlist
async function loadCustomWordlist() {
    const wordlistTextarea = document.getElementById('customWordlistInput');
    if (!wordlistTextarea) {
        alert('Wordlist textarea not found');
        return;
    }

    const wordlistText = wordlistTextarea.value.trim();
    if (!wordlistText) {
        alert('Please enter subdomain prefixes (one per line)');
        return;
    }

    // Parse wordlist (one per line)
    const words = wordlistText.split('\n')
        .map(w => w.trim())
        .filter(w => w && !w.startsWith('#'));

    if (words.length === 0) {
        alert('No valid entries found in wordlist');
        return;
    }

    try {
        // Upload wordlist as a text file
        const blob = new Blob([words.join('\n')], { type: 'text/plain' });
        const formData = new FormData();
        formData.append('file', blob, 'custom_wordlist.txt');

        const response = await fetch('/api/wordlist/upload', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const result = await response.json();
            alert(`✅ Loaded ${result.count || words.length} wordlist entries!`);
            updateWordlistStatus();
        } else {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || 'Failed to load wordlist');
        }
    } catch (error) {
        console.error('Error loading wordlist:', error);
        alert('Error loading wordlist: ' + error.message);
    }
}

// Clear custom wordlist
async function clearCustomWordlist() {
    if (!confirm('Are you sure you want to clear the custom wordlist?')) {
        return;
    }

    try {
        const response = await fetch('/api/wordlist/clear', {
            method: 'POST'
        });

        if (response.ok) {
            alert('✅ Custom wordlist cleared!');
            const wordlistTextarea = document.getElementById('customWordlistInput');
            if (wordlistTextarea) wordlistTextarea.value = '';
            updateWordlistStatus();
        } else {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || 'Failed to clear wordlist');
        }
    } catch (error) {
        console.error('Error clearing wordlist:', error);
        alert('Error clearing wordlist: ' + error.message);
    }
}

// Update wordlist status display
async function updateWordlistStatus() {
    try {
        const response = await fetch('/api/wordlist/list');
        if (response.ok) {
            const data = await response.json();
            const count = data.count || 0;
            const statusEl = document.getElementById('wordlistStatus');
            if (statusEl) {
                statusEl.textContent = count > 0 ? `${count} entries loaded` : 'Using default wordlist';
                statusEl.style.color = count > 0 ? 'var(--success)' : 'var(--text-muted)';
            }
        }
    } catch (error) {
        console.error('Error fetching wordlist status:', error);
    }
}

// ========================
// TOGGLE FUNCTIONS
// ========================

// Toggle brute force options visibility
function toggleBruteForceOptions() {
    const checkbox = document.getElementById('chkBruteForce');
    const options = document.getElementById('bruteForceOptions');
    if (options) {
        options.style.display = checkbox && checkbox.checked ? 'block' : 'none';
    }
}

// Toggle proxy options visibility
function toggleProxyOptions() {
    const checkbox = document.getElementById('chkProxy');
    const options = document.getElementById('proxyOptions');
    if (options) {
        options.style.display = checkbox && checkbox.checked ? 'block' : 'none';
    }
}

// Hide subdomain detail modal
function hideSubdomainModal() {
    const modal = document.getElementById('subdomainModal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        hideSubdomainModal();
        if (typeof hideReportDialog === 'function') {
            hideReportDialog();
        } else if (window.hideReportDialog) {
            window.hideReportDialog();
        }
    }
});

// Toggle chat settings panel
function toggleChatSettings() {
    const section = document.getElementById('chatProviderSection');
    if (section) {
        section.classList.toggle('collapsed');
    }
}
window.toggleChatSettings = toggleChatSettings;



// ===== USER PROFILE & ADMIN PANEL =====
async function fetchUserProfile() {
    try {
        const response = await fetch('/api/auth/me');
        if (handleAuthError(response)) return;

        if (response.ok) {
            const user = await response.json();
            const userNameEl = document.getElementById('userName');
            const userRoleEl = document.getElementById('userRole');
            const userInitialEl = document.getElementById('userInitial');

            if (userNameEl) userNameEl.textContent = user.username || 'User';
            if (userInitialEl) userInitialEl.textContent = (user.username || 'U').charAt(0).toUpperCase();

            if (user.role === 'admin') {
                // Show admin nav button if exists
                const navAdmin = document.getElementById('navAdmin');
                if (navAdmin) navAdmin.classList.remove('hidden');

                // Legacy button support
                const btnAdminPanel = document.getElementById('btnAdminPanel');
                if (btnAdminPanel) btnAdminPanel.classList.remove('hidden');

                // Show SUPER ADMIN for primary admin, otherwise show Admin
                if (userRoleEl) {
                    if (user.is_primary_admin) {
                        userRoleEl.innerHTML = '<span class="role-badge super-admin">Super Admin</span>';
                    } else {
                        userRoleEl.innerHTML = '<span class="role-badge admin">Admin</span>';
                    }
                }
            } else {
                if (userRoleEl) userRoleEl.innerHTML = '<span class="role-badge user">User</span>';
            }
        }
    } catch (error) {
        console.error('Failed to fetch user profile:', error);
    }
}

let isAdminPanelOpen = false;

async function toggleAdminPanel() {
    const adminPanel = document.getElementById('adminPanel');
    const resultsContainer = document.getElementById('resultsContainer');
    const emptyState = document.getElementById('emptyState');
    const btn = document.getElementById('btnAdminPanel');

    isAdminPanelOpen = !isAdminPanelOpen;

    if (isAdminPanelOpen) {
        adminPanel.classList.remove('hidden');
        resultsContainer.classList.add('hidden');
        emptyState.classList.add('hidden');
        btn.classList.add('active');

        // Initialize and load admin panel data
        if (!window.adminPanel) {
            window.adminPanel = new AdminPanel();
        }
        await window.adminPanel.loadUsers();
        await window.adminPanel.loadStats();
    } else {
        adminPanel.classList.add('hidden');
        btn.classList.remove('active');

        // Restore view
        if (window.dashboard && window.dashboard.currentScanId) {
            resultsContainer.classList.remove('hidden');
        } else {
            emptyState.classList.remove('hidden');
        }
    }
}

async function loadAdminUsers() {
    const tbody = document.querySelector('#usersTable tbody');
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center">Loading...</td></tr>';

    try {
        const response = await fetch('/api/admin/users');
        if (handleAuthError(response)) return;

        if (response.ok) {
            const users = await response.json();

            if (users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center">No users found</td></tr>';
                return;
            }

            tbody.innerHTML = users.map(user => `
                <tr>
                    <td>${user.id}</td>
                    <td>${user.username}</td>
                    <td><span class="role-badge ${user.role}">${user.role}</span></td>
                    <td>${new Date(user.created_at).toLocaleDateString()}</td>
                    <td>
                        <button class="btn-delete-icon" onclick="deleteUser(${user.id}, '${user.username}')" title="Delete User">
                             <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="3 6 5 6 21 6"></polyline>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                            </svg>
                        </button>
                    </td>
                </tr>
            `).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--danger)">Failed to load users</td></tr>';
        }
    } catch (error) {
        console.error('Failed to load users:', error);
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--danger)">Connection error</td></tr>';
    }
}

async function deleteUser(userId, username) {
    if (!confirm(`Are you sure you want to delete user "${username}"?\nThis action cannot be undone.`)) {
        return;
    }

    try {
        const response = await fetch(`/api/admin/users/${userId}`, {
            method: 'DELETE'
        });

        if (handleAuthError(response)) return;

        if (response.ok) {
            toast.success('User deleted successfully');
            loadAdminUsers();
        } else {
            const data = await response.json();
            toast.error(data.detail || 'Failed to delete user');
        }
    } catch (error) {
        toast.error('Connection error');
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    fetchUserProfile();
});

// Global toggle for CVE Explorer
function toggleCveExplorer() {
    if (window.dashboard) {
        window.dashboard.toggleCveExplorer();
    }
}
window.toggleCveExplorer = toggleCveExplorer;

// ===== PUBLIC SCANS PANEL =====
let isPublicScansPanelOpen = false;

async function togglePublicScans() {
    const panel = document.getElementById('publicScansPanel');
    const resultsContainer = document.getElementById('resultsContainer');
    const emptyState = document.getElementById('emptyState');
    const cveExplorer = document.getElementById('cveExplorer');
    const adminPanel = document.getElementById('adminPanel');
    const btn = document.getElementById('btnPublicScans');

    isPublicScansPanelOpen = !isPublicScansPanelOpen;

    // Reset sidebar buttons
    document.querySelectorAll('.btn-sidebar').forEach(b => b.classList.remove('active'));

    if (isPublicScansPanelOpen) {
        panel.classList.remove('hidden');
        resultsContainer.classList.add('hidden');
        emptyState.classList.add('hidden');
        if (cveExplorer) cveExplorer.classList.add('hidden');
        if (adminPanel) adminPanel.classList.add('hidden');
        if (btn) btn.classList.add('active');
        await loadPublicScans();
    } else {
        panel.classList.add('hidden');
        if (btn) btn.classList.remove('active');

        if (window.dashboard && window.dashboard.currentScanId) {
            resultsContainer.classList.remove('hidden');
        } else {
            emptyState.classList.remove('hidden');
        }
    }
}

async function loadPublicScans() {
    const grid = document.getElementById('publicScansGrid');
    if (!grid) return;

    grid.innerHTML = '<div class=\"empty-state-small\">Loading public scans...</div>';

    try {
        const response = await fetch('/api/scans/public');
        if (handleAuthError(response)) return;

        if (response.ok) {
            const scans = await response.json();
            renderPublicScans(scans);
        } else {
            grid.innerHTML = '<div class=\"empty-state-small\" style=\"color:var(--danger)\">Failed to load</div>';
        }
    } catch (error) {
        console.error('Public scans load error:', error);
        grid.innerHTML = '<div class=\"empty-state-small\" style=\"color:var(--danger)\">Connection error</div>';
    }
}

function renderPublicScans(scans) {
    const grid = document.getElementById('publicScansGrid');

    if (!scans || scans.length === 0) {
        grid.innerHTML = '<div class="empty-state-small">No public scans available yet.</div>';
        return;
    }

    grid.innerHTML = scans.map(scan => {
        const date = new Date(scan.created_at).toLocaleDateString();
        const ownerName = scan.owner_name || 'User ' + scan.user_id;
        return '<div class="public-scan-card" onclick="viewPublicScan(\'' + scan.id + '\')">' +
            '<div class="public-scan-header">' +
            '<span class="public-scan-domain">' + scan.domain + '</span>' +
            '<span class="public-scan-owner">by ' + ownerName + '</span>' +
            '</div>' +
            '<div class="public-scan-stats">' +
            '<span class="public-scan-stat">IPs: ' + (scan.ips_count || 0) + '</span>' +
            '<span class="public-scan-stat">Subs: ' + (scan.subdomains_count || 0) + '</span>' +
            '<span class="public-scan-stat">CVEs: ' + (scan.cves_count || 0) + '</span>' +
            '</div>' +
            '<div class="public-scan-date">' + date + '</div>' +
            '</div>';
    }).join('');
}

function viewPublicScan(scanId) {
    // Close panel and load the scan
    isPublicScansPanelOpen = false;
    document.getElementById('publicScansPanel').classList.add('hidden');
    document.getElementById('btnPublicScans').classList.remove('active');

    if (window.dashboard) {
        window.dashboard.loadScan(scanId);
    }
}

window.togglePublicScans = togglePublicScans;

// ===== VIEW SWITCHING =====
function switchView(viewName) {
    // Use requestAnimationFrame to prevent UI freeze during view switch
    requestAnimationFrame(() => {
        // Hide all views
        document.querySelectorAll('.view-section').forEach(el => el.classList.add('hidden'));
        document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));

        // Deactivate all nav items
        document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

        // Show selected view
        const view = document.getElementById(`view${viewName.charAt(0).toUpperCase() + viewName.slice(1)}`);
        if (view) {
            view.classList.remove('hidden');
            view.classList.add('active');
        }

        // Activate nav item
        const navItem = document.getElementById(`nav${viewName.charAt(0).toUpperCase() + viewName.slice(1)}`);
        if (navItem) navItem.classList.add('active');

        // Initialize view specific logic (deferred to not block UI)
        setTimeout(() => {
            if (viewName === 'files') {
                if (!window.fileExplorer) {
                    window.fileExplorer = new FileExplorer();
                }
            } else if (viewName === 'admin') {
                if (!window.adminPanel) {
                    window.adminPanel = new AdminPanel();
                }
                window.adminPanel.loadUsers();
                window.adminPanel.loadStats();
            } else if (viewName === 'shodan') {
                if (!window.shodanPanel) {
                    window.shodanPanel = new ShodanPanel();
                }
                window.shodanPanel.refreshStatus();
            }
        }, 0);
    });
}
window.switchView = switchView;

// ===== FILE EXPLORER =====
class FileExplorer {
    constructor() {
        this.currentCategory = 'scans';
        this.currentPath = '';
        this.init();
    }

    init() {
        // Initial load only if view is active
    }

    updateActiveCategory(category) {
        document.querySelectorAll('.file-category').forEach(el => el.classList.remove('active'));
        // Find the matching category by data or text content
        const categories = document.querySelectorAll('.file-category');
        categories.forEach(el => {
            const text = el.textContent.toLowerCase().trim();
            if (
                (category === 'scans' && text.includes('scan result')) ||
                (category === 'reports' && text.includes('report') && !text.includes('scan')) ||
                (category === 'results' && text.includes('raw')) ||
                (category === 'wordlists' && text.includes('wordlist')) ||
                (category === 'logs' && text.includes('log')) ||
                (category === 'config' && text.includes('config'))
            ) {
                el.classList.add('active');
            }
        });
    }

    async loadFiles(category) {
        this.currentCategory = category;
        this.currentPath = '';

        this.updateActiveCategory(category);
        this.renderLoading();

        try {
            const response = await fetch(`/api/files/tree?category=${category}`);
            if (handleAuthError(response)) return;

            if (response.ok) {
                const data = await response.json();
                this.renderFileTree(data);
            } else {
                this.renderError('Failed to load files');
            }
        } catch (error) {
            console.error('File load error:', error);
            this.renderError('Connection error');
        }
    }

    async loadScanSummaries() {
        this.renderLoading();
        try {
            const response = await fetch('/api/files/scan-summaries');
            if (handleAuthError(response)) return;

            if (response.ok) {
                const data = await response.json();
                this.renderScanSummaries(data);
            } else {
                this.renderError('Failed to load scan summaries');
            }
        } catch (error) {
            console.error('Scan summaries error:', error);
            this.renderError('Connection error');
        }
    }

    async loadReportsList() {
        this.renderLoading();
        try {
            const response = await fetch('/api/files/reports-list');
            if (handleAuthError(response)) return;

            if (response.ok) {
                const data = await response.json();
                this.renderReportsList(data);
            } else {
                this.renderError('Failed to load reports');
            }
        } catch (error) {
            console.error('Reports list error:', error);
            this.renderError('Connection error');
        }
    }

    renderLoading() {
        const browser = document.getElementById('fileBrowser');
        if (browser) browser.innerHTML = '<div class="empty-state-small"><span class="spinner-small"></span> Loading...</div>';
    }

    renderError(msg) {
        const browser = document.getElementById('fileBrowser');
        if (browser) browser.innerHTML = `<div class="empty-state-small" style="color:var(--danger)">${msg}</div>`;
    }

    renderFileTree(files) {
        const browser = document.getElementById('fileBrowser');
        if (!browser) return;

        if (!files || files.length === 0) {
            browser.innerHTML = '<div class="empty-state-small">No files found.</div>';
            return;
        }

        let html = '<div class="file-list">';

        files.forEach(file => {
            const icon = file.type === 'directory' ?
                '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>' :
                this.getFileIcon(file.extension || file.name);

            const safePath = file.path.replace(/'/g, "\\'");
            const sizeStr = file.size ? this.formatSize(file.size) : '';
            const fileCount = file.file_count ? `(${file.file_count} files)` : '';

            html += `
                <div class="file-item" onclick="window.fileExplorer.previewFile('${safePath}', '${file.type}')">
                    <span class="file-icon">${icon}</span>
                    <span class="file-name">${file.name}</span>
                    <span class="file-meta">${sizeStr} ${fileCount}</span>
                </div>
            `;
        });

        html += '</div>';
        browser.innerHTML = html;
    }

    renderScanSummaries(scans) {
        const browser = document.getElementById('fileBrowser');
        if (!browser) return;

        if (!scans || scans.length === 0) {
            browser.innerHTML = '<div class="empty-state-small">No scans found. Run a scan to see results here.</div>';
            return;
        }

        let html = '<div class="scan-summaries-list">';

        scans.forEach(scan => {
            const statusIcons = [];
            if (scan.has_results) statusIcons.push('📊');
            if (scan.has_report) statusIcons.push('📄');
            if (scan.has_ai_analysis) statusIcons.push('🤖');

            const createdDate = scan.created ? new Date(scan.created).toLocaleDateString() : 'Unknown';

            html += `
                <div class="scan-summary-card" onclick="window.fileExplorer.viewScanFiles('${scan.scan_id}')">
                    <div class="scan-summary-header">
                        <span class="scan-id">${scan.domain || scan.scan_id}</span>
                        <span class="scan-status">${statusIcons.join(' ')}</span>
                    </div>
                    <div class="scan-summary-stats">
                        <span class="stat-item">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/></svg>
                            ${scan.ip_count} IPs
                        </span>
                        <span class="stat-item ${scan.cve_count > 0 ? 'has-cves' : ''}">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
                            ${scan.cve_count} CVEs
                        </span>
                        <span class="stat-item date">${createdDate}</span>
                    </div>
                    <div class="scan-files-count">${scan.files.length} files</div>
                </div>
            `;
        });

        html += '</div>';
        browser.innerHTML = html;
    }

    renderReportsList(reports) {
        const browser = document.getElementById('fileBrowser');
        if (!browser) return;

        if (!reports || reports.length === 0) {
            browser.innerHTML = '<div class="empty-state-small">No reports generated yet. Complete a scan to generate reports.</div>';
            return;
        }

        let html = '<div class="reports-list">';

        reports.forEach(report => {
            const icon = report.extension === '.pdf'
                ? '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>'
                : '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';

            const modifiedDate = report.modified ? new Date(report.modified).toLocaleString() : '';
            const sizeStr = this.formatSize(report.size);
            const typeLabel = report.type === 'scan_report' ? 'Scan Report' : 'Generated Report';

            html += `
                <div class="report-item" onclick="window.fileExplorer.openReport('${report.path}', '${report.type}')">
                    <span class="report-icon">${icon}</span>
                    <div class="report-info">
                        <span class="report-name">${report.name}</span>
                        <span class="report-meta">${typeLabel} • ${sizeStr} • ${modifiedDate}</span>
                    </div>
                    <button class="btn-icon btn-icon-small" onclick="event.stopPropagation(); window.fileExplorer.downloadReport('${report.path}')" title="Download">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    </button>
                </div>
            `;
        });

        html += '</div>';
        browser.innerHTML = html;
    }

    viewScanFiles(scanId) {
        this.currentCategory = 'results';
        this.currentPath = scanId;
        this.loadFiles('results');
    }

    openReport(path, type) {
        if (type === 'scan_report') {
            // Scan reports are in results directory
            window.open(`/results/${path}`, '_blank');
        } else {
            // Generated reports are served via API
            window.open(`/api/files/report/${path}`, '_blank');
        }
    }

    downloadReport(path) {
        const link = document.createElement('a');
        // Use the API endpoint for downloads too
        link.href = `/api/files/report/${path}`;
        link.download = path.split('/').pop();
        link.click();
    }

    getFileIcon(extOrName) {
        const ext = extOrName.startsWith('.') ? extOrName : `.${extOrName.split('.').pop()}`;

        const icons = {
            '.json': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--warning)" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
            '.html': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
            '.txt': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
            '.log': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
            '.pdf': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>'
        };

        return icons[ext] || '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>';
    }

    formatSize(bytes) {
        if (!bytes) return '';
        const units = ['B', 'KB', 'MB', 'GB'];
        let i = 0;
        while (bytes >= 1024 && i < units.length - 1) {
            bytes /= 1024;
            i++;
        }
        return `${bytes.toFixed(1)} ${units[i]}`;
    }

    async previewFile(path, type) {
        if (type === 'directory') {
            // Navigate into directory
            this.currentPath = path;
            this.loadFiles(this.currentCategory);
            return;
        }

        const preview = document.getElementById('filePreview');
        if (preview) preview.innerHTML = '<div class="empty-state-small"><span class="spinner-small"></span> Loading...</div>';

        try {
            const response = await fetch(`/api/files/content?category=${this.currentCategory}&path=${encodeURIComponent(path)}`);
            if (handleAuthError(response)) return;

            if (response.ok) {
                const data = await response.json();
                const ext = path.split('.').pop().toLowerCase();

                if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext)) {
                    preview.innerHTML = `<div class="file-preview-content"><img src="data:image/png;base64,${data.content}" style="max-width:100%"></div>`;
                } else if (ext === 'json') {
                    try {
                        const formatted = JSON.stringify(JSON.parse(data.content), null, 2);
                        preview.innerHTML = `<pre class="file-preview-content json-preview"><code>${this.escapeHtml(formatted)}</code></pre>`;
                    } catch {
                        preview.innerHTML = `<pre class="file-preview-content"><code>${this.escapeHtml(data.content)}</code></pre>`;
                    }
                } else if (ext === 'html') {
                    preview.innerHTML = `
                        <div class="html-preview-actions">
                            <button class="btn btn-sm btn-secondary" onclick="window.open('/results/${path}', '_blank')">Open in New Tab</button>
                        </div>
                        <iframe class="file-preview-iframe" srcdoc="${this.escapeHtml(data.content).replace(/"/g, '&quot;')}"></iframe>
                    `;
                } else {
                    preview.innerHTML = `<pre class="file-preview-content"><code>${this.escapeHtml(data.content)}</code></pre>`;
                }
            } else {
                preview.innerHTML = '<div class="empty-state-small" style="color:var(--danger)">Failed to load content</div>';
            }
        } catch (error) {
            console.error(error);
            if (preview) preview.innerHTML = '<div class="empty-state-small" style="color:var(--danger)">Error loading content</div>';
        }
    }

    escapeHtml(text) {
        if (!text) return '';
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
}

window.initFileExplorer = (cat) => {
    if (!window.fileExplorer) window.fileExplorer = new FileExplorer();

    if (cat === 'scans') {
        window.fileExplorer.loadScanSummaries();
    } else if (cat === 'reports') {
        window.fileExplorer.loadReportsList();
    } else {
        window.fileExplorer.loadFiles(cat || 'results');
    }
};
window.switchFileCategory = (cat) => window.initFileExplorer(cat);


// ===== ADMIN PANEL =====
class AdminPanel {
    constructor() {
        this.init();
    }

    init() {
        // Init
    }

    async loadUsers() {
        const tbody = document.querySelector('#usersTable tbody');
        if (!tbody) return;

        tbody.innerHTML = '<tr><td colspan="5" class="text-center">Loading users...</td></tr>';

        try {
            const response = await fetch('/api/admin/users');
            if (handleAuthError(response)) return;

            if (response.ok) {
                const users = await response.json();
                this.renderUsers(users);
            } else {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-danger">Failed to load users</td></tr>';
            }
        } catch (error) {
            console.error(error);
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-danger">Connection error</td></tr>';
        }
    }

    renderUsers(users) {
        const tbody = document.querySelector('#usersTable tbody');
        if (!tbody) return;

        if (!users || users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">No users found</td></tr>';
            return;
        }

        tbody.innerHTML = users.map(user => {
            const isSuperAdmin = user.is_primary_admin;
            const isAdmin = user.role === 'admin';

            // Role badge display
            let roleBadge;
            if (isSuperAdmin) {
                roleBadge = `<span class="badge badge-warning" style="background: linear-gradient(135deg, #ffc107, #ff9800);">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" style="margin-right:4px;vertical-align:middle;">
                        <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/>
                    </svg>SUPER ADMIN</span>`;
            } else if (isAdmin) {
                roleBadge = `<span class="badge badge-primary">ADMIN</span>`;
            } else {
                roleBadge = `<span class="badge badge-secondary">USER</span>`;
            }

            // Action buttons based on role hierarchy
            let actionButtons;
            if (isSuperAdmin) {
                // Super admin: completely protected, no edit/delete by anyone
                actionButtons = `<span class="text-muted" style="font-size:0.85em;color:#6c757d;" title="Super Admin cannot be modified">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px;">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                    </svg>Protected</span>`;
            } else if (isAdmin) {
                // Regular admin: only super admin can edit/delete
                actionButtons = `
                    <button class="btn-icon btn-info" onclick="window.adminPanel.editUser(${user.id})" title="Edit Admin (Super Admin Only)">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                        </svg>
                    </button>
                    <button class="btn-icon btn-danger" onclick="window.adminPanel.deleteUser(${user.id})" title="Delete Admin (Super Admin Only)">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                             <polyline points="3 6 5 6 21 6" />
                             <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                        </svg>
                    </button>
                `;
            } else {
                // Regular user: any admin can edit/delete
                actionButtons = `
                    <button class="btn-icon btn-info" onclick="window.adminPanel.editUser(${user.id})" title="Edit User">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                        </svg>
                    </button>
                    <button class="btn-icon btn-danger" onclick="window.adminPanel.deleteUser(${user.id})" title="Delete User">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                             <polyline points="3 6 5 6 21 6" />
                             <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
                        </svg>
                    </button>
                `;
            }

            return `
                <tr>
                    <td>${user.id}</td>
                    <td>${user.username}${isSuperAdmin ? ' <svg width="16" height="16" viewBox="0 0 24 24" fill="#ffc107" title="Super Admin"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>' : ''}</td>
                    <td>${roleBadge}</td>
                    <td>${new Date(user.created_at).toLocaleDateString()}</td>
                    <td>${actionButtons}</td>
                </tr>
            `;
        }).join('');
    }

    async editUser(userId) {
        try {
            const response = await fetch(`/api/admin/users/${userId}`);
            if (handleAuthError(response)) return;

            if (response.ok) {
                const user = await response.json();

                // Populate the edit modal - only set elements that exist
                const editUserId = document.getElementById('editUserId');
                const editUsername = document.getElementById('editUsername');
                const editNewPassword = document.getElementById('editNewPassword');
                const editUserRole = document.getElementById('editUserRole');

                if (editUserId) editUserId.value = user.id;
                if (editUsername) editUsername.value = user.username;
                if (editNewPassword) editNewPassword.value = '';
                if (editUserRole) editUserRole.value = user.role;

                // Show the modal
                const modal = document.getElementById('editUserModal');
                if (modal) {
                    modal.classList.add('active');
                    modal.classList.remove('hidden');
                    document.body.style.overflow = 'hidden';
                }
            } else {
                const errorData = await response.json().catch(() => ({}));
                toast.error('Error', errorData.detail || 'Failed to load user details');
            }
        } catch (error) {
            console.error('Edit user error:', error);
            toast.error('Error', 'Failed to load user details');
        }
    }

    async saveUserChanges() {
        const userId = document.getElementById('editUserId').value;
        const newPassword = document.getElementById('editNewPassword').value;
        const newRole = document.getElementById('editUserRole').value;

        // Build request body - only include fields that need updating
        const requestBody = {};

        // Only include role if it's changed/selected
        if (newRole) {
            requestBody.role = newRole;
        }

        // Only include password if it's provided
        if (newPassword && newPassword.trim().length > 0) {
            requestBody.password = newPassword.trim();
        }

        // Don't send empty request
        if (Object.keys(requestBody).length === 0) {
            toast.warning('No Changes', 'No changes to save');
            return;
        }

        try {
            const response = await fetch(`/api/admin/users/${userId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody)
            });

            if (handleAuthError(response)) return;

            if (response.ok) {
                toast.success('User Updated', 'User has been updated successfully');
                this.hideEditModal();
                this.loadUsers();
                this.loadStats();
            } else {
                // Properly parse error response
                try {
                    const errorData = await response.json();
                    const errorMsg = errorData.detail || errorData.message || 'Failed to update user';
                    toast.error('Update Failed', typeof errorMsg === 'string' ? errorMsg : JSON.stringify(errorMsg));
                } catch (parseError) {
                    toast.error('Error', `Server error: ${response.status}`);
                }
            }
        } catch (error) {
            console.error('Save user error:', error);
            toast.error('Error', 'Connection failed');
        }
    }

    hideEditModal() {
        const modal = document.getElementById('editUserModal');
        if (modal) {
            modal.classList.remove('active');
            modal.classList.add('hidden');
            document.body.style.overflow = '';
        }
    }

    async deleteUser(userId) {
        if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;

        try {
            const response = await fetch(`/api/admin/users/${userId}`, { method: 'DELETE' });
            if (handleAuthError(response)) return;

            if (response.ok) {
                toast.success('User Deleted', 'User has been removed successfully');
                this.loadUsers();
                this.loadStats();
            } else {
                // Properly parse error response
                try {
                    const errorData = await response.json();
                    const errorMsg = errorData.detail || errorData.message || 'Failed to delete user';
                    toast.error('Delete Failed', typeof errorMsg === 'string' ? errorMsg : JSON.stringify(errorMsg));
                } catch (parseError) {
                    toast.error('Error', `Server error: ${response.status}`);
                }
            }
        } catch (error) {
            console.error('Delete user error:', error);
            toast.error('Error', 'Connection failed');
        }
    }

    async loadStats() {
        try {
            const response = await fetch('/api/admin/users');
            if (handleAuthError(response)) return;

            if (response.ok) {
                const users = await response.json();
                const totalUsers = users.length;
                const adminCount = users.filter(u => u.role === 'admin').length;

                // Update stats cards
                const totalUsersEl = document.getElementById('totalUsersCount');
                const adminCountEl = document.getElementById('totalAdminsCount');

                if (totalUsersEl) {
                    totalUsersEl.textContent = totalUsers;
                    totalUsersEl.classList.add('stat-update');
                    setTimeout(() => totalUsersEl.classList.remove('stat-update'), 500);
                }
                if (adminCountEl) {
                    adminCountEl.textContent = adminCount;
                    adminCountEl.classList.add('stat-update');
                    setTimeout(() => adminCountEl.classList.remove('stat-update'), 500);
                }
            }
        } catch (error) {
            console.error('Failed to load admin stats:', error);
        }

        // Load comprehensive stats from admin endpoint
        try {
            const statsResponse = await fetch('/api/admin/stats');
            if (statsResponse.ok) {
                const stats = await statsResponse.json();

                // Update scan count
                const totalScansEl = document.getElementById('totalScansCount');
                if (totalScansEl && stats.scans) {
                    totalScansEl.textContent = stats.scans.total || 0;
                }

                // Update CVE count if element exists
                const totalCvesEl = document.getElementById('totalCvesCount');
                if (totalCvesEl && stats.scans) {
                    totalCvesEl.textContent = stats.scans.total_cves || 0;
                }

                // Update storage if elements exist
                const storageSizeEl = document.getElementById('storageSize');
                if (storageSizeEl && stats.storage) {
                    storageSizeEl.textContent = `${stats.storage.results_mb + stats.storage.reports_mb} MB`;
                }
            }
        } catch (error) {
            console.error('Failed to load admin stats:', error);
        }
    }

    filterUsers(searchTerm) {
        const rows = document.querySelectorAll('#usersTable tbody tr');
        const term = searchTerm.toLowerCase().trim();

        rows.forEach(row => {
            const username = row.cells[1]?.textContent?.toLowerCase() || '';
            const role = row.cells[2]?.textContent?.toLowerCase() || '';

            if (!term || username.includes(term) || role.includes(term)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    showCreateModal() {
        const modal = document.getElementById('createUserModal');
        if (modal) {
            modal.classList.remove('hidden');
            modal.classList.add('active');
            document.body.style.overflow = 'hidden';
            // Focus on username field
            setTimeout(() => {
                const usernameInput = document.getElementById('newUsername');
                if (usernameInput) usernameInput.focus();
            }, 100);
        }
    }

    hideCreateModal() {
        const modal = document.getElementById('createUserModal');
        if (modal) {
            modal.classList.add('hidden');
            modal.classList.remove('active');
            document.body.style.overflow = '';
            // Clear form
            const form = document.getElementById('createUserForm');
            if (form) form.reset();
        }
    }

    async createUser() {
        const username = document.getElementById('newUsername')?.value?.trim();
        const password = document.getElementById('newPassword')?.value;
        const confirmPassword = document.getElementById('confirmPassword')?.value;
        const role = document.getElementById('newUserRole')?.value || 'user';

        // Validation
        if (!username || username.length < 3) {
            toast.error('Validation Error', 'Username must be at least 3 characters');
            return;
        }

        if (!password || password.length < 6) {
            toast.error('Validation Error', 'Password must be at least 6 characters');
            return;
        }

        if (password !== confirmPassword) {
            toast.error('Validation Error', 'Passwords do not match');
            return;
        }

        const submitBtn = document.querySelector('#createUserForm button[type="submit"]');
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-small"></span> Creating...';
        }

        try {
            const response = await fetch('/api/admin/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password, role })
            });

            if (handleAuthError(response)) return;

            if (response.ok) {
                toast.success('User Created', `User "${username}" has been created successfully`);
                this.hideCreateModal();
                this.loadUsers();
                this.loadStats();
            } else {
                const error = await response.json();
                toast.error('Error', error.detail || 'Failed to create user');
            }
        } catch (error) {
            console.error('Create user error:', error);
            toast.error('Error', 'Connection failed');
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg> Create User';
            }
        }
    }
}

// Global admin panel functions
window.showCreateUserModal = () => window.adminPanel?.showCreateModal();
window.hideCreateUserModal = () => window.adminPanel?.hideCreateModal();
window.createNewUser = () => window.adminPanel?.createUser();
window.filterUsers = (term) => window.adminPanel?.filterUsers(term);
window.hideEditUserModal = () => window.adminPanel?.hideEditModal();
window.saveUserChanges = () => window.adminPanel?.saveUserChanges();

// Toggle password visibility
window.togglePasswordVisibility = (inputId) => {
    const input = document.getElementById(inputId);
    if (input) {
        input.type = input.type === 'password' ? 'text' : 'password';
    }
};

// Copy password hash to clipboard
window.copyPasswordHash = () => {
    const hash = document.getElementById('editPasswordHash')?.value;
    if (hash) {
        navigator.clipboard.writeText(hash).then(() => {
            toast.success('Copied', 'Password hash copied to clipboard');
        }).catch(() => {
            toast.error('Error', 'Failed to copy');
        });
    }
};

// ===== SHODAN PANEL =====
class ShodanPanel {
    constructor() {
        this.status = null;
        this.features = null;
        this.lastResults = null;
        this.init();
    }

    init() {
        this.refreshStatus();
    }

    async refreshStatus() {
        try {
            const response = await fetch('/api/shodan/status');
            if (handleAuthError(response)) return;

            if (response.ok) {
                this.status = await response.json();
                this.updateStatusUI();
            } else if (response.status === 400) {
                // No API key configured
                this.status = { configured: false };
                this.updateStatusUI();
            } else {
                toast.error('Error', 'Failed to fetch Shodan status');
            }
        } catch (error) {
            console.error('Shodan status error:', error);
            this.status = { configured: false, error: true };
            this.updateStatusUI();
        }
    }

    updateStatusUI() {
        const planBadge = document.getElementById('shodanPlanBadge');
        const planText = document.getElementById('shodanPlanText');
        const queryCredits = document.getElementById('shodanQueryCredits');
        const scanCredits = document.getElementById('shodanScanCredits');
        const unlockedEl = document.getElementById('shodanUnlocked');

        if (!this.status || !this.status.configured) {
            if (planBadge) planBadge.className = 'shodan-plan-badge plan-free';
            if (planText) planText.textContent = 'Not Configured';
            if (queryCredits) queryCredits.textContent = '-';
            if (scanCredits) scanCredits.textContent = '-';
            if (unlockedEl) unlockedEl.textContent = '-';
            return;
        }

        // Use the plan from the API response
        const plan = this.status.plan || 'free';
        const planDisplay = this.status.plan_display || plan.toUpperCase();

        // Update plan badge with correct class
        if (planBadge) planBadge.className = `shodan-plan-badge plan-${plan}`;
        if (planText) planText.textContent = planDisplay;

        // Update credits
        if (queryCredits) queryCredits.textContent = this.status.query_credits ?? '-';
        if (scanCredits) scanCredits.textContent = this.status.scan_credits ?? '-';
        if (unlockedEl) unlockedEl.textContent = this.status.unlocked ? 'Yes' : 'No';
    }

    formatPlanName(plan) {
        if (!plan) return 'FREE';
        return plan.toUpperCase();
    }

    async loadFeatures() {
        try {
            const response = await fetch('/api/shodan/features');
            if (response.ok) {
                this.features = await response.json();
                this.updateFeaturesUI();
            }
        } catch (error) {
            console.error('Failed to load Shodan features:', error);
        }
    }

    updateFeaturesUI() {
        const grid = document.getElementById('shodanFeaturesGrid');
        if (!grid || !this.features) return;

        grid.innerHTML = '';

        // Define feature display info
        const featureInfo = {
            host_lookup: 'Host Lookup',
            internetdb: 'InternetDB (Free)',
            search: 'Search',
            search_facets: 'Search Facets',
            search_filters: 'Search Filters',
            scan: 'On-Demand Scan',
            alerts: 'Network Alerts',
            dns: 'DNS Resolution',
            exploits: 'Exploit Search',
            monitor_network: 'Network Monitoring',
            monitor_alerts: 'Monitor Alerts'
        };

        const available = this.features.available_features || [];
        const unavailable = this.features.unavailable_features || [];

        // Render available features
        available.forEach(feature => {
            const name = featureInfo[feature] || feature;
            grid.innerHTML += `
                <div class="feature-item available">
                    <span class="feature-status available"></span>
                    <span class="feature-name">${name}</span>
                </div>
            `;
        });

        // Render unavailable features
        unavailable.forEach(feature => {
            const name = featureInfo[feature] || feature;
            grid.innerHTML += `
                <div class="feature-item">
                    <span class="feature-status unavailable"></span>
                    <span class="feature-name">${name}</span>
                </div>
            `;
        });
    }

    showConfigModal() {
        const currentKey = this.status?.account_info?.api_key_masked || '';
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.id = 'shodanConfigModal';
        modal.innerHTML = `
            <div class="modal" style="max-width: 500px;">
                <div class="modal-header">
                    <h2>Configure Shodan API</h2>
                    <button class="modal-close" onclick="window.shodanPanel.hideConfigModal()">✕</button>
                </div>
                <div class="modal-body">
                    <div class="shodan-config-form">
                        <div class="form-group">
                            <label>API Key</label>
                            <div class="api-key-input-group">
                                <input type="password" id="shodanApiKeyInput" class="form-input" 
                                       placeholder="Enter your Shodan API key">
                                <button type="button" class="btn btn-secondary" 
                                        onclick="window.shodanPanel.toggleApiKeyVisibility()">
                                    👁
                                </button>
                            </div>
                            <small class="form-hint">
                                Get your API key from <a href="https://account.shodan.io" target="_blank">account.shodan.io</a>
                            </small>
                        </div>
                        ${currentKey ? `<p class="text-muted">Current key: ${currentKey}</p>` : ''}
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="window.shodanPanel.hideConfigModal()">Cancel</button>
                    <button class="btn btn-primary" onclick="window.shodanPanel.saveApiKey()">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>
                            <polyline points="17 21 17 13 7 13 7 21"/>
                            <polyline points="7 3 7 8 15 8"/>
                        </svg>
                        Save & Verify
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }

    hideConfigModal() {
        const modal = document.getElementById('shodanConfigModal');
        if (modal) modal.remove();
    }

    toggleApiKeyVisibility() {
        const input = document.getElementById('shodanApiKeyInput');
        if (input) {
            input.type = input.type === 'password' ? 'text' : 'password';
        }
    }

    async saveApiKey() {
        const input = document.getElementById('shodanApiKeyInput');
        const apiKey = input?.value?.trim();

        if (!apiKey) {
            toast.warning('Warning', 'Please enter an API key');
            return;
        }

        try {
            const response = await fetch('/api/shodan/configure', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ api_key: apiKey })
            });

            if (handleAuthError(response)) return;

            if (response.ok) {
                const result = await response.json();
                toast.success('Success', `API key configured! Plan: ${result.plan_display}`);
                this.hideConfigModal();
                this.refreshStatus();
            } else {
                const error = await response.json();
                toast.error('Error', error.detail || 'Invalid API key');
            }
        } catch (error) {
            console.error('Save API key error:', error);
            toast.error('Error', 'Connection failed');
        }
    }

    showLoading(message) {
        const resultsContent = document.getElementById('shodanResultsContent');
        const resultsTitle = document.getElementById('shodanResultsTitle');

        if (resultsTitle) resultsTitle.textContent = 'Loading...';
        if (resultsContent) {
            resultsContent.innerHTML = `
                <div class="results-loading">
                    <div class="spinner"></div>
                    <p>${message || 'Loading...'}</p>
                </div>
            `;
        }
    }

    displayError(message) {
        const resultsContent = document.getElementById('shodanResultsContent');
        const resultsTitle = document.getElementById('shodanResultsTitle');

        if (resultsTitle) resultsTitle.textContent = 'Error';
        if (resultsContent) {
            resultsContent.innerHTML = `
                <div class="results-error">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="15" y1="9" x2="9" y2="15"></line>
                        <line x1="9" y1="9" x2="15" y2="15"></line>
                    </svg>
                    <p>${message}</p>
                </div>
            `;
        }
    }

    clearResults() {
        const resultsContent = document.getElementById('shodanResultsContent');
        const resultsTitle = document.getElementById('shodanResultsTitle');

        if (resultsTitle) resultsTitle.textContent = 'Results';
        if (resultsContent) {
            resultsContent.innerHTML = `
                <div class="results-placeholder">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1">
                        <circle cx="11" cy="11" r="8"></circle>
                        <path d="M21 21l-4.35-4.35"></path>
                    </svg>
                    <p>Enter an IP address or search query</p>
                    <p class="hint">Results will appear here</p>
                </div>
            `;
        }
        this.lastResults = null;
    }

    exportResults() {
        if (!this.lastResults) {
            toast.warning('Warning', 'No results to export');
            return;
        }

        const blob = new Blob([JSON.stringify(this.lastResults, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `shodan_results_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success('Exported', 'Results downloaded as JSON');
    }

    async lookupIP() {
        const input = document.getElementById('shodanIpInput');
        const ip = input?.value?.trim();

        if (!ip) {
            toast.warning('Warning', 'Please enter an IP address');
            return;
        }

        // Validate IP format (basic)
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip)) {
            toast.warning('Warning', 'Please enter a valid IP address');
            return;
        }

        this.showLoading('Looking up IP...');

        try {
            // Use quick endpoint which handles fallback automatically
            const response = await fetch(`/api/shodan/quick/${ip}`);

            if (handleAuthError(response)) return;

            if (response.ok) {
                const data = await response.json();
                this.displayIPResult(data);
            } else {
                const error = await response.json();
                this.displayError(error.detail || 'Failed to lookup IP');
            }
        } catch (error) {
            console.error('IP lookup error:', error);
            this.displayError('Connection failed');
        }
    }

    displayIPResult(data) {
        this.lastResults = data;
        const resultsTitle = document.getElementById('shodanResultsTitle');
        const resultsContent = document.getElementById('shodanResultsContent');

        // Show source indicator (API vs InternetDB)
        const source = data.source || 'api';
        const sourceLabel = source === 'internetdb' ? '(InternetDB - Free)' : '(Shodan API)';

        if (resultsTitle) resultsTitle.textContent = `IP Lookup ${sourceLabel}`;

        const hostnames = data.hostnames?.join(', ') || data.hostname || 'N/A';
        const ports = data.ports || [];
        const vulns = data.vulns || [];
        const tags = data.tags || [];
        const cpes = data.cpes || [];

        let portsHTML = '';
        if (ports.length > 0) {
            portsHTML = `
                <div class="ip-result-ports">
                    <h5>Open Ports (${ports.length})</h5>
                    <div class="ports-grid">
                        ${ports.map(p => `
                            <span class="port-badge">
                                <span class="port-num">${typeof p === 'object' ? p.port : p}</span>
                            </span>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        let vulnsHTML = '';
        if (vulns.length > 0) {
            vulnsHTML = `
                <div class="ip-vulns">
                    <h5>⚠️ Vulnerabilities (${vulns.length})</h5>
                    <div class="vulns-list">
                        ${vulns.slice(0, 20).map(v => `<span class="vuln-tag">${v}</span>`).join('')}
                        ${vulns.length > 20 ? `<span class="text-muted">+${vulns.length - 20} more</span>` : ''}
                    </div>
                </div>
            `;
        }

        let tagsHTML = '';
        if (tags.length > 0) {
            tagsHTML = `
                <div style="margin-top: 1rem;">
                    <h5 style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.5rem;">Tags</h5>
                    <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                        ${tags.map(t => `<span class="tag">${t}</span>`).join('')}
                    </div>
                </div>
            `;
        }

        let cpesHTML = '';
        if (cpes.length > 0) {
            cpesHTML = `
                <div style="margin-top: 1rem;">
                    <h5 style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.5rem;">CPEs</h5>
                    <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                        ${cpes.slice(0, 10).map(c => `<span class="tag">${c}</span>`).join('')}
                        ${cpes.length > 10 ? `<span class="text-muted">+${cpes.length - 10} more</span>` : ''}
                    </div>
                </div>
            `;
        }

        if (resultsContent) {
            resultsContent.innerHTML = `
                <div class="ip-result-card">
                    <div class="ip-result-header">
                        <div>
                            <h4>${data.ip || data.ip_str}</h4>
                            <div class="hostnames">${hostnames}</div>
                        </div>
                        ${data.org ? `<span class="org-badge">${data.org}</span>` : ''}
                    </div>
                    <div class="ip-result-body">
                        <div class="ip-result-meta">
                            ${data.country_name || data.country ? `
                                <div class="ip-meta-item">
                                    <label>Country</label>
                                    <span>${data.country_name || data.country}</span>
                                </div>
                            ` : ''}
                            ${data.city ? `
                                <div class="ip-meta-item">
                                    <label>City</label>
                                    <span>${data.city}</span>
                                </div>
                            ` : ''}
                            ${data.isp ? `
                                <div class="ip-meta-item">
                                    <label>ISP</label>
                                    <span>${data.isp}</span>
                                </div>
                            ` : ''}
                            ${data.asn ? `
                                <div class="ip-meta-item">
                                    <label>ASN</label>
                                    <span>${data.asn}</span>
                                </div>
                            ` : ''}
                            ${data.os ? `
                                <div class="ip-meta-item">
                                    <label>OS</label>
                                    <span>${data.os}</span>
                                </div>
                            ` : ''}
                            ${data.last_update ? `
                                <div class="ip-meta-item">
                                    <label>Last Update</label>
                                    <span>${new Date(data.last_update).toLocaleDateString()}</span>
                                </div>
                            ` : ''}
                        </div>
                        ${portsHTML}
                        ${vulnsHTML}
                        ${cpesHTML}
                        ${tagsHTML}
                    </div>
                </div>
            `;
        }
    }

    async search() {
        const input = document.getElementById('shodanSearchInput');
        const query = input?.value?.trim();

        if (!query) {
            toast.warning('Warning', 'Please enter a search query');
            return;
        }

        if (!this.status?.configured) {
            toast.error('Error', 'Please configure your Shodan API key first');
            this.showConfigModal();
            return;
        }

        this.showLoading('Searching Shodan...');

        try {
            const response = await fetch('/api/shodan/search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query, page: 1 })
            });

            if (handleAuthError(response)) return;

            if (response.ok) {
                const data = await response.json();
                this.displaySearchResults(data);
            } else {
                const error = await response.json();
                this.displayError(error.detail || 'Search failed');
            }
        } catch (error) {
            console.error('Search error:', error);
            this.displayError('Connection failed');
        }
    }

    displaySearchResults(data) {
        this.lastResults = data;
        const resultsTitle = document.getElementById('shodanResultsTitle');
        const resultsContent = document.getElementById('shodanResultsContent');

        if (resultsTitle) resultsTitle.textContent = `Search Results`;

        const total = data.total || 0;
        const matches = data.matches || [];

        let resultsHTML = `
            <div class="search-results-summary">
                <span class="total">${total.toLocaleString()}</span>
                <span class="label">total results found</span>
            </div>
        `;

        if (matches.length > 0) {
            resultsHTML += `<div class="search-results-list">`;
            matches.forEach(match => {
                resultsHTML += `
                    <div class="search-result-item" onclick="window.shodanPanel.lookupFromResult('${match.ip_str || match.ip}')">
                        <div class="ip">${match.ip_str || match.ip}</div>
                        <div class="meta">
                            ${match.port ? `Port: ${match.port}` : ''}
                            ${match.org ? ` • ${match.org}` : ''}
                            ${match.location?.country_name ? ` • ${match.location.country_name}` : ''}
                        </div>
                        ${match.product ? `<div class="meta">Product: ${match.product}</div>` : ''}
                    </div>
                `;
            });
            resultsHTML += `</div>`;
        } else {
            resultsHTML += `<p class="text-muted">No results found</p>`;
        }

        if (resultsContent) resultsContent.innerHTML = resultsHTML;
    }

    lookupFromResult(ip) {
        document.getElementById('shodanIpInput').value = ip;
        this.lookupIP();
    }

    async dnsLookup() {
        const input = document.getElementById('shodanDnsInput');
        const typeSelect = document.getElementById('shodanDnsType');
        const value = input?.value?.trim();
        const type = typeSelect?.value || 'resolve';

        if (!value) {
            toast.warning('Warning', 'Please enter a hostname or IP');
            return;
        }

        this.showLoading(`Performing ${type === 'resolve' ? 'DNS resolution' : 'reverse DNS'}...`);

        try {
            let response;
            if (type === 'resolve') {
                response = await fetch('/api/shodan/dns/resolve', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ hostnames: [value] })
                });
            } else {
                response = await fetch('/api/shodan/dns/reverse', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ips: [value] })
                });
            }

            if (handleAuthError(response)) return;

            if (response.ok) {
                const data = await response.json();
                this.displayDnsResults(data, type);
            } else {
                const error = await response.json();
                this.displayError(error.detail || 'DNS lookup failed');
            }
        } catch (error) {
            console.error('DNS lookup error:', error);
            this.displayError('Connection failed');
        }
    }

    displayDnsResults(data, type) {
        const resultsTitle = document.getElementById('shodanResultsTitle');
        const resultsContent = document.getElementById('shodanResultsContent');

        if (resultsTitle) resultsTitle.textContent = type === 'resolve' ? 'DNS Resolution' : 'Reverse DNS';

        let resultsHTML = '<div class="dns-results">';

        if (typeof data === 'object') {
            Object.entries(data).forEach(([key, value]) => {
                resultsHTML += `
                    <div class="dns-result-item">
                        <span class="hostname">${key}</span>
                        <span class="ip">${value || 'N/A'}</span>
                    </div>
                `;
            });
        }

        resultsHTML += '</div>';
        if (resultsContent) resultsContent.innerHTML = resultsHTML;
    }

    async searchExploits() {
        const input = document.getElementById('shodanExploitInput');
        const query = input?.value?.trim();

        if (!query) {
            toast.warning('Warning', 'Please enter a search term');
            return;
        }

        this.showLoading('Searching exploits...');

        try {
            const response = await fetch('/api/shodan/exploits/search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query })
            });

            if (handleAuthError(response)) return;

            if (response.ok) {
                const data = await response.json();
                this.displayExploitResults(data);
            } else {
                const error = await response.json();
                this.displayError(error.detail || 'Exploit search failed');
            }
        } catch (error) {
            console.error('Exploit search error:', error);
            this.displayError('Connection failed');
        }
    }

    displayExploitResults(data) {
        this.lastResults = data;
        const resultsTitle = document.getElementById('shodanResultsTitle');
        const resultsContent = document.getElementById('shodanResultsContent');

        if (resultsTitle) resultsTitle.textContent = `Exploit Search Results`;

        const total = data.total || 0;
        const matches = data.matches || [];

        let resultsHTML = `
            <div class="search-results-summary">
                <span class="total">${total.toLocaleString()}</span>
                <span class="label">exploits found</span>
            </div>
        `;

        if (matches.length > 0) {
            resultsHTML += `<div class="exploit-results-list">`;
            matches.forEach(exploit => {
                const cves = exploit.cve || [];
                resultsHTML += `
                    <div class="exploit-result-item">
                        <div class="title">${exploit.description || exploit.title || 'Unknown Exploit'}</div>
                        <div>
                            ${cves.map(cve => `<span class="cve">${cve}</span>`).join('')}
                        </div>
                        <div class="meta">
                            ${exploit.source ? `Source: ${exploit.source}` : ''}
                            ${exploit.type ? ` • Type: ${exploit.type}` : ''}
                            ${exploit.date ? ` • ${exploit.date}` : ''}
                        </div>
                    </div>
                `;
            });
            resultsHTML += `</div>`;
        } else {
            resultsHTML += `<p class="text-muted">No exploits found</p>`;
        }

        if (resultsContent) resultsContent.innerHTML = resultsHTML;
    }

    async getMyIP() {
        this.showLoading('Getting your IP...');

        try {
            const response = await fetch('/api/shodan/myip');
            if (response.ok) {
                const data = await response.json();
                // Extract IP string from response object
                const ip = typeof data === 'object' ? data.ip : data;

                if (!ip) {
                    this.displayError('Could not retrieve IP address');
                    return;
                }

                const resultsTitle = document.getElementById('shodanResultsTitle');
                const resultsContent = document.getElementById('shodanResultsContent');

                if (resultsTitle) resultsTitle.textContent = 'Your IP Address';
                if (resultsContent) {
                    resultsContent.innerHTML = `
                        <div class="ip-result-card">
                            <div class="ip-result-header">
                                <div>
                                    <h4>${ip}</h4>
                                    <div class="hostnames">Your public IP address</div>
                                </div>
                                <button class="btn btn-sm btn-primary" onclick="window.shodanPanel.lookupFromResult('${ip}')">
                                    🔍 Lookup Details
                                </button>
                            </div>
                        </div>
                    `;
                }
            } else {
                this.displayError('Failed to get IP');
            }
        } catch (error) {
            console.error('Get my IP error:', error);
            this.displayError('Connection failed');
        }
    }

    showScanModal() {
        toast.info('Scan', 'On-demand scanning requires a paid Shodan plan with scan credits');
    }

    showFilters() {
        const filters = {
            'General': ['port', 'hostname', 'ip', 'net', 'org', 'isp', 'asn', 'os', 'product', 'version'],
            'Location': ['country', 'city', 'state', 'postal', 'geo'],
            'HTTP': ['http.title', 'http.status', 'http.html', 'http.component', 'http.favicon.hash'],
            'SSL': ['ssl', 'ssl.cert.subject.cn', 'ssl.cert.issuer.cn', 'ssl.cert.expired', 'has_ssl'],
            'Vulnerability': ['vuln', 'cve', 'has_vuln'],
            'Cloud': ['cloud.provider', 'cloud.service', 'cloud.region'],
            'Tags': ['tag', 'has_screenshot', 'screenshot.label']
        };

        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.id = 'shodanFiltersModal';

        let filtersHTML = '<div class="filters-categories">';
        Object.entries(filters).forEach(([category, filterList]) => {
            filtersHTML += `
                <div class="filter-category">
                    <h4>${category}</h4>
                    <div class="filter-list">
                        ${filterList.map(f => `<span class="filter-tag" onclick="window.shodanPanel.insertFilter('${f}')">${f}</span>`).join('')}
                    </div>
                </div>
            `;
        });
        filtersHTML += '</div>';

        modal.innerHTML = `
            <div class="modal" style="max-width: 600px;">
                <div class="modal-header">
                    <h2>Shodan Search Filters</h2>
                    <button class="modal-close" onclick="document.getElementById('shodanFiltersModal').remove()">✕</button>
                </div>
                <div class="modal-body">
                    ${filtersHTML}
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="document.getElementById('shodanFiltersModal').remove()">Close</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
    }

    insertFilter(filter) {
        const input = document.getElementById('shodanSearchInput');
        const currentValue = input.value;
        input.value = currentValue ? `${currentValue} ${filter}:` : `${filter}:`;
        input.focus();
        document.getElementById('shodanFiltersModal')?.remove();
    }

    showScanModal() {
        if (!this.status?.configured) {
            toast.error('Error', 'Please configure your Shodan API key first');
            this.showConfigModal();
            return;
        }

        const scanCredits = this.status?.account_info?.scan_credits || 0;

        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.id = 'shodanScanModal';
        modal.innerHTML = `
            <div class="modal" style="max-width: 500px;">
                <div class="modal-header">
                    <h2>Request On-Demand Scan</h2>
                    <button class="modal-close" onclick="document.getElementById('shodanScanModal').remove()">✕</button>
                </div>
                <div class="modal-body">
                    <p class="text-muted" style="margin-bottom: 1rem;">
                        Request Shodan to scan specific IPs. This uses your scan credits.
                    </p>
                    <p style="margin-bottom: 1rem;">
                        <strong>Available scan credits:</strong> <span style="color: var(--accent-cyan);">${scanCredits}</span>
                    </p>
                    <div class="form-group">
                        <label>IP Addresses (comma-separated)</label>
                        <textarea id="shodanScanIps" class="form-input" rows="3" 
                                  placeholder="192.168.1.1, 10.0.0.1"></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" onclick="document.getElementById('shodanScanModal').remove()">Cancel</button>
                    <button class="btn btn-primary" onclick="window.shodanPanel.submitScan()" ${scanCredits === 0 ? 'disabled' : ''}>
                        Request Scan
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }

    async submitScan() {
        const textarea = document.getElementById('shodanScanIps');
        const ipsText = textarea?.value?.trim();

        if (!ipsText) {
            toast.warning('Warning', 'Please enter at least one IP address');
            return;
        }

        const ips = ipsText.split(',').map(ip => ip.trim()).filter(ip => ip);

        try {
            const response = await fetch('/api/shodan/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ips })
            });

            if (handleAuthError(response)) return;

            if (response.ok) {
                const result = await response.json();
                toast.success('Success', `Scan submitted! ID: ${result.id}`);
                document.getElementById('shodanScanModal')?.remove();
                this.refreshStatus(); // Refresh to update credits
            } else {
                const error = await response.json();
                toast.error('Error', error.detail || 'Failed to submit scan');
            }
        } catch (error) {
            console.error('Scan submit error:', error);
            toast.error('Error', 'Connection failed');
        }
    }
}
