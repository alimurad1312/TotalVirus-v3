document.addEventListener('DOMContentLoaded', () => {
    const tabMeta = {
        FILE: {
            btnText: 'Analyze File Now'
        },
        URL: {
            label: 'Enter URL to inspect',
            placeholder: 'https://example.com/suspicious-payload',
            hint: 'Scans URL against phishing databases, malicious redirects, and VirusTotal engines.',
            btnText: 'Scan URL'
        },
        SEARCH: {
            label: 'Search Threat Intelligence Database',
            placeholder: 'Enter keyword, CVE, malware family, or indicator...',
            hint: 'Queries global threat telemetry for matching indicators and signatures.',
            btnText: 'Search Intelligence'
        },
        IP: {
            label: 'Enter IPv4 or IPv6 Address',
            placeholder: 'e.g. 185.220.101.4',
            hint: 'Checks ASN reputation, C2 server blacklists, and passive DNS telemetry.',
            btnText: 'Analyze IP Address'
        },
        DOMAIN: {
            label: 'Enter Domain Name',
            placeholder: 'e.g. suspicious-login-portal.xyz',
            hint: 'Inspects domain age, DNS records, WHOIS telemetry, and vendor flags.',
            btnText: 'Analyze Domain'
        },
        HASH: {
            label: 'Enter MD5, SHA-1, or SHA-256 File Hash',
            placeholder: 'e.g. 44d88612fea8a8f36de82e1278abb02f',
            hint: 'Looks up cryptographic file digest directly without uploading the binary.',
            btnText: 'Lookup Hash'
        }
    };

    const tabButtons = document.querySelectorAll('.tab-btn');
    const scanTypeInput = document.getElementById('scan-type-input');
    const filePanel = document.getElementById('panel-FILE');
    const indicatorPanel = document.getElementById('panel-INDICATOR');
    const fileInput = document.getElementById('file-input');
    const indicatorInput = document.getElementById('indicator-input');
    const iocLabel = document.getElementById('ioc-label');
    const iocHint = document.getElementById('ioc-hint');
    const submitBtnText = document.getElementById('submit-btn-text');

    function activateTab(tabName) {
        tabButtons.forEach(b => {
            b.classList.toggle('active', b.getAttribute('data-tab') === tabName);
        });
        if (scanTypeInput) scanTypeInput.value = tabName;

        if (tabName === 'FILE') {
            if (filePanel) filePanel.classList.remove('hidden');
            if (indicatorPanel) indicatorPanel.classList.add('hidden');
            if (indicatorInput) indicatorInput.required = false;
        } else {
            if (filePanel) filePanel.classList.add('hidden');
            if (indicatorPanel) indicatorPanel.classList.remove('hidden');
            if (indicatorInput) {
                indicatorInput.required = true;
                indicatorInput.placeholder = tabMeta[tabName].placeholder;
                indicatorInput.focus();
            }
            if (iocLabel) iocLabel.textContent = tabMeta[tabName].label;
            if (iocHint) iocHint.textContent = tabMeta[tabName].hint;
        }
        if (submitBtnText && tabMeta[tabName]) {
            submitBtnText.textContent = tabMeta[tabName].btnText;
        }
    }

    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            activateTab(btn.getAttribute('data-tab'));
        });
    });

    if (scanTypeInput && scanTypeInput.value) {
        activateTab(scanTypeInput.value);
    }

    // Drag & Drop File Uploader
    const dropzone = document.getElementById('dropzone');
    const promptBox = document.getElementById('dropzone-prompt');
    const previewBox = document.getElementById('file-preview');
    const filenameEl = document.getElementById('selected-filename');
    const filesizeEl = document.getElementById('selected-filesize');
    const clearBtn = document.getElementById('clear-file');
    const scanForm = document.getElementById('unified-scan-form');
    const submitBtn = document.getElementById('submit-scan');

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    }

    function showFilePreview(file) {
        if (!file) return;
        filenameEl.textContent = file.name;
        filesizeEl.textContent = formatBytes(file.size);
        promptBox.classList.add('hidden');
        previewBox.classList.remove('hidden');
    }

    if (dropzone && fileInput) {
        dropzone.addEventListener('click', (e) => {
            if (e.target.closest('#clear-file')) return;
            fileInput.click();
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) showFilePreview(fileInput.files[0]);
        });

        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.classList.add('dragover');
        });

        dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));

        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                showFilePreview(e.dataTransfer.files[0]);
            }
        });

        if (clearBtn) {
            clearBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                fileInput.value = '';
                previewBox.classList.add('hidden');
                promptBox.classList.remove('hidden');
            });
        }
    }

    if (scanForm && submitBtn) {
        scanForm.addEventListener('submit', () => {
            submitBtn.disabled = true;
            submitBtn.innerHTML = 'Querying Threat Intelligence Engines...';
        });
    }

    // Copy SHA-256 Hash to Clipboard
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const hash = btn.getAttribute('data-hash');
            navigator.clipboard.writeText(hash).then(() => {
                const originalHTML = btn.innerHTML;
                btn.innerHTML = '<span style="color:#10b981;font-size:0.75rem;font-weight:600;">Copied!</span>';
                setTimeout(() => {
                    btn.innerHTML = originalHTML;
                    if (window.lucide) lucide.createIcons();
                }, 1500);
            });
        });
    });

    // Live Search Filter
    const searchInput = document.getElementById('history-search');
    const historyTable = document.getElementById('history-table');
    if (searchInput && historyTable) {
        searchInput.addEventListener('input', () => {
            const query = searchInput.value.toLowerCase();
            historyTable.querySelectorAll('tbody tr').forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(query) ? '' : 'none';
            });
        });
    }

    // Auto-dismiss Toast Alerts
    setTimeout(() => {
        document.querySelectorAll('.toast').forEach(toast => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.4s ease';
            setTimeout(() => toast.remove(), 400);
        });
    }, 4000);
});

function togglePassword(inputId, btn) {
    const input = document.getElementById(inputId);
    if (input.type === 'password') {
        input.type = 'text';
        btn.innerHTML = '<i data-lucide="eye-off"></i>';
    } else {
        input.type = 'password';
        btn.innerHTML = '<i data-lucide="eye"></i>';
    }
    if (window.lucide) lucide.createIcons();
}
