/**
 * CryptAudio Web — Master Application Controller (Phases 10, 10.1 & M6)
 *
 * Full Frontend-Backend API Integration:
 * - Real API communication via CryptAudioAPI (api.js)
 * - Live backend connection health monitoring
 * - Multi-algorithm steganography: LSB, DWT-DCT-QIM, Echo Hiding
 * - Reactive backend-driven capacity estimation (POST /api/capacity)
 * - Real AES-256-GCM embedding with WAV blob download
 * - Real message extraction and decryption (Auto-detection & Explicit modes)
 * - Safe DOM text insertion (never innerHTML for decrypted plaintext)
 * - Real audio header inspection and capacity evaluation
 * - Real numerical signal distortion analysis (MSE, SNR, PSNR, Pearson r)
 * - Safe error handling, zero memory leakage, and credentials protection
 */

(function () {
  'use strict';

  // --------------------------------------------------------------------------
  // Application State
  // --------------------------------------------------------------------------
  const state = {
    embedFile: null,
    embedCarrierSamples: 0,
    embedCarrierRawBytes: 0,
    embedCarrierDuration: 0,
    selectedEmbedAlgorithm: 'lsb',
    embedDelta: 32.0,
    embedAlpha: 0.08,
    embedCanFit: false,
    capacityStatus: 'none', // 'none' | 'pending' | 'ready' | 'unavailable'
    lastCapacityData: null,
    capacityFingerprint: null,
    capacityRequestId: 0,
    inspectionRequestId: 0,
    capacityAbortController: null,
    capacityDebounceTimer: null,
    stegoDownloadUrl: null,
    stegoDownloadFilename: 'stego.wav',

    extractFile: null,
    selectedExtractAlgorithm: 'auto',
    extractDelta: 32.0,
    extractAlpha: 0.08,

    inspectFile: null,
    analyzeOrigFile: null,
    analyzeStegoFile: null,
  };

  // --------------------------------------------------------------------------
  // 1. Toast Notification System
  // --------------------------------------------------------------------------
  window.showToast = function (message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let iconSvg = '';
    if (type === 'success') {
      iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>';
    } else if (type === 'error') {
      iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>';
    } else {
      iconSvg = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    }

    const iconSpan = document.createElement('span');
    iconSpan.innerHTML = iconSvg;
    const textSpan = document.createElement('span');
    textSpan.textContent = String(message ?? '');
    toast.appendChild(iconSpan);
    toast.appendChild(textSpan);
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(50px)';
      setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 250);
    }, 3800);
  };

  function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/[&<>'"]/g, tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag));
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    if (!bytes || isNaN(bytes)) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KiB', 'MiB', 'GiB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // --------------------------------------------------------------------------
  // 2. Navigation & Hash Routing
  // --------------------------------------------------------------------------
  function navigateTo(viewId) {
    const rawTarget = viewId.replace('#', '');
    const parts = rawTarget.split('?');
    const targetId = parts[0];
    const query = new URLSearchParams(parts[1] || '');

    const views = document.querySelectorAll('.view-section');
    const links = document.querySelectorAll('.nav-link');

    let matched = false;
    views.forEach(view => {
      if (view.id === `view-${targetId}`) {
        view.classList.add('active');
        matched = true;
      } else {
        view.classList.remove('active');
      }
    });

    if (!matched && views.length > 0) {
      document.getElementById('view-dashboard')?.classList.add('active');
    }

    links.forEach(link => {
      const href = link.getAttribute('href');
      if (href === `#${targetId}` || (!matched && href === '#dashboard')) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    // Support optional query params for algorithm deep-linking
    const algoParam = query.get('algo');
    if (algoParam) {
      if (targetId === 'embed') {
        const card = document.querySelector(`#form-embed .algo-card[data-algo="${algoParam}"]`);
        if (card) card.click();
      } else if (targetId === 'extract') {
        const select = document.getElementById('extract-algorithm-select');
        if (select) {
          select.value = algoParam;
          select.dispatchEvent(new Event('change'));
        }
      }
    }

    closeMobileSidebar();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function setupNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', function (e) {
        e.preventDefault();
        const href = this.getAttribute('href');
        if (href && href.startsWith('#')) {
          window.location.hash = href;
        }
      });
    });

    document.querySelectorAll('[data-target-view], [data-nav-target]').forEach(btn => {
      btn.addEventListener('click', function (e) {
        e.preventDefault();
        const target = this.getAttribute('data-target-view') || this.getAttribute('data-nav-target');
        if (target) window.location.hash = target;
      });
    });

    const initialHash = window.location.hash || '#dashboard';
    navigateTo(initialHash);

    window.addEventListener('hashchange', function () {
      navigateTo(window.location.hash || '#dashboard');
    });
  }

  // --------------------------------------------------------------------------
  // 3. Mobile Sidebar Navigation
  // --------------------------------------------------------------------------
  function openMobileSidebar() {
    const sidebar = document.getElementById('app-sidebar');
    const backdrop = document.getElementById('sidebar-backdrop');
    if (sidebar) sidebar.classList.add('open');
    if (backdrop) backdrop.classList.add('open');
  }

  function closeMobileSidebar() {
    const sidebar = document.getElementById('app-sidebar');
    const backdrop = document.getElementById('sidebar-backdrop');
    if (sidebar) sidebar.classList.remove('open');
    if (backdrop) backdrop.classList.remove('open');
  }

  function setupMobileSidebar() {
    const toggleBtn = document.getElementById('btn-mobile-nav');
    const backdrop = document.getElementById('sidebar-backdrop');

    if (toggleBtn) {
      toggleBtn.addEventListener('click', function () {
        const sidebar = document.getElementById('app-sidebar');
        if (sidebar && sidebar.classList.contains('open')) {
          closeMobileSidebar();
        } else {
          openMobileSidebar();
        }
      });
    }

    if (backdrop) {
      backdrop.addEventListener('click', closeMobileSidebar);
    }
  }

  // --------------------------------------------------------------------------
  // 4. Backend Health Monitoring
  // --------------------------------------------------------------------------
  async function refreshBackendStatus() {
    const statusPill = document.getElementById('backend-status-pill');
    const statusDot = document.getElementById('backend-status-dot');
    const statusText = document.getElementById('backend-status-text');
    const dashDot = document.getElementById('dash-backend-dot');
    const dashText = document.getElementById('dash-backend-text');

    if (statusDot) statusDot.className = 'status-dot checking';
    if (statusText) statusText.textContent = 'Backend: Checking...';
    if (dashDot) dashDot.className = 'status-dot checking';
    if (dashText) dashText.textContent = 'Checking...';

    try {
      const data = await window.CryptAudioAPI.checkHealth();
      if (data.status === 'healthy') {
        if (statusDot) statusDot.className = 'status-dot';
        if (statusText) statusText.textContent = `Backend: Connected (v${data.version})`;
        if (statusPill) statusPill.title = `${data.application} v${data.version} operational. Click to refresh.`;
        if (dashDot) dashDot.className = 'status-dot';
        if (dashText) dashText.textContent = `Connected (v${data.version})`;
      } else {
        throw new Error('Unhealthy status reported');
      }
    } catch (err) {
      if (statusDot) statusDot.className = 'status-dot disconnected';
      if (statusText) statusText.textContent = 'Backend: Disconnected (Retry)';
      if (statusPill) statusPill.title = 'Cannot reach backend server. Click to retry.';
      if (dashDot) dashDot.className = 'status-dot disconnected';
      if (dashText) dashText.textContent = 'Disconnected';
    }
  }

  function setupHealthMonitor() {
    const statusPill = document.getElementById('backend-status-pill');
    if (statusPill) {
      statusPill.addEventListener('click', function () {
        refreshBackendStatus();
        window.showToast('Checking backend connection status...', 'info');
      });
    }
    // Initial check
    refreshBackendStatus();
  }

  // --------------------------------------------------------------------------
  // 5. Password Visibility Toggles
  // --------------------------------------------------------------------------
  function setupPasswordToggles() {
    document.querySelectorAll('.btn-toggle-password').forEach(btn => {
      btn.addEventListener('click', function () {
        const targetId = this.getAttribute('data-target');
        const input = document.getElementById(targetId);
        if (!input) return;

        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';

        const eyeIcon = this.querySelector('.icon-eye');
        const eyeOffIcon = this.querySelector('.icon-eye-off');
        if (eyeIcon && eyeOffIcon) {
          eyeIcon.style.display = isPassword ? 'none' : 'block';
          eyeOffIcon.style.display = isPassword ? 'block' : 'none';
        }
        this.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
      });
    });
  }

  // --------------------------------------------------------------------------
  // 6. Message Counter & Accurate Capacity Display (Phase 10.1 & M6)
  // --------------------------------------------------------------------------
  function setupMessageCounter() {
    const textarea = document.getElementById('embed-message-input');
    const charCounter = document.getElementById('embed-char-counter');
    const byteCounter = document.getElementById('embed-byte-counter');

    if (!textarea) return;

    textarea.addEventListener('input', function () {
      const text = this.value;
      const charCount = text.length;
      const byteCount = new TextEncoder().encode(text).length;

      if (charCounter) charCounter.textContent = `${charCount} char${charCount === 1 ? '' : 's'}`;
      if (byteCounter) byteCounter.textContent = `${byteCount} byte${byteCount === 1 ? '' : 's'}`;

      updateCapacityDisplay();
      triggerCapacityCheck();
    });
  }

  function renderAuthoritativeCapacity(data) {
    const textarea = document.getElementById('embed-message-input');
    const message = textarea ? textarea.value : '';
    const msgChars = message.length;

    const elMsgSize = document.getElementById('embed-cap-msg-size');
    const elCryptoSize = document.getElementById('embed-cap-crypto-size');
    const elFramedSize = document.getElementById('embed-cap-framed-size');
    const elReqSamples = document.getElementById('embed-cap-req-samples');
    const elAvailSamples = document.getElementById('embed-cap-avail-samples');
    const elMaxPlaintext = document.getElementById('embed-cap-max-plaintext');
    const fill = document.getElementById('embed-capacity-fill');
    const percentLabel = document.getElementById('embed-capacity-percent');

    if (elMsgSize) {
      elMsgSize.textContent = `${data.message_utf8_bytes} B (${msgChars} char${msgChars === 1 ? '' : 's'})`;
    }
    if (elCryptoSize) {
      elCryptoSize.textContent = `${data.estimated_crypto_bytes} B`;
    }
    if (elFramedSize) {
      elFramedSize.textContent = `${data.framed_payload_bytes} B`;
    }
    if (elReqSamples) {
      elReqSamples.textContent = `${data.required_bits.toLocaleString()} bits (${Math.ceil(data.required_bits / 8).toLocaleString()} B)`;
    }
    if (elAvailSamples) {
      elAvailSamples.textContent = `${data.available_bits.toLocaleString()} bits (${data.bits_per_sample} b/sample)`;
    }
    if (elMaxPlaintext) {
      const overheadBytes = data.framed_payload_bytes - data.message_utf8_bytes;
      const maxPlainBytes = Math.max(0, Math.floor(data.available_bits / 8) - overheadBytes);
      elMaxPlaintext.textContent = `${maxPlainBytes.toLocaleString()} B (${(maxPlainBytes / 1024).toFixed(2)} KiB)`;
    }

    const precision = data.utilization_percent < 0.01 && data.utilization_percent > 0 ? 4 : 2;
    if (percentLabel) {
      const fitStatus = data.can_fit ? 'Within capacity' : 'EXCEEDED';
      percentLabel.textContent = `${data.utilization_percent.toFixed(precision)}% utilized (${fitStatus})`;
    }

    if (fill) {
      const displayWidth = Math.min(100, Math.max(1, data.utilization_percent));
      fill.style.width = `${displayWidth}%`;
      fill.classList.remove('safe', 'warning', 'danger');
      if (!data.can_fit || data.utilization_percent > 100) {
        fill.classList.add('danger');
      } else if (data.utilization_percent > 85) {
        fill.classList.add('warning');
      } else {
        fill.classList.add('safe');
      }
    }
  }

  function updateCapacityDisplay() {
    const textarea = document.getElementById('embed-message-input');
    const message = textarea ? textarea.value : '';
    const msgChars = message.length;
    const msgBytes = new TextEncoder().encode(message).length;

    // 1. Authoritative message UTF-8 byte counting
    const elMsgSize = document.getElementById('embed-cap-msg-size');
    if (elMsgSize) {
      elMsgSize.textContent = `${msgBytes} B (${msgChars} char${msgChars === 1 ? '' : 's'})`;
    }

    // 2. Authoritative capacity display:
    // If a valid backend capacity evaluation response exists for the current file, message,
    // algorithm, and parameters, render it directly.
    if (state.lastCapacityData) {
      renderAuthoritativeCapacity(state.lastCapacityData);
      return;
    }

    // 3. Explicit pending/unavailable state:
    // Do NOT calculate or display fabricated legacy CSLB / algorithm-independent overheads
    // (e.g. 13-byte header, 49-byte crypto overhead, 62-byte total, or 1 bit/sample).
    const elCryptoSize = document.getElementById('embed-cap-crypto-size');
    const elFramedSize = document.getElementById('embed-cap-framed-size');
    const elReqSamples = document.getElementById('embed-cap-req-samples');
    const elAvailSamples = document.getElementById('embed-cap-avail-samples');
    const elMaxPlaintext = document.getElementById('embed-cap-max-plaintext');
    const fill = document.getElementById('embed-capacity-fill');
    const percentLabel = document.getElementById('embed-capacity-percent');

    if (elCryptoSize) elCryptoSize.textContent = '—';
    if (elFramedSize) elFramedSize.textContent = '—';
    if (elReqSamples) elReqSamples.textContent = '—';
    if (elMaxPlaintext) elMaxPlaintext.textContent = '—';

    if (elAvailSamples) {
      if (state.capacityStatus === 'unavailable') {
        elAvailSamples.textContent = 'Capacity unavailable (Inspection failed)';
      } else if (state.embedCarrierSamples > 0) {
        elAvailSamples.textContent = `${state.embedCarrierSamples.toLocaleString()} samples (${state.embedCarrierDuration.toFixed(2)} s) — Pending evaluation`;
      } else if (state.embedFile) {
        elAvailSamples.textContent = 'Inspecting carrier...';
      } else {
        elAvailSamples.textContent = 'Select carrier WAV';
      }
    }

    if (percentLabel) {
      if (!state.embedFile) {
        percentLabel.textContent = '0.00% utilized (Carrier not selected)';
      } else if (state.capacityStatus === 'unavailable') {
        percentLabel.textContent = 'Capacity unavailable (Inspection failed)';
      } else if (!message.trim()) {
        percentLabel.textContent = '0.00% utilized (Enter secret message)';
      } else {
        percentLabel.textContent = 'Pending capacity evaluation...';
      }
    }

    if (fill) {
      fill.style.width = '0%';
      fill.classList.remove('safe', 'warning', 'danger');
    }
  }

  // --------------------------------------------------------------------------
  // 7. Multi-Algorithm Selection & Parameter Controls (Phase M6)
  // --------------------------------------------------------------------------
  function setupAlgorithmSelection() {
    const algoCards = document.querySelectorAll('#form-embed .algo-card');
    const hiddenInput = document.getElementById('embed-algorithm-input');
    const selectedBadge = document.getElementById('embed-selected-algo-badge');
    const capAlgoBadge = document.getElementById('embed-cap-algo-badge');
    const capTitle = document.getElementById('embed-capacity-title');
    const paramsPanel = document.getElementById('embed-params-panel');
    const dwtParams = document.getElementById('embed-params-dwt');
    const echoParams = document.getElementById('embed-params-echo');
    const deltaSelect = document.getElementById('embed-delta-input');
    const alphaInput = document.getElementById('embed-alpha-input');

    function applySelectedAlgorithm(algoId) {
      state.selectedEmbedAlgorithm = algoId;
      if (hiddenInput) hiddenInput.value = algoId;

      algoCards.forEach(c => {
        const isMatch = c.getAttribute('data-algo') === algoId;
        c.classList.toggle('active', isMatch);
        c.setAttribute('aria-checked', isMatch ? 'true' : 'false');
      });

      // Update badges & titles
      const algoLabels = {
        lsb: 'LSB Active',
        dwt_dct_qim: 'DWT-DCT-QIM Active',
        echo: 'Echo Hiding Active'
      };
      const capModeLabels = {
        lsb: 'LSB Mode',
        dwt_dct_qim: 'DWT-DCT-QIM Mode',
        echo: 'Echo Hiding Mode'
      };
      const titleLabels = {
        lsb: 'LSB Capacity & Framing Calculation',
        dwt_dct_qim: 'DWT-DCT-QIM Capacity & Framing Calculation',
        echo: 'Echo Hiding Capacity & Framing Calculation'
      };

      if (selectedBadge) selectedBadge.textContent = algoLabels[algoId] || `${algoId.toUpperCase()} Active`;
      if (capAlgoBadge) capAlgoBadge.textContent = capModeLabels[algoId] || `${algoId.toUpperCase()} Mode`;
      if (capTitle) capTitle.textContent = titleLabels[algoId] || 'Capacity & Framing Calculation';

      // Parameter visibility: Hide DWT and Echo controls when LSB selected
      if (paramsPanel) {
        if (algoId === 'dwt_dct_qim') {
          paramsPanel.style.display = 'block';
          if (dwtParams) dwtParams.style.display = 'block';
          if (echoParams) echoParams.style.display = 'none';
        } else if (algoId === 'echo') {
          paramsPanel.style.display = 'block';
          if (dwtParams) dwtParams.style.display = 'none';
          if (echoParams) echoParams.style.display = 'block';
        } else {
          paramsPanel.style.display = 'none';
          if (dwtParams) dwtParams.style.display = 'none';
          if (echoParams) echoParams.style.display = 'none';
        }
      }

      // Reactive capacity evaluation
      triggerCapacityCheck();
    }

    algoCards.forEach(card => {
      card.addEventListener('click', function () {
        const algo = this.getAttribute('data-algo');
        if (algo) applySelectedAlgorithm(algo);
      });

      card.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          const algo = this.getAttribute('data-algo');
          if (algo) applySelectedAlgorithm(algo);
        }
      });
    });

    if (deltaSelect) {
      deltaSelect.addEventListener('change', function () {
        state.embedDelta = parseFloat(this.value);
        triggerCapacityCheck();
      });
    }

    if (alphaInput) {
      alphaInput.addEventListener('input', function () {
        const val = parseFloat(this.value);
        if (!isNaN(val)) {
          state.embedAlpha = val;
          triggerCapacityCheck();
        }
      });
    }
  }

  function setupExtractAlgorithmSelection() {
    const algoSelect = document.getElementById('extract-algorithm-select');
    const paramsPanel = document.getElementById('extract-params-panel');
    const dwtParams = document.getElementById('extract-params-dwt');
    const echoParams = document.getElementById('extract-params-echo');
    const deltaSelect = document.getElementById('extract-delta-input');
    const alphaInput = document.getElementById('extract-alpha-input');

    if (!algoSelect) return;

    algoSelect.addEventListener('change', function () {
      const selected = this.value;
      state.selectedExtractAlgorithm = selected;

      if (paramsPanel) {
        if (selected === 'dwt_dct_qim') {
          paramsPanel.style.display = 'block';
          if (dwtParams) dwtParams.style.display = 'block';
          if (echoParams) echoParams.style.display = 'none';
        } else if (selected === 'echo') {
          paramsPanel.style.display = 'block';
          if (dwtParams) dwtParams.style.display = 'none';
          if (echoParams) echoParams.style.display = 'block';
        } else {
          // Automatic or LSB: hide parameter controls
          paramsPanel.style.display = 'none';
          if (dwtParams) dwtParams.style.display = 'none';
          if (echoParams) echoParams.style.display = 'none';
        }
      }
    });

    if (deltaSelect) {
      deltaSelect.addEventListener('change', function () {
        state.extractDelta = parseFloat(this.value);
      });
    }

    if (alphaInput) {
      alphaInput.addEventListener('input', function () {
        const val = parseFloat(this.value);
        if (!isNaN(val)) {
          state.extractAlpha = val;
        }
      });
    }
  }

  // --------------------------------------------------------------------------
  // 8. Reactive Backend Capacity Evaluation (POST /api/capacity) & State Fingerprinting
  // --------------------------------------------------------------------------
  function computeEmbedInputFingerprint() {
    const file = state.embedFile;
    const fileSig = file ? `${file.name}:${file.size}:${file.lastModified || 0}` : 'no_file';
    const textarea = document.getElementById('embed-message-input');
    const message = textarea ? textarea.value.trim() : '';
    const algo = state.selectedEmbedAlgorithm || 'lsb';
    let paramSig = 'none';
    if (algo === 'dwt_dct_qim') {
      const deltaSelect = document.getElementById('embed-delta-input');
      paramSig = String(deltaSelect ? deltaSelect.value : state.embedDelta);
    } else if (algo === 'echo') {
      const alphaInput = document.getElementById('embed-alpha-input');
      paramSig = String(alphaInput ? alphaInput.value : state.embedAlpha);
    }
    return `${fileSig}::${message}::${algo}::${paramSig}`;
  }

  function updateEmbedButtonState() {
    const btnSubmit = document.getElementById('btn-embed-submit');
    if (!btnSubmit) return;

    const textarea = document.getElementById('embed-message-input');
    const message = textarea ? textarea.value.trim() : '';
    const currentFingerprint = computeEmbedInputFingerprint();

    // The button must remain disabled if:
    // - No carrier file is assigned
    // - Message is empty
    // - No current capacity response exists
    // - Capacity status is unavailable, pending, or none
    // - state.embedCanFit !== true
    // - Current input fingerprint does not match the fingerprint that was evaluated
    const isReadyAndSufficient = (
      state.embedFile !== null &&
      message.length > 0 &&
      state.lastCapacityData !== null &&
      state.capacityStatus === 'ready' &&
      state.embedCanFit === true &&
      state.capacityFingerprint === currentFingerprint
    );

    btnSubmit.disabled = !isReadyAndSufficient;
  }

  function triggerCapacityCheck() {
    // Invalidate pending requests and active debounce timers
    state.capacityRequestId++;
    if (state.capacityAbortController) {
      state.capacityAbortController.abort();
      state.capacityAbortController = null;
    }
    if (state.capacityDebounceTimer) {
      clearTimeout(state.capacityDebounceTimer);
      state.capacityDebounceTimer = null;
    }

    // Invalidate old capacity data immediately when carrier, message, algorithm, or parameters change
    state.lastCapacityData = null;
    state.capacityFingerprint = null;
    state.embedCanFit = false;

    const textarea = document.getElementById('embed-message-input');
    const message = textarea ? textarea.value : '';
    const fileInput = document.getElementById('embed-file-input');
    const file = state.embedFile || (fileInput && fileInput.files ? fileInput.files[0] : null);
    const warningBanner = document.getElementById('embed-capacity-warning');

    if (!file || !message || !message.trim()) {
      state.capacityStatus = 'none';
      if (warningBanner) warningBanner.style.display = 'none';
      updateEmbedButtonState();
      updateCapacityDisplay();
      return;
    }

    state.capacityStatus = 'pending';
    updateEmbedButtonState();
    updateCapacityDisplay();

    state.capacityDebounceTimer = setTimeout(runCapacityEvaluation, 200);
  }

  async function runCapacityEvaluation() {
    const textarea = document.getElementById('embed-message-input');
    const message = textarea ? textarea.value : '';
    const fileInput = document.getElementById('embed-file-input');
    const file = state.embedFile || (fileInput && fileInput.files ? fileInput.files[0] : null);
    const warningBanner = document.getElementById('embed-capacity-warning');
    const warningText = document.getElementById('embed-capacity-warning-text');

    if (!file || !message || !message.trim()) {
      state.capacityStatus = 'none';
      state.lastCapacityData = null;
      state.capacityFingerprint = null;
      state.embedCanFit = false;
      if (warningBanner) warningBanner.style.display = 'none';
      updateEmbedButtonState();
      updateCapacityDisplay();
      return;
    }

    const algo = state.selectedEmbedAlgorithm || 'lsb';
    const options = {};
    if (algo === 'dwt_dct_qim') {
      const deltaSelect = document.getElementById('embed-delta-input');
      options.delta = deltaSelect ? parseFloat(deltaSelect.value) : state.embedDelta;
    } else if (algo === 'echo') {
      const alphaInput = document.getElementById('embed-alpha-input');
      options.alpha = alphaInput ? parseFloat(alphaInput.value) : state.embedAlpha;
    }

    // Capture the request fingerprint at dispatch time
    const requestFingerprint = computeEmbedInputFingerprint();

    // Sequence counter and AbortController to guarantee only latest request updates UI
    const thisRequestId = ++state.capacityRequestId;
    if (state.capacityAbortController) {
      state.capacityAbortController.abort();
    }
    const abortCtrl = new AbortController();
    state.capacityAbortController = abortCtrl;

    try {
      const data = await window.CryptAudioAPI.checkCapacity(file, message, algo, options, { signal: abortCtrl.signal });

      // Stale response guard: ignore if a newer request was dispatched or inputs changed while in-flight
      const currentFingerprint = computeEmbedInputFingerprint();
      if (thisRequestId !== state.capacityRequestId || requestFingerprint !== currentFingerprint) {
        return;
      }

      state.lastCapacityData = data;
      state.capacityFingerprint = currentFingerprint;
      state.embedCanFit = data.can_fit;
      state.capacityStatus = 'ready';

      renderAuthoritativeCapacity(data);

      if (!data.can_fit) {
        // Insufficient carrier capacity condition
        if (warningBanner) {
          warningBanner.style.display = 'flex';
          warningBanner.className = 'capacity-warning-banner';
        }
        if (warningText) {
          warningText.textContent = `⚠️ INSUFFICIENT CARRIER CAPACITY: The message requires ${data.required_bits.toLocaleString()} bits, but this carrier audio only provides ${data.available_bits.toLocaleString()} bits for ${data.algorithm.toUpperCase()} (utilization: ${data.utilization_percent.toFixed(2)}%). Recommended minimum audio duration: ${data.recommended_min_duration_sec} s. Please select a longer carrier file, reduce message length, or choose an algorithm with higher capacity (e.g. LSB).`;
        }
      } else {
        // Sufficient capacity condition
        if (warningBanner) warningBanner.style.display = 'none';
      }
      updateEmbedButtonState();
    } catch (err) {
      // Stale response guard or expected abort
      if (thisRequestId !== state.capacityRequestId || err.name === 'AbortError') {
        return;
      }

      // Latest request failed: do not leave old capacity result presented as current
      state.lastCapacityData = null;
      state.capacityFingerprint = null;
      state.embedCanFit = false;
      state.capacityStatus = 'unavailable';

      updateCapacityDisplay();

      if (warningBanner) {
        warningBanner.style.display = 'flex';
        warningBanner.className = 'capacity-warning-banner';
      }
      if (warningText) {
        warningText.textContent = `⚠️ CAPACITY UNAVAILABLE: Unable to evaluate carrier capacity (${err.message || 'Server error'}). Embedding is disabled until authoritative capacity verification succeeds.`;
      }
      updateEmbedButtonState();
    }
  }

  // --------------------------------------------------------------------------
  // 9. Drag-and-Drop File Upload Dropzones
  // --------------------------------------------------------------------------
  function setupDropzones() {
    document.querySelectorAll('.dropzone').forEach(dropzone => {
      const input = dropzone.querySelector('input[type="file"]');
      const previewId = dropzone.getAttribute('data-preview');
      const preview = previewId ? document.getElementById(previewId) : null;

      if (!input) return;

      ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, e => {
          e.preventDefault();
          e.stopPropagation();
          dropzone.classList.add('dragover');
        });
      });

      ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, e => {
          e.preventDefault();
          e.stopPropagation();
          dropzone.classList.remove('dragover');
        });
      });

      dropzone.addEventListener('drop', e => {
        const files = e.dataTransfer.files;
        if (files && files.length > 0) {
          const droppedFile = files[0];
          if (!droppedFile.name || !droppedFile.name.toLowerCase().endsWith('.wav')) {
            input.value = '';
            if (preview) preview.style.display = 'none';
            handleFileAssignment(input.id, null, preview);
            window.showToast('Invalid file format. Please select an uncompressed WAV audio file (.wav).', 'error');
            return;
          }
          input.files = files;
          handleFileAssignment(input.id, droppedFile, preview);
        }
      });

      input.addEventListener('change', function () {
        if (this.files && this.files.length > 0) {
          handleFileAssignment(this.id, this.files[0], preview);
        }
      });
    });
  }

  function handleFileAssignment(inputId, file, previewElement) {
    const input = document.getElementById(inputId);

    // Reject non-.wav or missing file immediately; never assign to state or trigger inspection
    if (!file || !file.name || !file.name.toLowerCase().endsWith('.wav')) {
      if (input) input.value = '';
      if (previewElement) previewElement.style.display = 'none';

      if (inputId === 'embed-file-input') {
        state.inspectionRequestId++;
        state.capacityRequestId++;
        if (state.capacityAbortController) {
          state.capacityAbortController.abort();
          state.capacityAbortController = null;
        }
        if (state.capacityDebounceTimer) {
          clearTimeout(state.capacityDebounceTimer);
          state.capacityDebounceTimer = null;
        }
        state.embedFile = null;
        state.embedCarrierSamples = 0;
        state.embedCarrierRawBytes = 0;
        state.embedCarrierDuration = 0;
        state.lastCapacityData = null;
        state.capacityFingerprint = null;
        state.embedCanFit = false;
        state.capacityStatus = 'none';
        updateCapacityDisplay();
        updateEmbedButtonState();
        const warningBanner = document.getElementById('embed-capacity-warning');
        if (warningBanner) warningBanner.style.display = 'none';
      } else if (inputId === 'extract-file-input') {
        state.extractFile = null;
      } else if (inputId === 'inspect-file-input') {
        state.inspectFile = null;
      } else if (inputId === 'analyze-orig-input') {
        state.analyzeOrigFile = null;
      } else if (inputId === 'analyze-stego-input') {
        state.analyzeStegoFile = null;
      }

      if (file) {
        window.showToast('Invalid file format. Please select an uncompressed WAV audio file (.wav).', 'error');
      }
      return;
    }

    // Client-side extension check is solely a preliminary filter; backend inspection is authoritative
    if (inputId === 'embed-file-input') {
      // 1. Immediately invalidate pending capacity and inspection requests
      state.capacityRequestId++;
      const thisInspectionId = ++state.inspectionRequestId;

      if (state.capacityAbortController) {
        state.capacityAbortController.abort();
        state.capacityAbortController = null;
      }
      if (state.capacityDebounceTimer) {
        clearTimeout(state.capacityDebounceTimer);
        state.capacityDebounceTimer = null;
      }

      // 2. Clear previous capacity evaluation results and set status to pending
      state.embedFile = file;
      state.lastCapacityData = null;
      state.capacityFingerprint = null;
      state.embedCanFit = false;
      state.capacityStatus = 'pending';

      // 3. Reset carrier samples/duration pending authoritative backend inspection
      state.embedCarrierSamples = 0;
      state.embedCarrierRawBytes = 0;
      state.embedCarrierDuration = 0;

      // 4. Keep embed button disabled until inspection and fresh capacity evaluation succeed
      updateEmbedButtonState();
      updateCapacityDisplay();

      // 5. Authoritative carrier metadata from backend inspection
      if (window.CryptAudioAPI && typeof window.CryptAudioAPI.inspectAudio === 'function') {
        window.CryptAudioAPI.inspectAudio(file).then(data => {
          // Stale inspection guard: ensure an earlier file's inspection cannot overwrite newer carrier metadata
          if (thisInspectionId !== state.inspectionRequestId || state.embedFile !== file) {
            return;
          }

          // Validate that the response contains the expected data.capacity object and required capacity metadata
          const isCapacityValid = Boolean(
            data &&
            typeof data === 'object' &&
            data.capacity &&
            typeof data.capacity === 'object' &&
            Number.isFinite(data.capacity.total_samples) &&
            Number.isInteger(data.capacity.total_samples) &&
            data.capacity.total_samples >= 0 &&
            Number.isFinite(data.capacity.raw_capacity_bytes) &&
            Number.isInteger(data.capacity.raw_capacity_bytes) &&
            data.capacity.raw_capacity_bytes >= 0
          );

          if (!isCapacityValid) {
            // Malformed or missing capacity metadata: set unavailable, clear data/fingerprint, keep button disabled
            state.embedCarrierSamples = 0;
            state.embedCarrierDuration = 0;
            state.embedCarrierRawBytes = 0;
            state.lastCapacityData = null;
            state.capacityFingerprint = null;
            state.embedCanFit = false;
            state.capacityStatus = 'unavailable';
            updateCapacityDisplay();
            updateEmbedButtonState();

            const warningBanner = document.getElementById('embed-capacity-warning');
            const warningText = document.getElementById('embed-capacity-warning-text');
            if (warningBanner) {
              warningBanner.style.display = 'flex';
              warningBanner.className = 'capacity-warning-banner';
            }
            if (warningText) {
              warningText.textContent = '⚠️ CAPACITY UNAVAILABLE: Audio inspection returned malformed or missing capacity metadata. Embedding is disabled.';
            }
            window.showToast('Inspection failed: Carrier audio capacity metadata is missing or malformed.', 'error');
            return;
          }

          // Valid capacity metadata received
          if (data.audio && typeof data.audio.duration_seconds === 'number' && !isNaN(data.audio.duration_seconds)) {
            state.embedCarrierDuration = data.audio.duration_seconds;
          } else {
            state.embedCarrierDuration = 0;
          }
          state.embedCarrierSamples = data.capacity.total_samples;
          state.embedCarrierRawBytes = data.capacity.raw_capacity_bytes;

          const warningBanner = document.getElementById('embed-capacity-warning');
          if (warningBanner && state.capacityStatus !== 'unavailable') {
            warningBanner.style.display = 'none';
          }

          updateCapacityDisplay();
          triggerCapacityCheck();
        }).catch(() => {
          // Stale inspection guard
          if (thisInspectionId !== state.inspectionRequestId || state.embedFile !== file) {
            return;
          }

          // Do NOT estimate samples using unverified heuristics on raw file size.
          // If backend inspection fails, show capacity as unavailable and keep embedding disabled.
          state.embedCarrierSamples = 0;
          state.embedCarrierDuration = 0;
          state.embedCarrierRawBytes = 0;
          state.lastCapacityData = null;
          state.capacityFingerprint = null;
          state.embedCanFit = false;
          state.capacityStatus = 'unavailable';
          updateCapacityDisplay();
          updateEmbedButtonState();

          const warningBanner = document.getElementById('embed-capacity-warning');
          const warningText = document.getElementById('embed-capacity-warning-text');
          if (warningBanner) {
            warningBanner.style.display = 'flex';
            warningBanner.className = 'capacity-warning-banner';
          }
          if (warningText) {
            warningText.textContent = '⚠️ CAPACITY UNAVAILABLE: Carrier audio inspection failed. File could not be verified as a valid uncompressed PCM WAV. Embedding is disabled.';
          }
          window.showToast('Carrier inspection failed. Please ensure the file is a valid PCM WAV.', 'error');
        });
      }
    } else if (inputId === 'extract-file-input') {
      state.extractFile = file;
    } else if (inputId === 'inspect-file-input') {
      state.inspectFile = file;
    } else if (inputId === 'analyze-orig-input') {
      state.analyzeOrigFile = file;
    } else if (inputId === 'analyze-stego-input') {
      state.analyzeStegoFile = file;
    }

    if (previewElement) {
      const nameEl = previewElement.querySelector('.file-preview-name');
      const sizeEl = previewElement.querySelector('.file-preview-size');
      if (nameEl) nameEl.textContent = file.name;
      if (sizeEl) sizeEl.textContent = formatBytes(file.size);
      previewElement.style.display = 'flex';
    }

    window.showToast(`Loaded: ${file.name} (${formatBytes(file.size)})`, 'info');
  }

  // --------------------------------------------------------------------------
  // 10. Embed Message Controller (POST /api/embed)
  // --------------------------------------------------------------------------
  function setupEmbedController() {
    const btnSubmit = document.getElementById('btn-embed-submit');
    const resultCard = document.getElementById('embed-result-card');
    const downloadBtn = document.getElementById('btn-download-stego');

    if (!btnSubmit) return;

    btnSubmit.addEventListener('click', async function () {
      const fileInput = document.getElementById('embed-file-input');
      const messageInput = document.getElementById('embed-message-input');
      const passwordInput = document.getElementById('embed-password-input');

      const file = state.embedFile || (fileInput && fileInput.files ? fileInput.files[0] : null);
      const message = messageInput ? messageInput.value.trim() : '';
      const password = passwordInput ? passwordInput.value : '';

      // Client-side validations
      if (!file) {
        window.showToast('Please select a carrier WAV audio file.', 'error');
        return;
      }
      if (!message) {
        window.showToast('Secret message cannot be empty.', 'error');
        if (messageInput) messageInput.focus();
        return;
      }
      if (!password) {
        window.showToast('Passphrase cannot be empty.', 'error');
        if (passwordInput) passwordInput.focus();
        return;
      }

      // Re-verify capacity evaluation and fingerprint against current input state immediately before embedding
      const currentFingerprint = computeEmbedInputFingerprint();
      const isCapacityVerified = (
        state.capacityStatus === 'ready' &&
        state.capacityFingerprint === currentFingerprint &&
        state.lastCapacityData !== null &&
        state.embedCanFit === true
      );

      if (!isCapacityVerified || !state.lastCapacityData || state.embedCanFit !== true) {
        if (state.capacityStatus === 'unavailable') {
          window.showToast('Cannot embed: carrier capacity is unavailable or inspection failed.', 'error');
        } else if (state.capacityStatus === 'ready' && state.lastCapacityData && state.embedCanFit !== true) {
          window.showToast('Cannot embed: secret message exceeds carrier capacity for the chosen algorithm.', 'error');
        } else {
          window.showToast('Carrier capacity is not verified for current inputs. Evaluating capacity now...', 'error');
          triggerCapacityCheck();
        }
        updateEmbedButtonState();
        return;
      }

      const algo = state.selectedEmbedAlgorithm || 'lsb';
      const options = {};

      if (algo === 'dwt_dct_qim') {
        const deltaSelect = document.getElementById('embed-delta-input');
        const deltaVal = deltaSelect ? parseFloat(deltaSelect.value) : state.embedDelta;
        if (![8.0, 16.0, 32.0, 64.0].includes(deltaVal)) {
          window.showToast(`Invalid QIM delta: ${deltaVal}. Allowed: 8, 16, 32, 64.`, 'error');
          return;
        }
        options.delta = deltaVal;
      } else if (algo === 'echo') {
        const alphaInput = document.getElementById('embed-alpha-input');
        const alphaVal = alphaInput ? parseFloat(alphaInput.value) : state.embedAlpha;
        if (isNaN(alphaVal) || alphaVal < 0.001 || alphaVal > 0.50) {
          window.showToast('Echo amplitude alpha must be between 0.001 and 0.50.', 'error');
          return;
        }
        options.alpha = alphaVal;
      }

      // Prevent duplicate clicks & set loading state
      btnSubmit.disabled = true;
      const originalHtml = btnSubmit.innerHTML;
      btnSubmit.innerHTML = `<span class="spinner"></span> Encrypting &amp; Embedding (${algo.toUpperCase()})...`;

      try {
        const result = await window.CryptAudioAPI.embedMessage(file, message, password, algo, options);

        // Revoke prior blob URL to avoid memory leaks
        if (state.stegoDownloadUrl) {
          URL.revokeObjectURL(state.stegoDownloadUrl);
          state.stegoDownloadUrl = null;
        }

        // Store new Blob URL
        state.stegoDownloadUrl = URL.createObjectURL(result.blob);
        state.stegoDownloadFilename = result.filename || 'stego.wav';

        // Populate actual response metrics
        const algoEl = document.getElementById('embed-result-algorithm');
        const paramsEl = document.getElementById('embed-result-parameters');
        const durationEl = document.getElementById('embed-result-duration');
        const payloadEl = document.getElementById('embed-result-payload-size');
        const framedEl = document.getElementById('embed-result-framed-size');
        const utilEl = document.getElementById('embed-result-utilization');
        const reqBitsEl = document.getElementById('embed-result-required-bits');
        const availBitsEl = document.getElementById('embed-result-available-bits');

        const algoNames = {
          lsb: 'LSB (Least Significant Bit)',
          dwt_dct_qim: 'DWT-DCT-QIM (Wavelet + DCT)',
          echo: 'Echo Hiding (Acoustic Domain)'
        };

        if (algoEl) algoEl.textContent = algoNames[result.algorithm] || (result.algorithm ? result.algorithm.toUpperCase() : algo.toUpperCase());
        if (paramsEl) {
          if (algo === 'dwt_dct_qim') {
            paramsEl.textContent = `Delta (Δ) = ${options.delta}`;
          } else if (algo === 'echo') {
            paramsEl.textContent = `Alpha (α) = ${options.alpha}`;
          } else {
            paramsEl.textContent = 'None (Standard LSB)';
          }
        }
        if (durationEl) {
          durationEl.textContent = state.embedCarrierDuration ? `${state.embedCarrierDuration.toFixed(2)} s` : '—';
        }
        if (payloadEl) payloadEl.textContent = `${result.payloadSize} B`;
        if (framedEl) framedEl.textContent = `${result.framedSize} B`;

        const utilVal = result.utilizationPercent < 0.01 && result.utilizationPercent > 0
          ? result.utilizationPercent.toFixed(4)
          : result.utilizationPercent.toFixed(2);
        if (utilEl) utilEl.textContent = `${utilVal}%`;

        if (reqBitsEl) reqBitsEl.textContent = (result.requiredBits || 0).toLocaleString();
        if (availBitsEl) availBitsEl.textContent = (result.availableBits || 0).toLocaleString();

        if (resultCard) {
          resultCard.style.display = 'block';
          resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        window.showToast(`Message encrypted with AES-256-GCM and embedded using ${algo.toUpperCase()} successfully!`, 'success');

        // Security best practice: Clear sensitive password from memory
        if (passwordInput) passwordInput.value = '';
      } catch (err) {
        window.showToast(err.message || 'Failed to embed message into audio carrier.', 'error');
        if (resultCard) resultCard.style.display = 'none';
      } finally {
        btnSubmit.innerHTML = originalHtml;
        updateEmbedButtonState();
      }
    });

    // Download button handler
    if (downloadBtn) {
      downloadBtn.addEventListener('click', function () {
        if (!state.stegoDownloadUrl) {
          window.showToast('No stego audio file available for download.', 'error');
          return;
        }

        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = state.stegoDownloadUrl;
        a.download = state.stegoDownloadFilename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);

        window.showToast(`Downloading: ${state.stegoDownloadFilename}`, 'info');
      });
    }
  }

  // --------------------------------------------------------------------------
  // 11. Extract Message Controller (POST /api/extract)
  // --------------------------------------------------------------------------
  function setupExtractController() {
    const btnSubmit = document.getElementById('btn-extract-submit');
    const resultCard = document.getElementById('extract-result-card');
    const payloadDisplay = document.getElementById('recovered-message-text');
    const charsEl = document.getElementById('extract-summary-chars');
    const bytesEl = document.getElementById('extract-summary-bytes');
    const algoEl = document.getElementById('extract-summary-algorithm');
    const framingEl = document.getElementById('extract-summary-framing');
    const authEl = document.getElementById('extract-summary-auth');
    const btnClearRecovered = document.getElementById('btn-clear-recovered');

    if (!btnSubmit) return;

    btnSubmit.addEventListener('click', async function () {
      const fileInput = document.getElementById('extract-file-input');
      const passwordInput = document.getElementById('extract-password-input');
      const algoSelect = document.getElementById('extract-algorithm-select');

      const file = state.extractFile || (fileInput && fileInput.files ? fileInput.files[0] : null);
      const password = passwordInput ? passwordInput.value : '';
      const algo = algoSelect ? algoSelect.value : (state.selectedExtractAlgorithm || 'auto');

      if (!file) {
        window.showToast('Please select a stego WAV audio file.', 'error');
        return;
      }
      if (!password) {
        window.showToast('Passphrase is required to decrypt the hidden message.', 'error');
        if (passwordInput) passwordInput.focus();
        return;
      }

      const options = {};
      if (algo === 'dwt_dct_qim') {
        const deltaSelect = document.getElementById('extract-delta-input');
        const deltaVal = deltaSelect ? parseFloat(deltaSelect.value) : state.extractDelta;
        if (![8.0, 16.0, 32.0, 64.0].includes(deltaVal)) {
          window.showToast(`Invalid QIM delta: ${deltaVal}. Allowed: 8, 16, 32, 64.`, 'error');
          return;
        }
        options.delta = deltaVal;
      } else if (algo === 'echo') {
        const alphaInput = document.getElementById('extract-alpha-input');
        const alphaVal = alphaInput ? parseFloat(alphaInput.value) : state.extractAlpha;
        if (isNaN(alphaVal) || alphaVal < 0.001 || alphaVal > 0.50) {
          window.showToast('Echo amplitude alpha must be between 0.001 and 0.50.', 'error');
          return;
        }
        options.alpha = alphaVal;
      }

      // Clear previous output
      if (payloadDisplay) payloadDisplay.textContent = '';
      if (charsEl) charsEl.textContent = '0';
      if (bytesEl) bytesEl.textContent = '0 B';
      if (resultCard) resultCard.style.display = 'none';

      btnSubmit.disabled = true;
      const originalHtml = btnSubmit.innerHTML;
      btnSubmit.innerHTML = '<span class="spinner"></span> Extracting &amp; Decrypting...';

      try {
        const result = await window.CryptAudioAPI.extractMessage(file, password, algo, options);

        // Safe DOM text insertion — NEVER innerHTML
        if (payloadDisplay) {
          payloadDisplay.textContent = result.message;
        }

        const charCount = result.message ? result.message.length : 0;
        const byteCount = result.message ? new TextEncoder().encode(result.message).length : 0;

        if (charsEl) charsEl.textContent = charCount.toLocaleString();
        if (bytesEl) bytesEl.textContent = `${byteCount.toLocaleString()} B (${(byteCount / 1024).toFixed(2)} KiB)`;

        const algoNames = {
          lsb: 'LSB',
          dwt_dct_qim: 'DWT-DCT-QIM',
          echo: 'Echo Hiding',
          legacy_cslb: 'Legacy CSLB'
        };
        const detectedName = algoNames[result.algorithm] || (result.algorithm ? result.algorithm.toUpperCase() : 'Auto');
        if (algoEl) algoEl.textContent = `${detectedName}${algo === 'auto' ? ' (Auto-Detected)' : ' (Explicit)'}`;

        // API Success Contract:
        // A successful HTTP 200 response from POST /api/extract guarantees that
        // AES-256-GCM authenticated decryption succeeded and the 16-byte authentication tag
        // verified against the ciphertext and derived key. If authentication failed or the
        // payload was tampered with, the backend raises an exception and returns HTTP 400/401/422.
        //
        // CRC32 is strictly an outer transmission framing checksum that verifies framing
        // boundary integrity across audio carrier samples. It does NOT prove cryptographic
        // authenticity, anti-tampering, or steganographic undetectability.
        if (framingEl) {
          framingEl.textContent = result.framing_checksum_verified ? 'CRC32 Verified (Framing Checksum)' : 'CRC32 Check Failed (Framing Error)';
          framingEl.className = `summary-pill-val ${result.framing_checksum_verified ? 'success' : 'poor'}`;
        }
        if (authEl) {
          authEl.textContent = 'Verified (AES-256-GCM Tag)';
          authEl.className = 'summary-pill-val success';
        }

        if (resultCard) {
          resultCard.style.display = 'block';
          resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        window.showToast('Secret message extracted and decrypted successfully!', 'success');

        // Security: clear password field
        if (passwordInput) passwordInput.value = '';
      } catch (err) {
        window.showToast(err.message || 'Extraction failed: incorrect passphrase or no hidden data found.', 'error');
        // Clear password field on failed attempt
        if (passwordInput) passwordInput.value = '';
      } finally {
        btnSubmit.disabled = false;
        btnSubmit.innerHTML = originalHtml;
      }
    });

    // Clear Recovered Message action (Phase 10.1)
    if (btnClearRecovered) {
      btnClearRecovered.addEventListener('click', function () {
        if (payloadDisplay) payloadDisplay.textContent = '';
        if (charsEl) charsEl.textContent = '0';
        if (bytesEl) bytesEl.textContent = '0 B';
        if (resultCard) resultCard.style.display = 'none';
        window.showToast('Recovered message cleared from view.', 'info');
      });
    }
  }

  // --------------------------------------------------------------------------
  // 12. Audio Inspector Controller (POST /api/audio/inspect)
  // --------------------------------------------------------------------------
  function setupInspectController() {
    const btnSubmit = document.getElementById('btn-inspect-submit');
    const resultsGrid = document.getElementById('inspect-results-grid');

    if (!btnSubmit) return;

    btnSubmit.addEventListener('click', async function () {
      const fileInput = document.getElementById('inspect-file-input');
      const file = state.inspectFile || (fileInput && fileInput.files ? fileInput.files[0] : null);

      if (!file) {
        window.showToast('Please select a WAV audio file to inspect.', 'error');
        return;
      }

      btnSubmit.disabled = true;
      const originalHtml = btnSubmit.innerHTML;
      btnSubmit.innerHTML = '<span class="spinner"></span> Inspecting Header...';

      try {
        const data = await window.CryptAudioAPI.inspectAudio(file);

        // Populate actual metadata
        const formatEl = document.getElementById('inspect-format');
        const rateEl = document.getElementById('inspect-sample-rate');
        const channelsEl = document.getElementById('inspect-channels');
        const depthEl = document.getElementById('inspect-bit-depth');
        const durationEl = document.getElementById('inspect-duration');
        const samplesEl = document.getElementById('inspect-total-samples');
        const rawCapEl = document.getElementById('inspect-raw-capacity');
        const usableCapEl = document.getElementById('inspect-usable-capacity');

        const totalSamples = data.capacity.total_samples || 0;
        const rawBytes = data.capacity.raw_capacity_bytes || 0;

        if (formatEl) formatEl.textContent = data.audio.audio_format || 'PCM (WAVE)';
        if (rateEl) rateEl.textContent = `${data.audio.sample_rate.toLocaleString()} Hz`;
        if (channelsEl) {
          const chDesc = data.audio.channels === 1 ? 'Mono' : data.audio.channels === 2 ? 'Stereo' : 'Multi';
          channelsEl.textContent = `${data.audio.channels} (${chDesc})`;
        }
        if (depthEl) depthEl.textContent = `${data.audio.bit_depth}-bit`;
        if (durationEl) durationEl.textContent = `${data.audio.duration_seconds.toFixed(2)} s`;
        if (samplesEl) samplesEl.textContent = totalSamples.toLocaleString();
        if (rawCapEl) rawCapEl.textContent = `${rawBytes.toLocaleString()} B (${(rawBytes / 1024).toFixed(2)} KiB)`;
        if (usableCapEl) {
          usableCapEl.textContent = `${rawBytes.toLocaleString()} B raw (Algorithm-dependent: usable capacity varies for LSB, DWT-DCT-QIM, and Echo Hiding)`;
        }
        const usableDescEl = usableCapEl && usableCapEl.parentElement ? usableCapEl.parentElement.querySelector('.stat-desc') : null;
        if (usableDescEl) {
          usableDescEl.textContent = 'Usable capacity varies by algorithm (evaluate via Embed view)';
        }

        if (resultsGrid) {
          resultsGrid.style.display = 'grid';
        }

        const overheadPanel = document.getElementById('inspect-overhead-panel');
        if (overheadPanel) {
          overheadPanel.style.display = 'block';
        }

        if (resultsGrid) {
          resultsGrid.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        window.showToast(`Inspected ${data.filename}: ${data.audio.bit_depth}-bit, ${data.audio.sample_rate} Hz.`, 'info');
      } catch (err) {
        window.showToast(err.message || 'Failed to inspect audio file.', 'error');
        if (resultsGrid) resultsGrid.style.display = 'none';
      } finally {
        btnSubmit.disabled = false;
        btnSubmit.innerHTML = originalHtml;
      }
    });
  }

  // --------------------------------------------------------------------------
  // 13. Quality Analysis Controller (POST /api/analyze)
  // --------------------------------------------------------------------------
  function setupAnalyzeController() {
    const btnSubmit = document.getElementById('btn-simulate-analyze') || document.getElementById('btn-analyze-submit');
    const resultsCard = document.getElementById('analyze-results-card');

    if (!btnSubmit) return;

    btnSubmit.addEventListener('click', async function () {
      const origInput = document.getElementById('analyze-orig-input');
      const stegoInput = document.getElementById('analyze-stego-input');

      const origFile = state.analyzeOrigFile || (origInput && origInput.files ? origInput.files[0] : null);
      const stegoFile = state.analyzeStegoFile || (stegoInput && stegoInput.files ? stegoInput.files[0] : null);

      if (!origFile) {
        window.showToast('Please select the original carrier WAV file.', 'error');
        return;
      }
      if (!stegoFile) {
        window.showToast('Please select the stego WAV file to compare.', 'error');
        return;
      }

      btnSubmit.disabled = true;
      const originalHtml = btnSubmit.innerHTML;
      btnSubmit.innerHTML = '<span class="spinner"></span> Computing Distortion Metrics...';

      try {
        const data = await window.CryptAudioAPI.analyzeAudio(origFile, stegoFile);
        const analysis = data.analysis;

        // Display MSE
        const mseEl = document.getElementById('analyze-mse');
        const mseVal = analysis.mse !== null && analysis.mse !== undefined ? Number(analysis.mse).toFixed(6) : 'N/A';
        if (mseEl) mseEl.textContent = mseVal;

        // Display SNR
        const snrEl = document.getElementById('analyze-snr');
        let snrVal = 'N/A';
        if (analysis.snr_db === 'Infinity' || analysis.snr_db === Infinity) {
          snrVal = '∞ (Identical)';
        } else if (analysis.snr_db !== null && analysis.snr_db !== undefined && !isNaN(analysis.snr_db)) {
          snrVal = `${Number(analysis.snr_db).toFixed(2)} dB`;
        }
        if (snrEl) snrEl.textContent = snrVal;

        // Display PSNR with illustrative numerical interpretation bands
        const psnrEl = document.getElementById('analyze-psnr');
        const psnrDesc = document.getElementById('analyze-psnr-desc');
        let psnrVal = 'N/A';
        if (analysis.psnr_db === 'Infinity' || analysis.psnr_db === Infinity) {
          psnrVal = '∞ (Identical)';
          if (psnrDesc) psnrDesc.textContent = 'Identical audio signals (zero distortion)';
        } else if (analysis.psnr_db !== null && analysis.psnr_db !== undefined && !isNaN(analysis.psnr_db)) {
          const psnrNum = Number(analysis.psnr_db);
          psnrVal = `${psnrNum.toFixed(2)} dB`;
          if (psnrDesc) {
            if (psnrNum >= 50) {
              psnrDesc.textContent = 'Very high numerical fidelity (> 50 dB)';
            } else if (psnrNum >= 40) {
              psnrDesc.textContent = 'High numerical fidelity (40–50 dB)';
            } else if (psnrNum >= 30) {
              psnrDesc.textContent = 'Moderate numerical fidelity (30–40 dB)';
            } else {
              psnrDesc.textContent = 'Lower numerical fidelity (< 30 dB)';
            }
          }
        }
        if (psnrEl) psnrEl.textContent = psnrVal;

        // Display Pearson Correlation
        const corrEl = document.getElementById('analyze-correlation');
        const corrDesc = document.getElementById('analyze-corr-desc');
        let corrVal = 'N/A';
        if (analysis.correlation !== null && analysis.correlation !== undefined && !isNaN(analysis.correlation)) {
          const corrNum = Number(analysis.correlation);
          corrVal = corrNum.toFixed(6);
          if (corrDesc) {
            if (Math.abs(corrNum - 1.0) < 0.000001) {
              corrDesc.textContent = 'r = 1.000000 — Perfect positive linear correlation';
            } else {
              corrDesc.textContent = `Linear correlation coefficient: ${corrVal}`;
            }
          }
        }
        if (corrEl) corrEl.textContent = corrVal;

        // Display Modified Samples Metrics
        const totalSamplesEl = document.getElementById('analyze-total-samples');
        const modSamplesEl = document.getElementById('analyze-modified-samples');
        const modPercentEl = document.getElementById('analyze-modified-percent');

        const totalSamples = Number(analysis.total_samples) || 0;
        const modSamples = Number(analysis.modified_samples) || 0;
        const modPercent = totalSamples > 0 ? (modSamples / totalSamples) * 100 : 0.0;

        if (totalSamplesEl) totalSamplesEl.textContent = totalSamples.toLocaleString();
        if (modSamplesEl) modSamplesEl.textContent = modSamples.toLocaleString();
        if (modPercentEl) {
          const precision = modPercent < 0.01 && modPercent > 0 ? 4 : 2;
          modPercentEl.textContent = `${modPercent.toFixed(precision)}%`;
        }

        // Quality assessment badge
        const badge = document.getElementById('analyze-assessment-badge');
        if (badge) {
          const assess = analysis.quality_assessment || 'Unknown';
          badge.textContent = `✓ ${assess}`;
          badge.className = 'badge-quality';
          if (assess.includes('Excellent')) {
            badge.classList.add('excellent');
          } else if (assess.includes('Good')) {
            badge.classList.add('good');
          } else {
            badge.classList.add('poor');
          }
        }

        // Table rows
        const tPsnr = document.getElementById('analyze-table-psnr');
        const tSnr = document.getElementById('analyze-table-snr');
        const tMse = document.getElementById('analyze-table-mse');
        const tCorr = document.getElementById('analyze-table-correlation');

        if (tPsnr) tPsnr.textContent = psnrVal;
        if (tSnr) tSnr.textContent = snrVal;
        if (tMse) tMse.textContent = mseVal;
        if (tCorr) tCorr.textContent = corrVal;

        if (resultsCard) {
          resultsCard.style.display = 'block';
          resultsCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        window.showToast(`Audio analysis completed. Quality: ${analysis.quality_assessment}`, 'success');
      } catch (err) {
        window.showToast(err.message || 'Failed to compare audio files.', 'error');
        if (resultsCard) resultsCard.style.display = 'none';
      } finally {
        btnSubmit.disabled = false;
        btnSubmit.innerHTML = originalHtml;
      }
    });
  }

  // --------------------------------------------------------------------------
  // 14. Copy to Clipboard Utility
  // --------------------------------------------------------------------------
  function setupClipboard() {
    document.querySelectorAll('[data-copy-target]').forEach(btn => {
      btn.addEventListener('click', function () {
        const targetId = this.getAttribute('data-copy-target');
        const targetEl = document.getElementById(targetId);
        if (!targetEl) return;

        const text = targetEl.textContent || targetEl.value || '';
        if (!text) {
          window.showToast('No recovered message text to copy.', 'error');
          return;
        }

        navigator.clipboard.writeText(text).then(() => {
          window.showToast('Recovered secret message copied to clipboard!', 'success');
        }).catch(() => {
          const textarea = document.createElement('textarea');
          textarea.value = text;
          document.body.appendChild(textarea);
          textarea.select();
          document.execCommand('copy');
          document.body.removeChild(textarea);
          window.showToast('Copied to clipboard', 'success');
        });
      });
    });
  }

  // --------------------------------------------------------------------------
  // 15. Form Reset Controllers
  // --------------------------------------------------------------------------
  function setupFormResets() {
    document.querySelectorAll('[data-reset-form]').forEach(btn => {
      btn.addEventListener('click', function () {
        const formId = this.getAttribute('data-reset-form');
        const form = document.getElementById(formId);
        if (!form) return;

        form.reset();

        if (formId === 'form-embed') {
          state.embedFile = null;
          state.embedCarrierSamples = 0;
          state.embedCarrierRawBytes = 0;
          state.embedCarrierDuration = 0;
          state.selectedEmbedAlgorithm = 'lsb';
          state.embedDelta = 32.0;
          state.embedAlpha = 0.08;
          state.embedCanFit = false;
          state.capacityStatus = 'none';
          state.lastCapacityData = null;
          state.capacityFingerprint = null;
          state.capacityRequestId++;
          state.inspectionRequestId++;

          if (state.capacityAbortController) {
            state.capacityAbortController.abort();
            state.capacityAbortController = null;
          }
          if (state.capacityDebounceTimer) {
            clearTimeout(state.capacityDebounceTimer);
            state.capacityDebounceTimer = null;
          }

          if (state.stegoDownloadUrl) {
            URL.revokeObjectURL(state.stegoDownloadUrl);
            state.stegoDownloadUrl = null;
          }
          const resultCard = document.getElementById('embed-result-card');
          if (resultCard) resultCard.style.display = 'none';
          const charCounter = document.getElementById('embed-char-counter');
          const byteCounter = document.getElementById('embed-byte-counter');
          if (charCounter) charCounter.textContent = '0 chars';
          if (byteCounter) byteCounter.textContent = '0 bytes';

          // Reset algorithm cards
          form.querySelectorAll('.algo-card').forEach(c => {
            const isLsb = c.getAttribute('data-algo') === 'lsb';
            c.classList.toggle('active', isLsb);
            c.setAttribute('aria-checked', isLsb ? 'true' : 'false');
          });
          const hiddenInput = document.getElementById('embed-algorithm-input');
          if (hiddenInput) hiddenInput.value = 'lsb';
          const badge = document.getElementById('embed-selected-algo-badge');
          if (badge) badge.textContent = 'LSB Active';
          const capBadge = document.getElementById('embed-cap-algo-badge');
          if (capBadge) capBadge.textContent = 'LSB Mode';
          const capTitle = document.getElementById('embed-capacity-title');
          if (capTitle) capTitle.textContent = 'LSB Capacity & Framing Calculation';

          // Reset visible parameter controls to approved defaults
          const deltaSelect = document.getElementById('embed-delta-input');
          if (deltaSelect) deltaSelect.value = '32';
          const alphaInput = document.getElementById('embed-alpha-input');
          if (alphaInput) alphaInput.value = '0.08';

          // Reset parameter panels visibility
          const paramsPanel = document.getElementById('embed-params-panel');
          if (paramsPanel) paramsPanel.style.display = 'none';
          const dwtParams = document.getElementById('embed-params-dwt');
          if (dwtParams) dwtParams.style.display = 'none';
          const echoParams = document.getElementById('embed-params-echo');
          if (echoParams) echoParams.style.display = 'none';

          const warningBanner = document.getElementById('embed-capacity-warning');
          if (warningBanner) warningBanner.style.display = 'none';

          updateEmbedButtonState();
          updateCapacityDisplay();
        } else if (formId === 'form-extract') {
          state.extractFile = null;
          state.selectedExtractAlgorithm = 'auto';
          state.extractDelta = 32.0;
          state.extractAlpha = 0.08;

          const resultCard = document.getElementById('extract-result-card');
          if (resultCard) resultCard.style.display = 'none';
          const payloadDisplay = document.getElementById('recovered-message-text');
          if (payloadDisplay) payloadDisplay.textContent = '';
          const charsEl = document.getElementById('extract-summary-chars');
          const bytesEl = document.getElementById('extract-summary-bytes');
          if (charsEl) charsEl.textContent = '0';
          if (bytesEl) bytesEl.textContent = '0 B';

          const algoSelect = document.getElementById('extract-algorithm-select');
          if (algoSelect) algoSelect.value = 'auto';

          // Reset visible extract parameter controls to approved defaults
          const deltaSelect = document.getElementById('extract-delta-input');
          if (deltaSelect) deltaSelect.value = '32';
          const alphaInput = document.getElementById('extract-alpha-input');
          if (alphaInput) alphaInput.value = '0.08';

          // Reset parameter panels visibility
          const paramsPanel = document.getElementById('extract-params-panel');
          if (paramsPanel) paramsPanel.style.display = 'none';
          const dwtParams = document.getElementById('extract-params-dwt');
          if (dwtParams) dwtParams.style.display = 'none';
          const echoParams = document.getElementById('extract-params-echo');
          if (echoParams) echoParams.style.display = 'none';
        } else if (formId === 'form-inspect') {
          state.inspectFile = null;
          const resultsGrid = document.getElementById('inspect-results-grid');
          if (resultsGrid) resultsGrid.style.display = 'none';
          const overheadPanel = document.getElementById('inspect-overhead-panel');
          if (overheadPanel) overheadPanel.style.display = 'none';
        } else if (formId === 'form-analyze') {
          state.analyzeOrigFile = null;
          state.analyzeStegoFile = null;
          const resultsCard = document.getElementById('analyze-results-card');
          if (resultsCard) resultsCard.style.display = 'none';
        }

        form.querySelectorAll('.file-preview').forEach(p => p.style.display = 'none');
      });
    });
  }

  function setupFormSubmits() {
    document.querySelectorAll('form').forEach(form => {
      form.addEventListener('submit', function (e) {
        e.preventDefault();
      });
    });
  }

  // --------------------------------------------------------------------------
  // Document Ready Initialization
  // --------------------------------------------------------------------------
  document.addEventListener('DOMContentLoaded', function () {
    setupFormSubmits();
    setupNavigation();
    setupMobileSidebar();
    setupHealthMonitor();
    setupPasswordToggles();
    setupMessageCounter();
    setupAlgorithmSelection();
    setupExtractAlgorithmSelection();
    updateCapacityDisplay();
    setupDropzones();
    setupClipboard();
    setupFormResets();

    // Controllers
    setupEmbedController();
    setupExtractController();
    setupInspectController();
    setupAnalyzeController();

    // Ensure embed submit button is initially disabled until capacity is authoritatively confirmed
    const btnEmbedSubmit = document.getElementById('btn-embed-submit');
    if (btnEmbedSubmit) btnEmbedSubmit.disabled = true;
  });

  // Expose internals for executable unit and behavioral testing
  if (typeof window !== 'undefined') {
    window.__cryptaudio_internals = {
      state,
      computeEmbedInputFingerprint,
      updateEmbedButtonState,
      triggerCapacityCheck,
      runCapacityEvaluation,
      handleFileAssignment,
      setupEmbedController,
      setupAlgorithmSelection,
      updateCapacityDisplay,
    };
  }

})();
