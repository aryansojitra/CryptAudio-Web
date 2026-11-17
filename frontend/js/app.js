/**
 * CryptAudio Web — Master Application Controller (Phase 10)
 *
 * Full Frontend-Backend API Integration:
 * - Real API communication via CryptAudioAPI (api.js)
 * - Live backend connection health monitoring
 * - Real AES-256-GCM / LSB embedding with WAV blob download
 * - Real message extraction and decryption with clipboard copy
 * - Real audio header inspection and capacity estimation
 * - Real numerical signal distortion analysis (MSE, SNR, PSNR, Pearson r)
 * - Safe error handling and credentials protection
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
    embedCarrierMaxPlaintext: 0,
    extractFile: null,
    inspectFile: null,
    analyzeOrigFile: null,
    analyzeStegoFile: null,
    stegoDownloadUrl: null,
    stegoDownloadFilename: 'stego.wav',
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
    const targetId = viewId.replace('#', '');
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
      views[0].classList.add('active');
    }

    links.forEach(link => {
      const href = link.getAttribute('href');
      if (href === `#${targetId}`) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });

    closeMobileSidebar();

    if (history.pushState) {
      history.pushState(null, null, `#${targetId}`);
    } else {
      location.hash = `#${targetId}`;
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function setupNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', function (e) {
        e.preventDefault();
        navigateTo(this.getAttribute('href'));
      });
    });

    document.querySelectorAll('[data-target-view]').forEach(btn => {
      btn.addEventListener('click', function (e) {
        e.preventDefault();
        navigateTo(this.getAttribute('data-target-view'));
      });
    });

    const initialHash = window.location.hash || '#dashboard';
    navigateTo(initialHash);

    window.addEventListener('hashchange', function () {
      navigateTo(window.location.hash || '#dashboard');
    });
  }

  // --------------------------------------------------------------------------
  // 3. Mobile Sidebar Drawer
  // --------------------------------------------------------------------------
  function openMobileSidebar() {
    const sidebar = document.getElementById('app-sidebar');
    const backdrop = document.getElementById('sidebar-backdrop');
    if (sidebar) sidebar.classList.add('open');
    if (backdrop) backdrop.classList.add('active');
  }

  function closeMobileSidebar() {
    const sidebar = document.getElementById('app-sidebar');
    const backdrop = document.getElementById('sidebar-backdrop');
    if (sidebar) sidebar.classList.remove('open');
    if (backdrop) backdrop.classList.remove('active');
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
  // 6. Message Counter & Accurate Capacity Display (Phase 10.1)
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
    });
  }

  function updateCapacityDisplay() {
    const textarea = document.getElementById('embed-message-input');
    const message = textarea ? textarea.value : '';
    const msgChars = message.length;
    const msgBytes = new TextEncoder().encode(message).length;

    // Cryptographic payload:
    // Fixed crypto header: 33 bytes (Magic 4B + Version 1B + Salt 16B + Nonce 12B)
    // Ciphertext: msgBytes
    // AES-GCM tag: 16 bytes
    // Encrypted payload size = msgBytes + 49
    const cryptoBytes = msgBytes > 0 ? msgBytes + 49 : 0;

    // LSB framing header: 13 bytes (Magic 4B + Version 1B + Length 4B + CRC32 4B)
    // Framed payload size = cryptoBytes + 13 = msgBytes + 62
    const framedBytes = cryptoBytes > 0 ? cryptoBytes + 13 : 0;

    // Required samples: 1 bit embedded per sample
    const reqSamples = framedBytes * 8;

    // Carrier samples & capacity
    const totalSamples = state.embedCarrierSamples || 0;
    const rawCapBytes = state.embedCarrierRawBytes || (totalSamples > 0 ? Math.floor(totalSamples / 8) : 0);
    const maxPlaintext = Math.max(0, rawCapBytes - 62);

    // Update UI elements
    const elMsgSize = document.getElementById('embed-cap-msg-size');
    const elCryptoSize = document.getElementById('embed-cap-crypto-size');
    const elFramedSize = document.getElementById('embed-cap-framed-size');
    const elReqSamples = document.getElementById('embed-cap-req-samples');
    const elAvailSamples = document.getElementById('embed-cap-avail-samples');
    const elMaxPlaintext = document.getElementById('embed-cap-max-plaintext');
    const fill = document.getElementById('embed-capacity-fill');
    const percentLabel = document.getElementById('embed-capacity-percent');

    if (elMsgSize) {
      elMsgSize.textContent = `${msgBytes} B (${msgChars} char${msgChars === 1 ? '' : 's'})`;
    }
    if (elCryptoSize) {
      elCryptoSize.textContent = cryptoBytes > 0 ? `${cryptoBytes} B` : '0 B';
    }
    if (elFramedSize) {
      elFramedSize.textContent = framedBytes > 0 ? `${framedBytes} B` : '0 B';
    }
    if (elReqSamples) {
      elReqSamples.textContent = `${reqSamples.toLocaleString()} sample${reqSamples === 1 ? '' : 's'}`;
    }
    if (elAvailSamples) {
      if (totalSamples > 0) {
        elAvailSamples.textContent = `${totalSamples.toLocaleString()} samples (${formatBytes(rawCapBytes)})`;
      } else if (state.embedFile) {
        elAvailSamples.textContent = 'Inspecting carrier...';
      } else {
        elAvailSamples.textContent = 'Select carrier WAV';
      }
    }
    if (elMaxPlaintext) {
      if (totalSamples > 0) {
        elMaxPlaintext.textContent = `${maxPlaintext.toLocaleString()} B (${(maxPlaintext / 1024).toFixed(2)} KiB)`;
      } else {
        elMaxPlaintext.textContent = '—';
      }
    }

    // Utilization percentage
    let percent = 0.0;
    if (totalSamples > 0 && reqSamples > 0) {
      percent = (reqSamples / totalSamples) * 100;
    }

    if (percentLabel) {
      if (totalSamples > 0) {
        const precision = percent < 0.01 && percent > 0 ? 4 : 2;
        percentLabel.textContent = `${percent.toFixed(precision)}% utilized (${framedBytes.toLocaleString()} / ${rawCapBytes.toLocaleString()} B)`;
      } else {
        percentLabel.textContent = '0.00% utilized (Carrier not selected)';
      }
    }

    if (fill) {
      const displayWidth = Math.min(100, percent);
      fill.style.width = `${reqSamples > 0 && totalSamples > 0 ? Math.max(1, displayWidth) : 0}%`;
      fill.classList.remove('safe', 'warning', 'danger');
      if (percent > 100) {
        fill.classList.add('danger');
      } else if (percent > 85) {
        fill.classList.add('warning');
      } else {
        fill.classList.add('safe');
      }
    }
  }

  // --------------------------------------------------------------------------
  // 7. Drag-and-Drop File Upload Dropzones
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
          input.files = files;
          handleFileAssignment(input.id, files[0], preview);
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
    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.wav')) {
      window.showToast('Invalid file format. Please select an uncompressed WAV audio file (.wav).', 'error');
      return;
    }

    // Map input to internal state
    if (inputId === 'embed-file-input') {
      state.embedFile = file;
      updateCapacityDisplay();

      // Retrieve authoritative carrier metadata & samples from backend
      if (window.CryptAudioAPI && typeof window.CryptAudioAPI.inspectAudio === 'function') {
        window.CryptAudioAPI.inspectAudio(file).then(data => {
          if (data && data.capacity) {
            state.embedCarrierSamples = data.capacity.total_samples || 0;
            state.embedCarrierRawBytes = data.capacity.raw_capacity_bytes || 0;
            state.embedCarrierMaxPlaintext = Math.max(0, state.embedCarrierRawBytes - 62);
            updateCapacityDisplay();
          }
        }).catch(() => {
          // Fallback approximate calculation if backend inspection is deferred
          const approxSamples = Math.floor(file.size / 2);
          state.embedCarrierSamples = approxSamples;
          state.embedCarrierRawBytes = Math.floor(approxSamples / 8);
          state.embedCarrierMaxPlaintext = Math.max(0, state.embedCarrierRawBytes - 62);
          updateCapacityDisplay();
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
  // 8. Embed Message Controller (POST /api/embed)
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

      // Prevent duplicate clicks & set loading state
      btnSubmit.disabled = true;
      const originalHtml = btnSubmit.innerHTML;
      btnSubmit.innerHTML = '<span class="spinner"></span> Encrypting &amp; Embedding...';

      try {
        const result = await window.CryptAudioAPI.embedMessage(file, message, password);

        // Revoke prior blob URL to avoid memory leaks
        if (state.stegoDownloadUrl) {
          URL.revokeObjectURL(state.stegoDownloadUrl);
          state.stegoDownloadUrl = null;
        }

        // Store new Blob URL
        state.stegoDownloadUrl = URL.createObjectURL(result.blob);
        state.stegoDownloadFilename = result.filename || 'stego.wav';

        // Populate actual response metrics
        const payloadEl = document.getElementById('embed-result-payload-size');
        const framedEl = document.getElementById('embed-result-framed-size');
        const utilEl = document.getElementById('embed-result-utilization');

        if (payloadEl) payloadEl.textContent = `${result.payloadSize} B`;
        if (framedEl) framedEl.textContent = `${result.framedSize} B`;
        const utilVal = result.utilizationPercent < 0.01 && result.utilizationPercent > 0
          ? result.utilizationPercent.toFixed(4)
          : result.utilizationPercent.toFixed(2);
        if (utilEl) utilEl.textContent = `${utilVal}%`;

        if (resultCard) {
          resultCard.style.display = 'block';
          resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        window.showToast('Message encrypted with AES-256-GCM and embedded successfully!', 'success');

        // Security best practice: Clear sensitive password from memory
        if (passwordInput) passwordInput.value = '';
      } catch (err) {
        window.showToast(err.message || 'Failed to embed message into audio carrier.', 'error');
        if (resultCard) resultCard.style.display = 'none';
      } finally {
        btnSubmit.disabled = false;
        btnSubmit.innerHTML = originalHtml;
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
  // 9. Extract Message Controller (POST /api/extract)
  // --------------------------------------------------------------------------
  function setupExtractController() {
    const btnSubmit = document.getElementById('btn-extract-submit');
    const resultCard = document.getElementById('extract-result-card');
    const payloadDisplay = document.getElementById('recovered-message-text');
    const charsEl = document.getElementById('extract-summary-chars');
    const bytesEl = document.getElementById('extract-summary-bytes');
    const btnClearRecovered = document.getElementById('btn-clear-recovered');

    if (!btnSubmit) return;

    btnSubmit.addEventListener('click', async function () {
      const fileInput = document.getElementById('extract-file-input');
      const passwordInput = document.getElementById('extract-password-input');

      const file = state.extractFile || (fileInput && fileInput.files ? fileInput.files[0] : null);
      const password = passwordInput ? passwordInput.value : '';

      if (!file) {
        window.showToast('Please select a stego WAV audio file.', 'error');
        return;
      }
      if (!password) {
        window.showToast('Passphrase is required to decrypt the hidden message.', 'error');
        if (passwordInput) passwordInput.focus();
        return;
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
        const result = await window.CryptAudioAPI.extractMessage(file, password);

        if (payloadDisplay) {
          payloadDisplay.textContent = result.message;
        }

        const charCount = result.message ? result.message.length : 0;
        const byteCount = result.message ? new TextEncoder().encode(result.message).length : 0;

        if (charsEl) charsEl.textContent = charCount.toLocaleString();
        if (bytesEl) bytesEl.textContent = `${byteCount.toLocaleString()} B (${(byteCount / 1024).toFixed(2)} KiB)`;

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
  // 10. Audio Inspector Controller (POST /api/audio/inspect)
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
        const maxPlaintext = Math.max(0, rawBytes - 62);

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
        if (usableCapEl) usableCapEl.textContent = `${maxPlaintext.toLocaleString()} B (${(maxPlaintext / 1024).toFixed(2)} KiB)`;

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
  // 11. Quality Analysis Controller (POST /api/analyze)
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

        // Display PSNR with illustrative numerical interpretation bands (Phase 10.1)
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

        // Display Modified Samples Metrics (Phase 10.1)
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
  // 12. Copy to Clipboard Utility
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
  // 13. Form Reset Controllers
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
          state.embedCarrierMaxPlaintext = 0;
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
          updateCapacityDisplay();
        } else if (formId === 'form-extract') {
          state.extractFile = null;
          const resultCard = document.getElementById('extract-result-card');
          if (resultCard) resultCard.style.display = 'none';
          const payloadDisplay = document.getElementById('recovered-message-text');
          if (payloadDisplay) payloadDisplay.textContent = '';
          const charsEl = document.getElementById('extract-summary-chars');
          const bytesEl = document.getElementById('extract-summary-bytes');
          if (charsEl) charsEl.textContent = '0';
          if (bytesEl) bytesEl.textContent = '0 B';
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
    updateCapacityDisplay();
    setupDropzones();
    setupClipboard();
    setupFormResets();

    // Controllers
    setupEmbedController();
    setupExtractController();
    setupInspectController();
    setupAnalyzeController();
  });

})();
