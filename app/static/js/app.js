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

    toast.innerHTML = `<span>${iconSvg}</span><span>${escapeHtml(message)}</span>`;
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
    if (bytes === 0) return '0 Bytes';
    if (!bytes || isNaN(bytes)) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
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

    if (!statusDot || !statusText) return;

    statusDot.className = 'status-dot checking';
    statusText.textContent = 'Backend: Checking...';

    try {
      const data = await window.CryptAudioAPI.checkHealth();
      if (data.status === 'healthy') {
        statusDot.className = 'status-dot';
        statusText.textContent = `Backend: Connected (v${data.version})`;
        if (statusPill) statusPill.title = `${data.application} v${data.version} operational. Click to refresh.`;
      } else {
        throw new Error('Unhealthy status reported');
      }
    } catch (err) {
      statusDot.className = 'status-dot disconnected';
      statusText.textContent = 'Backend: Disconnected (Retry)';
      if (statusPill) statusPill.title = 'Cannot reach backend at 127.0.0.1:8000. Click to retry.';
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
  // 6. Message Character & Byte Counter
  // --------------------------------------------------------------------------
  function setupMessageCounter() {
    const textarea = document.getElementById('embed-message-input');
    const charCounter = document.getElementById('embed-char-counter');
    const byteCounter = document.getElementById('embed-byte-counter');

    if (!textarea || !charCounter || !byteCounter) return;

    textarea.addEventListener('input', function () {
      const text = this.value;
      const charCount = text.length;
      const byteCount = new TextEncoder().encode(text).length;

      charCounter.textContent = `${charCount} char${charCount === 1 ? '' : 's'}`;
      byteCounter.textContent = `${byteCount} byte${byteCount === 1 ? '' : 's'}`;

      updateCapacityMeter(byteCount);
    });
  }

  function updateCapacityMeter(byteCount) {
    const fill = document.getElementById('embed-capacity-fill');
    const label = document.getElementById('embed-capacity-percent');
    if (!fill || !label) return;

    // Use selected carrier file size if available as a baseline approximation
    let estTotalCapacity = 55125;
    if (state.embedFile && state.embedFile.size > 100) {
      // 16-bit mono: 1 byte per sample = 0.5 bits per audio byte
      // Approximate theoretical capacity ~ file.size / (sample_width)
      estTotalCapacity = Math.floor(state.embedFile.size / 2);
    }

    const overhead = 46; // 13B stego header + 33B crypto header
    const totalBytes = byteCount > 0 ? byteCount + overhead : 0;
    const percent = Math.min(100, (totalBytes / Math.max(1, estTotalCapacity)) * 100).toFixed(2);

    fill.style.width = `${Math.max(1, percent)}%`;
    label.textContent = `${percent}% utilized (est. ${totalBytes} / ${estTotalCapacity.toLocaleString()} B)`;

    fill.classList.remove('safe', 'warning', 'danger');
    if (percent < 60) {
      fill.classList.add('safe');
    } else if (percent < 90) {
      fill.classList.add('warning');
    } else {
      fill.classList.add('danger');
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
      const msgTextarea = document.getElementById('embed-message-input');
      const currentBytes = msgTextarea ? new TextEncoder().encode(msgTextarea.value).length : 0;
      updateCapacityMeter(currentBytes);
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
        if (utilEl) utilEl.textContent = `${result.utilizationPercent.toFixed(2)}%`;

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
      if (resultCard) resultCard.style.display = 'none';

      btnSubmit.disabled = true;
      const originalHtml = btnSubmit.innerHTML;
      btnSubmit.innerHTML = '<span class="spinner"></span> Extracting &amp; Decrypting...';

      try {
        const result = await window.CryptAudioAPI.extractMessage(file, password);

        if (payloadDisplay) {
          payloadDisplay.textContent = result.message;
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

        if (formatEl) formatEl.textContent = data.audio.audio_format || 'PCM (WAVE)';
        if (rateEl) rateEl.textContent = `${data.audio.sample_rate.toLocaleString()} Hz`;
        if (channelsEl) {
          const chDesc = data.audio.channels === 1 ? 'Mono' : data.audio.channels === 2 ? 'Stereo' : 'Multi';
          channelsEl.textContent = `${data.audio.channels} (${chDesc})`;
        }
        if (depthEl) depthEl.textContent = `${data.audio.bit_depth}-bit`;
        if (durationEl) durationEl.textContent = `${data.audio.duration_seconds.toFixed(2)} s`;
        if (samplesEl) samplesEl.textContent = data.capacity.total_samples.toLocaleString();
        if (rawCapEl) rawCapEl.textContent = formatBytes(data.capacity.raw_capacity_bytes);
        if (usableCapEl) {
          const usable = Math.max(0, data.capacity.raw_capacity_bytes - 46);
          usableCapEl.textContent = formatBytes(usable);
        }

        if (resultsGrid) {
          resultsGrid.style.display = 'grid';
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
        const mseVal = analysis.mse !== null ? analysis.mse.toFixed(6) : 'N/A';
        if (mseEl) mseEl.textContent = mseVal;

        // Display SNR
        const snrEl = document.getElementById('analyze-snr');
        const snrVal = analysis.snr_db === 'Infinity' ? '∞' : (analysis.snr_db !== null ? `${analysis.snr_db.toFixed(2)} dB` : 'N/A');
        if (snrEl) snrEl.textContent = snrVal;

        // Display PSNR
        const psnrEl = document.getElementById('analyze-psnr');
        const psnrVal = analysis.psnr_db === 'Infinity' ? '∞' : (analysis.psnr_db !== null ? `${analysis.psnr_db.toFixed(2)} dB` : 'N/A');
        if (psnrEl) psnrEl.textContent = psnrVal;

        // Display Pearson Correlation
        const corrEl = document.getElementById('analyze-correlation');
        const corrVal = analysis.correlation !== null ? analysis.correlation.toFixed(6) : 'N/A';
        if (corrEl) corrEl.textContent = corrVal;

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
          updateCapacityMeter(0);
        } else if (formId === 'form-extract') {
          state.extractFile = null;
          const resultCard = document.getElementById('extract-result-card');
          if (resultCard) resultCard.style.display = 'none';
          const payloadDisplay = document.getElementById('recovered-message-text');
          if (payloadDisplay) payloadDisplay.textContent = '';
        }

        form.querySelectorAll('.file-preview').forEach(p => p.style.display = 'none');
      });
    });
  }

  // --------------------------------------------------------------------------
  // Document Ready Initialization
  // --------------------------------------------------------------------------
  document.addEventListener('DOMContentLoaded', function () {
    setupNavigation();
    setupMobileSidebar();
    setupHealthMonitor();
    setupPasswordToggles();
    setupMessageCounter();
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
