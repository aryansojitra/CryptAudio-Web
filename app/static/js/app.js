/**
 * CryptAudio Web — Core Frontend Interactions (Phase 9)
 *
 * Implements navigation routing, file drag-and-drop feedback, password visibility toggles,
 * live character counters, clipboard utilities, toast notifications, and client-side
 * demonstration workflows.
 *
 * NOTE: Backend API integration will connect in Phase 10.
 */

(function () {
  'use strict';

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
    }, 3200);
  };

  function escapeHtml(str) {
    return str.replace(/[&<>'"]/g, tag => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[tag] || tag));
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

    // Close mobile drawer if open
    closeMobileSidebar();

    // Update address bar hash smoothly
    if (history.pushState) {
      history.pushState(null, null, `#${targetId}`);
    } else {
      location.hash = `#${targetId}`;
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function setupNavigation() {
    // Navigation links in sidebar
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', function (e) {
        e.preventDefault();
        const target = this.getAttribute('href');
        navigateTo(target);
      });
    });

    // Quick navigation buttons across views
    document.querySelectorAll('[data-target-view]').forEach(btn => {
      btn.addEventListener('click', function (e) {
        e.preventDefault();
        const target = this.getAttribute('data-target-view');
        navigateTo(target);
      });
    });

    // Deep link support from URL hash
    const initialHash = window.location.hash || '#dashboard';
    navigateTo(initialHash);

    // Listen for hash changes (browser back/forward buttons)
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
  // 4. Password Visibility Toggles
  // --------------------------------------------------------------------------
  function setupPasswordToggles() {
    document.querySelectorAll('.btn-toggle-password').forEach(btn => {
      btn.addEventListener('click', function () {
        const targetId = this.getAttribute('data-target');
        const input = document.getElementById(targetId);
        if (!input) return;

        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';

        // Toggle icon visual
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
  // 5. Message Character and Byte Counter
  // --------------------------------------------------------------------------
  function setupMessageCounter() {
    const textarea = document.getElementById('embed-message-input');
    const charCounter = document.getElementById('embed-char-counter');
    const byteCounter = document.getElementById('embed-byte-counter');

    if (!textarea || !charCounter || !byteCounter) return;

    textarea.addEventListener('input', function () {
      const text = this.value;
      const charCount = text.length;
      // Calculate UTF-8 byte length
      const byteCount = new TextEncoder().encode(text).length;

      charCounter.textContent = `${charCount} char${charCount === 1 ? '' : 's'}`;
      byteCounter.textContent = `${byteCount} byte${byteCount === 1 ? '' : 's'}`;

      // Update demonstration capacity progress bar
      updateDemoCapacity(byteCount);
    });
  }

  function updateDemoCapacity(byteCount) {
    const fill = document.getElementById('embed-capacity-fill');
    const label = document.getElementById('embed-capacity-percent');
    if (!fill || !label) return;

    // Demo carrier capacity assumed to be ~55,125 bytes (~500k samples)
    const demoTotalCapacity = 55125;
    const overhead = 46; // 13B stego header + 33B crypto header
    const totalBytes = byteCount > 0 ? byteCount + overhead : 0;
    const percent = Math.min(100, ((totalBytes / demoTotalCapacity) * 100)).toFixed(2);

    fill.style.width = `${Math.max(1, percent)}%`;
    label.textContent = `${percent}% utilized (est. ${totalBytes} / ${demoTotalCapacity.toLocaleString()} B)`;

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
  // 6. Drag-and-Drop File Dropzone Handlers
  // --------------------------------------------------------------------------
  function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

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
          handleFileSelection(files[0], preview);
        }
      });

      input.addEventListener('change', function () {
        if (this.files && this.files.length > 0) {
          handleFileSelection(this.files[0], preview);
        }
      });
    });
  }

  function handleFileSelection(file, previewElement) {
    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.wav')) {
      window.showToast('Please select a PCM WAV audio file (.wav)', 'error');
      return;
    }

    if (previewElement) {
      const nameEl = previewElement.querySelector('.file-preview-name');
      const sizeEl = previewElement.querySelector('.file-preview-size');
      if (nameEl) nameEl.textContent = file.name;
      if (sizeEl) sizeEl.textContent = formatBytes(file.size);
      previewElement.style.display = 'flex';
    }

    window.showToast(`Selected: ${file.name} (${formatBytes(file.size)})`, 'info');
  }

  // --------------------------------------------------------------------------
  // 7. Copy to Clipboard Utility
  // --------------------------------------------------------------------------
  function setupClipboard() {
    document.querySelectorAll('[data-copy-target]').forEach(btn => {
      btn.addEventListener('click', function () {
        const targetId = this.getAttribute('data-copy-target');
        const targetEl = document.getElementById(targetId);
        if (!targetEl) return;

        const text = targetEl.textContent || targetEl.value || '';
        if (!text) {
          window.showToast('No text available to copy', 'error');
          return;
        }

        navigator.clipboard.writeText(text).then(() => {
          window.showToast('Recovered message copied to clipboard!', 'success');
        }).catch(() => {
          // Fallback for older browsers
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
  // 8. Demonstration Mode Action Handlers (Phase 9 Frontend Demo)
  // --------------------------------------------------------------------------
  function setupDemoInteractions() {
    // Embed Demo
    const btnSimulateEmbed = document.getElementById('btn-simulate-embed');
    const embedResult = document.getElementById('embed-result-card');
    if (btnSimulateEmbed && embedResult) {
      btnSimulateEmbed.addEventListener('click', function () {
        const messageInput = document.getElementById('embed-message-input');
        const passwordInput = document.getElementById('embed-password-input');

        if (!messageInput.value.trim()) {
          window.showToast('Please enter a secret message to simulate embedding.', 'error');
          messageInput.focus();
          return;
        }

        if (!passwordInput.value) {
          window.showToast('Please enter a password to derive the encryption key.', 'error');
          passwordInput.focus();
          return;
        }

        btnSimulateEmbed.disabled = true;
        btnSimulateEmbed.innerHTML = '<span class="spinner"></span> Simulating Embedding...';

        setTimeout(() => {
          btnSimulateEmbed.disabled = false;
          btnSimulateEmbed.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg> Simulate Embed (Demo)';
          embedResult.style.display = 'block';
          embedResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          window.showToast('Demonstration embed successful! (Demo simulation only — APIs connect in Phase 10)', 'success');
        }, 1100);
      });
    }

    // Extract Demo
    const btnSimulateExtract = document.getElementById('btn-simulate-extract');
    const extractResult = document.getElementById('extract-result-card');
    if (btnSimulateExtract && extractResult) {
      btnSimulateExtract.addEventListener('click', function () {
        const passwordInput = document.getElementById('extract-password-input');
        if (!passwordInput.value) {
          window.showToast('Please enter the secret passphrase.', 'error');
          passwordInput.focus();
          return;
        }

        btnSimulateExtract.disabled = true;
        btnSimulateExtract.innerHTML = '<span class="spinner"></span> Simulating Extraction...';

        setTimeout(() => {
          btnSimulateExtract.disabled = false;
          btnSimulateExtract.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg> Simulate Extract (Demo)';
          extractResult.style.display = 'block';
          extractResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          window.showToast('Demonstration extraction successful! (Recovered sample decrypted message)', 'success');
        }, 1000);
      });
    }

    // Audio Inspector Demo
    const btnSimulateInspect = document.getElementById('btn-simulate-inspect');
    const inspectResults = document.getElementById('inspect-results-grid');
    if (btnSimulateInspect && inspectResults) {
      btnSimulateInspect.addEventListener('click', function () {
        btnSimulateInspect.disabled = true;
        btnSimulateInspect.innerHTML = '<span class="spinner"></span> Inspecting Audio...';

        setTimeout(() => {
          btnSimulateInspect.disabled = false;
          btnSimulateInspect.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Simulate Inspection (Demo)';
          inspectResults.style.display = 'grid';
          inspectResults.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          window.showToast('Loaded demonstration audio inspection profile.', 'info');
        }, 800);
      });
    }

    // Quality Analysis Demo
    const btnSimulateAnalyze = document.getElementById('btn-simulate-analyze');
    const analyzeResults = document.getElementById('analyze-results-card');
    if (btnSimulateAnalyze && analyzeResults) {
      btnSimulateAnalyze.addEventListener('click', function () {
        btnSimulateAnalyze.disabled = true;
        btnSimulateAnalyze.innerHTML = '<span class="spinner"></span> Computing Numerical Metrics...';

        setTimeout(() => {
          btnSimulateAnalyze.disabled = false;
          btnSimulateAnalyze.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg> Simulate Analysis (Demo)';
          analyzeResults.style.display = 'block';
          analyzeResults.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          window.showToast('Calculated demonstration fidelity metrics (PSNR > 90 dB).', 'success');
        }, 1000);
      });
    }

    // Reset Demo Buttons
    document.querySelectorAll('[data-reset-form]').forEach(btn => {
      btn.addEventListener('click', function () {
        const formId = this.getAttribute('data-reset-form');
        const form = document.getElementById(formId);
        if (form) {
          form.reset();
          const previews = form.querySelectorAll('.file-preview');
          previews.forEach(p => p.style.display = 'none');
          const charCounter = document.getElementById('embed-char-counter');
          const byteCounter = document.getElementById('embed-byte-counter');
          if (charCounter) charCounter.textContent = '0 chars';
          if (byteCounter) byteCounter.textContent = '0 bytes';
          updateDemoCapacity(0);
        }
      });
    });
  }

  // --------------------------------------------------------------------------
  // Document Ready Initialization
  // --------------------------------------------------------------------------
  document.addEventListener('DOMContentLoaded', function () {
    setupNavigation();
    setupMobileSidebar();
    setupPasswordToggles();
    setupMessageCounter();
    setupDropzones();
    setupClipboard();
    setupDemoInteractions();
  });

})();
