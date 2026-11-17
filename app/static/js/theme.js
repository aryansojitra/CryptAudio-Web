/**
 * CryptAudio Web — Theme Manager (Phase 9)
 *
 * Implements Light Theme as primary/default with optional Dark Theme toggle.
 * Manages localStorage persistence, root attribute 'data-theme', and UI iconography.
 */

(function () {
  'use strict';

  const STORAGE_KEY = 'cryptaudio_theme';
  const THEME_LIGHT = 'light';
  const THEME_DARK = 'dark';

  /**
   * Safely retrieve the stored theme from localStorage.
   * Defaults strictly to 'light' per specification.
   */
  function getStoredTheme() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored === THEME_DARK || stored === THEME_LIGHT) {
        return stored;
      }
    } catch (e) {
      // localStorage unavailable (e.g. private browsing or strict security)
      console.warn('localStorage not available; defaulting to light theme.', e);
    }
    return THEME_LIGHT;
  }

  /**
   * Persist the chosen theme in localStorage.
   */
  function storeTheme(theme) {
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch (e) {
      console.warn('Failed to save theme in localStorage.', e);
    }
  }

  /**
   * Apply the theme to the root <html> element and update toggle button state.
   */
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);

    const toggleBtn = document.getElementById('theme-toggle-btn');
    const sunIcon = document.getElementById('icon-theme-sun');
    const moonIcon = document.getElementById('icon-theme-moon');

    if (toggleBtn) {
      const isDark = theme === THEME_DARK;
      toggleBtn.setAttribute('aria-label', isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme');
      toggleBtn.setAttribute('title', isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme');

      if (sunIcon && moonIcon) {
        if (isDark) {
          sunIcon.style.display = 'block';
          moonIcon.style.display = 'none';
        } else {
          sunIcon.style.display = 'none';
          moonIcon.style.display = 'block';
        }
      }
    }

    // Dispatch event for any other components listening to theme shifts
    window.dispatchEvent(new CustomEvent('cryptaudio:theme-change', { detail: { theme } }));
  }

  /**
   * Toggle between light and dark themes.
   */
  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || THEME_LIGHT;
    const next = current === THEME_LIGHT ? THEME_DARK : THEME_LIGHT;
    storeTheme(next);
    applyTheme(next);

    if (window.showToast) {
      window.showToast(`Switched to ${next === THEME_DARK ? 'Dark' : 'Light'} Theme`, 'info');
    }
  }

  // Initialize theme on DOMContentLoaded
  document.addEventListener('DOMContentLoaded', function () {
    const initialTheme = getStoredTheme();
    applyTheme(initialTheme);

    const toggleBtn = document.getElementById('theme-toggle-btn');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', toggleTheme);
    }
  });

  // Expose toggle function globally if needed
  window.CryptAudioTheme = {
    getTheme: function () {
      return document.documentElement.getAttribute('data-theme') || THEME_LIGHT;
    },
    toggle: toggleTheme,
    set: function (theme) {
      if (theme === THEME_LIGHT || theme === THEME_DARK) {
        storeTheme(theme);
        applyTheme(theme);
      }
    }
  };
})();
