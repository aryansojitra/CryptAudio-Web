/**
 * CryptAudio Web — Centralized API Client (Phase 10)
 *
 * Provides asynchronous API communication, multipart/form-data encoding,
 * response parsing, and unified error handling for CryptAudio-Web REST endpoints.
 */

(function () {
  'use strict';

  class APIError extends Error {
    constructor(code, message, status = 0) {
      super(message);
      this.name = 'APIError';
      this.code = code;
      this.status = status;
    }
  }

  /**
   * Safe parser for JSON responses and standard error structures.
   */
  async function parseResponseJson(response) {
    let data = null;
    try {
      data = await response.json();
    } catch (e) {
      throw new APIError(
        'INVALID_RESPONSE',
        `Server returned an unparseable response (HTTP ${response.status}).`,
        response.status
      );
    }

    if (!response.ok || (data && data.success === false)) {
      const err = data && data.error ? data.error : {};
      const code = err.code || `HTTP_${response.status}`;
      const message = err.message || `Request failed with status ${response.status}.`;
      throw new APIError(code, message, response.status);
    }

    return data;
  }

  /**
   * CryptAudio API service object
   */
  const CryptAudioAPI = {
    /**
     * GET /api/health — Checks backend status.
     * @returns {Promise<{status: string, application: string, version: string}>}
     */
    async checkHealth() {
      try {
        const response = await fetch('/api/health', {
          method: 'GET',
          headers: { 'Accept': 'application/json' },
          cache: 'no-cache',
        });
        if (!response.ok) {
          throw new APIError('BACKEND_UNHEALTHY', `Backend returned status ${response.status}`, response.status);
        }
        return await response.json();
      } catch (err) {
        if (err instanceof APIError) throw err;
        throw new APIError('NETWORK_ERROR', 'Unable to reach backend server at 127.0.0.1:8000.', 0);
      }
    },

    /**
     * POST /api/audio/inspect — Inspects WAV carrier audio metadata & capacity.
     * @param {File} file - Audio WAV file
     * @returns {Promise<{audio: object, capacity: object, filename: string}>}
     */
    async inspectAudio(file) {
      if (!file) {
        throw new APIError('MISSING_FILE', 'No audio file provided.');
      }

      const formData = new FormData();
      formData.append('file', file, file.name);

      try {
        const response = await fetch('/api/audio/inspect', {
          method: 'POST',
          body: formData,
          headers: { 'Accept': 'application/json' },
        });
        return await parseResponseJson(response);
      } catch (err) {
        if (err instanceof APIError) throw err;
        throw new APIError('NETWORK_ERROR', 'Network connection failed during audio inspection.', 0);
      }
    },

    /**
     * POST /api/embed — Encrypts and embeds message into carrier WAV sample LSBs.
     * Returns a streaming binary audio file with utilization metadata in response headers.
     *
     * @param {File} file - Carrier WAV audio
     * @param {string} message - Plaintext message
     * @param {string} password - Passphrase
     * @returns {Promise<{blob: Blob, filename: string, payloadSize: number, framedSize: number, utilizationPercent: number}>}
     */
    async embedMessage(file, message, password) {
      if (!file) throw new APIError('MISSING_FILE', 'Carrier audio file is required.');
      if (!message || !message.trim()) throw new APIError('INVALID_MESSAGE', 'Secret message cannot be empty.');
      if (!password) throw new APIError('INVALID_PASSWORD', 'Passphrase cannot be empty.');

      const formData = new FormData();
      formData.append('file', file, file.name);
      formData.append('message', message);
      formData.append('password', password);

      try {
        const response = await fetch('/api/embed', {
          method: 'POST',
          body: formData,
        });

        if (!response.ok) {
          // Parse error JSON body
          return await parseResponseJson(response);
        }

        // Extract metadata from response headers
        const payloadSize = parseInt(response.headers.get('X-Payload-Size-Bytes') || '0', 10);
        const framedSize = parseInt(response.headers.get('X-Framed-Size-Bytes') || '0', 10);
        const utilizationPercent = parseFloat(response.headers.get('X-Utilization-Percent') || '0.0');

        // Extract filename from Content-Disposition if present
        let filename = 'stego.wav';
        const disposition = response.headers.get('Content-Disposition');
        if (disposition && disposition.includes('filename=')) {
          const match = disposition.match(/filename="?([^";]+)"?/i);
          if (match && match[1]) {
            filename = match[1].trim();
          }
        } else if (file.name) {
          const stem = file.name.replace(/\.[^/.]+$/, '');
          filename = `${stem}_stego.wav`;
        }

        const blob = await response.blob();
        return {
          blob,
          filename,
          payloadSize,
          framedSize,
          utilizationPercent,
        };
      } catch (err) {
        if (err instanceof APIError) throw err;
        throw new APIError('NETWORK_ERROR', 'Network connection failed during message embedding.', 0);
      }
    },

    /**
     * POST /api/extract — Extracts and decrypts hidden message from stego WAV file.
     * @param {File} file - Stego WAV file
     * @param {string} password - Passphrase
     * @returns {Promise<{success: boolean, message: string}>}
     */
    async extractMessage(file, password) {
      if (!file) throw new APIError('MISSING_FILE', 'Stego audio file is required.');
      if (!password) throw new APIError('INVALID_PASSWORD', 'Passphrase cannot be empty.');

      const formData = new FormData();
      formData.append('file', file, file.name);
      formData.append('password', password);

      try {
        const response = await fetch('/api/extract', {
          method: 'POST',
          body: formData,
          headers: { 'Accept': 'application/json' },
        });
        return await parseResponseJson(response);
      } catch (err) {
        if (err instanceof APIError) throw err;
        throw new APIError('NETWORK_ERROR', 'Network connection failed during message extraction.', 0);
      }
    },

    /**
     * POST /api/analyze — Compares original and stego WAV files to compute distortion metrics.
     * @param {File} originalFile - Carrier WAV
     * @param {File} stegoFile - Stego WAV
     * @returns {Promise<{success: boolean, analysis: object}>}
     */
    async analyzeAudio(originalFile, stegoFile) {
      if (!originalFile) throw new APIError('MISSING_ORIGINAL', 'Original carrier WAV file is required.');
      if (!stegoFile) throw new APIError('MISSING_STEGO', 'Stego WAV file is required.');

      const formData = new FormData();
      formData.append('original_file', originalFile, originalFile.name);
      formData.append('stego_file', stegoFile, stegoFile.name);

      try {
        const response = await fetch('/api/analyze', {
          method: 'POST',
          body: formData,
          headers: { 'Accept': 'application/json' },
        });
        return await parseResponseJson(response);
      } catch (err) {
        if (err instanceof APIError) throw err;
        throw new APIError('NETWORK_ERROR', 'Network connection failed during quality analysis.', 0);
      }
    },
  };

  // Expose globally
  window.CryptAudioAPI = CryptAudioAPI;
  window.APIError = APIError;
})();
