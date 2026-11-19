/**
 * CryptAudio Web — Centralized API Client (Phases 10 & M6)
 *
 * Provides asynchronous API communication, multipart/form-data encoding,
 * response parsing, and unified error handling for CryptAudio-Web REST endpoints.
 * Supports multi-algorithm steganography (LSB, DWT-DCT-QIM, Echo Hiding).
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
        throw new APIError('NETWORK_ERROR', 'Unable to reach backend server.', 0);
      }
    },

    /**
     * GET /api/algorithms — Lists registered steganography algorithms.
     * @returns {Promise<{success: boolean, algorithms: Array<{algorithm_id: string, display_name: string, domain: string, robustness_objective: string}>}>}
     */
    async listAlgorithms() {
      try {
        const response = await fetch('/api/algorithms', {
          method: 'GET',
          headers: { 'Accept': 'application/json' },
          cache: 'no-cache',
        });
        return await parseResponseJson(response);
      } catch (err) {
        if (err instanceof APIError) throw err;
        throw new APIError('NETWORK_ERROR', 'Failed to retrieve available steganography algorithms.', 0);
      }
    },

    /**
     * POST /api/audio/inspect — Inspects WAV carrier audio metadata & capacity.
     * @param {File} file - Audio WAV file
     * @param {string|null} algorithm - Optional algorithm filter
     * @returns {Promise<{audio: object, capacity: object, filename: string, stego_inspection: object, available_algorithms: Array}>}
     */
    async inspectAudio(file, algorithm = null) {
      if (!file) {
        throw new APIError('MISSING_FILE', 'No audio file provided.');
      }

      if (algorithm !== null && algorithm !== undefined) {
        if (typeof algorithm !== 'string') {
          throw new APIError('INVALID_PARAMETER', 'Algorithm parameter must be a string identifier.');
        }
      }

      const formData = new FormData();
      formData.append('file', file, file.name);
      if (algorithm && typeof algorithm === 'string' && algorithm.trim()) {
        formData.append('algorithm', algorithm.trim().toLowerCase());
      }

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
     * POST /api/capacity — Estimates carrier capacity for target message and algorithm.
     * Authoritative backend capacity endpoint for all steganography algorithms.
     *
     * @param {File} file - Carrier WAV audio
     * @param {string} message - Target plaintext message
     * @param {string} algorithm - Steganography algorithm ('lsb', 'dwt_dct_qim', 'echo')
     * @param {object} options - Optional algorithm parameters (delta, alpha)
     * @param {object} requestOptions - Optional fetch options (e.g. signal for AbortController)
     * @returns {Promise<{success: boolean, can_fit: boolean, algorithm: string, message_utf8_bytes: number, estimated_crypto_bytes: number, framed_payload_bytes: number, required_bits: number, available_bits: number, utilization_percent: number, bits_per_sample: number, recommended_min_duration_sec: number}>}
     */
    async checkCapacity(file, message, algorithm = 'lsb', options = {}, requestOptions = {}) {
      if (!file) throw new APIError('MISSING_FILE', 'Carrier audio file is required.');
      if (!message || !message.trim()) throw new APIError('INVALID_MESSAGE', 'Secret message cannot be empty.');

      if (algorithm !== null && algorithm !== undefined && typeof algorithm !== 'string') {
        throw new APIError('INVALID_PARAMETER', 'Algorithm parameter must be a string identifier.');
      }
      if (options !== null && options !== undefined && typeof options !== 'object') {
        throw new APIError('INVALID_PARAMETER', 'Algorithm options must be an object.');
      }

      const cleanAlgo = (typeof algorithm === 'string' && algorithm.trim()) ? algorithm.trim().toLowerCase() : 'lsb';
      const formData = new FormData();
      formData.append('file', file, file.name);
      formData.append('message', message);
      formData.append('algorithm', cleanAlgo);

      if (cleanAlgo === 'dwt_dct_qim' && options && options.delta !== undefined && options.delta !== null) {
        if (typeof options.delta !== 'number' || isNaN(options.delta)) {
          throw new APIError('INVALID_PARAMETER', 'Delta parameter must be a valid number.');
        }
        formData.append('delta', options.delta);
      } else if (cleanAlgo === 'echo' && options && options.alpha !== undefined && options.alpha !== null) {
        if (typeof options.alpha !== 'number' || isNaN(options.alpha)) {
          throw new APIError('INVALID_PARAMETER', 'Alpha parameter must be a valid number.');
        }
        formData.append('alpha', options.alpha);
      }

      try {
        const fetchOptions = {
          method: 'POST',
          body: formData,
          headers: { 'Accept': 'application/json' },
        };
        if (requestOptions && requestOptions.signal) {
          fetchOptions.signal = requestOptions.signal;
        }

        const response = await fetch('/api/capacity', fetchOptions);
        return await parseResponseJson(response);
      } catch (err) {
        if (err.name === 'AbortError') throw err;
        if (err instanceof APIError) throw err;
        throw new APIError('NETWORK_ERROR', 'Network connection failed during capacity evaluation.', 0);
      }
    },

    /**
     * POST /api/embed — Encrypts and embeds message into carrier WAV using chosen algorithm.
     * Returns a streaming binary audio file with utilization metadata in response headers.
     *
     * @param {File} file - Carrier WAV audio
     * @param {string} message - Plaintext message
     * @param {string} password - Passphrase
     * @param {string} algorithm - Steganography algorithm ('lsb', 'dwt_dct_qim', 'echo')
     * @param {object} options - Algorithm-specific options (delta, alpha)
     * @returns {Promise<{blob: Blob, filename: string, payloadSize: number, framedSize: number, utilizationPercent: number, algorithm: string, requiredBits: number, availableBits: number}>}
     */
    async embedMessage(file, message, password, algorithm = 'lsb', options = {}) {
      if (!file) throw new APIError('MISSING_FILE', 'Carrier audio file is required.');
      if (!message || !message.trim()) throw new APIError('INVALID_MESSAGE', 'Secret message cannot be empty.');
      if (!password) throw new APIError('INVALID_PASSWORD', 'Passphrase cannot be empty.');

      if (algorithm !== null && algorithm !== undefined && typeof algorithm !== 'string') {
        throw new APIError('INVALID_PARAMETER', 'Algorithm parameter must be a string identifier.');
      }
      if (options !== null && options !== undefined && typeof options !== 'object') {
        throw new APIError('INVALID_PARAMETER', 'Algorithm options must be an object.');
      }

      const cleanAlgo = (typeof algorithm === 'string' && algorithm.trim()) ? algorithm.trim().toLowerCase() : 'lsb';
      const formData = new FormData();
      formData.append('file', file, file.name);
      formData.append('message', message);
      formData.append('password', password);
      formData.append('algorithm', cleanAlgo);

      if (cleanAlgo === 'dwt_dct_qim' && options && options.delta !== undefined && options.delta !== null) {
        if (typeof options.delta !== 'number' || isNaN(options.delta)) {
          throw new APIError('INVALID_PARAMETER', 'Delta parameter must be a valid number.');
        }
        formData.append('delta', options.delta);
      } else if (cleanAlgo === 'echo' && options && options.alpha !== undefined && options.alpha !== null) {
        if (typeof options.alpha !== 'number' || isNaN(options.alpha)) {
          throw new APIError('INVALID_PARAMETER', 'Alpha parameter must be a valid number.');
        }
        formData.append('alpha', options.alpha);
      }

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
        const stegoAlgorithm = response.headers.get('X-Stego-Algorithm') || cleanAlgo;
        const requiredBits = parseInt(response.headers.get('X-Required-Bits') || '0', 10);
        const availableBits = parseInt(response.headers.get('X-Available-Bits') || '0', 10);

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
          algorithm: stegoAlgorithm,
          requiredBits,
          availableBits,
        };
      } catch (err) {
        if (err instanceof APIError) throw err;
        throw new APIError('NETWORK_ERROR', 'Network connection failed during message embedding.', 0);
      }
    },

    /**
     * POST /api/extract — Extracts and decrypts hidden message from stego WAV file.
     * Supports automatic detection or explicit algorithm selection.
     *
     * @param {File} file - Stego WAV file
     * @param {string} password - Passphrase
     * @param {string|null} algorithm - Optional algorithm ('auto', 'lsb', 'dwt_dct_qim', 'echo')
     * @param {object} options - Algorithm-specific options (delta, alpha)
     * @returns {Promise<{success: boolean, message: string, algorithm: string, payload_size_bytes: number, framing_checksum_verified: boolean}>}
     */
    async extractMessage(file, password, algorithm = null, options = {}) {
      if (!file) throw new APIError('MISSING_FILE', 'Stego audio file is required.');
      if (!password) throw new APIError('INVALID_PASSWORD', 'Passphrase cannot be empty.');

      if (algorithm !== null && algorithm !== undefined && typeof algorithm !== 'string') {
        throw new APIError('INVALID_PARAMETER', 'Algorithm parameter must be a string identifier.');
      }
      if (options !== null && options !== undefined && typeof options !== 'object') {
        throw new APIError('INVALID_PARAMETER', 'Algorithm options must be an object.');
      }

      const formData = new FormData();
      formData.append('file', file, file.name);
      formData.append('password', password);

      const cleanAlgo = (typeof algorithm === 'string' && algorithm.trim()) ? algorithm.trim().toLowerCase() : null;
      if (cleanAlgo && cleanAlgo !== 'auto') {
        formData.append('algorithm', cleanAlgo);
        if (cleanAlgo === 'dwt_dct_qim' && options && options.delta !== undefined && options.delta !== null) {
          if (typeof options.delta !== 'number' || isNaN(options.delta)) {
            throw new APIError('INVALID_PARAMETER', 'Delta parameter must be a valid number.');
          }
          formData.append('delta', options.delta);
        } else if (cleanAlgo === 'echo' && options && options.alpha !== undefined && options.alpha !== null) {
          if (typeof options.alpha !== 'number' || isNaN(options.alpha)) {
            throw new APIError('INVALID_PARAMETER', 'Alpha parameter must be a valid number.');
          }
          formData.append('alpha', options.alpha);
        }
      } else if (cleanAlgo === 'auto') {
        formData.append('algorithm', 'auto');
      }

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
