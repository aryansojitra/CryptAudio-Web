/**
 * tests/test_frontend_logic.js
 * Comprehensive unit and behavioral test suite for CryptAudio-Web Phase M6.1 & M6.2.
 *
 * Verifies:
 * 1. Defensive API Parameter Validation in api.js.
 * 2. No active rawBytes - 62 capacity calculation remains anywhere in app.js.
 * 3. Changing a valid carrier immediately invalidates previous capacity requests.
 * 4. An older inspection response cannot overwrite a newer carrier's metadata.
 * 5. An older capacity response cannot update the current interface.
 * 6. Button state derived from state in finally (no unconditional re-enabling).
 * 7. Changing message, algorithm, or parameters invalidates previous capacity.
 * 8. Audio Inspector usable capacity does not assume universal fixed overhead.
 * 9. CRC32 framing checksum vs AES-GCM verification separation.
 * 10. Embed and extract reset restore parameter defaults.
 * 11. Behavioral: Carrier inspection resolves with malformed or missing capacity metadata.
 * 12. Behavioral: Carrier inspection failure leaves embedding disabled and unavailable.
 * 13. Behavioral: Controlled promise race — Old inspection response cannot overwrite newer carrier metadata.
 * 14. Behavioral: Capacity result becomes stale after message, algorithm, parameter, or file changes.
 * 15. Behavioral: Stale capacity result cannot permit embedding.
 * 16. Behavioral: Current successful capacity result permits embedding.
 * 17. Behavioral: Embed click handler rejects stale capacity even if invoked directly.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

// 1. Setup DOM Mock for testing app.js and api.js
class MockClassList {
  constructor() {
    this.classes = new Set();
  }
  add(...names) { names.forEach(n => this.classes.add(n)); }
  remove(...names) { names.forEach(n => this.classes.delete(n)); }
  contains(name) { return this.classes.has(name); }
  toggle(name, force) {
    if (force !== undefined) {
      if (force) this.classes.add(name);
      else this.classes.delete(name);
      return force;
    }
    if (this.classes.has(name)) {
      this.classes.delete(name);
      return false;
    }
    this.classes.add(name);
    return true;
  }
}

class MockElement {
  constructor(id = '', tagName = 'div') {
    this.id = id;
    this.tagName = tagName.toUpperCase();
    this.textContent = '';
    this.value = '';
    this.style = {};
    this.classList = new MockClassList();
    this.attributes = new Map();
    this.disabled = false;
    this.children = [];
    this.files = [];
    this.eventListeners = {};
    this.parentElement = null;
  }
  setAttribute(name, val) { this.attributes.set(name, String(val)); }
  getAttribute(name) { return this.attributes.get(name) || null; }
  addEventListener(event, fn) {
    if (!this.eventListeners[event]) this.eventListeners[event] = [];
    this.eventListeners[event].push(fn);
  }
  dispatchEvent(event) {
    const list = this.eventListeners[event.type] || [];
    for (const fn of list) {
      fn.call(this, event);
    }
  }
  click() {
    this.dispatchEvent({ type: 'click' });
  }
  querySelector(sel) {
    for (const child of this.children) {
      if (sel.startsWith('.') && child.classList.contains(sel.slice(1))) return child;
      if (sel.startsWith('#') && child.id === sel.slice(1)) return child;
    }
    return null;
  }
  querySelectorAll(sel) {
    const res = [];
    for (const child of this.children) {
      if (sel.startsWith('.') && child.classList.contains(sel.slice(1))) res.push(child);
      if (sel.startsWith('#') && child.id === sel.slice(1)) res.push(child);
    }
    return res;
  }
  appendChild(child) {
    child.parentElement = this;
    this.children.push(child);
    return child;
  }
  removeChild(child) {
    const idx = this.children.indexOf(child);
    if (idx >= 0) {
      child.parentElement = null;
      this.children.splice(idx, 1);
    }
  }
  reset() { this.value = ''; }
  focus() {}
}

const mockDocElements = new Map();
function getOrCreateElement(id, tagName = 'div') {
  if (!mockDocElements.has(id)) {
    mockDocElements.set(id, new MockElement(id, tagName));
  }
  return mockDocElements.get(id);
}

const domReadyCallbacks = [];
const toastLog = [];

// Global window and document mock
global.window = {
  location: { hash: '#dashboard' },
  addEventListener: () => {},
  scrollTo: () => {},
  showToast: (msg, type) => {
    toastLog.push({ msg, type });
  },
};
global.document = {
  getElementById: (id) => getOrCreateElement(id),
  querySelectorAll: (sel) => [],
  addEventListener: (event, fn) => {
    if (event === 'DOMContentLoaded') domReadyCallbacks.push(fn);
  },
  createElement: (tagName) => new MockElement('', tagName),
  body: new MockElement('body', 'body'),
};
global.FormData = class {
  constructor() { this.entries = []; }
  append(k, v) { this.entries.push([k, v]); }
};
global.TextEncoder = require('util').TextEncoder;

// Load api.js
const apiCode = fs.readFileSync(path.join(__dirname, '../frontend/js/api.js'), 'utf8');
eval(apiCode);

const CryptAudioAPI = global.window.CryptAudioAPI;
const APIError = global.window.APIError;

// Read app.js code
const appCode = fs.readFileSync(path.join(__dirname, '../frontend/js/app.js'), 'utf8');
eval(appCode);

// Trigger DOMContentLoaded so app.js registers controllers and test hooks
domReadyCallbacks.forEach(fn => fn());

const internals = global.window.__cryptaudio_internals;

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

async function runTests() {
  console.log('=== CryptAudio-Web Phase M6.1 & M6.2 Logic & Regression Tests ===\n');

  // --------------------------------------------------------------------------
  // TEST 1: Defensive API Parameter Validation
  // --------------------------------------------------------------------------
  console.log('Test 1: Defensive API Parameter Validation in api.js');
  await assert.rejects(async () => {
    await CryptAudioAPI.checkCapacity({ name: 'test.wav' }, 'hello', 12345);
  }, (err) => err instanceof APIError && err.code === 'INVALID_PARAMETER' && err.message.includes('Algorithm parameter must be a string identifier'));

  await assert.rejects(async () => {
    await CryptAudioAPI.embedMessage({ name: 'test.wav' }, 'hello', 'pass', { algo: 'lsb' });
  }, (err) => err instanceof APIError && err.code === 'INVALID_PARAMETER');

  await assert.rejects(async () => {
    await CryptAudioAPI.extractMessage({ name: 'test.wav' }, 'pass', true);
  }, (err) => err instanceof APIError && err.code === 'INVALID_PARAMETER');

  await assert.rejects(async () => {
    await CryptAudioAPI.inspectAudio({ name: 'test.wav' }, 42);
  }, (err) => err instanceof APIError && err.code === 'INVALID_PARAMETER');

  await assert.rejects(async () => {
    await CryptAudioAPI.checkCapacity({ name: 'test.wav' }, 'hello', 'dwt_dct_qim', 'invalid_options');
  }, (err) => err instanceof APIError && err.code === 'INVALID_PARAMETER' && err.message.includes('options must be an object'));

  await assert.rejects(async () => {
    await CryptAudioAPI.checkCapacity({ name: 'test.wav' }, 'hello', 'dwt_dct_qim', { delta: 'not-a-number' });
  }, (err) => err instanceof APIError && err.code === 'INVALID_PARAMETER' && err.message.includes('Delta parameter must be a valid number'));

  await assert.rejects(async () => {
    await CryptAudioAPI.checkCapacity({ name: 'test.wav' }, 'hello', 'echo', { alpha: NaN });
  }, (err) => err instanceof APIError && err.code === 'INVALID_PARAMETER' && err.message.includes('Alpha parameter must be a valid number'));
  console.log('  ✔ api.js defensive validation passed.\n');

  // --------------------------------------------------------------------------
  // TEST 2: No active rawBytes - 62 capacity calculation remains
  // --------------------------------------------------------------------------
  console.log('Test 2: No active rawBytes - 62 capacity calculation remains');
  assert(!appCode.includes('rawBytes - 62'), 'No active rawBytes - 62 capacity calculation allowed');
  assert(!appCode.includes('msgBytes + 62'), 'No active msgBytes + 62 capacity calculation allowed');
  assert(!appCode.includes('msgBytes + 49'), 'No active msgBytes + 49 crypto overhead allowed');
  assert(!appCode.includes('cryptoBytes + 13'), 'No active cryptoBytes + 13 framing overhead allowed');
  assert(!appCode.includes('embedCarrierMaxPlaintext'), 'state.embedCarrierMaxPlaintext must be removed');
  console.log('  ✔ Legacy fixed-overhead calculations completely removed.\n');

  // --------------------------------------------------------------------------
  // TEST 3: Immediate Invalidation When Valid Carrier Changes
  // --------------------------------------------------------------------------
  console.log('Test 3: Changing carrier file immediately invalidates previous capacity requests');
  assert(appCode.includes('state.capacityRequestId++;'), 'Must increment capacityRequestId immediately on new file');
  assert(appCode.includes('state.lastCapacityData = null;'), 'Must clear lastCapacityData immediately on new file');
  assert(appCode.includes('state.embedCanFit = false;'), 'Must reset embedCanFit to false on new file');
  assert(appCode.includes("state.capacityStatus = 'pending';"), 'Must set status to pending on new file');
  console.log('  ✔ Immediate carrier change invalidation logic verified.\n');

  // --------------------------------------------------------------------------
  // TEST 4: Out-of-Order Inspection Protection (Inspection Sequence Counter)
  // --------------------------------------------------------------------------
  console.log('Test 4: Older inspection response cannot overwrite newer carrier metadata');
  assert(appCode.includes('state.inspectionRequestId'), 'state must track inspectionRequestId sequence counter');
  assert(appCode.includes('const thisInspectionId = ++state.inspectionRequestId;'), 'Must generate inspection sequence ID');
  assert(appCode.includes('thisInspectionId !== state.inspectionRequestId || state.embedFile !== file'), 'Must guard inspection response against stale sequence or file mismatch');
  console.log('  ✔ Inspection sequence counter and stale inspection guards verified.\n');

  // --------------------------------------------------------------------------
  // TEST 5: Out-of-Order Capacity Protection (Sequence Counter & Input Fingerprint)
  // --------------------------------------------------------------------------
  console.log('Test 5: Older capacity response cannot update the current interface');
  assert(appCode.includes('computeEmbedInputFingerprint()'), 'Input fingerprint function must exist');
  assert(appCode.includes('requestFingerprint !== currentFingerprint'), 'Stale response guard must compare input fingerprints');
  assert(appCode.includes('thisRequestId !== state.capacityRequestId'), 'Stale response guard must check sequence counter');
  console.log('  ✔ Capacity response fingerprinting and stale response discarding verified.\n');

  // --------------------------------------------------------------------------
  // TEST 6: Embed Button Gating and Correct Finally Restoration
  // --------------------------------------------------------------------------
  console.log('Test 6: Button state derived from state in finally (no unconditional re-enabling)');
  const embedControllerCode = appCode.slice(
    appCode.indexOf('function setupEmbedController()'),
    appCode.indexOf('function setupExtractController()')
  );
  assert(!embedControllerCode.includes('btnSubmit.disabled = false'),
    'setupEmbedController finally block must not unconditionally enable submit button');
  assert(embedControllerCode.includes('updateEmbedButtonState();'),
    'setupEmbedController must call updateEmbedButtonState in finally');
  console.log('  ✔ Derived button state in finally verified.\n');

  // --------------------------------------------------------------------------
  // TEST 7: Input Fingerprint Function & State Verification
  // --------------------------------------------------------------------------
  console.log('Test 7: Changing message, algorithm, or parameters invalidates previous capacity');
  assert(appCode.includes('state.capacityFingerprint = null;'), 'triggerCapacityCheck must clear capacityFingerprint immediately');
  assert(appCode.includes('state.lastCapacityData = null;'), 'triggerCapacityCheck must clear lastCapacityData immediately');
  assert(appCode.includes('state.embedCanFit = false;'), 'triggerCapacityCheck must set embedCanFit to false immediately');
  console.log('  ✔ State invalidation on input change verified.\n');

  // --------------------------------------------------------------------------
  // TEST 8: Audio Inspector Usable Capacity Does Not Assume Universal Fixed Overhead
  // --------------------------------------------------------------------------
  console.log('Test 8: Audio Inspector usable capacity does not assume universal fixed overhead');
  assert(!appCode.match(/setupInspectController[\s\S]*?rawBytes\s*-\s*62/), 'Audio Inspector must not compute rawBytes - 62');
  assert(appCode.includes('Algorithm-dependent: usable capacity varies'), 'Audio Inspector must explain capacity is algorithm-dependent');
  console.log('  ✔ Audio Inspector algorithm-dependent capacity verified.\n');

  // --------------------------------------------------------------------------
  // TEST 9: CRC32 vs AES-GCM Label Separation
  // --------------------------------------------------------------------------
  console.log('Test 9: CRC32 framing checksum vs AES-GCM verification separation');
  assert(appCode.includes('CRC32 Verified (Framing Checksum)'), 'CRC32 must be labeled strictly as framing checksum');
  assert(appCode.includes('Verified (AES-256-GCM Tag)'), 'AES-GCM must be explicitly identified as tag verification');
  assert(appCode.includes('API Success Contract:'), 'API success contract must be documented in comments');
  console.log('  ✔ Extraction verification separation verified.\n');

  // --------------------------------------------------------------------------
  // TEST 10: Complete Reset
  // --------------------------------------------------------------------------
  console.log('Test 10: Embed and extract reset restore parameter defaults');
  assert(appCode.includes('state.embedDelta = 32.0'), 'Embed reset must restore embedDelta to 32.0');
  assert(appCode.includes('state.embedAlpha = 0.08'), 'Embed reset must restore embedAlpha to 0.08');
  assert(appCode.includes('state.extractDelta = 32.0'), 'Extract reset must restore extractDelta to 32.0');
  assert(appCode.includes('state.extractAlpha = 0.08'), 'Extract reset must restore extractAlpha to 0.08');
  assert(appCode.includes("deltaSelect.value = '32'"), 'Reset must restore visible delta select to 32');
  assert(appCode.includes("alphaInput.value = '0.08'"), 'Reset must restore visible alpha input to 0.08');
  console.log('  ✔ Parameter reset logic verified.\n');

  // --------------------------------------------------------------------------
  // TEST 11: Behavioral — Inspection Resolves With Malformed or Missing Capacity Metadata
  // --------------------------------------------------------------------------
  console.log('Test 11: Behavioral — Carrier inspection resolves with malformed or missing capacity metadata');
  const btnEmbedSubmit = getOrCreateElement('btn-embed-submit');
  const fileInput = getOrCreateElement('embed-file-input');
  const preview = getOrCreateElement('embed-file-preview');

  async function assertInvalidCapacityResponse(label, capacityPayload) {
    global.window.CryptAudioAPI.inspectAudio = async () => ({
      success: true,
      audio: { duration_seconds: 2.0 },
      capacity: capacityPayload,
    });
    const testFile = { name: `test_${Math.random()}.wav`, size: 100000, lastModified: 1000 };
    internals.handleFileAssignment('embed-file-input', testFile, preview);
    await new Promise(r => setTimeout(r, 15));

    assert.strictEqual(internals.state.capacityStatus, 'unavailable', `${label}: capacityStatus must be unavailable`);
    assert.strictEqual(internals.state.lastCapacityData, null, `${label}: lastCapacityData must be null`);
    assert.strictEqual(internals.state.capacityFingerprint, null, `${label}: capacityFingerprint must be null`);
    assert.strictEqual(internals.state.embedCanFit, false, `${label}: embedCanFit must be false`);
    assert.strictEqual(internals.state.embedCarrierSamples, 0, `${label}: embedCarrierSamples must be 0`);
    assert.strictEqual(btnEmbedSubmit.disabled, true, `${label}: embed button must remain disabled`);
  }

  // 11.1 capacity is null
  await assertInvalidCapacityResponse('capacity: null', null);

  // 11.2 total_samples is NaN
  await assertInvalidCapacityResponse('total_samples: NaN', { total_samples: NaN, raw_capacity_bytes: 1000 });

  // 11.3 total_samples is Infinity
  await assertInvalidCapacityResponse('total_samples: Infinity', { total_samples: Infinity, raw_capacity_bytes: 5000 });

  // 11.4 total_samples is -Infinity
  await assertInvalidCapacityResponse('total_samples: -Infinity', { total_samples: -Infinity, raw_capacity_bytes: 5000 });

  // 11.5 raw_capacity_bytes is Infinity
  await assertInvalidCapacityResponse('raw_capacity_bytes: Infinity', { total_samples: 44100, raw_capacity_bytes: Infinity });

  // 11.6 raw_capacity_bytes is -Infinity
  await assertInvalidCapacityResponse('raw_capacity_bytes: -Infinity', { total_samples: 44100, raw_capacity_bytes: -Infinity });

  // 11.7 Fractional total_samples
  await assertInvalidCapacityResponse('Fractional total_samples', { total_samples: 44100.5, raw_capacity_bytes: 5000 });

  // 11.8 Fractional raw_capacity_bytes
  await assertInvalidCapacityResponse('Fractional raw_capacity_bytes', { total_samples: 44100, raw_capacity_bytes: 5000.75 });

  // 11.9 Negative total_samples
  await assertInvalidCapacityResponse('Negative total_samples', { total_samples: -10, raw_capacity_bytes: 5000 });

  // 11.10 Negative raw_capacity_bytes
  await assertInvalidCapacityResponse('Negative raw_capacity_bytes', { total_samples: 44100, raw_capacity_bytes: -5 });

  // 11.11 String total_samples
  await assertInvalidCapacityResponse('String total_samples', { total_samples: '44100', raw_capacity_bytes: 5000 });

  // 11.12 Valid integer metadata is accepted
  global.window.CryptAudioAPI.inspectAudio = async () => ({
    success: true,
    audio: { duration_seconds: 2.0 },
    capacity: { total_samples: 44100, raw_capacity_bytes: 5512 },
  });
  const fileValid = { name: 'valid_test.wav', size: 100000, lastModified: 1010 };
  internals.handleFileAssignment('embed-file-input', fileValid, preview);
  await new Promise(r => setTimeout(r, 15));
  assert.strictEqual(internals.state.embedCarrierSamples, 44100, 'Valid integer samples must be accepted');
  assert.strictEqual(internals.state.embedCarrierRawBytes, 5512, 'Valid integer raw capacity bytes must be accepted');

  console.log('  ✔ Malformed, non-finite, and fractional capacity inspection handled correctly; valid integer metadata accepted.\n');

  // --------------------------------------------------------------------------
  // TEST 12: Behavioral — Carrier Inspection Failure Leaves Embedding Disabled
  // --------------------------------------------------------------------------
  console.log('Test 12: Behavioral — Carrier inspection failure leaves embedding disabled and unavailable');
  global.window.CryptAudioAPI.inspectAudio = async () => {
    throw new Error('Carrier inspection 500 internal server error');
  };
  const fileFailed = { name: 'failed.wav', size: 80000, lastModified: 1002 };
  internals.handleFileAssignment('embed-file-input', fileFailed, preview);
  await new Promise(r => setTimeout(r, 15));

  assert.strictEqual(internals.state.capacityStatus, 'unavailable');
  assert.strictEqual(internals.state.embedCanFit, false);
  assert.strictEqual(btnEmbedSubmit.disabled, true);

  // Even if message and password are provided in the DOM:
  getOrCreateElement('embed-message-input').value = 'Top secret';
  getOrCreateElement('embed-password-input').value = 'StrongPass123';
  internals.updateEmbedButtonState();
  assert.strictEqual(btnEmbedSubmit.disabled, true, 'Button must remain disabled when inspection failed');
  console.log('  ✔ Inspection failure behavior verified: status unavailable, embed disabled.\n');

  // --------------------------------------------------------------------------
  // TEST 13: Behavioral — Controlled Promise Async Race: Old Inspection Cannot Overwrite Newer Carrier
  // --------------------------------------------------------------------------
  console.log('Test 13: Behavioral — Controlled promise race: Old inspection response cannot overwrite newer carrier metadata');
  const defFile1 = deferred();
  const defFile2 = deferred();

  global.window.CryptAudioAPI.inspectAudio = (file) => {
    if (file.name === 'carrier1.wav') return defFile1.promise;
    if (file.name === 'carrier2.wav') return defFile2.promise;
    return Promise.reject(new Error('Unknown file'));
  };

  const file1 = { name: 'carrier1.wav', size: 50000, lastModified: 2001 };
  const file2 = { name: 'carrier2.wav', size: 90000, lastModified: 2002 };

  // 1. User selects carrier1
  internals.handleFileAssignment('embed-file-input', file1, preview);
  assert.strictEqual(internals.state.embedFile, file1);

  // 2. User quickly replaces carrier1 with carrier2 before inspection 1 completes
  internals.handleFileAssignment('embed-file-input', file2, preview);
  assert.strictEqual(internals.state.embedFile, file2);

  // 3. Inspection 1 resolves late with carrier1 metadata
  defFile1.resolve({
    audio: { duration_seconds: 1.1 },
    capacity: { total_samples: 11111, raw_capacity_bytes: 22222 },
  });
  await new Promise(r => setTimeout(r, 15));

  // Verify carrier1 response was completely ignored
  assert.strictEqual(internals.state.embedCarrierSamples, 0, 'Old inspection 1 must not overwrite newer state');

  // 4. Inspection 2 resolves with carrier2 metadata
  defFile2.resolve({
    audio: { duration_seconds: 4.5 },
    capacity: { total_samples: 44444, raw_capacity_bytes: 88888 },
  });
  await new Promise(r => setTimeout(r, 15));

  // Verify carrier2 response was accepted
  assert.strictEqual(internals.state.embedCarrierSamples, 44444, 'Latest inspection 2 must be accepted');
  assert.strictEqual(internals.state.embedCarrierRawBytes, 88888);
  console.log('  ✔ Controlled asynchronous race verified: older inspection correctly discarded.\n');

  // --------------------------------------------------------------------------
  // TEST 14: Behavioral — Capacity Result Becomes Stale After Input Changes
  // --------------------------------------------------------------------------
  console.log('Test 14: Behavioral — Capacity result becomes stale after message, algorithm, parameter, or file changes');
  const msgInput = getOrCreateElement('embed-message-input');
  const passInput = getOrCreateElement('embed-password-input');
  const deltaInput = getOrCreateElement('embed-delta-input');
  const alphaInput = getOrCreateElement('embed-alpha-input');

  internals.state.embedFile = file2;
  internals.state.selectedEmbedAlgorithm = 'lsb';
  msgInput.value = 'Initial Secret Message';
  passInput.value = 'Pass123';

  // Simulate a verified successful capacity evaluation for Initial Secret Message + LSB
  internals.state.lastCapacityData = {
    can_fit: true,
    required_bits: 500,
    available_bits: 100000,
    algorithm: 'lsb',
    utilization_percent: 0.5,
  };
  internals.state.capacityFingerprint = internals.computeEmbedInputFingerprint();
  internals.state.embedCanFit = true;
  internals.state.capacityStatus = 'ready';
  internals.updateEmbedButtonState();

  assert.strictEqual(btnEmbedSubmit.disabled, false, 'Button should be enabled when capacity matches current inputs');

  // Case 14a: Message change invalidates fingerprint & disables button
  msgInput.value = 'Modified Secret Message';
  internals.updateEmbedButtonState();
  assert.strictEqual(btnEmbedSubmit.disabled, true, 'Message change must immediately make button disabled');

  // Restore message
  msgInput.value = 'Initial Secret Message';
  internals.updateEmbedButtonState();
  assert.strictEqual(btnEmbedSubmit.disabled, false, 'Restoring exact message re-enables button');

  // Case 14b: Algorithm change invalidates fingerprint & disables button
  internals.state.selectedEmbedAlgorithm = 'dwt_dct_qim';
  internals.updateEmbedButtonState();
  assert.strictEqual(btnEmbedSubmit.disabled, true, 'Algorithm change must immediately make button disabled');

  // Case 14c: Parameter change invalidates fingerprint & disables button
  deltaInput.value = '64';
  internals.updateEmbedButtonState();
  assert.strictEqual(btnEmbedSubmit.disabled, true, 'Delta parameter change must keep button disabled');

  // Case 14d: File change invalidates fingerprint & disables button
  internals.state.selectedEmbedAlgorithm = 'lsb';
  internals.state.embedFile = { name: 'other_carrier.wav', size: 99999, lastModified: 999 };
  internals.updateEmbedButtonState();
  assert.strictEqual(btnEmbedSubmit.disabled, true, 'File change must immediately make button disabled');
  console.log('  ✔ Dynamic input fingerprinting verified: all input mutations immediately invalidate capacity.\n');

  // --------------------------------------------------------------------------
  // TEST 15: Behavioral — Stale Capacity Result Cannot Permit Embedding
  // --------------------------------------------------------------------------
  console.log('Test 15: Behavioral — Stale capacity result cannot permit embedding');
  // Inputs differ from evaluated fingerprint, but lastCapacityData still has can_fit = true:
  internals.state.embedFile = file2;
  msgInput.value = 'New unverified text';
  internals.state.selectedEmbedAlgorithm = 'lsb';
  // lastCapacityData still has can_fit = true from earlier
  assert.strictEqual(internals.state.lastCapacityData.can_fit, true);
  internals.updateEmbedButtonState();
  assert.strictEqual(btnEmbedSubmit.disabled, true, 'Stale capacity data must never enable the button');
  console.log('  ✔ Stale capacity protection verified.\n');

  // --------------------------------------------------------------------------
  // TEST 16: Behavioral — Current Successful Capacity Result Permits Embedding
  // --------------------------------------------------------------------------
  console.log('Test 16: Behavioral — Current successful capacity result permits embedding');
  internals.state.capacityFingerprint = internals.computeEmbedInputFingerprint();
  internals.state.capacityStatus = 'ready';
  internals.state.embedCanFit = true;
  internals.updateEmbedButtonState();
  assert.strictEqual(btnEmbedSubmit.disabled, false, 'Current matching capacity result must enable button');
  console.log('  ✔ Button accurately enabled when capacity is current and sufficient.\n');

  // --------------------------------------------------------------------------
  // TEST 17: Behavioral — Embed Click Handler Rejects Stale Capacity Even If Invoked Directly
  // --------------------------------------------------------------------------
  console.log('Test 17: Behavioral — Embed click handler rejects stale capacity even if invoked directly');
  // Mutate message so input fingerprint is stale
  msgInput.value = 'Secret message mutated after capacity check';
  assert.notStrictEqual(internals.state.capacityFingerprint, internals.computeEmbedInputFingerprint());

  // Manually force button enabled (simulating DOM manipulation or direct programmatic call)
  btnEmbedSubmit.disabled = false;

  let embedApiCallCount = 0;
  global.window.CryptAudioAPI.embedMessage = async () => {
    embedApiCallCount++;
    return { blob: { size: 1000 }, filename: 'stego.wav', algorithm: 'lsb' };
  };

  let capacityCheckTriggered = false;
  // Track capacity check trigger
  const originalCheckCapacity = global.window.CryptAudioAPI.checkCapacity;
  global.window.CryptAudioAPI.checkCapacity = async () => {
    capacityCheckTriggered = true;
    return { can_fit: true, required_bits: 100, available_bits: 10000, algorithm: 'lsb', utilization_percent: 1.0 };
  };

  // Directly invoke the click handler on btnEmbedSubmit
  btnEmbedSubmit.click();
  await new Promise(r => setTimeout(r, 20));

  assert.strictEqual(embedApiCallCount, 0, 'Embed API must NOT be called when capacity fingerprint is stale');
  assert.strictEqual(btnEmbedSubmit.disabled, true, 'Button must be reset to disabled by updateEmbedButtonState');

  // Test with capacityStatus = 'unavailable'
  internals.state.capacityStatus = 'unavailable';
  btnEmbedSubmit.disabled = false;
  btnEmbedSubmit.click();
  await new Promise(r => setTimeout(r, 20));
  assert.strictEqual(embedApiCallCount, 0, 'Embed API must NOT be called when capacityStatus is unavailable');

  // Test with embedCanFit = false
  internals.state.capacityStatus = 'ready';
  internals.state.capacityFingerprint = internals.computeEmbedInputFingerprint();
  internals.state.embedCanFit = false;
  btnEmbedSubmit.disabled = false;
  btnEmbedSubmit.click();
  await new Promise(r => setTimeout(r, 20));
  assert.strictEqual(embedApiCallCount, 0, 'Embed API must NOT be called when embedCanFit is false');

  console.log('  ✔ Direct click handler verification verified: stale or unverified capacity strictly blocked.\n');

  console.log('===========================================================');
  console.log('ALL PHASE M6.1 LOGIC AND REGRESSION TESTS PASSED (17/17).');
  console.log('===========================================================');
}

runTests().catch(err => {
  console.error('\n❌ Test failure:', err);
  process.exit(1);
});
