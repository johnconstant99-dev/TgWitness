// Secret display rules: useful signals, preserved ordinary text, bounded scan time.
const assert = require('node:assert/strict');
global.window = {addEventListener() {}};
Object.defineProperty(globalThis, 'localStorage', {value: {getItem() {return null;}, setItem() {}}});
require('../tgwitness/static/privacy.js');
const privacy = window.TgWitnessPrivacy;
for (const [input, secret] of [
  ['Password: TopSecret-1234', 'TopSecret-1234'],
  ['пароль: секретный123', 'секретный123'],
  ['card 4111 1111 1111 1111', '4111 1111 1111 1111'],
  ['api_key=abcdef123456', 'abcdef123456'],
  ['token '+'sk-'+'proj-'+'abcdefghijklmnopqrstuvwxyz', 'abcdefghijklmnopqrstuvwxyz'],
  ['password: "phrase with spaces"', 'phrase with spaces'],
  ['Bearer eyJabcdefghij.abcdefghij.abcdefghijklmnop', 'abcdefghij'],
  ['-----BEGIN '+'PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----', 'secret'],
  ['bot 123456789:'+ 'abcdefghijklmnopqrstuvwxyz123456789', 'abcdefghijklmnopqrstuvwxyz123456789'],
  ['login code: 123456', '123456'],
  ['код входа: 654321', '654321'],
  ['session '+'1'+'A'.repeat(350), 'A'.repeat(20)],
]) {
  const masked = privacy.preview(input);
  assert(masked.includes('•••••'), input);
  assert(!masked.includes(secret), input);
}
for (const ordinary of ['card 4111 1111 1111 1112', 'ordinary text <b>literal</b>', 'Meeting at 14:15', '2026-11-01']) {
  assert.equal(privacy.preview(ordinary), ordinary);
}
const original = {hash: 'ab'.repeat(32), previous_hash: 'a'.repeat(24)+'4111111111111111'+'b'.repeat(24),
  signature: 'cd'.repeat(64), payload: {text: 'Password: sensitive123', api_hash: 'secret_api_hash'}};
const snapshot = JSON.stringify(original), shown = JSON.parse(privacy.recordPreview(original));
assert.equal(shown.hash, original.hash);
assert.equal(shown.previous_hash, original.previous_hash, 'A chain hash must not be mistaken for a card number');
assert.equal(shown.signature, original.signature);
assert(!shown.payload.text.includes('sensitive123'));
assert(!shown.payload.api_hash.includes('secret_api_hash'));
assert.equal(JSON.stringify(original), snapshot);
const start = performance.now();
privacy.preview('password '.repeat(100000));
assert(performance.now() - start < 5000, 'Large pasted messages must not freeze the panel');
console.log('PASS: secrets and cards masked, ordinary text retained, journal untouched, bounded scan');
