const fs = require("node:fs");
const crypto = require("node:crypto");
const assert = require("node:assert/strict");
const workflow = JSON.parse(fs.readFileSync("integrations/n8n-tgwitness.json", "utf8"));
const code = workflow.nodes.find(node => node.type === "n8n-nodes-base.code").parameters.jsCode;
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const verify = new AsyncFunction("$input", "$env", "require", code);
const secret = "synthetic-test-key";
const body = Buffer.from(JSON.stringify({schema: "tgwitness.webhook/1", event_id: "a".repeat(64)}));
function signature(timestamp, bytes = body) {
  return `t=${timestamp},v1=${crypto.createHmac("sha256", secret).update(timestamp + ".").update(bytes).digest("hex")}`;
}
function run(header, bytes = body) {
  return verify.call({helpers: {getBinaryDataBuffer: async () => bytes}},
    {first: () => ({json: {headers: {"x-tgwitness-signature": header}}})},
    {TGWITNESS_WEBHOOK_SECRET: secret}, require);
}
(async () => {
  const now = Math.floor(Date.now() / 1000);
  assert.equal((await run(signature(now)))[0].json.accepted, true);
  await assert.rejects(run(signature(now - 600)), /Expired/);
  await assert.rejects(run(signature(now), Buffer.from("changed")), /Signature mismatch/);
  await assert.rejects(run("invalid"), /invalid/);
  assert.equal(workflow.active, false);
  console.log("n8n example passed: valid signature, tamper rejection and timestamp expiry.");
})().catch(error => { console.error(error); process.exitCode = 1; });
