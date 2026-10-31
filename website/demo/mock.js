


(() => {
  "use strict";
  window.TGW_ONLINE_DEMO = true;
  const base = new URL(".", document.currentScript.src);
  const realFetch = window.fetch.bind(window);
  const answers = realFetch(new URL("fixtures.json", base), {cache: "no-cache"}).then(r => r.json());
  const READ_ONLY = "This online demo is read-only. Run the local demo (scripts\\Demo.cmd or sh start.sh --demo) " +
    "or your own workspace to try actions.";
  const MISSING = "Not included in the online demo. Run the local demo to explore everything.";

  const CATEGORIES = {
    membership: ["membership."],
    messages: ["message.new", "message.snapshot", "message.recovered"],
    media: ["media."], actions: ["interaction."],
    coverage: ["coverage.", "connection.", "collector.", "process.", "observation.", "snapshot.", "target.",
      "capture.", "monitoring.", "source.", "scope.", "telegram.", "clock.", "media.failed", "media.retry",
      "media.recovered", "deletion.unscoped"],
  };

  const json = (status, value) => new Response(JSON.stringify(value),
    {status, headers: {"Content-Type": "application/json"}});

  async function recorded(answer) {
    if ("file" in answer) {
      const response = await realFetch(new URL(answer.file, base));
      if (!response.ok) return response;
      return new Response(response.body, {status: 200, headers: {
        "Content-Type": answer.type, "Content-Length": String(answer.bytes),
      }});
    }
    if ("base64" in answer) {
      const bytes = Uint8Array.from(atob(answer.base64), c => c.charCodeAt(0));
      return new Response(bytes, {status: 200, headers: {"Content-Type": answer.type}});
    }
    return new Response(answer.text, {status: 200, headers: {"Content-Type": answer.type}});
  }


  function events(all, params) {
    const known = new Map();
    for (const [key, answer] of Object.entries(all)) {
      if (!/\/api\/events(\?|$)/.test(key)) continue;
      for (const event of JSON.parse(answer.text).events) known.set(event.seq, event);
    }
    const kinds = (params.get("kind") || "").split(",").map(kind => kind.trim()).filter(Boolean), search = (params.get("search") || "").toLowerCase();
    const chat = params.get("chat_id"), message = params.get("message_id"), before = params.get("before"), after = params.get("after");
    const since = params.get("since"), until = params.get("until");
    const hideSystem = ["true", "1"].includes(params.get("hide_system"));
    const limit = Math.min(500, Math.max(1, Number(params.get("limit")) || 100));
    const matches = [...known.values()].filter(e =>
      (chat === null || String(e.chat_id) === chat) && (message === null || String(e.message_id) === message) &&
      (!kinds.length || kinds.some(kind => (CATEGORIES[kind] || [kind]).some(p => p.endsWith(".") ? e.kind.startsWith(p) : e.kind === p))) &&
      (!hideSystem || !["collector.heartbeat", "host.state"].includes(e.kind) && !(e.kind === "media.skipped" && e.payload.reason === "media download disabled")) &&
      (!since || Date.parse(e.observed_at) >= Date.parse(since)) && (!until || Date.parse(e.observed_at) <= Date.parse(until)) &&
      (!search || JSON.stringify(e.payload).toLowerCase().includes(search)))
      .sort((a, b) => b.seq - a.seq);
    const eligible = matches.filter(e => (before === null || e.seq < Number(before)) && (after === null || e.seq > Number(after)));
    const page = after === null ? eligible.slice(0, limit) : eligible.slice(-limit);
    const counted = ["true", "1"].includes(params.get("include_count"));
    return {events: page,
      next_before: page.length && matches.some(e => e.seq < page.at(-1).seq) ? page.at(-1).seq : null,
      next_after: page.length && matches.some(e => e.seq > page[0].seq) ? page[0].seq : null,
      matched: counted ? matches.length : null, count_exact: counted};
  }

  function chatMessages(all, path, params) {
    const known = new Map(); let included = false;
    for (const [key, answer] of Object.entries(all)) {
      if (key.split('?')[0] !== path) continue;
      included = true;
      for (const message of JSON.parse(answer.text).messages) known.set(message.message_id, message);
    }
    if (!included) return null;
    const before = params.get('before_id'), after = params.get('after_id');
    const limit = Math.min(200, Math.max(1, Number(params.get('limit')) || 60));
    const ordered = [...known.values()].sort((a, b) => a.message_id - b.message_id);
    const matching = ordered.filter(message => (before === null || message.message_id < Number(before))
      && (after === null || message.message_id > Number(after)));
    const messages = after === null ? matching.slice(-limit) : matching.slice(0, limit);
    const first = messages[0]?.message_id, last = messages.at(-1)?.message_id;
    return {messages, next_before: ordered.some(message => message.message_id < first) ? first : null,
      next_after: ordered.some(message => message.message_id > last) ? last : null};
  }

  window.fetch = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.url, location.href);
    const found = url.pathname.match(/\/((?:profiles\/[a-f0-9]{32}\/)?api\/.*)$/);
    if (!found) return realFetch(input, init);
    const method = (init.method || (typeof input === "string" ? "GET" : input.method) || "GET").toUpperCase();
    const path = "/" + found[1];
    if (method === "POST" && path === "/api/verify") {
      const all = await answers;
      if (all[path]) return recorded(all[path]);
    }
    if (method !== "GET") return json(403, {detail: READ_ONLY});
    const all = await answers;
    if (path.endsWith("/api/exports/history")) return json(200, {exports: [], limit: 20});
    if (/\/api\/chats\/-?\d+\/messages$/.test(path)) {
      const messages = chatMessages(all, path, url.searchParams);
      return messages ? json(200, messages) : json(404, {detail: MISSING});
    }
    if (all[path + url.search]) return recorded(all[path + url.search]);
    if (path.endsWith("/api/events")) return json(200, events(all, url.searchParams));
    if (all[path]) return recorded(all[path]);
    return json(404, {detail: MISSING});
  };
})();
