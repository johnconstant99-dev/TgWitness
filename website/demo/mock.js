/* TgWitness online demo: the real panel, answered from recorded demo records.
   Loaded before the panel scripts. Every change is refused, so nothing can be stored,
   sent or connected from the website. Records are fictional (tools/capture_demo.py). */
(() => {
  "use strict";
  const base = new URL(".", document.currentScript.src);
  const realFetch = window.fetch.bind(window);
  const answers = realFetch(new URL("fixtures.json", base), {cache: "no-cache"}).then(r => r.json());
  const READ_ONLY = "This online demo is read-only. Run the local demo (scripts\\Demo.cmd or sh start.sh --demo) " +
    "or your own workspace to try actions.";
  const MISSING = "Not included in the online demo. Run the local demo to explore everything.";
  // Journal categories, as the collector groups them (tgwitness/store.py).
  const CATEGORIES = {
    membership: ["membership."],
    coverage: ["coverage.", "connection.", "collector.", "process.", "observation.", "snapshot.", "target.",
      "capture.", "monitoring.", "source.", "scope.", "telegram.", "clock.", "media.failed", "media.retry",
      "media.recovered", "deletion.unscoped"],
  };

  const json = (status, value) => new Response(JSON.stringify(value),
    {status, headers: {"Content-Type": "application/json"}});

  function recorded(answer) {
    if ("base64" in answer) {
      const bytes = Uint8Array.from(atob(answer.base64), c => c.charCodeAt(0));
      return new Response(bytes, {status: 200, headers: {"Content-Type": answer.type}});
    }
    return new Response(answer.text, {status: 200, headers: {"Content-Type": answer.type}});
  }

  // Answers journal queries that were not recorded verbatim from every recorded record.
  function events(all, params) {
    const known = new Map();
    for (const [key, answer] of Object.entries(all)) {
      if (!/\/api\/events(\?|$)/.test(key)) continue;
      for (const event of JSON.parse(answer.text).events) known.set(event.seq, event);
    }
    const kind = params.get("kind"), search = (params.get("search") || "").toLowerCase();
    const chat = params.get("chat_id"), message = params.get("message_id"), before = params.get("before");
    const limit = Math.min(500, Math.max(1, Number(params.get("limit")) || 100));
    const matches = [...known.values()].filter(e =>
      (chat === null || String(e.chat_id) === chat) && (message === null || String(e.message_id) === message) &&
      (!kind || (CATEGORIES[kind] ? CATEGORIES[kind].some(p => e.kind.startsWith(p)) : e.kind === kind)) &&
      (before === null || e.seq < Number(before)) &&
      (!search || JSON.stringify(e.payload).toLowerCase().includes(search)))
      .sort((a, b) => b.seq - a.seq).slice(0, limit);
    return {events: matches, next_before: matches.length === limit ? matches[matches.length - 1].seq : null};
  }

  window.fetch = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.url, location.href);
    const found = url.pathname.match(/\/((?:profiles\/[a-f0-9]{32}\/)?api\/.*)$/);
    if (!found) return realFetch(input, init);
    const method = (init.method || (typeof input === "string" ? "GET" : input.method) || "GET").toUpperCase();
    if (method !== "GET") return json(403, {detail: READ_ONLY});
    const all = await answers, path = "/" + found[1];
    if (all[path + url.search]) return recorded(all[path + url.search]);
    if (path.endsWith("/api/events")) return json(200, events(all, url.searchParams));
    if (all[path]) return recorded(all[path]);
    return json(404, {detail: MISSING});
  };
})();
