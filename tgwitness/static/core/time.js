// All panel dates share one display zone. Saved journal timestamps stay untouched.
export function createTimeFormatter({locale = "en", translate = text => text, zone = "UTC", now = Date.now} = {}) {
  let displayZone = zone === "local" ? "local" : "UTC";
  const language = locale === "en" ? "en-GB" : locale;
  let absolute, calendar;
  const relative = new Intl.RelativeTimeFormat(language, {numeric: "auto"});

  function rebuild() {
    const timezone = displayZone === "UTC" ? {timeZone: "UTC"} : {};
    absolute = new Intl.DateTimeFormat(language, {...timezone, year: "numeric", month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23", timeZoneName: "short"});
    calendar = new Intl.DateTimeFormat(language, {...timezone, weekday: "long", year: "numeric", month: "long", day: "numeric"});
  }
  function date(value) {
    if (value === null || value === undefined || value === "") return null;
    const result = value instanceof Date ? value : new Date(value);
    return Number.isFinite(result.getTime()) ? result : null;
  }
  function fmtTime(value, {mode = "absolute"} = {}) {
    const instant = date(value);
    if (!instant) return translate("Not supplied");
    if (mode !== "relative") return absolute.format(instant);
    const seconds = (instant.getTime() - now()) / 1000;
    const magnitude = Math.abs(seconds);
    const [unit, size] = magnitude < 60 ? ["second", 1] : magnitude < 3600 ? ["minute", 60]
      : magnitude < 86400 ? ["hour", 3600] : magnitude < 2592000 ? ["day", 86400]
      : magnitude < 31536000 ? ["month", 2592000] : ["year", 31536000];
    return relative.format(Math.trunc(seconds / size), unit);
  }
  function day(value) {
    const instant = date(value);
    return instant ? calendar.format(instant) : translate("Unknown date");
  }
  function dayKey(value) {
    const instant = date(value);
    if (!instant) return "unknown";
    const prefix = displayZone === "UTC" ? "getUTC" : "get";
    return [instant[prefix + "FullYear"](), instant[prefix + "Month"]() + 1, instant[prefix + "Date"]()]
      .map((part, index) => String(part).padStart(index ? 2 : 4, "0")).join("-");
  }
  function setZone(value) { displayZone = value === "local" ? "local" : "UTC"; rebuild(); }
  rebuild();
  return {fmtTime, day, dayKey, setZone, get zone() { return displayZone; }};
}
