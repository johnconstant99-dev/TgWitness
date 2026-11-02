export function createTimeFormatter({locale = "en", translate = text => text, zone = "UTC", now = Date.now} = {}) {
  const valid=value=>{try{new Intl.DateTimeFormat('en',{timeZone:value});return value;}catch{return 'UTC';}};
  let displayZone = zone === 'local' ? 'local' : valid(zone);
  const language = locale === "en" ? "en-GB" : locale;
  let absolute, calendar;
  const relative = new Intl.RelativeTimeFormat(language, {numeric: "auto"});

  function rebuild() {
    const timezone = displayZone === 'local' ? {} : {timeZone:displayZone};
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
    if (!instant) return translate("No data");
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
    const parts=new Intl.DateTimeFormat('en-CA',{...(displayZone==='local'?{}:{timeZone:displayZone}),year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(instant);
    return ['year','month','day'].map(key=>parts.find(p=>p.type===key).value).join('-');
  }
  function setZone(value) { displayZone = value === 'local' ? 'local' : valid(value); rebuild(); }
  rebuild();
  return {fmtTime, day, dayKey, setZone, get zone() { return displayZone; }};
}
