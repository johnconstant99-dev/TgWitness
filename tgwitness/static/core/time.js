export function createTimeFormatter({locale = "en", translate = text => text, zone = "UTC", now = Date.now} = {}) {
  const valid=value=>{try{new Intl.DateTimeFormat('en',{timeZone:value});return value;}catch{return 'UTC';}};
  let displayZone = zone === 'local' ? 'local' : valid(zone);
  const language = locale === "en" ? "en-GB" : locale;
  let absolute, calendar, clock, monthDay, yearDay, weekday, numeric, dayParts;
  const relative = new Intl.RelativeTimeFormat(language, {numeric: "auto"});
  const capital = text => text.charAt(0).toLocaleUpperCase(language) + text.slice(1);

  function rebuild() {
    const timezone = displayZone === 'local' ? {} : {timeZone:displayZone};
    absolute = new Intl.DateTimeFormat(language, {...timezone, year: "numeric", month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23", timeZoneName: "short"});
    calendar = new Intl.DateTimeFormat(language, {...timezone, weekday: "long", year: "numeric", month: "long", day: "numeric"});
    clock = new Intl.DateTimeFormat(language, {...timezone, hour: "2-digit", minute: "2-digit", hourCycle: "h23"});
    monthDay = new Intl.DateTimeFormat(language, {...timezone, month: "long", day: "numeric"});
    yearDay = new Intl.DateTimeFormat(language, {...timezone, year: "numeric", month: "long", day: "numeric"});
    weekday = new Intl.DateTimeFormat(language, {...timezone, weekday: "short"});
    numeric = new Intl.DateTimeFormat(language, {...timezone, year: "2-digit", month: "2-digit", day: "2-digit"});
    dayParts = new Intl.DateTimeFormat('en-CA', {...timezone, year: 'numeric', month: '2-digit', day: '2-digit'});
  }
  function date(value) {
    if (value === null || value === undefined || value === "") return null;
    const result = value instanceof Date ? value : new Date(value);
    return Number.isFinite(result.getTime()) ? result : null;
  }
  function ordinal(value) {
    const [year, month, number] = dayKey(value).split('-').map(Number);
    return Date.UTC(year, month - 1, number) / 86400000;
  }
  function fmtTime(value, {mode = "absolute"} = {}) {
    const instant = date(value);
    if (!instant) return mode === "clock" || mode === "list" ? "" : translate("No data");
    if (mode === "clock") return clock.format(instant);
    if (mode === "list") {
      const age = ordinal(now()) - ordinal(instant);
      return age === 0 ? clock.format(instant) : age > 0 && age < 7 ? weekday.format(instant) : numeric.format(instant);
    }
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
    if (!instant) return translate("Unknown date");
    const age = ordinal(now()) - ordinal(instant);
    if (age === 0 || age === 1) return capital(relative.format(-age, "day"));
    return dayKey(instant).slice(0, 4) === dayKey(now()).slice(0, 4) ? monthDay.format(instant) : yearDay.format(instant);
  }
  function fullDay(value) {
    const instant = date(value);
    return instant ? calendar.format(instant) : translate("Unknown date");
  }
  function dayKey(value) {
    const instant = date(value);
    if (!instant) return "unknown";
    const parts=dayParts.formatToParts(instant);
    return ['year','month','day'].map(key=>parts.find(p=>p.type===key).value).join('-');
  }
  function setZone(value) { displayZone = value === 'local' ? 'local' : valid(value); rebuild(); }
  rebuild();
  return {fmtTime, day, fullDay, dayKey, setZone, get zone() { return displayZone; }};
}
