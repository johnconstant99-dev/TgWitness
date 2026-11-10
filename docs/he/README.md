<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">שפות נוספות</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — עקבו אחר השובל. שמרו את הראיות. יומן חתום המקושר בגיבובים, נקודת ביקורת שנשמרת בנפרד וארכיון ראיות שניתן לאמת.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=he"><b>לסיור בהדגמה&nbsp;↗</b></a><br><sub>הממשק האמיתי עם רשומות בדויות</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>הורדה והפעלה&nbsp;↓</b></a><br><sub>פקודה אחת ל-Linux, ל-macOS ול-Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>לקריאת המדריך&nbsp;↗</b></a><br><sub>מדריכי חקירה, צעד אחר צעד</sub></td>
</tr>
</table>

<p align="center"><strong>סביבת עבודה באירוח עצמי לחקירות ב-Telegram.</strong><br>שמרו צ'אטים ואת העריכות והמחיקות שבהם, ראו מי קשור למי<br>ומסרו ייצואים חתומים שכל אחד יכול לבדוק.</p>

<p align="center"><strong>אפס אמון.</strong> TgWitness אינו נוקט צד: אותן בדיקות חלות על המפעיל, על PhishDestroy ועל כל אחד אחר.<br>נחשב רק מה שצד שלישי או המתמטיקה מאשרים. <a href="../LIMITS-AND-OBJECTIONS.md">מגבלות והשגות</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.2 · גרסה מקדימה"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">סביבות שנבדקו</a> · 25 שפות ממשק · 26 שפות מדריך</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=he">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="הדגמת TgWitness בפעולה: הודעות שנלכדו, גרסאות שמורות ותוכן שנשמר אחרי מחיקה. רשומות הדגמה בדויות.">
</picture>
</a>

<p align="center"><sub>סיירו בממשק האמיתי עם רשומות בדויות. לחצו על סביבת העבודה כדי לנסות.</sub></p>

## מה TgWitness עושה

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">כל עריכה וכל מחיקה נשמרות</a></b><br><sub>כל גרסה של הודעה נשמרת, והטקסט שלה נשאר גם אחרי התראת מחיקה.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">הוכחה שכל אחד יכול לבדוק</a></b><br><sub>רשומות חתומות בשרשרת גיבובים. הנמען מאמת את הארכיון במצב לא מקוון בפקודה אחת.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">מקור שאפשר להראות</a></b><br><sub>ההודעות מתקבלות דרך סשן ה-MTProto המאומת של החשבון ונחתמות עם הגעתן; GitHub Actions ו-Intel TDX מוסיפים אטסטציה.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">נמדד בקנה מידה גדול</a></b><br><sub>48 ארכיונים מאומתים עם 3,598,381 רשומות; שמונה חשבונות אספו 768,007 רשומות היסטוריה בקצב של 687.5 רשומות לשנייה.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">בנוי לחקירות</a></b><br><sub>רשימות מעקב על טקסט, קודי QR ו-OCR, בדיקת ארנקים, כרטיסי מושא, לוח התיק וחבילה לבית המשפט.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">בשליטתכם</a></b><br><sub>אירוח עצמי ללא טלמטריה. הסשנים נשמרים בכספת מוצפנת; הפאנל מאזין ב-localhost.</sub></td>
</tr>
</table>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## התקנה

ההתקנה כוללת Python. אותן פקודות משמשות גם לעדכון.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell או CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>בשרת Ubuntu: הריצו כ-root. במחשב שולחני: הריצו כמשתמש הרגיל שלכם. `-ExecutionPolicy Bypass` חל רק על תהליך PowerShell זה.</sub>

בניות חתומות מגיעות מ[תהליך העבודה של המתקין](../../.github/workflows/installer.yml) הציבורי, והמתקין בודק את ה-SHA-256 ואת חתימת ה-RSA של כל חבילה לפני ההתקנה.

[אמתו קודם את הסקריפט](../INSTALLATION.md#verify-before-running) · [הגדרה ראשונה](../SETTINGS.md) · [גרסאות](https://github.com/phishdestroy/TgWitness/releases) · [Docker](../DEPLOYMENT.md)

<details>
<summary><strong>איך המתקין והנתונים שלכם מוגנים</strong></summary>

אתר ההורדות של הפרויקט הוא `get.destroy.tools`.
[תהליך העבודה של המתקין](../../.github/workflows/installer.yml) הציבורי בונה אותו מתוך
[`deploy/installer/`](../../deploy/installer/README.md) עבור הרוויזיה המדויקת של `main`,
מפרסם אותו אחרי שבדיקות ההתקנה ב-Linux וב-Windows עוברות, וחותם על
סקריפטי ההתקנה ועל חבילות היישום במפתח השחרור שב-[`release-signing.pub`](../../deploy/installer/release-signing.pub).
המתקין בודק את ה-SHA-256 ואת חתימת ה-RSA של החבילה
ושל קובץ נעילת התלויות לפני ההתקנה.
כדי לבדוק קודם את הסקריפט עצמו, הורידו אותו יחד עם החתימה שלו והריצו את
[פקודות האימות המוקדם](../INSTALLATION.md#verify-before-running). בנייה שנכשלה
משאירה את ההורדה הקודמת; פאנלים מותקנים מתעדכנים כשמריצים שוב את המתקין.
דרכי ההתקנה האחרות הן [גרסאות GitHub](https://github.com/phishdestroy/TgWitness/releases), קוד המקור
ו-[Docker](../DEPLOYMENT.md).

**הסשנים והנתונים שלכם.** TgWitness פועל במחשב או בשרת שלכם, והפאנל
מאזין כברירת מחדל ב-localhost. סשני Telegram, פרטי הגישה לפרוקסי וגיבובי אסימוני הגישה
נשמרים בכספת המוצפנת של כל סביבת עבודה, ואפשר גם להשתמש
ב[מפתח ראשי חיצוני](../SECURITY-MODEL.md#external-master-key). ליישום
אין טלמטריה. הוא מתחבר ל-Telegram ולשירותים שבהם משתמשות ההגדרות שלו:
רשימות MTProxy ציבוריות, הפרוקסי שלכם, אחסון S3, בוט העד, רשויות
חותמות זמן, ספקי AI ו-webhooks. [מפת המערכת](../SYSTEM-MAP.md)
מפרטת את החיבורים שתהליך היישום יוצר.
לתצפית השתמשו ב[חשבון Telegram ייעודי](https://phishdestroy.github.io/TgWitness/he/docs/dedicated-account/).

תג הגרסה מתאר את עץ המקור הזה. בניות להתקנה מופיעות תחת
[גרסאות](https://github.com/phishdestroy/TgWitness/releases); יכולת שמוזגה ל-`main`
מגיעה להורדות האלה עם הגרסה הבאה.

[התקנה וגישה לפאנל](../INSTALLATION.md) ·
[חתימות ו-SHA-256](https://get.destroy.tools/#verification) ·
[עדכון](../INSTALLATION.md#update-an-existing-installation) ·
[יכולות נוכחיות והסמכה](../STATUS.md) ·
[בחירת שיטת איסוף](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## רשומה שמישהו אחר יכול לבדוק

בדקו בלי חשבון ובלי התקנה. הדוגמה שפורסמה כוללת כלי אימות משלה:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # כלי האימות נמצא בתוך הארכיון
python verify.py tgwitness-demo.zip          # Python 3.11+, נדרשת רק `cryptography`
```

הוא מדפיס את הרשומות החתומות, את גיבוב הראש ואת טביעת האצבע של החותם, ויוצא עם קוד `0`.
הדוגמה בדויה; אותו כלי אימות פועל על כל ייצוא אמיתי.

ייצוא כולל את ההודעות, הקבצים וכלי האימות. שלחו לנמען את טביעת האצבע
של המפתח שלכם בערוץ אחר, והוא יוכל לבדוק בעצמו:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

כלי האימות בודק את החתימות, את שרשרת היומן, את רשימת הקבצים ואת הקבצים המצורפים.
לרמת ראיה הוא דורש את טביעת האצבע של המפתח שלכם וחותמת זמן של צד שלישי שמכסה את
הרשומה האחרונה, למשל חותמת זמן RFC 3161 שנבדקה מול אישור הבסיס של הרשות המנפיקה.

**מאיפה ההודעות מגיעות.** TgWitness מקבל אותן מ-Telegram דרך
סשן ה-MTProto המוצפן של החשבון, כמו היישומים הרשמיים, וחותם כל אחת מהן לתוך
היומן עם הגעתה. [לכידה ב-GitHub Actions](../SEALED-ACTIONS.md) ו-[Phala Intel TDX](../HIGH-ASSURANCE.md)
מספקים גם אטסטציה לרכיב האיסוף שקיבל אותן.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="הודעות חדשות, עריכות שמורות ותצפיות על מחיקות יוצרות יומן חתום ומקושר. אמתו אותו מול מפתח שהאמון בו נקבע באופן עצמאי.">
</picture>

[אימות ארכיון](../wiki/Exports-and-Verification.md) · [פורמט הראיות](../EVIDENCE.md) · [עד בלתי תלוי](../WITNESS.md) · [חותמות זמן חיצוניות](../TIMESTAMP.md) · [בדיקות והיקף שנבדק](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## משיחה לתיק

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="שלושה תהליכי עבודה מונפשים: ייצוא צ'אט ל-HTML ול-JSON, איתור קישור משותף בצ'אטים המתועדים, ושמירת גרסאות שנלכדו אחרי התראת מחיקה.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>ייצוא צ'אט&nbsp;↗</b></a><br><sub>צ'אט אחד ל-HTML ול-JSON חתומים</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>חקירה&nbsp;↗</b></a><br><sub>עקבו אחר קצה חוט בצ'אטים המתועדים</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>גרסאות שמורות&nbsp;↗</b></a><br><sub>עריכות והתראות מחיקה, נשמרות</sub></td>
</tr>
</table>

שתי דרכי שימוש: [ייצוא החשבון](../ACCOUNT-EXPORT.md) פעם אחת, או
[מעקב אחר חקירה](../INVESTIGATION.md) ושמירת שינויים לאורך זמן.
בחרו כמה צ'אטים, תיקיית Telegram או את החשבון כולו. כל חשבון מקבל
סביבת עבודה, סשן ומפתח חתימה משלו.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## עוד לגלות

<details>
<summary><strong>ייצואים שנמדדו · 6 בנובמבר 2026</strong> · 56,329 הודעות, שני הארכיונים אומתו</summary>

**56,329 הודעות יוצאו בשתי ריצות חדשות.** שני הארכיונים החתומים עברו אימות מול מפתחות רכיב איסוף מוצמדים.

[![מהירות האיסוף והייצוא המלא שנמדדה](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/he/docs/validation/)

| ריצה | הודעות | זמן איסוף | מהירות איסוף | ייצוא מלא | מהירות מקצה לקצה |
| --- | ---: | ---: | ---: | ---: | ---: |
| שרת A | 27,030 | 189.043 שנ' | **142.983 הודעות/שנ'** | 211.647 שנ' | 127.713 הודעות/שנ' |
| שרת B | 29,299 | 182.513 שנ' | **160.531 הודעות/שנ'** | 206.650 שנ' | 141.781 הודעות/שנ' |

טקסט ומטא-נתונים דרך WARP, שני חשבונות לכל שרת, ללא קבצים מצורפים וללא רשומות בשימוש חוזר.
נמדד ברוויזיה [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e).
כל ריצה שפורסמה מפרטת את רוויזיית המקור, עומס העבודה, התזמונים ותוצאת האימות:
[עומס עבודה, תזמונים ואימות](../EXPORT-BENCHMARK-2026-11-06.md). שינויים ב-`main`
מריצים את [תהליכי ה-CI](../../.github/workflows/README.md) הציבוריים, כולל בדיקות מתקין ל-Linux ול-Windows
ובניית כלי האימות העצמאי.

[**לסיור בהדגמה →**](https://phishdestroy.github.io/TgWitness/demo/?lang=he) ·
[**מדידות, תאריכים ושיטה →**](https://phishdestroy.github.io/TgWitness/he/docs/validation/) ·
[הורדת ייצוא לדוגמה בדוי](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[ביקורת חתומה באנגלית](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>התחילו בפשטות. ראו כל מסלול.</strong> · הפעלה ראשונה ומפת המערכת</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="בהפעלה הראשונה מוצעות האפשרויות “רק להוריד”, “מעקב אחר צ'אטים” או “ראיות בתיק”, ומוצגים רק המקטעים המתאימים. מפת המערכת מקשרת בין הפאנל, רכיב האיסוף, Telegram, היומן, העד והשירותים החיצוניים, עם תצפיות רשת. ערכים בדויים.">
</picture>

ההפעלה הראשונה שואלת שאלה אחת: **רק להוריד**, **מעקב אחר צ'אטים** או
**ראיות בתיק**. התשובה קובעת את המטרה ואת רמת הממשק, כך
שהפאנל מציג רק את המקטעים שהמשימה הזו צריכה. אחר כך מגיעים החיבור, הכניסה ל-Telegram
ובחירת הצ'אטים, בחמישה שלבים. בדיקת החיבור רצה מעצמה, ואפשרויות
הניתוב נפתחות רק אם היא נכשלת. כלי המומחים נמצאים במרחק מתג אחד.

**מפת המערכת** מראה איך ההתקנה מגיעה ל-Telegram ולשירותים
חיצוניים: גישה לפאנל, המסלול של כל חשבון ויעד ה-Telegram שלו, מסלול היומן
והעד, ותצפיות הרשת האחרונות. תצפית חסרה
מסומנת כחסרה.

[הגדרה ראשונה](../SETTINGS.md) · [מפת המערכת](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>בנוי לשאר החקירה</strong> · כרטיסי מושא, רשימות מעקב, ארנקים, מעקב מצב מקוון, מסמכים לבית המשפט</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="עקבו אחר שמות ושמות משתמש לפי מזהה Telegram. תעדו אינטראקציות נתמכות עם בוטים עם קבלות חתומות. חפשו בהודעות שבארכיון וחברו לקוחות MCP לקריאה בלבד. פרסו רכיב איסוף עם SSH מוסתר ורשומות ספק לבדיקה. תעדו שיחה צעד אחר צעד עם הפניות ליומן. מסרו חבילת תיק BagIt עם תבניות לבית המשפט. תהליכי עבודה להמחשה.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>אנשים ותיקים אישיים&nbsp;↗</b></a><br><sub>שמות ושמות משתמש במעקב לפי מזהה Telegram</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>חקירת בוטים&nbsp;↗</b></a><br><sub>אינטראקציות עם בוטים עם קבלות חתומות</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/he/docs/archive/"><b>חיפוש בארכיון, AI ו-MCP&nbsp;↗</b></a><br><sub>חפשו בארכיון, חברו לקוחות לקריאה בלבד</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>פריסה אטומה בענן&nbsp;↗</b></a><br><sub>רכיב איסוף בתוך Intel TDX</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="שלושה שלבים מונפשים: כרטיס מושא שתמונת המצב המאוחרת שלו מתעדת שינוי שם, תוכנית שיחה שמטרותיה נסגרות ברשומות יומן, וקוד QR לתשלום שמפוענח לארנק עם סכום ביקורת תקין ומפעיל התאמה ברשימת מעקב. ערכים בדויים.">
</picture>

**תעדו את השיחה.** פתחו תיעוד לצ'אט במגירה **תיעוד**
וכל צעד נרשם מעצמו: פעולות בפאנל, תשובות עם ההשהיה שקדמה להן,
עריכות, התראות מחיקה, הערות וטיוטות AI. כל צעד מפנה לרשומת היומן שלו
ול-SHA-256 שלה. קיבוע המסמך חותם עליו וכותב את גיבוב ההצהרה
ליומן.

| | |
| --- | --- |
| [כרטיסי מושא](../INVESTIGATION-MODE.md#subject-cards) | תמונות מצב של פרופיל בוט, אדם, ערוץ או קבוצה עם התוויות BOT, VERIFIED, SCAM ו-FAKE של Telegram; תמונת מצב מאוחרת יותר מפרטת מה השתנה |
| [תוכניות שיחה](../INVESTIGATION-MODE.md#conversation-plans) | מטרות לגבי מסלול התשלום, התשתית או האנשים, הודעות מוכנות מראש, זמני תגובה, פעילות לפי שעה וסגנון הכתיבה של הצד השני |
| [תרגום](../INVESTIGATION-MODE.md#machine-translation) | מוצג מתחת למקור עם השפות, המודל ורשומת היומן |
| [רשימות מעקב](../INVESTIGATION-MODE.md#watchlists) | מילים, תבניות, ארנקים, שמות משתמש (@), מזהים, דומיינים, טלפונים וקישורים, עם התאמה בטקסט, בעריכות, ביעדי קישורים מוסתרים, בכפתורי בוטים, בקודי QR וב-OCR |
| [מעקב מצב מקוון](../INVESTIGATION-MODE.md#online-watch) | בדיקה כל 1–60 דקות, עד 100 חשבונות לבקשה, עם דפוס לפי שעה ויום בשבוע |
| [קודים וארנקים](../INVESTIGATION-MODE.md#codes-in-images) | קודי QR לתשלום; כתובות EVM שנבדקות מול EIP-55, כתובות TON בצורה גולמית, סכומי ביקורת של XRP Ledger, קישורי תשלום עם רשת, סכום וטוקן |
| [עקבות הלקוח](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-can-and-cannot-show) | עקבות מקודד בסרטוני עיגול ובהודעות קוליות; השוואת זמן ההעלאה לזמן השליחה חושפת הוכחה “חיה” שהוקלטה מראש |
| [כיסוי והרשאה](../INVESTIGATION-MODE.md#cover-and-authority) | זהויות בדויות, הרשאות ותיעוד פעילות סמויה שמסמן הודעות מחוץ לצ'אטים או לתקופה המורשים |
| [שליטה בחשבון](../INVESTIGATION-MODE.md#account-control) | עריכת פרופיל ופרטיות עם רשומות לפני ואחרי, בדיקת חשיפה ומעבר למצב לא מקוון מיד אחרי כל פעולה |
| [מסמכים לבית המשפט](../INVESTIGATION-MODE.md#documents-for-court) | חבילת תיק BagIt עם תבנית אישור לפי Rule 902(13)/(14), אינדקס מוצגים, נספח בקשה וכתוביות WebVTT/SRT להקלטות מסך |

תוכן שסומן כ-18+, כאלימות או כמידע אישי נשאר בעותק לבית המשפט, אטום
בהצפנת AES-256-GCM; המפתחות מועברים בנפרד.

[הגדרות הייצוא](../EXPORT_HASHES.md) מכסות איסוף דרך API רגיל ודרך Takeout,
היסטוריית הודעות לפני קבצים מצורפים, הורדת קבצים או גיבובי שרת, ותצוגות JSON/HTML
תואמות ל-Telegram Desktop. [ייצוא צ'אטים מבוזר](../DISTRIBUTED-EXPORT.md#history-acquisition)
מציע מסלול Takeout אופציונלי להיסטוריה ציבורית, נקודות ביקורת חתומות כל 100 הודעות,
ושחזור בתוך טווח עם אותו חשבון;
[תכנון הביצועים](../FAST-ACQUISITION.md) שלו מפרט את התנהגות האיסוף שנבדקה
ואת המדידות החיות המתוכננות.

</details>

<details>
<summary><strong>כל השאר</strong> · היסטוריה, חשבונות, פרוקסי, AI, שילובים</summary>

| | |
| --- | --- |
| [טעינת הודעות ישנות יותר](../HISTORY.md) | משיכת היסטוריה קודמת של צ'אטים נבחרים, עם השהיה והמשך בכל עת |
| [כמה חשבונות](../ACCOUNTS.md#multiple-accounts) | סביבות עבודה נפרדות, לכל אחת סשן Telegram, יומן ומפתח חתימה משלה |
| [ייבוא בכמות](../ACCOUNTS.md#bulk-import-and-account-groups) | גררו ערימה של קובצי סשן, ומיינו חשבונות לקבוצות עם הגדרות משותפות |
| [מאגר MTProxy](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | פינג, מדינות, מסננים, רשימות משלכם |
| [סשנים קיימים](../ACCOUNTS.md) | סשנים מסוג TData, Telethon, Pyrogram, StringSession, מפתח אימות או שורת `key:DC`; הרשאת QR עצמאית אופציונלית מסשן תורם מיובא |
| [אבטחת חשבון](../ACCOUNTS.md#create-an-independent-authorization) | התראות על סשנים חדשים, סיום סשנים אחרים, מצב סשן יחיד שגם מגדיר סיסמה לאימות דו-שלבי, ו[גשש העד](../ACCOUNTS.md#witness-probe) שמזהה מתי עדכונים חיים מפסיקים להגיע לסשן הזה |
| [ייצוא צ'אט שניתן לחדש](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | ייצוא שנעצר שומר עותק חלקי חתום: המשיכו אותו, התחילו מחדש או הורידו את מה שנשמר |
| [פרוקסי](../CONNECTION-SECURITY.md#ip-modes) | פרוקסי SOCKS5, HTTP CONNECT או MTProxy לכל סביבת עבודה. מצב **הסתר את הכתובת** לעולם אינו עובר לחיבור ישיר |
| [חיפוש ו-AI](../ANALYSIS.md) | חיפוש מקומי, AI אופציונלי עם מקורות שאפשר לבדוק |
| [חיפוש בטקסט מלא](../SEARCH.md) | צורות מילה, ביטויים מדויקים, דומיינים, שמות משתמש (@) וסינית ללא רווחים, ההתאמות הטובות ביותר ראשונות (**גרסת תצוגה מקדימה**) |
| [MCP](../MCP.md) | גישה לקריאה בלבד ללקוחות MCP, מוגבלת לצ'אטים שתבחרו |
| [שורת פקודה](../CLI.md) | הפקודות `search`, `context`, `messages`, `stats` ו-`export` בפורמט JSON Lines עם `--json` לסקריפטים ולסוכנים, מקומית או עם אסימון בהיקף מוגבל (**גרסת תצוגה מקדימה**) |
| [תמלול ו-OCR](../MEDIA-ANALYSIS.md) | פועל מקומית, הקבצים המקוריים נשארים ללא שינוי |
| [לכידה עצמאית](../OPTIONAL-CAPTURE.md) | מקליטים אופציונליים לדפדפן ול-AyuGram תחת **כלים נוספים → תוספות** (תצוגה מקדימה, כבוי כברירת מחדל) |
| [Trusted Live](../TRUSTED-LIVE.md) | סשן Desktop/Web רשמי, וידאו מוגן וניתוח רציפות מול הייצוא המקורי (תצוגה מקדימה; הסמכה חיה עדיין ממתינה) |
| [גרסת Web רשמית אטומה](../OFFICIAL-WITNESS.md) | דפדפן רשמי חדש ב-GitHub Actions, פקדים מוגבלים, וידאו חתום ומקור והגדרות הצפויים באופן עצמאי |
| [Webhooks](../WEBHOOKS.md) | אירועים יוצאים חתומים עם ניסיונות חוזרים, כולל דוגמת n8n |
| [גישה משותפת](../ACCESS.md) | תנו למישהו רק צ'אטים נבחרים, עם תפוגה ומגבלות IP |
| [מספרי הודעות חסרים](../EVIDENCE.md#missing-message-numbers-gap_summary) | מספרים ש-Telegram הקצה ולא נצפו מעולם, לכל ערוץ ולחשבון כולו, בכיסוי, בדוחות וב-MCP (**גרסת תצוגה מקדימה**) |
| [תמונות מצב של צ'אט](../COLLECTION.md) | תמונות מצב חתומות תקופתיות של הכותרת, התיאור, ההודעות המוצמדות, המנהלים והמתנות, עם מה שהשתנה (**גרסת תצוגה מקדימה**) |
| [מפת המערכת](../SYSTEM-MAP.md) | מפה חיה של הגישה לפאנל, מסלולי החשבונות, יעדי Telegram ושירותים חיצוניים, עם 200 התצפיות האחרונות מתוך עד 2,000 תצפיות רשת |

</details>

<details>
<summary><strong>בחרו על מה הרשומה נשענת</strong> · מקומי, ענן מבוקר, GitHub Actions או Intel TDX</summary>

הריצו מקומית, הוסיפו פריסת ענן מבוקרת, או אספו בתוך **מכונה וירטואלית חסויה של Phala Cloud
עם Intel TDX**. כל אפשרות שומרת על היומן החתום; הבדיקות הנוספות
מתייחסות לסביבה שבה הוא נאסף.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="שלוש אפשרויות פריסה: אימות מקומי של היומן; מכונה וירטואלית מבוקרת עם רשומות ספק וגישה; Phala Intel TDX עם מסמך אטסטציה מאומת, מערכת הפעלה ויישום שנמדדו ומפתח רכיב איסוף מקושר.">
</picture>

כלי האימות של TDX בודק את מסמך האטסטציה מול שורש Intel המוצמד ונתוני הביטול,
קושר אותו להצהרה חתומה של רכיב האיסוף ולאתגר חדש, ומשווה את
מערכת ההפעלה והיישום שנמדדו לקלטים הצפויים באופן עצמאי. הדוח
מפרט כל תוצאה בנפרד, כך שאפשר לבחון יחד את הסביבה שנמדדה, את זהות רכיב האיסוף, את רשומות
הלכידה ואת הכיסוי.

**לכידה עם תיעוד מקור מ-GitHub** (תצוגה מקדימה). אספו צ'אט במריץ שמתארח ב-GitHub
עם גרסת TgWitness מוצמדת וסשן Telegram חדש, ואז הורידו את הארכיון
המוצפן יחד עם האטסטציה של GitHub. כלי האימות בודק את תהליך העבודה המאושר ואת גרסת
רכיב האיסוף, את גיבוב הארכיון, את היומן ואת הקבצים המצורפים. זמין גם
תחת **ייצוא** בפאנל.
[לדף הלכידה](https://phishdestroy.github.io/TgWitness/he/docs/capture/) · [הוראות](../SEALED-ACTIONS.md)

לתצפית חיה, להיסטוריה או לייצוא חד-פעמי, בחרו
[שיטת איסוף](../COLLECTION-MODES.md). צ'אטים פרטיים בענן זמינים
כשלחשבון המחובר יש גישה אליהם. היישום שפורסם כולל גם
[שילוב צ'אטים סודיים](../PSEUDO-SECRET.md): התקינו את תלות הפרוטוקול האופציונלית
והפעילו את השילוב לכל חשבון כדי לתעד צ'אטים שנוצרים או מתקבלים שם.
ראו [היקף האיסוף](../COLLECTION.md) למסלולי האיסוף הזמינים.

[פריסות מבוקרות ו-Phala / Intel TDX](../HIGH-ASSURANCE.md) ·
[הסמכה חיה ב-Phala](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[גבולות אמון](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>בדקו את הלכידה ואת הרשומה השמורה</strong> · מה הנמען מאמת ו-Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="לכדו את השיחה. אמתו את הרשומה. שמרו הודעות, עריכות וקבצים, בדקו חתימות ונקודות ביקורת, ובחנו את תהליך הלכידה.">
</picture>

התוכן שנמסר לחשבון ה-Telegram המחובר נרשם ב-TgWitness יחד עם
מזהי הצ'אט, ההודעה והשולח, הגרסאות שנלכדו ומטא-נתוני האיסוף.
הארכיון מאגד את הרשומות האלה, את הקבצים המצורפים שנשמרו ואת נתוני האימות
לבדיקה.

| בדיקה | מה הנמען מאמת |
| --- | --- |
| יומן ומניפסט חתומים | חתימות הרשומות, שרשרת הגיבובים והקבצים שנמסרו מול מפתח החתימה הצפוי. |
| נקודת ביקורת שנשמרת בנפרד | היומן מול אורך וגיבוב ראש שתועדו קודם לכן. |
| עד בלתי תלוי | היומן מול נקודות ביקורת שנשמרות אצל עד נפרד. |
| לכידה ב-GitHub Actions | הארכיון מול האטסטציה שלו, תהליך העבודה המתארח המאושר וגרסת רכיב האיסוף. |

ב-[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
מוצגת שיחת Telegram לצד קובצי ייצוא של Desktop ששונו בכוונה.
השוו את הגרסאות, בדקו את השינויים, ועקבו אחר שלבי האיסוף
והאימות של ארכיון TgWitness חתום.

[שלבי אימות](../wiki/Exports-and-Verification.md) ·
[לכידה ב-GitHub](../SEALED-ACTIONS.md) ·
[מודל האמון הטכני](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>שמרו על רציפות החקירה</strong> · התראות, אחסון ושחזור</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="תהליכי עבודה מונפשים: Apprise שולח התראות מוגדרות; עותקים מחוץ לאתר מוצפנים לפני העלאה לאחסון תואם S3.">
</picture>

[התראות](../OPERATIONS.md#notifications) · [עותק מוצפן מחוץ לאתר](../wiki/Off-site-Copy.md) · [גיבוי ושחזור](../wiki/Backup-and-Recovery.md) · [פתרון בעיות](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/he/docs/start/"><b>מדריך התקנה&nbsp;↗</b></a><br><sub>מההתקנה ועד הצ'אט הראשון</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/he/docs/dedicated-account/"><b>הכנת החשבון&nbsp;↗</b></a><br><sub>חשבון Telegram ייעודי</sub></td>
<td width="33%" align="center"><a href="../DEPLOYMENT.md"><b>Docker ושרתים&nbsp;↗</b></a><br><sub>הפעלות מחדש, עדכונים ו-HTTPS</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>סיור במאגר</strong> · היכן נמצאים הקוד, התיעוד והכלים</summary>

| תיקייה | התחילו כאן |
| --- | --- |
| [docs/](../README.md) | התקנה, תהליכי חקירה ומדריך עיון טכני |
| [tgwitness/](../../tgwitness/README.md) | היישום הראשי, רכיב האיסוף, היומן ופאנל הווב |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | מקליטים עצמאיים וקוד האימות שלהם |
| [addons/](../../addons/README.md) | התקנה, הגדרה ובדיקות של לכידה אופציונלית |
| [deploy/](../../deploy/README.md) | מתקינים, קונטיינרים ושירותי רקע |
| [examples/](../../examples/README.md) | תצורות לייצוא חשבון וללכידה אטומה |
| [integrations/](../../integrations/README.md) | מקלט n8n ו-webhooks חתומים |
| [.agents/](../../.agents/README.md) | הוראות משימה לקריאת הארכיון דרך CLI |
| [scripts/](../../scripts/README.md) | משגרים וכלי עזר ל-CI |
| [tools/](../../tools/README.md) | בנייה, בדיקות ואריזה |
| [website/](../../website/README.md) | האתר הציבורי, מדריכים מתורגמים והדגמה אינטראקטיבית |
| [.github/](../../.github/AUTOMATION.md) | תהליכי עבודה, הנחיות תרומה ותמיכה |

[מדריך הפרויקט המלא](../PROJECT-GUIDE.md) ·
[תרומה](../../.github/CONTRIBUTING.md) · [קבלת עזרה](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ הודעה אתית והמשכיות היסטורית</strong></summary>

עמדת המחברים והודעת המפעיל, בשפה זו:

[הודעה בנושא הרישיון ואי־תאימות ארכיטקטונית](TAYLOR-WESSING-EXCLUSION.md) · [הודעת המפעיל](OPERATOR-INCOMPATIBILITY.md) · [רישיון MIT](../../LICENSE) · [קובץ NOTICE המקורי](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>קראו את סקירת הפרויקט בשפה שלכם</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · **עברית** · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>תיעוד טכני</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>מדריך חקירה</b></a> ·
  <a href="https://github.com/phishdestroy"><b>נבנה על ידי PhishDestroy</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>תרמו</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>קבלת עזרה</b></a> ·
  <a href="../../.github/SECURITY.md"><b>דיווח על פגיעות</b></a>
</p>

[אינדקס הפרויקט הקריא למכונה](../../llms.txt) · [המדריך הטקסטואלי המלא](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [כללי המאגר לסוכנים](../../AGENTS.md)
