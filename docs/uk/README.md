<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">Інші мови</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Ідіть по сліду. Зберігайте докази. Підписаний журнал, пов’язаний ланцюжком хешів, окремо збережена контрольна точка і перевірюваний архів доказів.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=uk"><b>Відкрити демо&nbsp;↗</b></a><br><sub>Справжній інтерфейс із вигаданими записами</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>Завантажити й запустити&nbsp;↓</b></a><br><sub>Одна команда для Linux, macOS і Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Читати посібник&nbsp;↗</b></a><br><sub>Покрокові інструкції для розслідувань</sub></td>
</tr>
</table>

<p align="center"><strong>Робоче місце для розслідувань у Telegram, розгорнуте у вас.</strong><br>Зберігайте чати, редагування й видалені повідомлення, дивіться, хто з ким пов’язаний,<br>і передавайте підписані експорти, які може перевірити будь-хто.</p>

<p align="center"><strong>НУЛЬОВА ДОВІРА.</strong> TgWitness не стає на жоден бік: ті самі перевірки застосовуються до оператора, до PhishDestroy і до будь-кого іншого.<br>Важить лише те, що підтверджує третя сторона або математика. <a href="../QUESTIONS-AND-CHECKS.md">Питання й перевірки</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.2 · попередній випуск"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">Перевірені середовища</a> · 25 мов інтерфейсу · 26 мов посібників</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=uk">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="Демо TgWitness у дії: зафіксовані повідомлення, збережені версії та вміст, що лишився після видалення. Вигадані демонстраційні записи.">
</picture>
</a>

<p align="center"><sub>Ознайомтеся зі справжнім інтерфейсом на вигаданих записах. Натисніть на робочу область, щоб спробувати.</sub></p>

## Що робить TgWitness

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">Кожне редагування й видалення зберігається</a></b><br><sub>Зберігається кожна версія повідомлення, а його текст лишається й після сповіщення про видалення.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">Докази, які може перевірити будь-хто</a></b><br><sub>Підписані записи, пов’язані ланцюжком хешів. Одержувач перевіряє архів офлайн однією командою.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">Походження, яке можна показати</a></b><br><sub>Повідомлення надходять через автентифіковану сесію MTProto облікового запису й підписуються під час отримання; GitHub Actions та Intel TDX додають атестацію.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">Виміряно на великих обсягах</a></b><br><sub>48 перевірених архівів із 3 598 381 записом; вісім облікових записів завантажили 768 007 записів історії зі швидкістю 687,5 запису/с.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">Створено для розслідувань</a></b><br><sub>Списки спостереження для тексту, QR-кодів і OCR, перевірка гаманців, картки суб’єктів, «Дошка справи» і пакет для суду.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">Під вашим контролем</a></b><br><sub>Розміщується у вас, без телеметрії. Сесії лежать у зашифрованому сховищі; панель слухає localhost.</sub></td>
</tr>
</table>

<p align="center"><sub>Розробка та тестування тривали близько шести місяців: спочатку колектор, підписаний журнал і верифікатор, потім панель та додаткові модулі. Цей репозиторій було створено 29 жовтня 2026 року для публікації, тому його вік не збігається з віком проєкту.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## Встановлення

Python входить до комплекту. Для оновлення використовуйте ті самі команди.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell або CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Сервер Ubuntu: запускайте від root. Робочий комп’ютер: від звичайного користувача. `-ExecutionPolicy Bypass` діє лише на цей процес PowerShell.</sub>

Підписані збірки створює публічний [робочий процес Installer](../../.github/workflows/installer.yml), а інсталятор перед встановленням перевіряє SHA-256 і підпис RSA кожного пакета.

[Спершу перевірити скрипт](../INSTALLATION.md#verify-before-running) · [Перше налаштування](../SETTINGS.md) · [Релізи](https://github.com/phishdestroy/TgWitness/releases) · [Docker](DEPLOYMENT.md)

<details>
<summary><strong>Як захищено інсталятор і ваші дані</strong></summary>

`get.destroy.tools` — сайт завантажень проєкту. Публічний
[робочий процес Installer](../../.github/workflows/installer.yml) збирає його з
[`deploy/installer/`](../../deploy/installer/README.md) для конкретної ревізії `main`,
публікує після успішних тестів встановлення на Linux і Windows та підписує
скрипти інсталятора й пакети застосунку ключем випуску з
[`release-signing.pub`](../../deploy/installer/release-signing.pub). Перед встановленням інсталятор перевіряє
SHA-256 і підпис RSA пакета та lock-файлу залежностей.
Щоб спершу перевірити сам скрипт, завантажте його разом із підписом і виконайте
[команди попередньої перевірки](../INSTALLATION.md#verify-before-running). Якщо збірка не вдалася,
для завантаження лишається попередня версія; встановлені панелі оновлюються, коли ви повторно запускаєте інсталятор.
[Релізи](https://github.com/phishdestroy/TgWitness/releases) на GitHub, вихідний код і
[Docker](DEPLOYMENT.md) — інші способи встановлення.

**Ваші сесії та дані.** TgWitness працює на вашому комп’ютері чи сервері, а панель
типово слухає localhost. Сесії Telegram, облікові дані проксі та хеші
токенів доступу зберігаються в зашифрованому сховищі кожної робочої області; можна додати
[зовнішній майстер-ключ](../SECURITY-MODEL.md#external-master-key). Застосунок
не має телеметрії. Він під’єднується до Telegram і до сервісів, указаних у налаштуваннях:
публічних списків MTProxy, ваших проксі, сховища S3, бота-свідка, служб
міток часу, постачальників ШІ та вебхуків. [Схема системи](../SYSTEM-MAP.md) показує
з’єднання, які встановлює процес застосунку.
Для спостереження використовуйте [спеціальний обліковий запис Telegram](https://phishdestroy.github.io/TgWitness/uk/docs/dedicated-account/).

Значок версії описує це дерево вихідного коду. Збірки для встановлення наведено в розділі
[Релізи](https://github.com/phishdestroy/TgWitness/releases); функція, злита в
`main`, потрапляє до них із наступним випуском.

[Встановлення й доступ до панелі](../INSTALLATION.md) ·
[Підписи та SHA-256](https://get.destroy.tools/#verification) ·
[Оновлення](../INSTALLATION.md#update-an-existing-installation) ·
[Поточні можливості та стан перевірки](../STATUS.md) ·
[Вибір способу збору](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## Запис, який може перевірити хтось інший

Перевірте без облікового запису й встановлення. Опублікований зразок містить власний верифікатор:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # верифікатор постачається всередині архіву
python verify.py tgwitness-demo.zip          # Python 3.11+, потрібен лише `cryptography`
```

Він виводить підписані записи, хеш найновішого запису й відбиток підписувача та завершується з кодом `0`.
Зразок вигаданий; той самий верифікатор працює з будь-яким реальним експортом.

Експорт містить повідомлення, файли й верифікатор. Передайте одержувачу відбиток
свого ключа іншим каналом, і він зможе перевірити експорт сам:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

Верифікатор перевіряє підписи, ланцюжок журналу, список файлів і вкладення.
Щоб експорт вважався доказом, потрібні відбиток вашого ключа та стороння мітка часу, що охоплює останній
запис, наприклад мітка часу RFC 3161, перевірена за кореневим сертифікатом служби міток часу.

**Звідки беруться повідомлення.** TgWitness отримує їх від Telegram через
зашифровану сесію MTProto облікового запису, як і офіційні застосунки, і щойно кожне надходить,
підписує його та заносить до журналу. [Збір через GitHub Actions](../SEALED-ACTIONS.md) і
[Phala Intel TDX](../HIGH-ASSURANCE.md) додатково атестують колектор, який їх отримав.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="Нові повідомлення, збережені редагування й зафіксовані видалення утворюють пов’язаний підписаний журнал. Перевірте його за ключем, довіру до якого встановлено незалежно.">
</picture>

[Перевірка архіву](../wiki/Exports-and-Verification.md) · [Формат доказів](../EVIDENCE.md) · [Незалежний свідок](../WITNESS.md) · [Зовнішні мітки часу](../TIMESTAMP.md) · [Перевірки та випробувані обсяги](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Від листування до справи

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="Три анімовані сценарії: експорт чату в HTML і JSON, пошук опублікованого посилання в усіх записаних чатах і збереження зафіксованих версій після сповіщення про видалення.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>Експорт чату&nbsp;↗</b></a><br><sub>Один чат у підписані HTML і JSON</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>Розслідування&nbsp;↗</b></a><br><sub>Ідіть за зачіпкою через записані чати</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>Збережені версії&nbsp;↗</b></a><br><sub>Редагування й сповіщення про видалення зберігаються</sub></td>
</tr>
</table>

Два способи роботи: одноразово [експортувати свій обліковий запис](../ACCOUNT-EXPORT.md) або
[вести розслідування](../INVESTIGATION.md) й далі зберігати зміни.
Оберіть кілька чатів, папку Telegram або весь обліковий запис. Кожен обліковий запис має
власну робочу область, сесію та ключ підпису.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Докладніше

<details>
<summary><strong>Виміри експорту · 6 листопада 2026 р.</strong> · 56 329 повідомлень, обидва архіви перевірено</summary>

**56 329 повідомлень експортовано за два нові прогони.** Обидва підписані архіви пройшли перевірку із закріпленими ключами колектора.

[![Виміряна швидкість збору та повного експорту](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/uk/docs/validation/)

| Прогін | Повідомлення | Час збору | Швидкість збору | Повний експорт | Наскрізна швидкість |
| --- | ---: | ---: | ---: | ---: | ---: |
| Сервер A | 27 030 | 189,043 с | **142,983 повід./с** | 211,647 с | 127,713 повід./с |
| Сервер B | 29 299 | 182,513 с | **160,531 повід./с** | 206,650 с | 141,781 повід./с |

Текст і метадані через WARP, по два облікові записи на сервер, без вкладень і повторно використаних записів.
Виміряно на ревізії [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e).
Для кожного опублікованого прогону вказано ревізію вихідного коду, навантаження, тривалість етапів і результат перевірки:
[навантаження, тривалість і перевірка](../EXPORT-BENCHMARK-2026-11-06.md). Зміни в `main`
проходять через публічні [робочі процеси CI](../../.github/workflows/README.md), зокрема тести інсталятора
на Linux і Windows та збирання автономного верифікатора.

[**Відкрити демо →**](https://phishdestroy.github.io/TgWitness/demo/?lang=uk) ·
[**Виміри, дати й методика →**](https://phishdestroy.github.io/TgWitness/uk/docs/validation/) ·
[Завантажити вигаданий зразок експорту](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[Підписаний аудит англійською](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>Простий старт. Усі маршрути на виду.</strong> · перший запуск і схема системи</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="Під час першого запуску пропонується вибрати «Просто завантажити», «Стежити за чатами» або «Докази у справі», і панель показує лише відповідні розділи. Схема системи пов’язує панель, колектор, Telegram, журнал, свідка та зовнішні сервіси й показує мережеві спостереження. Вигадані значення.">
</picture>

Під час першого запуску ставиться одне запитання: **Просто завантажити**, **Стежити за чатами** або
**Докази у справі**. Відповідь визначає мету й рівень інтерфейсу, тож
панель показує лише розділи, потрібні для цього завдання. Під’єднання, вхід у Telegram і
вибір чатів проходять у п’ять етапів. Перевірка під’єднання запускається сама, а
параметри маршруту відкриваються, лише якщо вона не пройшла. До експертних інструментів — один перемикач.

**Схема системи** показує, як інсталяція зв’язується з Telegram і зовнішніми
сервісами: доступ до панелі, маршрут кожного облікового запису та його адресу в Telegram, шлях журналу й
свідка, останні мережеві спостереження. Відсутнє спостереження
так і позначається — як відсутнє.

[Перше налаштування](../SETTINGS.md) · [Схема системи](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>Для всього іншого в розслідуванні</strong> · картки суб’єктів, списки спостереження, гаманці, відстеження онлайну, документи для суду</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Відстежуйте відображувані імена та імена користувачів за Telegram ID. Записуйте підтримувані взаємодії з ботами з підписаними квитанціями. Шукайте в архіві повідомлень і під’єднуйте MCP-клієнти лише для читання. Розгортайте колектор із прихованим SSH і записами провайдера для перевірки. Документуйте листування крок за кроком із посиланнями на журнал. Передавайте пакет справи BagIt із шаблонами для суду. Ілюстративні сценарії.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>Люди й досьє&nbsp;↗</b></a><br><sub>Відображувані імена та імена користувачів за Telegram ID</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>Розслідування ботів&nbsp;↗</b></a><br><sub>Взаємодії з ботами з підписаними квитанціями</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/uk/docs/archive/"><b>Пошук в архіві, ШІ та MCP&nbsp;↗</b></a><br><sub>Пошук в архіві й клієнти лише для читання</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>Запечатане хмарне розгортання&nbsp;↗</b></a><br><sub>Колектор усередині Intel TDX</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="Три анімовані кроки: картка суб’єкта, у пізнішому знімку якої зафіксовано перейменування; план розмови, цілі якого закриваються записами журналу; платіжний QR-код, декодований у гаманець із правильною контрольною сумою, що дає збіг зі списком спостереження. Вигадані значення.">
</picture>

**Документуйте листування.** Почніть документувати чат на бічній панелі **Документація**,
і кожен крок записуватиметься сам: дії в панелі, відповіді із затримкою перед
ними, редагування, сповіщення про видалення, нотатки й чернетки ШІ. Кожен крок посилається на свій запис
журналу та SHA-256. Фіксація документа підписує його й заносить хеш протоколу
до журналу.

| | |
| --- | --- |
| [Картки суб’єктів](../INVESTIGATION-MODE.md#subject-cards) | Знімки профілю бота, людини, каналу чи групи з мітками Telegram BOT, VERIFIED, SCAM і FAKE; пізніший знімок показує, що змінилося |
| [Плани розмови](../INVESTIGATION-MODE.md#conversation-plans) | Цілі щодо платіжного маршруту, інфраструктури чи людей, заготовлені повідомлення, час відповідей, активність за годинами та манера письма співрозмовника |
| [Переклад](../INVESTIGATION-MODE.md#machine-translation) | Показується під оригіналом із зазначенням мов, моделі та запису журналу |
| [Списки спостереження](../INVESTIGATION-MODE.md#watchlists) | Слова, шаблони, гаманці, @імена користувачів, ID, домени, телефони й посилання — збіги шукаються в тексті, редагуваннях, прихованих адресах посилань, кнопках ботів, QR-кодах і OCR |
| [Відстеження онлайну](../INVESTIGATION-MODE.md#online-watch) | Перевірка кожні 1–60 хвилин, до 100 облікових записів за запит, із картиною за годинами та днями тижня |
| [Коди й гаманці](../INVESTIGATION-MODE.md#codes-in-images) | Платіжні QR-коди; перевірка EVM-адрес за EIP-55, адреси TON у raw-форматі, контрольні суми XRP Ledger, платіжні посилання з мережею, сумою й токеном |
| [Сліди клієнта](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-show) | Сліди кодувальника у відеоповідомленнях-кружечках і голосових повідомленнях; порівняння часу завантаження з часом надсилання викриває заздалегідь записані «живі» докази |
| [Легенда й повноваження](../INVESTIGATION-MODE.md#cover-and-authority) | Персони, дозволи та облік роботи під прикриттям, який позначає повідомлення поза дозволеними чатами чи періодом |
| [Керування обліковим записом](../INVESTIGATION-MODE.md#account-control) | Редагування профілю й приватності із записами «до» і «після», перевірка розкриття та вихід в офлайн одразу після кожної дії |
| [Документи для суду](../INVESTIGATION-MODE.md#documents-for-court) | Пакет справи BagIt із шаблоном сертифікації за Rule 902(13)/(14), описом доказів, додатком до запиту та субтитрами WebVTT/SRT для записів екрана |

Матеріали з позначками 18+, «насильство» чи «персональні дані» лишаються в копії для суду, запечатані
AES-256-GCM; ключі передаються окремо.

[Налаштування експорту](../EXPORT_HASHES.md) охоплюють отримання через звичайний API і через Takeout,
завантаження історії повідомлень до вкладень, завантаження файлів або серверні хеші та сумісні
подання Telegram Desktop у JSON/HTML. [Розподілений експорт чатів](../DISTRIBUTED-EXPORT.md#history-acquisition)
пропонує необов’язковий шлях через Takeout для публічної історії, підписані контрольні точки кожні 100 повідомлень
і відновлення в межах діапазону з тим самим обліковим записом; у його
[проєкті продуктивності](../FAST-ACQUISITION.md) описано перевірену поведінку завантаження
та заплановані виміри в реальних умовах.

</details>

<details>
<summary><strong>Усе інше</strong> · історія, облікові записи, проксі, ШІ, інтеграції</summary>

| | |
| --- | --- |
| [Завантаження старих повідомлень](../HISTORY.md) | Завантажуйте минулу історію вибраних чатів, ставте на паузу й продовжуйте будь-коли |
| [Кілька облікових записів](../ACCOUNTS.md#multiple-accounts) | Окремі робочі області, кожна з власною сесією Telegram, журналом і ключем підпису |
| [Пакетний імпорт](../ACCOUNTS.md#bulk-import-and-account-groups) | Завантажте одразу купу файлів сесій і розподіліть облікові записи за групами зі спільними налаштуваннями |
| [Пул MTProxy](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Пінг, країни, фільтри, власні списки |
| [Наявні сесії](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key або рядок `key:DC`; за бажанням — незалежна авторизація через QR з імпортованого облікового запису-донора |
| [Безпека облікового запису](../ACCOUNTS.md#create-an-independent-authorization) | Сповіщення про нові сесії, завершення інших сесій, режим єдиної сесії, який також задає пароль двоетапної перевірки, і [перевірка свідком](../ACCOUNTS.md#witness-probe), що помічає, коли живі оновлення перестають надходити до цієї сесії |
| [Експорт чату з продовженням](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | Зупинений експорт зберігає підписану часткову копію: продовжте його, почніть заново або завантажте вже збережене |
| [Проксі](../CONNECTION-SECURITY.md#ip-modes) | SOCKS5, HTTP CONNECT або MTProxy для кожної робочої області. **Приховати IP** ніколи не переходить на пряме з’єднання |
| [Пошук і ШІ](../ANALYSIS.md) | Локальний пошук, ШІ за бажанням із джерелами, які можна перевірити |
| [Повнотекстовий пошук](../SEARCH.md) | Словоформи, точні фрази, домени, @імена користувачів і китайський текст без пробілів, найкращі збіги першими (**попередня версія**) |
| [MCP](../MCP.md) | Доступ лише для читання для MCP-клієнтів, обмежений вибраними вами чатами |
| [Командний рядок](../CLI.md) | `search`, `context`, `messages`, `stats` і `export` у JSON Lines із `--json` для скриптів та агентів — локально або з токеном обмеженого доступу (**попередня версія**) |
| [OCR і транскрибування](../MEDIA-ANALYSIS.md) | Працює локально, оригінали лишаються незмінними |
| [Незалежний збір даних](../OPTIONAL-CAPTURE.md) | Додаткові засоби запису через браузер/AyuGram у розділі **Інші інструменти → Додатки** (попередня версія, типово вимкнено) |
| [Trusted Live](../TRUSTED-LIVE.md) | Сесія офіційного Desktop/Web, захищений відеозапис та аналіз безперервності відносно штатного експорту (попередня версія; перевірка в реальних умовах ще не проведена) |
| [Запечатаний офіційний Web](../OFFICIAL-WITNESS.md) | Чистий офіційний браузер на GitHub Actions, обмежене керування, підписане відео та незалежно очікувані вихідний код і налаштування |
| [Вебхуки](../WEBHOOKS.md) | Підписані вихідні події з повторними спробами, приклад для n8n у комплекті |
| [Спільний доступ](../ACCESS.md) | Надавайте доступ лише до вибраних чатів, з терміном дії та обмеженням за IP |
| [Пропущені номери повідомлень](../EVIDENCE.md#missing-message-numbers-gap_summary) | Номери, які Telegram присвоїв, але які жодного разу не спостерігалися, — для кожного каналу й для всього облікового запису, у покритті, звітах і MCP (**попередня версія**) |
| [Знімки стану чату](../COLLECTION.md) | Періодичні підписані знімки назви, опису, закріплених повідомлень, адміністраторів і подарунків зі змінами (**попередня версія**) |
| [Схема системи](../SYSTEM-MAP.md) | Жива схема доступу до панелі, маршрутів облікових записів, адрес Telegram і зовнішніх сервісів з останніми 200 із не більш ніж 2000 мережевих спостережень |

</details>

<details>
<summary><strong>Оберіть, що підкріплює запис</strong> · локально, хмара з аудитом, GitHub Actions або Intel TDX</summary>

Запускайте локально, додайте хмарне розгортання з аудитом або збирайте дані всередині **конфіденційної ВМ Phala Cloud
з Intel TDX**. Кожен варіант зберігає підписаний журнал; додаткові
перевірки стосуються середовища, у якому його зібрано.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="Три варіанти розгортання: локальна перевірка журналу; ВМ з аудитом і записами провайдера та доступу; Phala Intel TDX із перевіреним звітом атестації, виміряними ОС і застосунком та прив’язаним ключем колектора.">
</picture>

Верифікатор TDX перевіряє звіт атестації за закріпленим кореневим сертифікатом Intel і даними про відкликання,
прив’язує його до підписаної заяви колектора та свіжого виклику й порівнює
виміряні ОС і застосунок із незалежно очікуваними вхідними даними. У підсумковому звіті
кожен результат наведено окремо, тож виміряне середовище, ідентичність колектора, записи
збору й покриття можна розглядати разом.

**Збір із підтвердженням походження від GitHub** (попередня версія). Зберіть чат на ранері GitHub
із закріпленою версією TgWitness і новою сесією Telegram, потім завантажте зашифрований
архів разом з атестацією GitHub. Верифікатор перевіряє схвалений робочий процес і
версію колектора, дайджест архіву, журнал і вкладення. Також доступно
на панелі в розділі **Експорт**.
[Відкрити сторінку збору](https://phishdestroy.github.io/TgWitness/uk/docs/capture/) · [Інструкція](../SEALED-ACTIONS.md)

Для спостереження в реальному часі, завантаження історії чи разового експорту оберіть
[спосіб збору](../COLLECTION-MODES.md). Приватні хмарні чати доступні,
якщо підключений обліковий запис має до них доступ. Опублікований застосунок також містить
[інтеграцію із секретними чатами](../PSEUDO-SECRET.md): встановіть необов’язкову залежність
протоколу й увімкніть її для облікового запису, щоб записувати створені або прийняті в ньому чати.
Доступні способи отримання даних описано в розділі [Межі збору](../COLLECTION.md).

[Phala / Intel TDX і розгортання з аудитом](../HIGH-ASSURANCE.md) ·
[Перевірка Phala в реальних умовах](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[Межі довіри](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>Перевірте збір і збережений запис</strong> · перевірки одержувача та Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="Зафіксуйте листування. Перевірте запис. Зберігайте повідомлення, редагування й файли, перевіряйте підписи та контрольні точки й вивчайте процес збору.">
</picture>

TgWitness записує вміст, доставлений до підключеного облікового запису Telegram, разом з
ідентифікаторами чату, повідомлення й відправника, зафіксованими версіями та метаданими збору.
Архів збирає ці записи, збережені вкладення й дані для перевірки
в одному місці, щоб їх можна було вивчити.

| Перевірка | Що перевіряє одержувач |
| --- | --- |
| Підписаний журнал і маніфест | Підписи записів, ланцюжок хешів і передані файли — за очікуваним ключем підпису. |
| Окремо збережена контрольна точка | Журнал — за раніше записаною довжиною та хешем найновішого запису. |
| Незалежний свідок | Журнал — за контрольними точками, які зберігає окремий свідок. |
| Збір через GitHub Actions | Архів — за його атестацією, схваленим робочим процесом на ранері GitHub і версією колектора. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
показує листування в Telegram поруч із навмисно зміненими файлами експорту Desktop.
Порівняйте версії, вивчіть зміни й пройдіть кроки збору та
перевірки підписаного архіву TgWitness.

[Кроки перевірки](../wiki/Exports-and-Verification.md) ·
[Збір через GitHub](../SEALED-ACTIONS.md) ·
[Технічна модель довіри](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>Розслідування без перерв</strong> · сповіщення, зберігання й відновлення</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="Анімовані сценарії: Apprise надсилає налаштовані сповіщення; зовнішні копії шифруються перед вивантаженням у S3-сумісне сховище.">
</picture>

[Сповіщення](../OPERATIONS.md#notifications) · [Зашифрована зовнішня копія](../wiki/Off-site-Copy.md) · [Резервне копіювання й відновлення](../wiki/Backup-and-Recovery.md) · [Усунення несправностей](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/uk/docs/start/"><b>Посібник із налаштування&nbsp;↗</b></a><br><sub>Від встановлення до першого чату</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/uk/docs/dedicated-account/"><b>Підготовка облікового запису&nbsp;↗</b></a><br><sub>Спеціальний обліковий запис Telegram</sub></td>
<td width="33%" align="center"><a href="DEPLOYMENT.md"><b>Docker і сервери&nbsp;↗</b></a><br><sub>HTTPS, перезапуски й оновлення</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>Огляд репозиторію</strong> · де лежать код, документація та інструменти</summary>

| Каталог | З чого почати |
| --- | --- |
| [docs/](../README.md) | Налаштування, сценарії розслідувань і технічний довідник |
| [tgwitness/](../../tgwitness/README.md) | Основний застосунок, колектор, журнал і вебпанель |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | Незалежні засоби запису та код їх перевірки |
| [addons/](../../addons/README.md) | Встановлення, налаштування й тести додаткових засобів збору |
| [deploy/](../../deploy/README.md) | Інсталятори, контейнери та фонові служби |
| [examples/](../../examples/README.md) | Конфігурації для експорту облікового запису та запечатаного збору |
| [integrations/](../../integrations/README.md) | Підписані вебхуки та приймач для n8n |
| [.agents/](../../.agents/README.md) | Інструкції до завдань із читання архіву через CLI |
| [scripts/](../../scripts/README.md) | Скрипти запуску та утиліти CI |
| [tools/](../../tools/README.md) | Збирання, перевірки й пакування |
| [website/](../../website/README.md) | Публічний сайт, перекладені посібники та інтерактивне демо |
| [.github/](../../.github/AUTOMATION.md) | Робочі процеси, правила участі та підтримка |

[Повний путівник проєктом](../PROJECT-GUIDE.md) ·
[Участь у розробці](../../.github/CONTRIBUTING.md) · [Отримати допомогу](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ Етичне повідомлення та історична спадкоємність</strong></summary>

Позиція авторів і повідомлення для операторів українською:

[Повідомлення для операторів](OPERATOR-INCOMPATIBILITY.md) · [Ліцензія MIT](../../LICENSE) · [Оригінальний NOTICE](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>Огляд проєкту вашою мовою</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · **Українська** · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>Технічна документація</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Посібник із розслідувань</b></a> ·
  <a href="https://github.com/phishdestroy"><b>Створено PhishDestroy</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>Долучитися</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>Отримати допомогу</b></a> ·
  <a href="../../.github/SECURITY.md"><b>Повідомити про вразливість</b></a>
</p>

[Машинозчитуваний індекс проєкту](../../llms.txt) · [Повний посібник одним текстом](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [Правила репозиторію для агентів](../../AGENTS.md)
