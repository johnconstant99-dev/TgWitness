<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">Другие языки</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Идите по следу. Сохраняйте доказательства. Подписанный журнал, связанный цепочкой хешей, отдельно хранимая контрольная точка и проверяемый архив доказательств.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=ru"><b>Открыть демо&nbsp;↗</b></a><br><sub>Настоящий интерфейс с вымышленными записями</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>Скачать и запустить&nbsp;↓</b></a><br><sub>Одна команда для Linux, macOS и Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Читать руководство&nbsp;↗</b></a><br><sub>Пошаговые инструкции для расследований</sub></td>
</tr>
</table>

<p align="center"><strong>Рабочее место для расследований в Telegram, развёрнутое у вас.</strong><br>Сохраняйте чаты, правки и удалённые сообщения, смотрите, кто с кем связан,<br>и передавайте подписанные экспорты, которые может проверить любой.</p>

<p align="center"><strong>НУЛЕВОЕ ДОВЕРИЕ.</strong> TgWitness ни на чьей стороне: одни и те же проверки применяются к оператору, к PhishDestroy и к кому угодно ещё.<br>Значение имеет только то, что подтверждает третья сторона или математика. <a href="../QUESTIONS-AND-CHECKS.md">Вопросы и проверки</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.3 · предварительный выпуск"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">Проверенные среды</a> · 25 языков интерфейса · 26 языков руководств</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=ru">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="Демо TgWitness в действии: зафиксированные сообщения, сохранённые версии и содержимое, оставшееся после удаления. Вымышленные демонстрационные записи.">
</picture>
</a>

<p align="center"><sub>Изучите настоящий интерфейс на вымышленных записях. Нажмите на рабочую область, чтобы попробовать.</sub></p>

## Что делает TgWitness

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">Каждая правка и каждое удаление сохраняются</a></b><br><sub>Сохраняется каждая версия сообщения, а его текст остаётся и после уведомления об удалении.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">Доказательства, которые может проверить любой</a></b><br><sub>Подписанные записи, связанные цепочкой хешей. Получатель проверяет архив офлайн одной командой.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">Происхождение, которое можно показать</a></b><br><sub>Сообщения приходят через аутентифицированный сеанс MTProto аккаунта и подписываются при получении; GitHub Actions и Intel TDX добавляют аттестацию.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">Замеры на больших объёмах</a></b><br><sub>48 проверенных архивов с 3 598 381 записью; восемь аккаунтов загрузили 768 007 записей истории со скоростью 687,5 записи/с.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">Создано для расследований</a></b><br><sub>Списки наблюдения по тексту, QR-кодам и OCR, проверка кошельков, карточки субъектов, «Доска дела» и пакет для суда.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">Под вашим контролем</a></b><br><sub>Размещается у вас, без телеметрии. Сеансы лежат в зашифрованном хранилище; панель слушает localhost.</sub></td>
</tr>
</table>

<p align="center"><sub>Разрабатывается и тестируется около полугода: сначала сборщик, подписанный журнал и верификатор, затем панель и дополнительные модули. Этот репозиторий создан 29 октября 2026 года для публикации, поэтому его возраст — не возраст проекта.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## Установка

Python входит в комплект. Для обновления используйте те же команды.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell или CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Сервер Ubuntu: запускайте от root. Рабочий компьютер: от обычного пользователя. `-ExecutionPolicy Bypass` действует только на этот процесс PowerShell.</sub>

Подписанные сборки создаёт публичный [рабочий процесс Installer](../../.github/workflows/installer.yml), а установщик перед установкой проверяет SHA-256 и подпись RSA каждого пакета.

[Сначала проверить скрипт](../INSTALLATION.md#verify-before-running) · [Первая настройка](SETTINGS.md) · [Релизы](https://github.com/phishdestroy/TgWitness/releases) · [Docker](DEPLOYMENT.md)

<details>
<summary><strong>Как защищены установщик и ваши данные</strong></summary>

`get.destroy.tools` — сайт загрузок проекта. Публичный
[рабочий процесс Installer](../../.github/workflows/installer.yml) собирает его из
[`deploy/installer/`](../../deploy/installer/README.md) для конкретной ревизии `main`,
публикует после успешных тестов установки на Linux и Windows и подписывает
скрипты установщика и пакеты приложения ключом выпуска из
[`release-signing.pub`](../../deploy/installer/release-signing.pub). Перед установкой установщик проверяет
SHA-256 и подпись RSA пакета и lock-файла зависимостей.
Чтобы сначала проверить сам скрипт, скачайте его вместе с подписью и выполните
[команды предварительной проверки](../INSTALLATION.md#verify-before-running). Если сборка не удалась,
для загрузки остаётся предыдущая версия; установленные панели обновляются при повторном запуске установщика.
[Релизы](https://github.com/phishdestroy/TgWitness/releases) на GitHub, исходный код и
[Docker](DEPLOYMENT.md) — другие способы установки.

**Ваши сеансы и данные.** TgWitness работает на вашем компьютере или сервере, а панель
по умолчанию слушает localhost. Сеансы Telegram, учётные данные прокси и хеши
токенов доступа хранятся в зашифрованном хранилище каждой рабочей области; можно добавить
[внешний мастер-ключ](../SECURITY-MODEL.md#external-master-key). У приложения
нет телеметрии. Оно подключается к Telegram и к сервисам, заданным в настройках:
публичным спискам MTProxy, вашим прокси, хранилищу S3, боту-свидетелю, службам
меток времени, провайдерам ИИ и веб-хукам. [Карта системы](../SYSTEM-MAP.md) показывает
соединения, которые устанавливает процесс приложения.
Для наблюдения используйте [выделенный аккаунт Telegram](https://phishdestroy.github.io/TgWitness/ru/docs/dedicated-account/).

Значок версии относится к этому дереву исходного кода. Сборки для установки перечислены в разделе
[Релизы](https://github.com/phishdestroy/TgWitness/releases); функция, влитая в
`main`, попадает в них со следующим выпуском.

[Установка и доступ к панели](../INSTALLATION.md) ·
[Подписи и SHA-256](https://get.destroy.tools/#verification) ·
[Обновление](../INSTALLATION.md#update-an-existing-installation) ·
[Текущие возможности и статус проверки](../STATUS.md) ·
[Выбор способа сбора](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## Запись, которую может проверить кто-то другой

Проверьте без аккаунта и установки. Опубликованный образец содержит собственный верификатор:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # верификатор поставляется внутри архива
python verify.py tgwitness-demo.zip          # Python 3.11+, нужен только `cryptography`
```

Он выводит подписанные записи, хеш заголовка и отпечаток подписанта и завершается с кодом `0`.
Образец вымышленный; тот же верификатор работает с любым реальным экспортом.

Экспорт содержит сообщения, файлы и верификатор. Передайте получателю отпечаток
своего ключа по другому каналу, и он сможет проверить экспорт сам:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

Верификатор проверяет подписи, цепочку журнала, список файлов и вложения.
Чтобы экспорт считался доказательством, нужны отпечаток вашего ключа и сторонняя метка времени, охватывающая последнюю
запись, например метка времени RFC 3161, проверенная по корневому сертификату службы меток времени.

**Откуда берутся сообщения.** TgWitness получает их от Telegram через
зашифрованный сеанс MTProto аккаунта, как и официальные приложения, и по мере поступления
подписывает каждое и заносит в журнал. [Сбор через GitHub Actions](SEALED-ACTIONS.md) и
[Phala Intel TDX](HIGH-ASSURANCE.md) дополнительно аттестуют коллектор, который их получил.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="Новые сообщения, сохранённые правки и зафиксированные удаления образуют связанный подписанный журнал. Проверьте его по ключу, доверие к которому установлено независимо.">
</picture>

[Проверка архива](../wiki/Exports-and-Verification.md) · [Формат доказательств](../EVIDENCE.md) · [Независимый свидетель](WITNESS.md) · [Внешние метки времени](../TIMESTAMP.md) · [Проверки и испытанные объёмы](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## От переписки к делу

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="Три анимированных сценария: экспорт чата в HTML и JSON, поиск опубликованной ссылки по всем записанным чатам и сохранение зафиксированных версий после уведомления об удалении.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>Экспорт чата&nbsp;↗</b></a><br><sub>Один чат в подписанные HTML и JSON</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>Расследование&nbsp;↗</b></a><br><sub>Идите по зацепке через записанные чаты</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>Сохранённые версии&nbsp;↗</b></a><br><sub>Правки и уведомления об удалении сохраняются</sub></td>
</tr>
</table>

Два способа работы: один раз [экспортировать свой аккаунт](ACCOUNT-EXPORT.md) или
[вести расследование](../INVESTIGATION.md) и продолжать сохранять изменения.
Выберите несколько чатов, папку Telegram или весь аккаунт. У каждого аккаунта
своя рабочая область, свой сеанс и свой ключ подписи.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Подробнее

<details>
<summary><strong>Замеры экспорта · 6 ноября 2026 г.</strong> · 56 329 сообщений, оба архива проверены</summary>

**56 329 сообщений экспортировано за два новых прогона.** Оба подписанных архива прошли проверку с закреплёнными ключами коллектора.

[![Измеренная скорость сбора и полного экспорта](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/ru/docs/validation/)

| Прогон | Сообщения | Время сбора | Скорость сбора | Полный экспорт | Сквозная скорость |
| --- | ---: | ---: | ---: | ---: | ---: |
| Сервер A | 27 030 | 189,043 с | **142,983 сообщ./с** | 211,647 с | 127,713 сообщ./с |
| Сервер B | 29 299 | 182,513 с | **160,531 сообщ./с** | 206,650 с | 141,781 сообщ./с |

Текст и метаданные через WARP, по два аккаунта на сервер, без вложений и повторно использованных записей.
Измерено на ревизии [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e).
Для каждого опубликованного прогона указаны ревизия исходного кода, нагрузка, тайминги и результат проверки:
[нагрузка, тайминги и проверка](../EXPORT-BENCHMARK-2026-11-06.md). Изменения в `main`
проходят через публичные [рабочие процессы CI](../../.github/workflows/README.md), включая тесты установщика
на Linux и Windows и сборку автономного верификатора.

[**Открыть демо →**](https://phishdestroy.github.io/TgWitness/demo/?lang=ru) ·
[**Замеры, даты и методика →**](https://phishdestroy.github.io/TgWitness/ru/docs/validation/) ·
[Скачать вымышленный образец экспорта](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[Подписанный аудит на английском](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>Простой старт. Все маршруты на виду.</strong> · первый запуск и карта системы</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="При первом запуске предлагается выбрать «Просто скачать», «Следить за чатами» или «Доказательства по делу», и панель показывает только подходящие разделы. Карта системы связывает панель, коллектор, Telegram, журнал, свидетеля и внешние сервисы и показывает сетевые наблюдения. Вымышленные значения.">
</picture>

При первом запуске задаётся один вопрос: **Просто скачать**, **Следить за чатами** или
**Доказательства по делу**. Ответ определяет цель и уровень интерфейса, поэтому
панель показывает только разделы, нужные для этой задачи. Подключение, вход в Telegram и
выбор чатов проходят в пять этапов. Проверка подключения запускается сама, а
параметры маршрута открываются, только если она не прошла. До экспертных инструментов — один переключатель.

**Карта системы** показывает, как установка связывается с Telegram и внешними
сервисами: доступ к панели, маршрут каждого аккаунта и его адрес в Telegram, путь журнала и
свидетеля, последние сетевые наблюдения. Отсутствующее наблюдение
так и помечается — как отсутствующее.

[Первая настройка](SETTINGS.md) · [Карта системы](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>Для всего остального в расследовании</strong> · карточки субъектов, списки наблюдения, кошельки, отслеживание онлайна, документы для суда</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Отслеживайте отображаемые имена и имена пользователей по Telegram ID. Записывайте поддерживаемые взаимодействия с ботами с подписанными квитанциями. Ищите по архиву сообщений и подключайте MCP-клиенты только для чтения. Разворачивайте коллектор со скрытым SSH и записями провайдера для проверки. Документируйте переписку шаг за шагом со ссылками на журнал. Передавайте пакет дела BagIt с шаблонами для суда. Иллюстративные сценарии.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>Люди и досье&nbsp;↗</b></a><br><sub>Отображаемые имена и имена пользователей по Telegram ID</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>Расследование ботов&nbsp;↗</b></a><br><sub>Взаимодействия с ботами с подписанными квитанциями</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/ru/docs/archive/"><b>Поиск по архиву, ИИ и MCP&nbsp;↗</b></a><br><sub>Поиск по архиву и клиенты только для чтения</sub></td>
<td width="50%" align="center"><a href="HIGH-ASSURANCE.md"><b>Запечатанное облачное развёртывание&nbsp;↗</b></a><br><sub>Коллектор внутри Intel TDX</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="Три анимированных шага: карточка субъекта, в более позднем снимке которой зафиксировано переименование; план разговора, цели которого закрываются записями журнала; платёжный QR-код, декодированный в кошелёк с верной контрольной суммой, который даёт совпадение по списку наблюдения. Вымышленные значения.">
</picture>

**Документируйте переписку.** Начните документирование чата в панели **Заметки и протокол**,
и каждый шаг будет записываться сам: действия в панели, ответы с задержкой перед
ними, правки, уведомления об удалении, заметки и черновики ИИ. Каждый шаг ссылается на свою запись
журнала и SHA-256. Фиксация документа подписывает его и заносит хеш протокола
в журнал.

| | |
| --- | --- |
| [Карточки субъектов](../INVESTIGATION-MODE.md#subject-cards) | Снимки профиля бота, человека, канала или группы с метками Telegram BOT, VERIFIED, SCAM и FAKE; более поздний снимок показывает, что изменилось |
| [Планы разговора](../INVESTIGATION-MODE.md#conversation-plans) | Цели по платёжному маршруту, инфраструктуре или людям, заготовленные сообщения, время ответов, активность по часам и манера письма собеседника |
| [Перевод](../INVESTIGATION-MODE.md#machine-translation) | Показывается под оригиналом с указанием языков, модели и записи журнала |
| [Списки наблюдения](../INVESTIGATION-MODE.md#watchlists) | Слова, шаблоны, кошельки, @имена пользователей, ID, домены, телефоны и ссылки — совпадения ищутся в тексте, правках, скрытых адресах ссылок, кнопках ботов, QR-кодах и OCR |
| [Отслеживание онлайна](../INVESTIGATION-MODE.md#online-watch) | Проверка каждые 1–60 минут, до 100 аккаунтов за запрос, с картиной по часам и дням недели |
| [Коды и кошельки](../INVESTIGATION-MODE.md#codes-in-images) | Платёжные QR-коды; проверка EVM-адресов по EIP-55, адреса TON в raw-формате, контрольные суммы XRP Ledger, платёжные ссылки с сетью, суммой и токеном |
| [Следы клиента](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-show) | Следы кодировщика в видеокружках и голосовых сообщениях; сравнение времени загрузки со временем отправки выявляет заранее записанные «живые» доказательства |
| [Легенда и полномочия](../INVESTIGATION-MODE.md#cover-and-authority) | Персоны, разрешения и учёт работы под прикрытием, который отмечает сообщения вне разрешённых чатов или периода |
| [Управление аккаунтом](../INVESTIGATION-MODE.md#account-control) | Изменение профиля и приватности с записями «до» и «после», проверка раскрытия и уход в офлайн сразу после каждого действия |
| [Документы для суда](../INVESTIGATION-MODE.md#documents-for-court) | Пакет дела BagIt с шаблоном сертификации по Rule 902(13)/(14), описью доказательств, приложением к запросу и субтитрами WebVTT/SRT для записей экрана |

Материалы с пометками 18+, «насилие» или «персональные данные» остаются в копии для суда, запечатанные
AES-256-GCM; ключи передаются отдельно.

[Настройки экспорта](../EXPORT_HASHES.md) охватывают получение через обычный API и через Takeout,
загрузку истории сообщений до вложений, скачивание файлов или серверные хеши и совместимые
представления Telegram Desktop в JSON/HTML. [Распределённый экспорт чатов](../DISTRIBUTED-EXPORT.md#history-acquisition)
предлагает включаемый по желанию путь через Takeout для публичной истории, подписанные контрольные точки каждые 100 сообщений
и восстановление в пределах диапазона с тем же аккаунтом; в его
[проекте производительности](../FAST-ACQUISITION.md) описано проверенное поведение загрузки
и запланированные замеры в реальных условиях.

</details>

<details>
<summary><strong>Всё остальное</strong> · история, аккаунты, прокси, ИИ, интеграции</summary>

| | |
| --- | --- |
| [Загрузка старых сообщений](../HISTORY.md) | Загружайте прошлую историю выбранных чатов, ставьте на паузу и продолжайте в любой момент |
| [Несколько аккаунтов](../ACCOUNTS.md#multiple-accounts) | Отдельные рабочие области, у каждой свой сеанс Telegram, журнал и ключ подписи |
| [Пакетный импорт](../ACCOUNTS.md#bulk-import-and-account-groups) | Загрузите сразу пачку файлов сеансов и распределите аккаунты по группам с общими настройками |
| [Пул MTProxy](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Пинг, страны, фильтры, собственные списки |
| [Существующие сеансы](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key или строка `key:DC`; по желанию — независимая авторизация по QR через импортированный аккаунт-донор |
| [Безопасность аккаунта](../ACCOUNTS.md#create-an-independent-authorization) | Оповещения о новых сеансах, завершение других сеансов, режим единственного сеанса, который также задаёт пароль двухэтапной проверки, и [проверка свидетелем](../ACCOUNTS.md#witness-probe), которая замечает, что живые обновления перестали доходить до этого сеанса |
| [Возобновляемый экспорт чата](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | Остановленный экспорт сохраняет подписанную частичную копию: продолжите его, начните заново или скачайте то, что уже сохранено |
| [Прокси](../CONNECTION-SECURITY.md#ip-modes) | SOCKS5, HTTP CONNECT или MTProxy для каждой рабочей области. **Скрыть IP** никогда не переключается на прямое подключение |
| [Поиск и ИИ](../ANALYSIS.md) | Локальный поиск, ИИ по желанию с источниками, которые можно проверить |
| [Полнотекстовый поиск](../SEARCH.md) | Словоформы, точные фразы, домены, @имена пользователей и китайский текст без пробелов, лучшие совпадения первыми (**предварительная версия**) |
| [MCP](../MCP.md) | Доступ только для чтения для MCP-клиентов, ограниченный выбранными вами чатами |
| [Командная строка](../CLI.md) | `search`, `context`, `messages`, `stats` и `export` в JSON Lines с `--json` для скриптов и агентов — локально или с токеном ограниченного доступа (**предварительная версия**) |
| [OCR и транскрибация](../MEDIA-ANALYSIS.md) | Работает локально, оригиналы не изменяются |
| [Независимый сбор данных](../OPTIONAL-CAPTURE.md) | Дополнительные средства записи через браузер/AyuGram в разделе **Инструменты → Дополнительно** (предварительная версия, по умолчанию выключены) |
| [Trusted Live](../TRUSTED-LIVE.md) | Сеанс официального Desktop/Web, защищённая видеозапись и анализ непрерывности относительно штатного экспорта (предварительная версия; проверка в реальных условиях ещё не проведена) |
| [Запечатанный официальный Web](../OFFICIAL-WITNESS.md) | Чистый официальный браузер на GitHub Actions, ограниченное управление, подписанное видео и независимо ожидаемые исходники и настройки |
| [Веб-хуки](../WEBHOOKS.md) | Подписанные исходящие события с повторными попытками, пример для n8n в комплекте |
| [Общий доступ](../ACCESS.md) | Открывайте доступ только к выбранным чатам, со сроком действия и ограничением по IP |
| [Пропущенные номера сообщений](../EVIDENCE.md#missing-message-numbers-gap_summary) | Номера, которые Telegram присвоил, но которые ни разу не наблюдались, — по каналам и по всему аккаунту, в покрытии, отчётах и MCP (**предварительная версия**) |
| [Снимки состояния чата](../COLLECTION.md) | Периодические подписанные снимки названия, описания, закреплённых сообщений, администраторов и подарков с указанием изменений (**предварительная версия**) |
| [Карта системы](../SYSTEM-MAP.md) | Живая карта доступа к панели, маршрутов аккаунтов, адресов Telegram и внешних сервисов с последними 200 из не более чем 2000 сетевых наблюдений |

</details>

<details>
<summary><strong>Выберите, чем подкрепить запись</strong> · локально, облако с аудитом, GitHub Actions или Intel TDX</summary>

Запускайте локально, добавьте облачное развёртывание с аудитом или собирайте данные внутри **конфиденциальной ВМ Phala Cloud
с Intel TDX**. Каждый вариант сохраняет подписанный журнал; дополнительные
проверки касаются среды, в которой он был собран.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="Три варианта развёртывания: локальная проверка журнала; ВМ с аудитом и записями провайдера и доступа; Phala Intel TDX с проверенным отчётом аттестации, измеренными ОС и приложением и привязанным ключом коллектора.">
</picture>

Верификатор TDX проверяет отчёт аттестации по закреплённому корневому сертификату Intel и данным об отзыве,
привязывает его к подписанному заявлению коллектора и свежему вызову и сравнивает
измеренные ОС и приложение с независимо ожидаемыми входными данными. В итоговом отчёте
каждый результат указан отдельно, поэтому измеренную среду, идентичность коллектора, записи
сбора и покрытие можно рассматривать вместе.

**Сбор с подтверждением происхождения от GitHub** (предварительная версия). Соберите чат на раннере GitHub
с закреплённой версией TgWitness и новым сеансом Telegram, затем скачайте зашифрованный
архив вместе с аттестацией GitHub. Верификатор проверяет одобренный рабочий процесс и
версию коллектора, дайджест архива, журнал и вложения. Также доступно
в панели в разделе **Экспорт**.
[Открыть страницу сбора](https://phishdestroy.github.io/TgWitness/ru/docs/capture/) · [Инструкция](SEALED-ACTIONS.md)

Для наблюдения в реальном времени, загрузки истории или разового экспорта выберите
[способ сбора](../COLLECTION-MODES.md). Приватные облачные чаты доступны,
если у подключённого аккаунта есть к ним доступ. Опубликованное приложение также включает
[интеграцию с секретными чатами](../PSEUDO-SECRET.md): установите необязательную зависимость
протокола и включите её для аккаунта, чтобы записывать созданные или принятые в нём чаты.
Доступные способы получения данных описаны в разделе [Границы сбора](../COLLECTION.md).

[Phala / Intel TDX и развёртывания с аудитом](HIGH-ASSURANCE.md) ·
[Проверка Phala в реальных условиях](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[Границы доверия](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>Проверьте сбор и сохранённую запись</strong> · проверки получателя и Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="Зафиксируйте переписку. Проверьте запись. Сохраняйте сообщения, правки и файлы, проверяйте подписи и контрольные точки и изучайте процесс сбора.">
</picture>

TgWitness записывает содержимое, доставленное в подключённый аккаунт Telegram, вместе с
идентификаторами чата, сообщения и отправителя, зафиксированными версиями и метаданными сбора.
Архив собирает эти записи, сохранённые вложения и данные для проверки
в одном месте, чтобы их можно было изучить.

| Проверка | Что проверяет получатель |
| --- | --- |
| Подписанный журнал и манифест | Подписи записей, цепочку хешей и переданные файлы — по ожидаемому ключу подписи. |
| Отдельно хранимая контрольная точка | Журнал — по ранее записанной длине и хешу заголовка. |
| Независимый свидетель | Журнал — по контрольным точкам, которые хранит отдельный свидетель. |
| Сбор через GitHub Actions | Архив — по его аттестации, одобренному рабочему процессу на раннере GitHub и версии коллектора. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
показывает переписку в Telegram рядом с намеренно изменёнными файлами экспорта Desktop.
Сравните версии, изучите изменения и пройдите шаги сбора и
проверки подписанного архива TgWitness.

[Шаги проверки](../wiki/Exports-and-Verification.md) ·
[Сбор через GitHub](SEALED-ACTIONS.md) ·
[Техническая модель доверия](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>Расследование без перерывов</strong> · уведомления, хранение и восстановление</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="Анимированные сценарии: Apprise отправляет настроенные оповещения; внешние копии шифруются перед загрузкой в S3-совместимое хранилище.">
</picture>

[Уведомления](../OPERATIONS.md#notifications) · [Зашифрованная внешняя копия](../wiki/Off-site-Copy.md) · [Резервное копирование и восстановление](../wiki/Backup-and-Recovery.md) · [Устранение неполадок](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/ru/docs/start/"><b>Руководство по настройке&nbsp;↗</b></a><br><sub>От установки до первого чата</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/ru/docs/dedicated-account/"><b>Подготовка аккаунта&nbsp;↗</b></a><br><sub>Выделенный аккаунт Telegram</sub></td>
<td width="33%" align="center"><a href="DEPLOYMENT.md"><b>Docker и серверы&nbsp;↗</b></a><br><sub>HTTPS, перезапуски и обновления</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>Обзор репозитория</strong> · где находятся код, документация и инструменты</summary>

| Каталог | С чего начать |
| --- | --- |
| [docs/](../README.md) | Настройка, сценарии расследований и технический справочник |
| [tgwitness/](../../tgwitness/README.md) | Основное приложение, коллектор, журнал и веб-панель |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | Независимые средства записи и код их проверки |
| [addons/](../../addons/README.md) | Установка, настройка и тесты дополнительных средств сбора |
| [deploy/](../../deploy/README.md) | Установщики, контейнеры и фоновые службы |
| [examples/](../../examples/README.md) | Конфигурации для экспорта аккаунта и запечатанного сбора |
| [integrations/](../../integrations/README.md) | Подписанные веб-хуки и приёмник для n8n |
| [.agents/](../../.agents/README.md) | Инструкции к задачам по чтению архива через CLI |
| [scripts/](../../scripts/README.md) | Скрипты запуска и утилиты CI |
| [tools/](../../tools/README.md) | Сборка, проверки и упаковка |
| [website/](../../website/README.md) | Публичный сайт, переведённые руководства и интерактивное демо |
| [.github/](../../.github/AUTOMATION.md) | Рабочие процессы, правила участия и поддержка |

[Полный путеводитель по проекту](../PROJECT-GUIDE.md) ·
[Участие в разработке](../../.github/CONTRIBUTING.md) · [Получить помощь](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ Этическое уведомление и историческая преемственность</strong></summary>

Позиция авторов и уведомление для операторов на русском языке:

[Уведомление для операторов](OPERATOR-INCOMPATIBILITY.md) · [Лицензия MIT](../../LICENSE) · [Оригинальный NOTICE](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>Обзор проекта на вашем языке</strong></summary>

[English](../../README.md) · **Русский** · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>Техническая документация</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Руководство по расследованиям</b></a> ·
  <a href="https://github.com/phishdestroy"><b>Создано PhishDestroy</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>Участвовать</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>Получить помощь</b></a> ·
  <a href="../../.github/SECURITY.md"><b>Сообщить об уязвимости</b></a>
</p>

[Машиночитаемый индекс проекта](../../llms.txt) · [Полное руководство одним текстом](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [Правила репозитория для агентов](../../AGENTS.md)
