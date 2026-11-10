<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">Weitere Sprachen</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Der Spur folgen. Beweise sichern. Ein per Hash verkettetes, signiertes Journal, ein separat aufbewahrter Checkpoint und ein überprüfbares Beweisarchiv.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=de"><b>Demo ansehen&nbsp;↗</b></a><br><sub>Die echte Oberfläche mit fiktiven Einträgen</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>Herunterladen und starten&nbsp;↓</b></a><br><sub>Ein Befehl für Linux, macOS und Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Handbuch lesen&nbsp;↗</b></a><br><sub>Ermittlungsanleitungen Schritt für Schritt</sub></td>
</tr>
</table>

<p align="center"><strong>Selbst gehostete Arbeitsumgebung für Telegram-Ermittlungen.</strong><br>Chats sichern, Bearbeitungen und Löschungen festhalten, sehen, wer mit wem verbunden ist,<br>und signierte Exporte übergeben, die jeder prüfen kann.</p>

<p align="center"><strong>ZERO TRUST.</strong> TgWitness ergreift keine Partei: Für den Betreiber, für PhishDestroy und für alle anderen gelten dieselben Prüfungen.<br>Es zählt nur, was ein Dritter oder die Mathematik bestätigt. <a href="../LIMITS-AND-OBJECTIONS.md">Grenzen und Einwände</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.2 · Vorabversion"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">Getestete Umgebungen</a> · 25 Oberflächensprachen · 26 Sprachen für Anleitungen</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=de">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="Die TgWitness-Demo in Aktion: erfasste Nachrichten, gespeicherte Versionen und Inhalte, die nach dem Löschen erhalten bleiben. Fiktive Demo-Einträge.">
</picture>
</a>

<p align="center"><sub>Erkunden Sie die echte Oberfläche mit fiktiven Einträgen. Klicken Sie auf den Arbeitsbereich, um sie auszuprobieren.</sub></p>

## Was TgWitness leistet

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">Jede Bearbeitung und Löschung bleibt erhalten</a></b><br><sub>Jede Version einer Nachricht wird gespeichert, und ihr Text bleibt auch nach einer Löschmeldung erhalten.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">Beweise, die jeder prüfen kann</a></b><br><sub>Signierte, per Hash verkettete Einträge. Der Empfänger prüft das Archiv offline mit einem Befehl.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">Nachweisbare Herkunft</a></b><br><sub>Empfangen über die authentifizierte MTProto-Sitzung des Kontos und beim Eintreffen signiert; GitHub Actions und Intel TDX ergänzen eine Attestierung.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">Im großen Maßstab gemessen</a></b><br><sub>48 verifizierte Archive mit 3.598.381 Einträgen; acht Konten haben 768.007 Verlaufseinträge mit 687,5 Einträgen/s abgerufen.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">Für Ermittlungen gebaut</a></b><br><sub>Beobachtungslisten für Text, QR-Codes und OCR, Wallet-Prüfungen, Subjektkarten, Fallübersicht und ein Gerichtspaket.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">Unter Ihrer Kontrolle</a></b><br><sub>Selbst gehostet, ohne Telemetrie. Sitzungen liegen in einem verschlüsselten Tresor; das Panel lauscht auf localhost.</sub></td>
</tr>
</table>

<p align="center"><sub>Entwicklung und Tests dauerten etwa sechs Monate: zunächst der Collector, das signierte Protokoll und der Verifier, anschließend das Panel und die Zusatzmodule. Dieses Repository wurde am 29. Oktober 2026 zur Veröffentlichung angelegt, sein Alter entspricht also nicht dem Alter des Projekts.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## Installation

Python ist enthalten. Für Updates dieselben Befehle verwenden.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell oder CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Ubuntu-Server: als root ausführen. Desktop: als normaler Benutzer ausführen. `-ExecutionPolicy Bypass` gilt nur für diesen einen PowerShell-Prozess.</sub>

Signierte Builds stammen aus dem öffentlichen [Installer-Workflow](../../.github/workflows/installer.yml), und der Installer prüft vor der Installation SHA-256 und RSA-Signatur jedes Pakets.

[Skript zuerst prüfen](../INSTALLATION.md#verify-before-running) · [Ersteinrichtung](../SETTINGS.md) · [Releases](https://github.com/phishdestroy/TgWitness/releases) · [Docker](../DEPLOYMENT.md)

<details>
<summary><strong>Wie der Installer und Ihre Daten geschützt sind</strong></summary>

`get.destroy.tools` ist die Download-Seite des Projekts. Der öffentliche
[Installer-Workflow](../../.github/workflows/installer.yml) baut sie aus
[`deploy/installer/`](../../deploy/installer/README.md) für die exakte `main`-Revision,
veröffentlicht sie, nachdem die Installationstests unter Linux und Windows bestanden sind, und signiert die
Installer-Skripte und Anwendungspakete mit dem Release-Schlüssel aus
[`release-signing.pub`](../../deploy/installer/release-signing.pub). Der Installer prüft
vor der Installation SHA-256 und RSA-Signatur des Pakets und des Dependency-Locks.
Um zuerst das Skript selbst zu prüfen, laden Sie es mit seiner Signatur herunter und führen die
[Befehle zur Vorabprüfung](../INSTALLATION.md#verify-before-running) aus. Ein fehlgeschlagener Build
lässt den vorherigen Download bestehen; installierte Panels werden aktualisiert, wenn Sie den Installer erneut ausführen.
[Releases](https://github.com/phishdestroy/TgWitness/releases) auf GitHub, Quellcode und
[Docker](../DEPLOYMENT.md) sind die anderen Installationswege.

**Ihre Sitzungen und Daten.** TgWitness läuft auf Ihrem Computer oder Server, und das Panel
lauscht standardmäßig auf localhost. Telegram-Sitzungen, Proxy-Zugangsdaten und Hashes von
Zugriffstokens liegen im verschlüsselten Tresor des jeweiligen Arbeitsbereichs, optional mit einem
[externen Hauptschlüssel](../SECURITY-MODEL.md#external-master-key). Die Anwendung
hat keine Telemetrie. Sie verbindet sich mit Telegram und mit den Diensten, die ihre Einstellungen nutzen:
öffentliche MTProxy-Listen, Ihre Proxys, S3-Speicher, ein Zeugen-Bot,
Zeitstempeldienste, KI-Anbieter und Webhooks. Die [Systemübersicht](../SYSTEM-MAP.md) listet
die Verbindungen auf, die der Anwendungsprozess aufbaut.
Beobachten Sie mit einem [dedizierten Telegram-Konto](https://phishdestroy.github.io/TgWitness/de/docs/dedicated-account/).

Das Versionsabzeichen beschreibt diesen Quellbaum. Installierbare Builds sind unter
[Releases](https://github.com/phishdestroy/TgWitness/releases) aufgeführt; ein in
`main` gemergtes Feature landet mit dem nächsten Release in diesen Downloads.

[Einrichtung und Panel-Zugriff](../INSTALLATION.md) ·
[Signaturen und SHA-256](https://get.destroy.tools/#verification) ·
[Aktualisierung](../INSTALLATION.md#update-an-existing-installation) ·
[Aktuelle Funktionen und Qualifizierung](../STATUS.md) ·
[Erfassungsmethode wählen](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## Eine Aufzeichnung, die andere prüfen können

Prüfen Sie es ohne Konto und ohne Installation. Das veröffentlichte Beispiel bringt sein eigenes Prüfprogramm mit:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # das Prüfprogramm liegt dem Archiv bei
python verify.py tgwitness-demo.zip          # Python 3.11+, benötigt nur `cryptography`
```

Es gibt die signierten Einträge, den Hash des neuesten Eintrags und den Fingerabdruck des Unterzeichners aus und endet mit `0`.
Das Beispiel ist fiktiv; dasselbe Prüfprogramm läuft mit jedem echten Export.

Ein Export enthält die Nachrichten, die Dateien und das Prüfprogramm. Senden Sie dem Empfänger den
Fingerabdruck Ihres Schlüssels über einen anderen Kanal, dann kann er den Export selbst prüfen:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

Das Prüfprogramm kontrolliert die Signaturen, die Journal-Kette, die Dateiliste und die Anhänge.
Damit der Export als Beweismittel gilt, braucht es den Fingerabdruck Ihres Schlüssels und einen Zeitstempel eines Dritten, der den letzten
Eintrag abdeckt, etwa einen Zeitstempel nach RFC 3161, geprüft gegen das Stammzertifikat des Zeitstempeldienstes.

**Woher die Nachrichten stammen.** TgWitness empfängt sie von Telegram über die
verschlüsselte MTProto-Sitzung des Kontos, so wie die offiziellen Apps, und schreibt jede beim Eintreffen signiert in das
Journal. Die [Erfassung mit GitHub Actions](../SEALED-ACTIONS.md) und
[Phala Intel TDX](../HIGH-ASSURANCE.md) attestieren zusätzlich den Collector, der sie empfangen hat.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="Neue Nachrichten, gespeicherte Bearbeitungen und beobachtete Löschungen bilden ein verkettetes, signiertes Journal. Prüfen Sie es gegen einen unabhängig als vertrauenswürdig bestätigten Schlüssel.">
</picture>

[Archivprüfung](../wiki/Exports-and-Verification.md) · [Beweisformat](../EVIDENCE.md) · [Unabhängiger Zeuge](../WITNESS.md) · [Externe Zeitstempel](../TIMESTAMP.md) · [Prüfungen und getestete Größenordnung](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Vom Gespräch zum Fall

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="Drei animierte Abläufe: einen Chat als HTML und JSON exportieren, einen geteilten Link in aufgezeichneten Chats finden und erfasste Versionen nach einer Löschmeldung behalten.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>Chat-Export&nbsp;↗</b></a><br><sub>Ein Chat als signiertes HTML und JSON</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>Ermittlung&nbsp;↗</b></a><br><sub>Einer Spur durch aufgezeichnete Chats folgen</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>Gespeicherte Versionen&nbsp;↗</b></a><br><sub>Bearbeitungen und Löschmeldungen, aufbewahrt</sub></td>
</tr>
</table>

Zwei Wege: [Ihr Konto einmalig exportieren](../ACCOUNT-EXPORT.md) oder
[eine Ermittlung begleiten](../INVESTIGATION.md) und Änderungen laufend sichern.
Wählen Sie einige Chats, einen Telegram-Ordner oder das ganze Konto. Jedes Konto erhält
seinen eigenen Arbeitsbereich, seine eigene Sitzung und seinen eigenen Signaturschlüssel.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Mehr entdecken

<details>
<summary><strong>Gemessene Exporte · 6. November 2026</strong> · 56.329 Nachrichten, beide Archive verifiziert</summary>

**56.329 Nachrichten in zwei frischen Durchläufen exportiert.** Beide signierten Archive bestanden die Verifizierung mit gepinnten Collector-Schlüsseln.

[![Gemessene Erfassungs- und Gesamtexportgeschwindigkeit](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/de/docs/validation/)

| Durchlauf | Nachrichten | Erfassungsdauer | Erfassungsrate | Vollständiger Export | Ende-zu-Ende-Rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| Server A | 27.030 | 189,043 s | **142,983 Nachr./s** | 211,647 s | 127,713 Nachr./s |
| Server B | 29.299 | 182,513 s | **160,531 Nachr./s** | 206,650 s | 141,781 Nachr./s |

Text und Metadaten über WARP, zwei Konten pro Server, keine Anhänge und keine wiederverwendeten Einträge.
Gemessen auf Revision [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e).
Jeder veröffentlichte Durchlauf nennt Quellrevision, Arbeitslast, Zeiten und Verifizierungsergebnis:
[Arbeitslast, Zeiten und Verifizierung](../EXPORT-BENCHMARK-2026-11-06.md). Änderungen an `main`
durchlaufen die öffentlichen [CI-Workflows](../../.github/workflows/README.md), einschließlich der Installer-Tests unter Linux und Windows
und des Builds des eigenständigen Prüfprogramms.

[**Demo ansehen →**](https://phishdestroy.github.io/TgWitness/demo/?lang=de) ·
[**Messungen, Zeitpunkte und Methode →**](https://phishdestroy.github.io/TgWitness/de/docs/validation/) ·
[Fiktiven Beispielexport herunterladen](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[Signiertes Audit auf Englisch](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>Einfach starten. Jede Route sehen.</strong> · erster Start und Systemübersicht</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="Beim ersten Start stehen „Einfach herunterladen“, „Chats beobachten“ oder „Beweismittel für einen Fall“ zur Wahl, und es werden nur die passenden Bereiche angezeigt. Die Systemübersicht verbindet Panel, Collector, Telegram, Journal, Zeuge und externe Dienste mit Netzwerkbeobachtungen. Fiktive Werte.">
</picture>

Der erste Start stellt eine Frage: **Einfach herunterladen**, **Chats beobachten** oder
**Beweismittel für einen Fall**. Die Antwort legt Ziel und Oberflächenstufe fest, sodass das
Panel nur die Bereiche zeigt, die diese Aufgabe braucht. Verbindung, Telegram-Anmeldung und
Chat-Auswahl folgen in fünf Schritten. Die Verbindungsprüfung läuft von selbst, und
Routenoptionen öffnen sich nur, wenn sie fehlschlägt. Expertenwerkzeuge sind nur einen Schalter entfernt.

Die **Systemübersicht** zeigt, wie die Installation Telegram und externe
Dienste erreicht: Panel-Zugriff, Route und Telegram-Ziel jedes Kontos, den Pfad von Journal und
Zeuge sowie die neuesten Netzwerkbeobachtungen. Eine fehlende Beobachtung wird
als fehlend gekennzeichnet.

[Ersteinrichtung](../SETTINGS.md) · [Systemübersicht](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>Für den Rest der Ermittlung gebaut</strong> · Subjektkarten, Beobachtungslisten, Wallets, Online-Überwachung, Gerichtsdokumente</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Namen und Benutzernamen über die Telegram-ID verfolgen. Unterstützte Bot-Interaktionen mit signierten Belegen aufzeichnen. Archivierte Nachrichten durchsuchen und schreibgeschützte MCP-Clients anbinden. Einen Collector mit maskiertem SSH und Anbieternachweisen zur Prüfung bereitstellen. Ein Gespräch Schritt für Schritt mit Journal-Verweisen dokumentieren. Ein BagIt-Fallpaket mit Gerichtsvorlagen übergeben. Beispielhafte Abläufe.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>Personen und Dossiers&nbsp;↗</b></a><br><sub>Namen und Benutzernamen nach Telegram-ID</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>Bot-Ermittlung&nbsp;↗</b></a><br><sub>Bot-Interaktionen mit signierten Belegen</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/de/docs/archive/"><b>Archivsuche, KI und MCP&nbsp;↗</b></a><br><sub>Archiv durchsuchen, schreibgeschützte Clients anbinden</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>Versiegelte Cloud-Bereitstellung&nbsp;↗</b></a><br><sub>Ein Collector in Intel TDX</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="Drei animierte Schritte: eine Subjektkarte, deren späterer Snapshot eine Umbenennung festhält, ein Gesprächsplan, dessen Ziele mit Journal-Einträgen abgeschlossen werden, und ein Zahlungs-QR-Code, der zu einer Wallet mit gültiger Prüfsumme dekodiert wird und einen Treffer auf der Beobachtungsliste auslöst. Fiktive Werte.">
</picture>

**Gespräch dokumentieren.** Starten Sie im Seitenbereich **Dokumentation** eine Aufzeichnung für einen Chat,
und jeder Schritt wird automatisch festgehalten: Panel-Aktionen, Antworten mit der Verzögerung
davor, Bearbeitungen, Löschmeldungen, Notizen und KI-Entwürfe. Jeder Schritt nennt seinen
Journal-Eintrag und SHA-256. Das Festschreiben des Dokuments signiert es und schreibt den Hash der Erklärung
in das Journal.

| | |
| --- | --- |
| [Subjektkarten](../INVESTIGATION-MODE.md#subject-cards) | Profil-Snapshots eines Bots, einer Person, eines Kanals oder einer Gruppe mit den Telegram-Kennzeichnungen BOT, VERIFIED, SCAM und FAKE; ein späterer Snapshot listet die Änderungen auf |
| [Gesprächspläne](../INVESTIGATION-MODE.md#conversation-plans) | Ziele zu Zahlungsweg, Infrastruktur oder Personen, vorbereitete Nachrichten, Antwortzeiten, Aktivität nach Stunde und der Schreibstil der Gegenseite |
| [Übersetzung](../INVESTIGATION-MODE.md#machine-translation) | Unter dem Original angezeigt, mit Sprachen, Modell und Journal-Eintrag |
| [Beobachtungslisten](../INVESTIGATION-MODE.md#watchlists) | Wörter, Muster, Wallets, @Benutzernamen, IDs, Domains, Telefonnummern und Links, abgeglichen in Text, Bearbeitungen, versteckten Linkzielen, Bot-Schaltflächen, QR-Codes und OCR |
| [Online-Überwachung](../INVESTIGATION-MODE.md#online-watch) | Prüfungen alle 1–60 Minuten, bis zu 100 Konten pro Anfrage, mit einem Muster nach Stunde und Wochentag |
| [Codes und Wallets](../INVESTIGATION-MODE.md#codes-in-images) | Zahlungs-QR-Codes; EVM-Adressen gegen EIP-55 geprüft, TON in Rohform, Prüfsummen für XRP Ledger, Zahlungslinks mit Chain, Betrag und Token |
| [Client-Spuren](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-can-and-cannot-show) | Encoder-Spuren von runden Videos und Sprachnachrichten; der Vergleich von Upload- und Sendezeit entlarvt vorab aufgezeichnete „Live“-Beweise |
| [Legende und Befugnis](../INVESTIGATION-MODE.md#cover-and-authority) | Personas, Genehmigungen und ein Nachweis verdeckter Tätigkeit, der Nachrichten außerhalb der genehmigten Chats oder des genehmigten Zeitraums markiert |
| [Kontosteuerung](../INVESTIGATION-MODE.md#account-control) | Bearbeitung von Profil und Privatsphäre mit Vorher-/Nachher-Einträgen, eine Expositionsprüfung und Offline-Schalten direkt nach jeder Aktion |
| [Dokumente für Gerichte](../INVESTIGATION-MODE.md#documents-for-court) | BagIt-Fallpaket mit Vorlage für eine Zertifizierung nach Rule 902(13)/(14), Beweismittelverzeichnis, Anfrageanhang und WebVTT/SRT-Untertiteln für Bildschirmaufnahmen |

Als 18+, Gewalt oder personenbezogene Daten markierte Inhalte bleiben in der Gerichtskopie, versiegelt mit
AES-256-GCM; die Schlüssel werden getrennt übermittelt.

[Exporteinstellungen](../EXPORT_HASHES.md) umfassen den Abruf über die reguläre API und über Takeout,
Nachrichtenverlauf vor Anhängen, Datei-Downloads oder Server-Hashes sowie kompatible
JSON/HTML-Ansichten von Telegram Desktop. [Verteilter Chat-Export](../DISTRIBUTED-EXPORT.md#history-acquisition)
bietet einen optionalen Takeout-Weg für öffentlichen Verlauf, signierte Checkpoints alle 100 Nachrichten
und Wiederaufnahme innerhalb eines Bereichs mit demselben Konto; sein
[Performance-Design](../FAST-ACQUISITION.md) beschreibt das getestete Abrufverhalten
und die geplanten Live-Messungen.

</details>

<details>
<summary><strong>Alles Weitere</strong> · Verlauf, Konten, Proxys, KI, Integrationen</summary>

| | |
| --- | --- |
| [Ältere Nachrichten laden](../HISTORY.md) | Früheren Verlauf ausgewählter Chats abrufen, jederzeit pausieren und fortsetzen |
| [Mehrere Konten](../ACCOUNTS.md#multiple-accounts) | Getrennte Arbeitsbereiche, jeder mit eigener Telegram-Sitzung, eigenem Journal und Signaturschlüssel |
| [Massenimport](../ACCOUNTS.md#bulk-import-and-account-groups) | Einen Stapel Sitzungsdateien hineinziehen, Konten in Gruppen mit gemeinsamen Einstellungen sortieren |
| [MTProxy-Pool](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping, Länder, Filter, eigene Listen |
| [Vorhandene Sitzungen](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key oder eine `key:DC`-Zeile; optional unabhängige QR-Autorisierung über ein importiertes Spenderkonto |
| [Kontosicherheit](../ACCOUNTS.md#create-an-independent-authorization) | Warnungen bei neuen Sitzungen, Beenden anderer Sitzungen, ein Einzelsitzungsmodus, der auch ein Passwort für die zweistufige Bestätigung setzt, und eine [Zeugen-Probe](../ACCOUNTS.md#witness-probe), die bemerkt, wenn Live-Updates diese Sitzung nicht mehr erreichen |
| [Fortsetzbarer Chat-Export](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | Ein gestoppter Export behält eine signierte Teilkopie: fortsetzen, neu beginnen oder das bereits Gespeicherte herunterladen |
| [Proxys](../CONNECTION-SECURITY.md#ip-modes) | SOCKS5, HTTP CONNECT oder MTProxy pro Arbeitsbereich. **IP verbergen** fällt nie auf eine direkte Verbindung zurück |
| [Suche und KI](../ANALYSIS.md) | Lokale Suche, optional KI mit überprüfbaren Quellen |
| [Volltextsuche](../SEARCH.md) | Wortformen, exakte Phrasen, Domains, @Benutzernamen und Chinesisch ohne Leerzeichen, beste Treffer zuerst (**Vorschau**) |
| [MCP](../MCP.md) | Lesezugriff für MCP-Clients, beschränkt auf die von Ihnen gewählten Chats |
| [Kommandozeile](../CLI.md) | `search`, `context`, `messages`, `stats` und `export` als JSON Lines mit `--json` für Skripte und Agenten, lokal oder mit einem eingeschränkten Token (**Vorschau**) |
| [OCR und Transkription](../MEDIA-ANALYSIS.md) | Läuft lokal, Originale bleiben unverändert |
| [Unabhängige Erfassung](../OPTIONAL-CAPTURE.md) | Optionale Browser-/AyuGram-Rekorder unter **Weitere Tools → Extras** (Vorschau, standardmäßig aus) |
| [Trusted Live](../TRUSTED-LIVE.md) | Offizielle Desktop-/Web-Sitzung, abgesichertes Video und Kontinuitätsanalyse gegenüber dem nativen Export (Vorschau; Live-Qualifizierung steht aus) |
| [Versiegeltes offizielles Web](../OFFICIAL-WITNESS.md) | Frischer offizieller Browser auf GitHub Actions, eingeschränkte Bedienung, signiertes Video und unabhängig erwartete Quelle/Einstellungen |
| [Webhooks](../WEBHOOKS.md) | Signierte ausgehende Ereignisse mit Wiederholungen, n8n-Beispiel inklusive |
| [Geteilter Zugriff](../ACCESS.md) | Jemandem nur ausgewählte Chats freigeben, mit Ablaufdatum und IP-Beschränkungen |
| [Fehlende Nachrichtennummern](../EVIDENCE.md#missing-message-numbers-gap_summary) | Von Telegram vergebene Nummern, die nie beobachtet wurden, pro Kanal und für das ganze Konto, in Abdeckung, Berichten und MCP (**Vorschau**) |
| [Snapshots des Chat-Zustands](../COLLECTION.md) | Regelmäßige signierte Snapshots von Titel, Beschreibung, angehefteten Nachrichten, Administratoren und Geschenken, mit den Änderungen (**Vorschau**) |
| [Systemübersicht](../SYSTEM-MAP.md) | Live-Karte von Panel-Zugriff, Kontorouten, Telegram-Zielen und externen Diensten, mit den neuesten 200 von bis zu 2.000 Netzwerkbeobachtungen |

</details>

<details>
<summary><strong>Wählen, was die Aufzeichnung absichert</strong> · lokal, auditierte Cloud, GitHub Actions oder Intel TDX</summary>

Lokal ausführen, eine auditierte Cloud-Bereitstellung hinzufügen oder in einer **vertraulichen VM in Phala Cloud
mit Intel TDX** erfassen. Jede Option behält das signierte Journal; die zusätzlichen
Prüfungen betreffen die Umgebung, in der es erfasst wurde.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="Drei Bereitstellungsoptionen: lokale Journal-Verifizierung; eine auditierte VM mit Anbieter- und Zugriffsnachweisen; Phala Intel TDX mit verifiziertem Quote, gemessenem Betriebssystem und gemessener Anwendung sowie gebundenem Collector-Schlüssel.">
</picture>

Das TDX-Prüfprogramm kontrolliert das Quote gegen das gepinnte Root-Zertifikat von Intel und die Sperrdaten,
bindet es an eine signierte Collector-Erklärung und eine frische Challenge und vergleicht
gemessenes Betriebssystem und Anwendung mit unabhängig erwarteten Eingaben. Der Bericht führt
jedes Ergebnis einzeln auf, sodass gemessene Umgebung, Collector-Identität,
Erfassungseinträge und Abdeckung gemeinsam geprüft werden können.

**Erfassung mit GitHub-Herkunftsnachweis** (Vorschau). Erfassen Sie einen Chat auf einem von GitHub gehosteten Runner
mit gepinntem TgWitness und frischer Telegram-Sitzung und laden Sie dann das verschlüsselte
Archiv mit seiner GitHub-Attestierung herunter. Das Prüfprogramm kontrolliert den genehmigten Workflow und
die Collector-Version, den Archiv-Digest, das Journal und die Anhänge. Auch im Panel
unter **Exporte** verfügbar.
[Erfassungsseite öffnen](https://phishdestroy.github.io/TgWitness/de/docs/capture/) · [Anleitung](../SEALED-ACTIONS.md)

Für Live-Beobachtung, Verlauf oder einen einmaligen Export wählen Sie eine
[Erfassungsmethode](../COLLECTION-MODES.md). Private Cloud-Chats sind verfügbar,
wenn das verbundene Konto darauf zugreifen kann. Die veröffentlichte Anwendung enthält außerdem die
[Integration für geheime Chats](../PSEUDO-SECRET.md): Installieren Sie die optionale
Protokollabhängigkeit und aktivieren Sie sie pro Konto, um dort erstellte oder angenommene Chats aufzuzeichnen.
Die verfügbaren Abrufwege beschreibt der [Erfassungsumfang](../COLLECTION.md).

[Phala / Intel TDX und auditierte Bereitstellungen](../HIGH-ASSURANCE.md) ·
[Live-Qualifizierung auf Phala](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[Vertrauensgrenzen](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>Erfassung und gespeicherte Aufzeichnung prüfen</strong> · was der Empfänger verifiziert und die Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="Das Gespräch erfassen. Die Aufzeichnung verifizieren. Nachrichten, Bearbeitungen und Dateien sichern, Signaturen und Checkpoints prüfen und den Erfassungsprozess nachvollziehen.">
</picture>

TgWitness zeichnet Inhalte auf, die an das verbundene Telegram-Konto zugestellt werden, mit
Chat-, Nachrichten- und Absenderkennungen, erfassten Versionen und Erfassungsmetadaten.
Das Archiv bringt diese Einträge, gesicherte Anhänge und Prüfdaten
für die Prüfung zusammen.

| Prüfung | Was der Empfänger verifiziert |
| --- | --- |
| Signiertes Journal und Manifest | Eintragssignaturen, die Hash-Kette und gelieferte Dateien gegen den erwarteten Signaturschlüssel. |
| Separat aufbewahrter Checkpoint | Das Journal gegen eine zuvor festgehaltene Länge und den Hash des neuesten Eintrags. |
| Unabhängiger Zeuge | Das Journal gegen Checkpoints, die ein separater Zeuge aufbewahrt. |
| Erfassung mit GitHub Actions | Das Archiv gegen seine Attestierung, den genehmigten gehosteten Workflow und die Collector-Version. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
zeigt ein Telegram-Gespräch neben absichtlich veränderten Desktop-Exportdateien.
Vergleichen Sie die Versionen, sehen Sie sich die Änderungen an und folgen Sie den Erfassungs- und
Verifizierungsschritten für ein signiertes TgWitness-Archiv.

[Verifizierungsschritte](../wiki/Exports-and-Verification.md) ·
[GitHub-Erfassung](../SEALED-ACTIONS.md) ·
[Technisches Vertrauensmodell](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>Die Ermittlung am Laufen halten</strong> · Benachrichtigungen, Speicherung und Wiederherstellung</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="Animierte Abläufe: Apprise sendet konfigurierte Warnungen; externe Kopien werden vor dem Hochladen in S3-kompatiblen Speicher verschlüsselt.">
</picture>

[Benachrichtigungen](../OPERATIONS.md#notifications) · [Verschlüsselte externe Kopie](../wiki/Off-site-Copy.md) · [Sicherung und Wiederherstellung](../wiki/Backup-and-Recovery.md) · [Fehlerbehebung](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/de/docs/start/"><b>Einrichtungsanleitung&nbsp;↗</b></a><br><sub>Von der Installation bis zum ersten Chat</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/de/docs/dedicated-account/"><b>Konto vorbereiten&nbsp;↗</b></a><br><sub>Ein dediziertes Telegram-Konto</sub></td>
<td width="33%" align="center"><a href="../DEPLOYMENT.md"><b>Docker und Server&nbsp;↗</b></a><br><sub>HTTPS, Neustarts und Updates</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>Das Repository erkunden</strong> · wo Code, Dokumentation und Werkzeuge liegen</summary>

| Verzeichnis | Hier beginnen |
| --- | --- |
| [docs/](../README.md) | Einrichtung, Ermittlungsabläufe und technische Referenz |
| [tgwitness/](../../tgwitness/README.md) | Hauptanwendung, Collector, Journal und Web-Panel |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | Unabhängige Rekorder und ihr Prüfcode |
| [addons/](../../addons/README.md) | Installation, Konfiguration und Tests der optionalen Erfassung |
| [deploy/](../../deploy/README.md) | Installer, Container und Hintergrunddienste |
| [examples/](../../examples/README.md) | Konfigurationen für Kontoexport und versiegelte Erfassung |
| [integrations/](../../integrations/README.md) | Signierte Webhooks und ein n8n-Empfänger |
| [.agents/](../../.agents/README.md) | Aufgabenanleitungen zum Lesen des Archivs über die CLI |
| [scripts/](../../scripts/README.md) | Startskripte und CI-Hilfsprogramme |
| [tools/](../../tools/README.md) | Builds, Prüfungen und Paketierung |
| [website/](../../website/README.md) | Öffentliche Website, übersetzte Anleitungen und interaktive Demo |
| [.github/](../../.github/AUTOMATION.md) | Workflows, Beitragsrichtlinien und Support |

[Vollständiger Projektleitfaden](../PROJECT-GUIDE.md) ·
[Mitwirken](../../.github/CONTRIBUTING.md) · [Hilfe erhalten](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ Ethischer Hinweis &amp; historische Kontinuität</strong></summary>

Die Position der Autoren und der Betreiberhinweis auf Deutsch:

[Betreiberhinweis](OPERATOR-INCOMPATIBILITY.md) · [MIT-Lizenz](../../LICENSE) · [Original-NOTICE](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>Projektüberblick in Ihrer Sprache lesen</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · **Deutsch** · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>Technische Dokumentation</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Ermittlungshandbuch</b></a> ·
  <a href="https://github.com/phishdestroy"><b>Entwickelt von PhishDestroy</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>Mitwirken</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>Hilfe erhalten</b></a> ·
  <a href="../../.github/SECURITY.md"><b>Sicherheitslücke melden</b></a>
</p>

[Maschinenlesbarer Projektindex](../../llms.txt) · [Vollständiges Handbuch als Text](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [Repository-Regeln für Agenten](../../AGENTS.md)
