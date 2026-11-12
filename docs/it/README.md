<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">Altre lingue</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Segui le tracce. Conserva le prove. Un registro firmato e concatenato tramite hash, un punto di controllo conservato separatamente e un archivio di prove verificabile.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=it"><b>Esplora la demo&nbsp;↗</b></a><br><sub>L'interfaccia reale con record fittizi</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>Scarica e avvia&nbsp;↓</b></a><br><sub>Un solo comando per Linux, macOS e Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Leggi il manuale&nbsp;↗</b></a><br><sub>Guide alle indagini, passo dopo passo</sub></td>
</tr>
</table>

<p align="center"><strong>Area di lavoro self-hosted per le indagini su Telegram.</strong><br>Salva le chat, conserva modifiche e cancellazioni, scopri chi è collegato a chi<br>e consegna esportazioni firmate che chiunque può verificare.</p>

<p align="center"><strong>ZERO TRUST.</strong> TgWitness non si schiera: gli stessi controlli valgono per l'operatore, per PhishDestroy e per chiunque altro.<br>Conta solo ciò che conferma una terza parte o la matematica. <a href="../QUESTIONS-AND-CHECKS.md">Domande e verifiche</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.3 · versione preliminare"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">Ambienti testati</a> · 25 lingue dell'interfaccia · 26 lingue delle guide</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=it">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="La demo di TgWitness in azione: messaggi acquisiti, versioni salvate e contenuti conservati dopo la cancellazione. Record dimostrativi fittizi.">
</picture>
</a>

<p align="center"><sub>Esplora l'interfaccia reale con record fittizi. Fai clic sull'area di lavoro per provarla.</sub></p>

## Cosa fa TgWitness

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">Ogni modifica e cancellazione conservata</a></b><br><sub>Ogni versione di un messaggio viene salvata e il testo resta anche dopo un avviso di cancellazione.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">Prove che chiunque può verificare</a></b><br><sub>Record firmati e concatenati tramite hash. Il destinatario verifica l'archivio offline con un solo comando.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">Un'origine dimostrabile</a></b><br><sub>Messaggi ricevuti tramite la sessione MTProto autenticata dell'account e firmati all'arrivo; GitHub Actions e Intel TDX aggiungono un'attestazione.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">Misurato su larga scala</a></b><br><sub>48 archivi verificati con 3.598.381 record; otto account hanno acquisito 768.007 record della cronologia a 687,5 record/s.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">Pensato per le indagini</a></b><br><sub>Watchlist su testo, codici QR e OCR, verifica dei portafogli, schede dei soggetti, Bacheca del caso e un pacchetto per il tribunale.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">Gestito da te</a></b><br><sub>Self-hosted e senza telemetria. Le sessioni sono custodite in un vault crittografato; il pannello è in ascolto su localhost.</sub></td>
</tr>
</table>

<p align="center"><sub>Sviluppo e test sono durati circa sei mesi: prima il collettore, il registro firmato e il verificatore, poi il pannello e i moduli aggiuntivi. Questo repository è stato creato il 29 ottobre 2026 a scopo di pubblicazione, pertanto la sua data di creazione non corrisponde all’età del progetto.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## Installazione

Python incluso. Usa gli stessi comandi per aggiornare.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell o CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Server Ubuntu: esegui come root. Desktop: esegui con il tuo utente abituale. `-ExecutionPolicy Bypass` vale solo per questo processo PowerShell.</sub>

Le build firmate provengono dal [workflow Installer](../../.github/workflows/installer.yml) pubblico e l'installer verifica lo SHA-256 e la firma RSA di ogni pacchetto prima dell'installazione.

[Verifica prima lo script](../INSTALLATION.md#verify-before-running) · [Prima configurazione](../SETTINGS.md) · [Release](https://github.com/phishdestroy/TgWitness/releases) · [Docker](../DEPLOYMENT.md)

<details>
<summary><strong>Come sono protetti l'installer e i tuoi dati</strong></summary>

`get.destroy.tools` è il sito di download del progetto. Il
[workflow Installer](../../.github/workflows/installer.yml) pubblico lo genera da
[`deploy/installer/`](../../deploy/installer/README.md) per l'esatta revisione di `main`,
lo pubblica dopo che i test di installazione su Linux e Windows sono stati superati e firma gli
script dell'installer e i pacchetti dell'applicazione con la chiave di rilascio in
[`release-signing.pub`](../../deploy/installer/release-signing.pub). Prima dell'installazione, l'installer verifica
lo SHA-256 e la firma RSA del pacchetto e del file di lock delle dipendenze.
Per controllare prima lo script stesso, scaricalo insieme alla sua firma ed esegui i
[comandi di verifica preliminare](../INSTALLATION.md#verify-before-running). Una build non riuscita
lascia invariato il download precedente; i pannelli installati si aggiornano quando esegui di nuovo l'installer.
Le [release](https://github.com/phishdestroy/TgWitness/releases) su GitHub, il codice sorgente e
[Docker](../DEPLOYMENT.md) sono gli altri modi per installarlo.

**Le tue sessioni e i tuoi dati.** TgWitness gira sul tuo computer o server e il pannello
è in ascolto su localhost per impostazione predefinita. Le sessioni Telegram, le credenziali dei proxy e gli hash dei token
di accesso sono custoditi nel vault crittografato di ogni area di lavoro, con una
[chiave master esterna](../SECURITY-MODEL.md#external-master-key) facoltativa. L'applicazione
non ha telemetria. Si connette a Telegram e ai servizi usati dalle sue impostazioni:
elenchi pubblici di MTProxy, i tuoi proxy, storage S3, un bot testimone, autorità
di marcatura temporale, provider di IA e webhook. La [Mappa del sistema](../SYSTEM-MAP.md) elenca
le connessioni effettuate dal processo dell'applicazione.
Osserva con un [account Telegram dedicato](https://phishdestroy.github.io/TgWitness/it/docs/dedicated-account/).

Il badge della versione descrive questo albero dei sorgenti. Le build installabili sono elencate in
[Release](https://github.com/phishdestroy/TgWitness/releases); una funzionalità integrata in
`main` arriva in quei download con la release successiva.

[Installazione e accesso al pannello](../INSTALLATION.md) ·
[Firme e SHA-256](https://get.destroy.tools/#verification) ·
[Aggiornamento](../INSTALLATION.md#update-an-existing-installation) ·
[Funzionalità attuali e qualificazione](../STATUS.md) ·
[Scegli un metodo di raccolta](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## Un record che altri possono verificare

Verificalo senza account e senza installare nulla. L'esempio pubblicato include il proprio verificatore:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # il verificatore è incluso nell'archivio
python verify.py tgwitness-demo.zip          # Python 3.11+, richiede solo `cryptography`
```

Stampa i record firmati, l'hash del record più recente e l'impronta del firmatario ed esce con `0`.
L'esempio è fittizio; lo stesso verificatore funziona su qualsiasi esportazione reale.

Un'esportazione contiene i messaggi, i file e il verificatore. Invia al destinatario l'impronta
della tua chiave tramite un altro canale e potrà verificarla da solo:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

Il verificatore controlla le firme, la catena del registro, l'elenco dei file e gli allegati.
Per valere come prova servono l'impronta della tua chiave e una marca temporale di terze parti che copra l'ultimo
record, ad esempio una marca temporale RFC 3161 verificata con il certificato radice dell'autorità.

**Da dove arrivano i messaggi.** TgWitness li riceve da Telegram tramite la
sessione MTProto crittografata dell'account, come fanno le app ufficiali, e li scrive nel
registro, firmati uno per uno, man mano che arrivano. L'[acquisizione con GitHub Actions](../SEALED-ACTIONS.md) e
[Phala Intel TDX](../HIGH-ASSURANCE.md) attestano anche il collector che li ha ricevuti.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="Nuovi messaggi, modifiche salvate e cancellazioni osservate formano un registro concatenato e firmato. Verificalo con una chiave attendibile ottenuta in modo indipendente.">
</picture>

[Verifica dell'archivio](../wiki/Exports-and-Verification.md) · [Formato delle prove](../EVIDENCE.md) · [Testimone indipendente](../WITNESS.md) · [Marche temporali esterne](../TIMESTAMP.md) · [Controlli e scala testata](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Da una conversazione a un caso

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="Tre flussi animati: esportare una chat in HTML e JSON, trovare un link condiviso nelle chat registrate e conservare le versioni acquisite dopo un avviso di cancellazione.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>Esportazione chat&nbsp;↗</b></a><br><sub>Una chat in HTML e JSON firmati</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>Indagine&nbsp;↗</b></a><br><sub>Segui una pista nelle chat registrate</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>Versioni salvate&nbsp;↗</b></a><br><sub>Modifiche e avvisi di cancellazione, conservati</sub></td>
</tr>
</table>

Due modi di usarlo: [esportare il tuo account](../ACCOUNT-EXPORT.md) una volta sola oppure
[seguire un'indagine](../INVESTIGATION.md) e continuare a salvare le modifiche.
Scegli alcune chat, una cartella di Telegram o l'intero account. Ogni account ha la propria
area di lavoro, sessione e chiave di firma.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Scopri di più

<details>
<summary><strong>Esportazioni misurate · 6 novembre 2026</strong> · 56.329 messaggi, entrambi gli archivi verificati</summary>

**56.329 messaggi esportati in due esecuzioni da zero.** Entrambi gli archivi firmati hanno superato la verifica con chiavi del collector fissate.

[![Velocità misurata di raccolta e di esportazione completa](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/it/docs/validation/)

| Esecuzione | Messaggi | Tempo di raccolta | Velocità di raccolta | Esportazione completa | Velocità complessiva |
| --- | ---: | ---: | ---: | ---: | ---: |
| Server A | 27.030 | 189,043 s | **142,983 messaggi/s** | 211,647 s | 127,713 messaggi/s |
| Server B | 29.299 | 182,513 s | **160,531 messaggi/s** | 206,650 s | 141,781 messaggi/s |

Testo e metadati tramite WARP, due account per server, senza allegati né record riutilizzati.
Misurato sulla revisione [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e).
Ogni esecuzione pubblicata riporta revisione sorgente, carico di lavoro, tempi e risultato della verifica:
[carico di lavoro, tempi e verifica](../EXPORT-BENCHMARK-2026-11-06.md). Le modifiche a `main`
passano per i [workflow CI](../../.github/workflows/README.md) pubblici, inclusi i test dell'installer su Linux e Windows
e la build del verificatore autonomo.

[**Esplora la demo →**](https://phishdestroy.github.io/TgWitness/demo/?lang=it) ·
[**Misurazioni, date e metodo →**](https://phishdestroy.github.io/TgWitness/it/docs/validation/) ·
[Scarica un'esportazione di esempio fittizia](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[Audit firmato in inglese](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>Inizia in modo semplice. Vedi ogni percorso.</strong> · primo avvio e mappa del sistema</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="Il primo avvio propone Scarica e basta, Seguire delle chat o Prove a sostegno di un caso e mostra solo le sezioni corrispondenti. La mappa del sistema collega pannello, collector, Telegram, registro, testimone e servizi esterni, con le osservazioni di rete. Valori fittizi.">
</picture>

Il primo avvio pone una sola domanda: **Scarica e basta**, **Seguire delle chat** o
**Prove a sostegno di un caso**. La risposta imposta l'obiettivo e il livello dell'interfaccia, così il
pannello mostra solo le sezioni necessarie per quel compito. Connessione, accesso a Telegram e
scelta delle chat seguono in cinque fasi. Il controllo della connessione parte da solo e
le opzioni di percorso si aprono solo se non riesce. Gli strumenti per esperti si attivano con un solo interruttore.

La **Mappa del sistema** mostra come l'installazione raggiunge Telegram e i servizi
esterni: accesso al pannello, percorso e destinazione Telegram di ogni account, percorso del registro e
del testimone e le ultime osservazioni di rete. Un'osservazione mancante viene
indicata come mancante.

[Prima configurazione](../SETTINGS.md) · [Mappa del sistema](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>Pensato per il resto dell'indagine</strong> · schede dei soggetti, watchlist, portafogli, monitoraggio online, documenti per il tribunale</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Traccia nomi e nomi utente tramite ID Telegram. Registra le interazioni supportate con i bot, con ricevute firmate. Cerca nei messaggi archiviati e collega client MCP in sola lettura. Distribuisci un collector con SSH oscurato e i record del provider da esaminare. Documenta una conversazione passo dopo passo con riferimenti al registro. Consegna un pacchetto del caso BagIt con modelli per il tribunale. Flussi illustrativi.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>Persone e dossier&nbsp;↗</b></a><br><sub>Nomi e nomi utente tracciati tramite ID Telegram</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>Indagini sui bot&nbsp;↗</b></a><br><sub>Interazioni con i bot, con ricevute firmate</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/it/docs/archive/"><b>Ricerca nell'archivio, IA e MCP&nbsp;↗</b></a><br><sub>Cerca nell'archivio e collega client in sola lettura</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>Distribuzione sigillata nel cloud&nbsp;↗</b></a><br><sub>Un collector dentro Intel TDX</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="Tre passaggi animati: una scheda soggetto la cui istantanea successiva registra un cambio di nome, un piano di conversazione i cui obiettivi si chiudono con record del registro e un codice QR di pagamento decodificato in un portafoglio con checksum valido che genera una corrispondenza in una watchlist. Valori fittizi.">
</picture>

**Documenta la conversazione.** Avvia un verbale per una chat nel pannello laterale **Documentazione**
e ogni passaggio si scrive da sé: azioni nel pannello, risposte con il tempo trascorso prima
di ciascuna, modifiche, avvisi di cancellazione, note e bozze dell'IA. Ogni passaggio cita il proprio record
nel registro e il relativo SHA-256. Alla chiusura definitiva il documento viene firmato e l'hash della dichiarazione viene scritto
nel registro.

| | |
| --- | --- |
| [Schede dei soggetti](../INVESTIGATION-MODE.md#subject-cards) | Istantanee del profilo di un bot, una persona, un canale o un gruppo con le etichette BOT, VERIFIED, SCAM e FAKE di Telegram; un'istantanea successiva elenca cosa è cambiato |
| [Piani di conversazione](../INVESTIGATION-MODE.md#conversation-plans) | Obiettivi per il percorso dei pagamenti, l'infrastruttura o le persone, messaggi preparati, tempi di risposta, attività per ora e stile di scrittura dell'interlocutore |
| [Traduzione](../INVESTIGATION-MODE.md#machine-translation) | Mostrata sotto l'originale con lingue, modello e record del registro |
| [Watchlist](../INVESTIGATION-MODE.md#watchlists) | Parole, pattern, portafogli, @nomi utente, ID, domini, telefoni e link, rilevati in testo, modifiche, destinazioni di link nascosti, pulsanti dei bot, codici QR e OCR |
| [Monitoraggio online](../INVESTIGATION-MODE.md#online-watch) | Controlli ogni 1–60 minuti, fino a 100 account per richiesta, con un andamento per ora e giorno della settimana |
| [Codici e portafogli](../INVESTIGATION-MODE.md#codes-in-images) | Codici QR di pagamento; indirizzi EVM verificati secondo EIP-55, TON in formato grezzo, checksum XRP Ledger, link di pagamento con rete, importo e token |
| [Tracce del client](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-show) | Tracce dell'encoder nei videomessaggi circolari e nei messaggi vocali; il confronto tra ora di caricamento e ora di invio smaschera prove «dal vivo» preregistrate |
| [Identità di copertura e autorizzazioni](../INVESTIGATION-MODE.md#cover-and-authority) | Identità fittizie, autorizzazioni e un resoconto delle attività sotto copertura che segnala i messaggi fuori dalle chat o dal periodo autorizzati |
| [Controllo dell'account](../INVESTIGATION-MODE.md#account-control) | Modifica di profilo e privacy con record prima/dopo, verifica dell'esposizione e passaggio offline subito dopo ogni azione |
| [Documenti per il tribunale](../INVESTIGATION-MODE.md#documents-for-court) | Pacchetto del caso BagIt con modello di certificazione Rule 902(13)/(14), indice delle prove, allegato alla richiesta e sottotitoli WebVTT/SRT per le registrazioni dello schermo |

I contenuti contrassegnati come 18+, violenza o dati personali restano nella copia per il tribunale, sigillati con
AES-256-GCM; le chiavi viaggiano separatamente.

Le [impostazioni di esportazione](../EXPORT_HASHES.md) coprono l'acquisizione tramite API normale e Takeout,
la cronologia dei messaggi prima degli allegati, il download dei file o gli hash del server e viste
JSON/HTML compatibili con Telegram Desktop. L'[esportazione distribuita delle chat](../DISTRIBUTED-EXPORT.md#history-acquisition)
offre un percorso Takeout facoltativo per la cronologia pubblica, punti di controllo firmati ogni 100 messaggi
e il recupero entro un intervallo con lo stesso account; il suo
[progetto delle prestazioni](../FAST-ACQUISITION.md) descrive il comportamento di acquisizione testato
e le misurazioni dal vivo previste.

</details>

<details>
<summary><strong>Tutto il resto</strong> · cronologia, account, proxy, IA, integrazioni</summary>

| | |
| --- | --- |
| [Carica i messaggi precedenti](../HISTORY.md) | Recupera la cronologia delle chat selezionate, metti in pausa e riprendi quando vuoi |
| [Diversi account](../ACCOUNTS.md#multiple-accounts) | Aree di lavoro separate, ciascuna con la propria sessione Telegram, registro e chiave di firma |
| [Importazione in blocco](../ACCOUNTS.md#bulk-import-and-account-groups) | Carica molti file di sessione insieme e suddividi gli account in gruppi con impostazioni condivise |
| [Pool di MTProxy](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping, paesi, filtri, elenchi personali |
| [Sessioni esistenti](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key o una riga `key:DC`; autorizzazione QR indipendente facoltativa da un donatore importato |
| [Sicurezza dell'account](../ACCOUNTS.md#create-an-independent-authorization) | Avvisi per le nuove sessioni, chiusura delle altre sessioni, una modalità a sessione unica che imposta anche una password per la verifica in due passaggi e una [sonda testimone](../ACCOUNTS.md#witness-probe) che si accorge quando gli aggiornamenti in tempo reale smettono di arrivare a questa sessione |
| [Esportazione chat riprendibile](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | Un'esportazione interrotta conserva una copia parziale firmata: riprendila, ricomincia da capo o scarica ciò che è stato salvato |
| [Proxy](../CONNECTION-SECURITY.md#ip-modes) | SOCKS5, HTTP CONNECT o MTProxy per area di lavoro. **Nascondi IP** non ripiega mai sulla connessione diretta |
| [Ricerca e IA](../ANALYSIS.md) | Ricerca locale, IA facoltativa con fonti verificabili |
| [Ricerca a testo completo](../SEARCH.md) | Forme flesse, frasi esatte, domini, @nomi utente e cinese senza spazi, prima i risultati migliori (**Anteprima**) |
| [MCP](../MCP.md) | Accesso in sola lettura per i client MCP, limitato alle chat che scegli |
| [Riga di comando](../CLI.md) | `search`, `context`, `messages`, `stats` ed `export` in JSON Lines con `--json` per script e agenti, in locale o con un token dall'ambito limitato (**Anteprima**) |
| [OCR e trascrizione](../MEDIA-ANALYSIS.md) | Eseguiti in locale; gli originali restano intatti |
| [Acquisizione indipendente](../OPTIONAL-CAPTURE.md) | Registratori facoltativi per browser/AyuGram in **Altri strumenti → Extra** (anteprima, disattivati per impostazione predefinita) |
| [Trusted Live](../TRUSTED-LIVE.md) | Sessione ufficiale Desktop/Web, video protetto e analisi della continuità con l'esportazione nativa (anteprima; qualificazione dal vivo in sospeso) |
| [Web ufficiale sigillato](../OFFICIAL-WITNESS.md) | Browser ufficiale appena avviato su GitHub Actions, controlli limitati, video firmato e sorgente/impostazioni attesi in modo indipendente |
| [Webhook](../WEBHOOKS.md) | Eventi in uscita firmati con nuovi tentativi, esempio per n8n incluso |
| [Accesso condiviso](../ACCESS.md) | Concedi a qualcuno solo le chat selezionate, con scadenza e limiti per IP |
| [Numeri dei messaggi mancanti](../EVIDENCE.md#missing-message-numbers-gap_summary) | Numeri assegnati da Telegram e mai osservati, per canale e per l'intero account, nella copertura, nei report e in MCP (**Anteprima**) |
| [Istantanee dello stato della chat](../COLLECTION.md) | Istantanee firmate periodiche di titolo, descrizione, messaggi fissati, amministratori e regali, con ciò che è cambiato (**Anteprima**) |
| [Mappa del sistema](../SYSTEM-MAP.md) | Mappa in tempo reale di accesso al pannello, percorsi degli account, destinazioni Telegram e servizi esterni, con le ultime 200 di un massimo di 2.000 osservazioni di rete |

</details>

<details>
<summary><strong>Scegli cosa sostiene il record</strong> · locale, cloud sottoposto ad audit, GitHub Actions o Intel TDX</summary>

Esegui in locale, aggiungi una distribuzione cloud sottoposta ad audit o raccogli dentro una **VM confidenziale
Phala Cloud con Intel TDX**. Ogni opzione conserva il registro firmato; i controlli
aggiuntivi riguardano l'ambiente in cui è stato raccolto.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="Tre scelte di distribuzione: verifica locale del registro; una VM sottoposta ad audit con record del provider e degli accessi; Phala Intel TDX con quote verificato, sistema operativo e applicazione misurati e una chiave del collector vincolata.">
</picture>

Il verificatore TDX controlla il quote rispetto alla radice fissata e ai dati di revoca di Intel,
lo vincola a una dichiarazione firmata del collector e a una nuova challenge e confronta il
sistema operativo e l'applicazione misurati con input attesi in modo indipendente. Il report elenca
ogni risultato separatamente, così l'ambiente misurato, l'identità del collector, i record
di acquisizione e la copertura possono essere esaminati insieme.

**Acquisizione con provenienza GitHub** (anteprima). Raccogli una chat su un runner ospitato da GitHub
con una versione fissata di TgWitness e una nuova sessione Telegram, poi scarica l'archivio
crittografato con la sua attestazione GitHub. Il verificatore controlla il workflow approvato e la
versione del collector, il digest dell'archivio, il registro e gli allegati. Disponibile anche
in **Esportazioni** nel pannello.
[Apri la pagina di acquisizione](https://phishdestroy.github.io/TgWitness/it/docs/capture/) · [Istruzioni](../SEALED-ACTIONS.md)

Per l'osservazione dal vivo, la cronologia o un'esportazione una tantum, scegli un
[metodo di raccolta](../COLLECTION-MODES.md). Le chat cloud private sono disponibili
quando l'account collegato vi ha accesso. L'applicazione pubblicata include anche
l'[integrazione con le chat segrete](../PSEUDO-SECRET.md): installa la dipendenza di protocollo facoltativa
e attivala per ciascun account per registrare le chat create o accettate lì.
Consulta l'[ambito della raccolta](../COLLECTION.md) per i percorsi di acquisizione disponibili.

[Phala / Intel TDX e distribuzioni sottoposte ad audit](../HIGH-ASSURANCE.md) ·
[Qualificazione dal vivo su Phala](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[Confini di fiducia](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>Verifica l'acquisizione e il record salvato</strong> · cosa verifica il destinatario ed Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="Acquisisci la conversazione. Verifica il record. Salva messaggi, modifiche e file, controlla firme e punti di controllo ed esamina il processo di acquisizione.">
</picture>

TgWitness registra i contenuti consegnati all'account Telegram collegato, con
identificatori di chat, messaggio e mittente, versioni acquisite e metadati di raccolta.
L'archivio riunisce questi record, gli allegati conservati e i dati di verifica
per l'esame.

| Controllo | Cosa verifica il destinatario |
| --- | --- |
| Registro firmato e manifest | Firme dei record, catena di hash e file consegnati rispetto alla chiave di firma prevista. |
| Punto di controllo conservato separatamente | Il registro rispetto a una lunghezza e a un hash del record più recente annotati in precedenza. |
| Testimone indipendente | Il registro rispetto ai punti di controllo conservati da un testimone separato. |
| Acquisizione con GitHub Actions | L'archivio rispetto alla sua attestazione, al workflow ospitato approvato e alla versione del collector. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
mostra una conversazione Telegram accanto a file di esportazione Desktop alterati di proposito.
Confronta le versioni, esamina le modifiche e segui i passaggi di raccolta e
verifica di un archivio TgWitness firmato.

[Passaggi di verifica](../wiki/Exports-and-Verification.md) ·
[Acquisizione su GitHub](../SEALED-ACTIONS.md) ·
[Modello di fiducia tecnico](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>Mantieni l'indagine operativa</strong> · notifiche, archiviazione e ripristino</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="Flussi animati: Apprise invia gli avvisi configurati; le copie fuori sede vengono crittografate prima del caricamento su uno storage compatibile con S3.">
</picture>

[Notifiche](../OPERATIONS.md#notifications) · [Copia crittografata fuori sede](../wiki/Off-site-Copy.md) · [Backup e ripristino](../wiki/Backup-and-Recovery.md) · [Risoluzione dei problemi](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/it/docs/start/"><b>Guida alla configurazione&nbsp;↗</b></a><br><sub>Dall'installazione alla prima chat</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/it/docs/dedicated-account/"><b>Prepara il tuo account&nbsp;↗</b></a><br><sub>Un account Telegram dedicato</sub></td>
<td width="33%" align="center"><a href="../DEPLOYMENT.md"><b>Docker e server&nbsp;↗</b></a><br><sub>HTTPS, riavvii e aggiornamenti</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>Esplora il repository</strong> · dove si trovano codice, documentazione e strumenti</summary>

| Directory | Inizia da qui |
| --- | --- |
| [docs/](../README.md) | Configurazione, flussi di indagine e riferimento tecnico |
| [tgwitness/](../../tgwitness/README.md) | Applicazione principale, collector, registro e pannello web |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | Registratori indipendenti e relativo codice di verifica |
| [addons/](../../addons/README.md) | Installazione, configurazione e test dell'acquisizione facoltativa |
| [deploy/](../../deploy/README.md) | Installer, container e servizi in background |
| [examples/](../../examples/README.md) | Configurazioni per l'esportazione dell'account e l'acquisizione sigillata |
| [integrations/](../../integrations/README.md) | Webhook firmati e un ricevitore n8n |
| [.agents/](../../.agents/README.md) | Istruzioni operative per leggere l'archivio tramite la CLI |
| [scripts/](../../scripts/README.md) | Script di avvio e utility per la CI |
| [tools/](../../tools/README.md) | Build, controlli e packaging |
| [website/](../../website/README.md) | Sito pubblico, guide tradotte e demo interattiva |
| [.github/](../../.github/AUTOMATION.md) | Workflow, linee guida per i contributi e supporto |

[Guida completa al progetto](../PROJECT-GUIDE.md) ·
[Contribuire](../../.github/CONTRIBUTING.md) · [Chiedi aiuto](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ Nota etica e continuità storica</strong></summary>

La posizione degli autori e l'avviso sull'operatore, in questa lingua:

[Avviso sull'operatore](OPERATOR-INCOMPATIBILITY.md) · [Licenza MIT](../../LICENSE) · [NOTICE originale](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>Leggi la panoramica del progetto nella tua lingua</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · **Italiano** · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>Documentazione tecnica</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Manuale delle indagini</b></a> ·
  <a href="https://github.com/phishdestroy"><b>Realizzato da PhishDestroy</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>Contribuisci</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>Chiedi aiuto</b></a> ·
  <a href="../../.github/SECURITY.md"><b>Segnala una vulnerabilità</b></a>
</p>

[Indice del progetto leggibile dalle macchine](../../llms.txt) · [Manuale testuale completo](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [Regole del repository per gli agenti](../../AGENTS.md)
