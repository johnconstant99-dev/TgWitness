[TgWitness](../../README.md) / [Documentazione](README.md) · [Avviso per gli operatori](OPERATOR-INCOMPATIBILITY.md)

![Il fascicolo GDPR di 106 giorni](../assets/presentation/chapter-case.svg)

# Valve, Taylor Wessing e 106 giorni di attesa ai sensi del GDPR: analisi del fascicolo e delle sue 70.717 parole

[Documento originale](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Avviso per gli operatori](OPERATOR-INCOMPATIBILITY.md) · [English](../TAYLOR-WESSING-GDPR-FILE.md)

Ci restano domande che non avranno mai risposta, perché non siamo parte della controversia. Nessuna persona comune riesce a resistere aspettando ogni volta cento giorni e affrontando avvocati d’élite, finanziati dalle aziende attraverso «borse del freelance» come questa. Non sapremo mai come si chiamasse davvero il servizio ordinato da Valve. Da fuori sembra un trattamento GDPR non del tutto lecito, e una comunicazione di dati in cui i segnalanti non sono stati oscurati ma divulgati, mentre mancano almeno 5.000–10.000 pagine dei dati stessi: ciò che è stato esportato non era il registro dell’utente, ma un registro ridotto fatto per i fornitori esterni. Non ha senso contestarlo. Manca oggettivamente un enorme strato di informazioni, così come non c’è nulla che confermi ciò che ha detto l’uno o l’altro dei due avvocati.

Quanto paga Valve per un servizio fatto di temporeggiamenti, oscuramenti applicati a mano e la firma di un Dottore sotto una segnalazione omofoba e un PDF rotto? Non è il nostro caso, ma qui il problema chiaramente non è la legge; è lo status e l’impunità. Il titolo di «Dottore» fa automaticamente di una persona colei che decide che cosa vale come prova inconfutabile, e di un’altra colei che presumibilmente capisce di numeri e di PDF (anche se in realtà non è così).

---

## 1. Le date, la parola del Dottore e un rapporto senza pagamenti

L’intestazione del documento riporta `Date of Report: 09-29-2025`, e i file sono stati consegnati il 1° o il 2 ottobre. Ma a queste date non crediamo. Crediamo alla dichiarazione diretta del **Dr. Patrick Vincent Zurheide**:

> „Bei der Zusammenstellung der personenbezogenen Daten Ihres Mandanten musste leider die volle Monatsfrist
> ausgeschöpft werden, da sich bei erneuter Prüfung der Daten gezeigt hat, dass auch nach dem 3. Mai 2025 neue
> Zahlungen durch einen Dritten über das Nutzerkonto Ihres Mandanten erfolgt sind und insofern manuell die Daten
> bereinigt werden mussten.“
>
> *(La raccolta dei dati personali del suo assistito ha purtroppo richiesto l’intero termine di un mese, perché un nuovo controllo ha mostrato che anche dopo il 3 maggio 2025 erano stati effettuati nuovi pagamenti da un terzo tramite l’account, motivo per cui i dati hanno dovuto essere ripuliti manualmente.)*

È proprio questa frase che ci fa smettere di credere ai numeri, alle parole del dottore nel primo paragrafo e alla sua firma. Certo, un dottore non mentirebbe; ha qualcosa in gioco, no? Il fatto è che, una volta esportato il file e rimosse le forme vettoriali, nel rapporto non è comparso un solo pagamento. Non contestiamo il lavoro del Dr. Patrick né il suo ritardo. Crediamo e accettiamo semplicemente «la verità del Dottore», e registriamo ciò che si vede nel file stesso.

---

## 2. 36 secondi e l’etichetta vulnerabile «Anlage 1 / Taylor Wessing»

Non siamo esperti di niente, ed è per questo, a quanto pare, che la nostra segnalazione di vulnerabilità è stata ignorata sia dalla piattaforma di freelance stessa sia dal dottore. La logica è abbastanza chiara: loro sono la legge, quali vulnerabilità potrebbero mai avere?

Ma mettiamo da parte le parole del Dottore e guardiamo la tecnica. Abbiamo predisposto un ambiente Windows equivalente, preso il file ripulito e provato a posizionare le forme. Posizionare a mano centinaia di forme nere in **36 secondi**, esattamente la durata della sessione registrata, è a nostro avviso impossibile; a quanto pare, i riquadri neri erano già sul documento. Propendiamo per l’idea che in quei 36 secondi sia stato aggiunto esattamente un oggetto, in alto a destra della pagina 1: l’etichetta `"Anlage 1 / Taylor Wessing"`. Ed è il software che l’ha posizionata a essere vulnerabile:

* **Oggetto, secondo i suoi marcatori:** da `(929, 294)` a `(1139, 372)`, cioè `210 × 78 px`, centrato all’incirca in `(1034, 333)`.
* **Cornice visibile:** da `(936, 300)` a `(1133, 367)`, circa `197 × 67 px`, proporzioni di circa `3 : 1`; il bordo superiore del foglio è a `y ≈ 275`.
* **Scala:** misurata sul righello sinistro del documento, `1 cm ≈ 82 px` (il righello è quasi certamente in centimetri; in pollici il foglio sarebbe più largo di `15″`).

Lo stile e l’aspetto del contrassegno corrispondono al file restituito. Ma senza accesso all’ambiente di creazione originale, o senza conoscere il formato iniziale (se c’è stata una conversione), l’esperimento non può essere pulito, quindi non possiamo affermarlo con certezza al 100%.

---

## 3. Pagina 444: l’ora nascosta e l’aritmetica delle segnalazioni

Le segnalazioni iniziano a pagina 444, compresa quella segnalazione omofoba. Un punto importante:

* Nelle segnalazioni che hanno scelto di mostrare (quelle comode per gli avvocati), il campo **`Time of Report`** è stato deliberatamente nascosto in aggiunta a tutto il resto. Non c’è un’ora esatta, ed è l’unica cosa dell’intero file nascosta in modo tecnicamente corretto.
* Nell’articolo principale abbiamo confrontato matematicamente le segnalazioni mostrate con le altre, per contenuto, stile di scrittura e nickname. Quasi ovunque viene riutilizzata grossolanamente la formula standard di generazione dei nomi di Reddit, e c’è un picco netto proprio nell’intervallo che serviva. Non diciamo che le segnalazioni siano state falsificate, ma diciamo che gli account probabilmente non sono reali, e che la maggior parte di essi somiglia matematicamente a una botnet.

---

## 4. Una domanda al Dr. Patrick Zurheide sulle voci `2025-02-03 16:29:23` e `2025-04-02 15:55:19`

Dottor Patrick, lei ha scritto di aver letto la battuta omofoba e di aver deciso di farne una sua. Bene, molto divertente. Le altre segnalazioni, come ha detto il suo collega, non contano nella sostanza (*„Unabhängig von den Einzelheiten der Beschwerden zeigt schon die bloße Anzahl…“*). Bene, le saltiamo. Speriamo che il **Dottor Tobias** spieghi ai suoi studenti a lezione perché un quarto casuale delle 1.938 segnalazioni (485), piene di auguri di morte e di dichiarazioni naziste, non conta, e per chi esattamente non conta. Se lo farà, ammetteremo immediatamente di aver sbagliato, ci scuseremo e cancelleremo le menzioni.

Chiamiamo le cose con il loro nome: lei ha consapevolmente consegnato i dati degli hater, quelli russi, quello tedesco, tutti, proprio alla persona che odiavano, e questo tra due paesi in guerra tra loro. È risultato che gli ha servito bambini russi: lui è entusiasta, e Tobias li ha indicati direttamente come il problema. Ma in realtà questa è la sua fuga di dati; solo che i bambini non sono suoi.

La nostra domanda, tuttavia, riguarda un altro utente, che non poteva sfuggire:

* **`2025-02-03 16:29:23`**: un link e una persona dello stesso paese, con cose molto gravi scritte lì che saltano subito all’occhio;
* **`2025-04-02 15:55:19`**: un riferimento diretto, un nome specifico e ciò che lui scrive.

Abbiamo verificato: è esattamente ciò che sembra. Lei ha apertamente messo dati statali e dati personali completi nelle mani di una persona che lei stesso considera un criminale. Non andava fatto, se non altro per il contesto. Che cosa succede se lui scrive lì? Da parte sua questo non è solo meschino; è un disprezzo totale per la vita e la salute delle persone. Mentre indagavamo, abbiamo fermato questa persona e messo tutti al sicuro. Questa è, nel complesso, la nostra unica vera lamentela; tutto il resto sono semplicemente fatti e una dimostrazione di come lavorano gli avvocati d’élite. Chiediamo al Dottor Patrick di assumersene la responsabilità adeguata, a meno che, naturalmente, il titolo davanti al suo nome non gli dia il diritto di agire così (non siamo avvocati e non conosciamo la legge).

---

## 5. Al pubblico, all’assicuratore, alle autorità di controllo e alle aziende statunitensi

* **Al pubblico e ai clienti di Taylor Wessing:** a giudicare dalla negligenza, Taylor Wessing ha un assicuratore generoso che considera tutto questo normale. Controllate i vostri file e informate l’autorità di controllo. Non serve dirlo agli avvocati stessi: hanno scelto di nasconderlo per più di un anno, da quando Valve si è rivolta a loro per la prima volta.
* **Alle autorità di controllo, sulla vulnerabilità di ogni file:** esaminate l’attività del Dr. Patrick e richiedete ogni PDF passato per le sue mani con il contrassegno `"Anlage 1 / Taylor Wessing"` (o uno simile) posto in cima alla prima pagina. La probabilità che non si tratti di un caso isolato, e che ogni suo documento con questo adesivo sia vulnerabile, è criticamente alta.
* **Alla compagnia di assicurazione:** sottoponete a verifica il vostro cliente e il software che usa per lavorare con i PDF e posizionare l’etichetta `"Anlage 1 / Taylor Wessing"` in cima alla pagina 1. Molto probabilmente è proprio lì che sta il problema, e non è un caso isolato. Non ha senso chiedere una verifica di tutta Taylor Wessing: a parte il nome, non sembrano condividere nulla in termini di ambienti di lavoro o regole di revisione della sicurezza, che dovrebbero esistere di per sé (a quanto pare una chiave di firma fisica e il titolo davanti a un nome coprono tutto questo).
* **Alle aziende statunitensi, e a chiunque alla Commissione europea capiti di leggere:** provate semplicemente a rispettare la legge. Assumere dottori rinomati di una rinomata «società di freelance» appare pericoloso e del tutto spregevole verso i vostri clienti. Se in Valve gli assegni vengono semplicemente firmati e nessuno controlla che cosa abbiano fatto gli avvocati per 106 giorni, allora forse pagare per il tempo dilatato invece che per i risultati è esattamente il motivo per cui il software è obsoleto e nessuno capisce come funziona un PDF. E se lì non ci sono altre fughe di dati, allora il Dottor Patrick è semplicemente riuscito a sfinire tutti con l’attesa o con le minacce. In sostanza, ciò che è in vendita è un servizio di non conformità al GDPR: un’esecuzione di scarsa qualità e minacce («non vincerà nemmeno una causa»), unite a una pulizia di alta qualità dei risultati di Google effettuata a loro stesso nome. Non redigiamo testi giuridici e non accusiamo nessuno. Scriviamo semplicemente ciò che abbiamo visto, e ciò che cercano con tanta insistenza di cancellare.

Visto che gli avvocati pensano di essere la legge, e che la vita delle persone, la vita dei bambini, non conta, è una loro scelta. Non è il nostro conflitto. Ma possiamo dire con certezza che l’impunità dello studio è storicamente confermata, a partire dal suo fondatore Goltz, uno degli otto che redassero le modifiche al §175, e dal suo unico caso famoso, che a volte viene letto come una difesa delle persone LGBT: il caso del generale von Fritsch. Salteremo la storia; l’abbiamo studiata direttamente da una fonte affidabile e dagli atti originali. Ma ecco come finì il caso: c’era un imputato, e noi abbiamo tre morti. Achim von Frisch, stritolato dagli ingranaggi della repressione. Otto Schmidt, fucilato nel 1943. E lo stesso generale Fritsch: non importa che sia stato assolto, il prezzo fu alto. Nel 1939, cercando la morte, si offrì volontario per il fronte in Polonia e fu ucciso (o si lasciò uccidere).

Naturalmente non abbiamo mai considerato questo caso una difesa delle persone LGBT da parte del fondatore dello studio. Ma l’esito è molto più interessante di una vittoria.

**Giustizia asimmetrica:** Goltz salvò davvero un ufficiale di alto rango, la cui colpa era stata interamente fabbricata dalla Gestapo. Ma questo alibi fu pagato con il sangue altrui. Lo stesso Goltz, come membro della Commissione di diritto penale dal 1933, progettò e introdusse personalmente la versione nazista del Paragrafo 175 (1935).

**Statistiche contro pubbliche relazioni:** difese un generale eterosessuale dell’élite della Wehrmacht dopo aver prima messo in moto una catena di montaggio giuridica che mandò circa 50.000 omosessuali reali in prigione e circa 15.000 nei campi di concentramento, con un tasso di mortalità del 60%. Salvare un generale non cancella l’architettura del genocidio.

**Denazificazione, aggirata con successo:** il caso Fritsch divenne la perfetta «porta sul retro» attraverso le commissioni di denazificazione del dopoguerra. L’architetto delle leggi repressive usò la difesa di un generale come prova della propria «indipendenza», sfuggì a Norimberga, mantenne il suo status e la sua abilitazione, e nel 1957 fondò lo studio che oggi vende il proprio progressismo sotto l’insegna Taylor Wessing.

Quindi sì, tutto sommato: siamo sicuri che non faccia differenza se si tratti di questa Taylor Wessing tedesca o di qualsiasi altra; non si tratta affatto della legge. Ciò che diciamo qui è una dichiarazione, non l’affermazione di un fatto ma un’ipotesi, perché in realtà cercheranno qualsiasi parola a cui aggrapparsi. Per questo va negli archivi: i tentativi di censura e occultamento, e i legami diretti con la loro eredità. Dal Dottor Patrick: la primissima segnalazione, con la volgare parola omofoba lasciata in chiaro. Forse per caso, certo, ma c’è, ed è la prima.

Dal Dottor Tobias ci aspettiamo naturalmente una lezione sulla prova inconfutabile sotto forma di conteggio delle segnalazioni, e una spiegazione di quale parte di quel quarto non conti per lui personalmente. Per la storia, e per capire dove stanno i limiti, questo conta.

Che Steam agisca come titolare del trattamento invece di moderare indica semplicemente l’ovvio: è stato il Dottor Patrick a divulgarli. Be’, è andata così. A quanto pare non sapeva che il software per l’adesivo era difettoso, trattandosi di dottori di primo piano, e Steam non ha pagato per questo: se trattare o meno la richiesta GDPR, e poi coprire la fuga di dati che aveva visto.

Chiediamo buon senso nel rapporto con la verità e vogliamo ricordare a tutti la fiducia zero: verso tutti, noi compresi. È tutto un ambiente ostile, e nel contesto di questa analisi letteralmente: ban del 9 maggio, nazisti, dottori, persone LGBT, bambini. È stato divertente.

Ma le nostre opzioni nei confronti di Taylor Wessing sono molto probabilmente esaurite, dato che la loro strategia è far rimuovere i link. Siamo costretti a preservare il nostro testo e i nostri dati, quindi li integriamo nel nostro software, che ha già tre lettere di ringraziamento confermate da enti pubblici, tra cui in Germania e in Belgio, e che non è nemmeno ancora uscito.

Vogliamo avvertire chi ama piegare la legge: non serve buttare giù il repository. In tutto questo tempo non siamo entrati in alcun conflitto con voi. Ma se decidete di rompere il nostro lavoro per nascondere la verità, allora senza un repository attivo le autorità di controllo e altri non potranno confrontare la firma di una versione (ma a chi lo sto dicendo), e allora entreremo in conflitto diretto. Con questo speriamo di congedarci dalla mega-competenza e dagli avvocati d’élite. Non è stato divertente, e non ne sono felice. Tutto il meglio.

[Documento originale](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Avviso per gli operatori](OPERATOR-INCOMPATIBILITY.md) · [licenza MIT](../../LICENSE)

[Progetto](../../README.md) · [Documentazione](README.md) · [Wiki](../wiki/Home.md)
