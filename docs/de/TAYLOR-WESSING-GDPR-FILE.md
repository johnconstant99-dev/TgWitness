[TgWitness](../../README.md) / [Dokumentation](README.md) · [Hinweis zum Betreiber](OPERATOR-INCOMPATIBILITY.md)

![Die DSGVO-Akte: 106 Tage](../assets/presentation/chapter-gdpr-file.svg)

# Valve, Taylor Wessing und 106 Tage Warten nach der DSGVO: Analyse der Datei und ihrer 70.717 Wörter

[Quelldatensatz](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Hinweis zum Betreiber](OPERATOR-INCOMPATIBILITY.md) · [English](../TAYLOR-WESSING-GDPR-FILE.md)

Es bleiben Fragen, auf die wir nie eine Antwort bekommen werden, weil wir nicht Partei des Streits sind. Jedes Mal
hundert Tage zu warten und es mit Elite-Juristen aufzunehmen, die Konzerne über solche „Freelance-Börsen“
finanzieren, hält ein gewöhnlicher Mensch nicht durch. Wir werden nie erfahren, wie die Leistung, die Valve bestellt
hat, eigentlich hieß. Von außen sieht es nach einer nicht ganz rechtmäßigen Verarbeitung nach der DSGVO aus und nach
einer Datenherausgabe, bei der die Meldenden nicht geschwärzt, sondern geleakt wurden, während von den Daten selbst
mindestens 5.000–10.000 Seiten fehlen: Exportiert wurde nicht das Nutzerprotokoll, sondern ein gekürztes Protokoll
für Outsourcer. Das anzufechten ist sinnlos. Objektiv fehlt eine riesige Schicht an Informationen, und ebenso wenig
gibt es eine Bestätigung für die Worte der beiden Juristen.

Was zahlt Valve für eine Leistung aus Zeitschinden, händischem Schwärzen und der Unterschrift eines Doktors unter
einer homophoben Meldung und einem kaputten PDF? Das ist nicht unser Fall, aber das Problem liegt hier eindeutig nicht
im Recht, sondern in Status und Straflosigkeit. Der Titel „Doktor“ macht den einen automatisch zu dem, der
entscheidet, was als unwiderlegbarer Beweis gilt, und den anderen zu dem, der sich angeblich mit Zahlen und PDFs
auskennt (obwohl er das in Wahrheit nicht tut).

---

## 1. Die Datumsangaben, das Wort des Doktors und ein Bericht ohne Zahlungen

Im Kopf des Dokuments steht `Date of Report: 09-29-2025`, übergeben wurden die Dateien selbst am 1. oder 2. Oktober.
Aber diesen Datumsangaben glauben wir nicht. Wir glauben der direkten Aussage von **Dr. Patrick Vincent Zurheide**:

> „Bei der Zusammenstellung der personenbezogenen Daten Ihres Mandanten musste leider die volle Monatsfrist
> ausgeschöpft werden, da sich bei erneuter Prüfung der Daten gezeigt hat, dass auch nach dem 3. Mai 2025 neue
> Zahlungen durch einen Dritten über das Nutzerkonto Ihres Mandanten erfolgt sind und insofern manuell die Daten
> bereinigt werden mussten.“

Genau dieser Satz ist der Grund, warum wir den Zahlen, den Worten des Doktors im ersten Absatz und seiner Unterschrift
nicht mehr glauben. Natürlich würde ein Doktor nicht lügen, er riskiert ja etwas, oder etwa nicht? Es ist nur so, dass
nach dem Export und dem Entfernen der Vektorformen im Bericht keine einzige Zahlung zum Vorschein kam. Wir bestreiten
weder die Arbeit von Dr. Patrick noch seine Verzögerung. Wir glauben und akzeptieren einfach „die Wahrheit des
Doktors“ und halten fest, was in der Datei selbst zu sehen ist.

---

## 2. 36 Sekunden und das verwundbare Etikett „Anlage 1 / Taylor Wessing“

Wir sind in nichts Experten, und offenbar wurde deshalb unser Hinweis auf die Schwachstelle sowohl von der
Freelance-Plattform selbst als auch vom Doktor ignoriert. Die Logik ist nachvollziehbar: Sie sind das Gesetz, welche
Schwachstellen sollten sie schon haben?

Lässt man die Worte des Doktors aber beiseite und betrachtet die Technik, ergibt sich Folgendes. Wir haben eine
passende Windows-Umgebung aufgesetzt, die bereinigte Datei genommen und versucht, die Formen zu platzieren. Hunderte
schwarze Formen in **36 Sekunden** von Hand zu setzen, genau so lange dauerte die aufgezeichnete Sitzung, halten wir
für unmöglich; allem Anschein nach waren die schwarzen Balken bereits auf dem Dokument. Wir gehen eher davon aus, dass
in diesen 36 Sekunden genau ein Objekt hinzugefügt wurde, oben rechts auf Seite 1: das Etikett
`"Anlage 1 / Taylor Wessing"`. Und verwundbar ist genau die Software, die es aufgebracht hat:

* **Objekt nach seinen Markierungen:** von `(929, 294)` bis `(1139, 372)`, also `210 × 78 px`, Mittelpunkt etwa bei `(1034, 333)`.
* **Sichtbarer Rahmen:** von `(936, 300)` bis `(1133, 367)`, also etwa `197 × 67 px`, Seitenverhältnis etwa `3 : 1`; die Oberkante des Blatts liegt bei `y ≈ 275`.
* **Maßstab:** gemessen am linken Lineal des Dokuments `1 cm ≈ 82 px` (das Lineal ist fast sicher in Zentimetern; in Zoll wäre das Blatt breiter als `15″`).

Stil und Aussehen des Etiketts entsprechen der zurückgegebenen Datei. Ohne Zugang zur ursprünglichen
Erstellungsumgebung oder Kenntnis des Ausgangsformats (falls konvertiert wurde) kann das Experiment jedoch nicht
sauber sein, deshalb können wir es nicht mit hundertprozentiger Sicherheit behaupten.

---

## 3. Seite 444: die verborgene Uhrzeit und die Arithmetik der Meldungen

Auf Seite 444 beginnen die Meldungen, darunter jene homophobe Meldung. Ein wichtiger Punkt:

* Bei den Meldungen, die man sichtbar zeigen wollte (den für die Juristen bequemen), wurde das Feld
  **`Time of Report`** absichtlich und zusätzlich verborgen. Eine genaue Uhrzeit gibt es nicht, und das ist das
  Einzige in der ganzen Datei, das technisch korrekt verborgen wurde.
* Im Hauptartikel haben wir die gezeigten Meldungen mit den übrigen mathematisch verglichen, nach Inhalt, Schreibstil
  und Nicknames. Fast überall wird primitiv die Standardformel von Reddit zur Namensgenerierung verwendet, und im
  benötigten Bereich zeigt sich ein scharfer Anstieg. Wir sagen nicht, dass die Meldungen gefälscht wurden, aber wir
  sagen, dass die Konten wahrscheinlich nicht echt sind und die meisten von ihnen mathematisch einem Botnetz ähneln.

---

## 4. Eine Frage an Dr. Patrick Zurheide zu den Einträgen `2025-02-03 16:29:23` und `2025-04-02 15:55:19`

Doktor Patrick, Sie haben geschrieben, Sie hätten den homophoben Witz gelesen und beschlossen, selbst einen Witz zu
machen. Gut, sehr lustig. Die übrigen Meldungen sind, wie Ihr Kollege sagte, inhaltlich unwichtig
(*„Unabhängig von den Einzelheiten der Beschwerden zeigt schon die bloße Anzahl…“*). Gut, die überspringen wir. Wir
hoffen, dass **Doktor Tobias** seinen Studierenden in einer Vorlesung erklärt, warum ein zufälliges Viertel der
1.938 Meldungen (485 Stück) voller Todeswünsche und nationalsozialistischer Äußerungen unwichtig ist, und für wen
genau es unwichtig ist. Wenn er das tut, räumen wir sofort ein, dass wir uns geirrt haben, entschuldigen uns und
löschen die Erwähnungen.

Nennen wir die Dinge beim Namen: Sie haben die Daten der Hater, der russischen, des deutschen, aller, wissentlich genau
der Person zum Fraß vorgeworfen, die sie angefeindet haben, und das zwischen zwei Ländern, die gegeneinander Krieg
führen. Es stellte sich heraus, dass Sie ihm russische Kinder zum Fraß vorgeworfen haben: Er freut sich, und Tobias
hat sie ausdrücklich als das Problem benannt. Aber in Wirklichkeit ist das Ihr Leck; nur sind es eben nicht Ihre
Kinder.

Unsere Frage betrifft jedoch einen anderen Nutzer, den man nicht übersehen konnte:

* **`2025-02-03 16:29:23`**: ein Link und eine Person aus demselben Land, dazu sehr ernste Dinge, die sofort ins Auge
  fallen;
* **`2025-04-02 15:55:19`**: ein direkter Hinweis, ein konkreter Name und das, was er schreibt.

Wir haben es geprüft: Es ist genau das, wonach es aussieht. Sie haben staatliche Daten und vollständige persönliche
Angaben offen in die Hände einer Person gegeben, die Sie selbst für einen Straftäter halten. Das hätte man schon wegen
des Kontexts nicht tun dürfen. Was passiert, wenn er dorthin schreibt? Von Ihrer Seite ist das nicht nur
niederträchtig, es ist eine offene Missachtung von Leben und Gesundheit von Menschen. Während unserer Untersuchung
haben wir diese Person gestoppt und alle in Sicherheit gebracht. Das ist im Großen und Ganzen unsere einzige echte
Beanstandung; alles andere sind schlicht Fakten und eine Vorführung, wie Elite-Juristen arbeiten. Wir fordern Doktor
Patrick auf, dafür die entsprechende Verantwortung zu übernehmen, es sei denn natürlich, der Titel vor seinem Namen
gibt ihm das Recht, so zu handeln (wir sind keine Juristen und kennen die Gesetze nicht).

---

## 5. An die Öffentlichkeit, die Versicherung, die Aufsichtsbehörden und US-Unternehmen

* **An die Öffentlichkeit und die Mandanten von Taylor Wessing:** Der Nachlässigkeit nach zu urteilen, hat Taylor
  Wessing eine großzügige Versicherung, die all das normal findet. Prüfen Sie Ihre Dateien und informieren Sie die
  Aufsichtsbehörde. Den Juristen selbst müssen Sie nichts sagen: Sie haben sich entschieden, das zu verbergen, und
  zwar seit über einem Jahr, seit Valve zum ersten Mal auf sie zukam.
* **An die Aufsichtsbehörden, zur Verwundbarkeit aller Dateien:** Prüfen Sie die Tätigkeit von Dr. Patrick und
  fordern Sie alle PDF-Dateien an, die durch seine Hände gingen und oben auf der ersten Seite das Etikett
  `"Anlage 1 / Taylor Wessing"` (oder ein ähnliches) tragen. Die Wahrscheinlichkeit, dass es sich nicht um einen
  Einzelfall handelt und alle Dokumente mit diesem Aufkleber von ihm verwundbar sind, ist kritisch hoch.
* **An die Versicherung:** Bitte prüfen Sie Ihren Kunden und die Software, mit der er PDFs bearbeitet und das Etikett
  `"Anlage 1 / Taylor Wessing"` oben auf Seite 1 aufbringt. Höchstwahrscheinlich liegt genau dort das Problem, und es
  ist kein Einzelfall. Eine Prüfung von ganz Taylor Wessing zu fordern ist sinnlos: Außer dem Namen scheinen sie
  nichts gemeinsam zu haben, weder Arbeitsumgebungen noch Regeln zur Sicherheitsprüfung, die es von vornherein geben
  müsste (offenbar decken ein physischer Signaturschlüssel und der Titel vor dem Namen all das ab).
* **An US-Unternehmen und an alle bei der Europäischen Kommission, die das zufällig lesen:** Versuchen Sie einfach,
  die Gesetze einzuhalten. Namhafte Doktoren aus einem namhaften „Freelance-Unternehmen“ zu engagieren, wirkt
  gefährlich und gegenüber Ihren Kunden äußerst widerlich. Wenn bei Valve einfach Schecks unterschrieben werden und
  niemand prüft, was die Juristen 106 Tage lang getan haben, dann ist vielleicht gerade die Bezahlung für verschleppte
  Zeit statt für Ergebnisse der Grund dafür, dass die Software veraltet ist und niemand versteht, wie ein PDF
  funktioniert. Und wenn es dort keine weiteren Lecks gibt, dann hat Doktor Patrick schlicht alle mit Warten oder
  Drohungen zermürbt. Im Kern wird eine Dienstleistung zur Nichteinhaltung der DSGVO verkauft: mangelhafte
  Ausführung und Drohungen („Sie werden keinen einzigen Prozess gewinnen“), kombiniert mit einer hochwertigen
  Bereinigung der Google-Ergebnisse im eigenen Namen. Wir verfassen keine juristischen Texte und beschuldigen
  niemanden. Wir schreiben einfach, was wir gesehen haben und was sie so eifrig zu löschen versuchen.

---

## 6. Was Valve gekauft hat, war keine DSGVO-Bearbeitung

Wir sind nicht Partei des Streits und verteidigen weder das Konto noch die Sperre. Es bleibt eine Frage. Valve hat Spitzenjuristen engagiert: zwei namhafte Doktoren aus einem namhaften „Freelance-Unternehmen“, **Dr. Tobias Schelinski** (`Dok.-Nr. 42282474`, 15. August 2025) und **Dr. Patrick Vincent Zurheide** (`Dok.-Nr. 42603633`, 1. Oktober 2025). Wofür hat Valve bezahlt? Nicht für eine DSGVO-Bearbeitung: Der Antrag wurde damals nicht erfüllt und ist es bis heute nicht.

### Was stattdessen geliefert wurde, in ihren eigenen Worten

* **Eine Frist mit Vorbehalt:** *„wenn überhaupt“* — Doktor Tobias.
* **Daten verlangt, Konto verloren:** gekündigt *„mit sofortiger Wirkung“*, als Antwort auf einen Auskunftsantrag — Doktor Tobias.
* **Beweis durch Menge:** *„Unabhängig von den Einzelheiten der Beschwerden…“* Inhalt egal, gezählt wird alles — Doktor Tobias.
* **Eine Diagnose des Antragstellers:** *„…Ihr Mandant bzw. dessen Komplizen…“* — Doktor Patrick.
* **Ein Urteil für jedes Gericht:** *„Aus unserer Erfahrung wird jedes Gericht…“* — Doktor Patrick. Kein Gericht hat entschieden; wir dachten, dafür seien Gerichte da.
* **Vier Paragrafen des Strafgesetzbuchs:** `§§ 263, 263a, 202a, 303a StGB`, für die Bitte um die eigenen Daten.
* **Statt der Daten:** fünf Seiten der öffentlichen Datenschutzerklärung von Steam, eine Kopie des Dashboards, das der Nutzer ohnehin sieht, und eine übersetzte Antwort des Steam-Supports. Zwei Doktoren der Rechte haben geliefert, was ein Support-Mitarbeiter bereits geschrieben hatte.
* **Ein Schuldschein:** *„Gerne beauskunften wir die restlichen … Daten, sobald …“* Der Rest, irgendwann.
* **Dritte geschützt, indem man sie leakt:** die Sperrdaten „zum Schutz Dritter“ zurückgehalten, die Daten Dritter in einem PDF verschickt, dessen schwarze Balken sich entfernen lassen.
* **Zwei Versionen der Fakten:** Der eine Doktor datiert den Nutzer auf Mai 2025, der andere auf 2019. Beide haben unterschrieben. Ein Doktor würde nichts Unwahres unterschreiben, also akzeptieren wir beide.
* **Premium-Rechtschreibung:** *„Die Antwortet lautet ja“*, gleich zweimal, und die eigene E-Mail-Adresse des Partners falsch geschrieben, in seiner eigenen Signatur.

### Kein Versehen

> [!IMPORTANT]
> Fehler werden normalerweise versteckt. Hier hat es niemand auch nur versucht. **Verkauft wird die Nichteinhaltung der DSGVO, und zwar offen.** Das ist kein Versehen, das ist Arroganz.

### Für sich selbst, für den Nutzer und für alle anderen

* **Für sich selbst:** Auslistung nach `Art. 17`. Doktor Patrick hat zuerst beantragt; wir haben Teil 3 auf Medium veröffentlicht; gleich danach wurden auch die Ergebnisse zu Doktor Tobias ausgelistet.
* **Für die betroffene Person:** siebzehn Monate, und es werden mehr.
* **Ohne Juristen:** Der Steam-Support hat den Antrag eines anderen Kontoinhabers in **3 Tagen** geschlossen, mit einem Link auf Account Data: *"there's no further information Steam Support can offer, this request will be closed"* (Ticket `HT-2YBP-F7JP-D4VB`; Screenshots des Antragstellers, [Abschnitt 18 des Steam-Dossiers](https://phishdestroy.io/steam_dossier/#gdpr-live-case)).
* **Mit Juristen:** dasselbe geschlossene Ticket in **106 Tagen**, auf Briefpapier. Wer hat Valve erlaubt, DSGVO-Anträge überhaupt nicht zu bearbeiten? Doktor Tobias?

### Titel

Wir nennen sie durchgehend „Doktor“, und das meinen wir respektvoll: Der Titel ist eine historische Tatsache. Der von Doktor Tobias beruht auf [einer Studie von 2005 darüber, wie deutsche Behörden ausländische Online-Dienste beaufsichtigen](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm), der von Doktor Patrick auf [einer Studie von 2020 über Softwareentwicklungsverträge in Scrum](https://books.google.pl/books/about/Herausforderungen_bei_einer_Softwareentw.html?id=uh4PzgEACAAJ&redir_esc=y). Jede davon ist eine schmale Forschungsarbeit zu einem schmalen Thema, einmal angefertigt. Das ist keine Expertise im Datenschutz, in PDF-Dateien oder darin, was jedes Gericht entscheiden wird. Unter den Titeln, in dieser Akte: keine Aufsicht, und ein PDF, erstellt mit `Aspose.PDF for .NET 20.8` aus dem Jahr 2020.

Wir haben keine der beiden Dissertationen gelesen, weder die von Doktor Tobias noch die von Doktor Patrick. Gelesen haben wir die Verlagsbeschreibung der Dissertation von Doktor Tobias. 2005 gab es die DSGVO natürlich noch nicht. Aber es klingt, als wäre die Lösung schon damals da gewesen.

<details>
<summary><b>Die Verlagsbeschreibung der Dissertation von Doktor Tobias (Originaltext)</b></summary>

> „Darüber hinaus geht der Autor auf Probleme ein, die sich aus der Durchführung der behördlichen Aufsicht über die Online-Dienste ergeben. Hier sind insbesondere die Ausführungen über die örtliche Zuständigkeit von Behörden hervorzuheben. Dem Autor gelingt es insoweit, anhand einzelner Gesetze Lösungsmöglichkeiten aufzuzeigen wie der Gegensatz einer beschränkten örtlichen Zuständigkeit im Verhältnis zu der weltweiten Präsenz von Online-Diensten zu lösen ist.“

Quelle: [Verlag Dr. Kovač](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm).

</details>

Nach dieser Akte zu urteilen, hat der Autor tatsächlich eine Lösung gefunden, auch für die DSGVO: Ein Jurist entscheidet, wer Anspruch auf seine eigenen Daten hat und wer nicht. Welche Gesetze nötig waren, um eine europäische Verordnung im Interesse eines einzigen amerikanischen Unternehmens einzuengen, wissen wir nicht. Eine mögliche Lösung wäre gewesen, den DSGVO-Antrag rechtmäßig zu bearbeiten. Aber der Autor ist ja schon Doktor.

### Drei Wege, einen Auskunftsantrag falsch zu behandeln

Soweit wir, keine Juristen, die Verordnung lesen können, gibt es drei, und alle drei wurden gegangen:

* **Die Daten nicht herausgeben:** rechtswidrig.
* **Sie unvollständig herausgeben:** rechtswidrig.
* **„Manuell bereinigen“ und Daten Dritter leaken:** doppelt rechtswidrig (`Art. 5(1)(f)`, `Art. 32`).

> [!TIP]
> **Der vierte Weg:** den Antrag einfach erfüllen. Es ist der einzige, den zwei Doktoren der Rechte nicht gegangen sind. Das ist kein Pech, das ist eine Entscheidung.

### Wer trägt die Verantwortung?

Soweit wir sehen: niemand, weder finanziell noch persönlich. Eine Bewertung kann man ihnen nicht hinterlassen. Eine Meinung kann man nicht schreiben. Die Kanzlei ist „dezentral“, also gibt es keine andere Gesellschaft, an die man sich wenden könnte. Und sobald man die Menschen nennt, die die Schreiben im Namen der Kanzlei unterschrieben haben, werden die Vertreter der Kanzlei plötzlich zu Privatpersonen, und das Recht auf Vergessenwerden, geschrieben für Privatpersonen, greift sofort. Dabei betraf alles, was ausgelistet wurde, ihre berufliche Arbeit. Fällt ein Bericht über einen Verstoß oder über berufliche Kompetenz wirklich unter das Recht auf Vergessenwerden? Wie sollen Menschen einen guten Anwalt von einem schlechten unterscheiden: am Profil auf der Website von Taylor Wessing selbst? Und kann man dem trauen, wenn die Kanzlei ihre eigene Wikipedia-Geschichte bearbeitet?

Wir verstehen einfach nicht, warum die historische Tatsache einer Promotion zu einem schmalen Thema jemandem das Recht gibt, DSGVO-Rechte abzuschalten. Vielleicht verstehen wir es falsch. Vielleicht bringt Doktor Tobias seinen Studierenden etwas nicht ganz Richtiges bei. Oder vielleicht ist es richtig, und Deutschland hat die DSGVO still und leise aufgegeben. Oder entscheidet das Doktor Tobias?

Und warum müssen wir, nur um unser Audit, unsere Meinung und unsere Erfahrung zu veröffentlichen (über Kompetenz und über das Leak-Risiko in der verwundbaren Software von Doktor Patrick), den Text in unsere eigene Software einbauen, damit er überlebt? Genau deshalb sieht das alles für uns nach Korporatokratie aus. Und wenn derjenige, der fragt, nichts bekommt, wozu dann die DSGVO? Als Umsatz für Juristen, die kein PDF bedienen können?

### Unser Fazit

Wir sind nicht Partei dieses Streits, und ehrlich gesagt sind wir ihn leid. In dieser Zeit haben wir uns alles angesehen: die zweimal gelöschte Wikipedia-Geschichte, die Kinder in den Meldungen, einen DSGVO-Antrag, der nie bearbeitet wurde, das Recht auf Vergessenwerden, für sich selbst genutzt, einen Gründer, der an der nationalsozialistischen Fassung des §175 mitgeschrieben hat, und eine „dezentrale“ Struktur, in der die Verantwortung niemandem gehört. Aus unserer kleinen Erfahrung ist das Fazit traurig: Titel sind Titel. Verantwortung auf Seiten der Juristen: null. Was bleibt, ist Arroganz und eine DSGVO, die nicht eingehalten wurde. Wir fragen nur, was Valve gekauft hat, denn eine DSGVO-Bearbeitung war es offensichtlich nicht.

---

Da die Juristen glauben, sie seien das Gesetz, und das Leben von Menschen, von Kindern, sei egal, ist das ihre
Entscheidung. Es ist nicht unser Konflikt. Aber wir können mit Gewissheit sagen, dass die Straflosigkeit der Kanzlei
historisch belegt ist, angefangen bei ihrem Gründer Goltz, einem der acht, die die Änderungen des §175 ausarbeiteten,
und bei seinem einzigen aufsehenerregenden Fall, der mitunter als Verteidigung von LGBT-Menschen gedeutet wird: dem
Fall des Generals von Fritsch.

<details>
<summary><b>Geschichte: Goltz, §175 und der Fall Fritsch</b></summary>

Die Geschichte überspringen wir; wir haben sie direkt aus einer verlässlichen Quelle
und dem Original studiert. Das Ende dieses Falls aber lautet: Es gab einen Angeklagten, und wir haben drei Tote.
Achim von Frisch, zermalmt von den Mühlsteinen der Repression. Otto Schmidt, 1943 erschossen. Und General Fritsch
selbst: Dass er freigesprochen wurde, spielt keine Rolle, der Preis war hoch. 1939 ging er, den Tod suchend,
freiwillig an die Front in Polen und wurde getötet (oder ließ sich töten).

Natürlich haben wir diesen Fall nie als Verteidigung von LGBT-Menschen durch den Gründer dieser Kanzlei gewertet.
Aber das Ergebnis ist weit interessanter als ein Sieg.

**Asymmetrie der Justiz:** Goltz hat tatsächlich einen hochrangigen Militär gerettet, dessen Schuld von der Gestapo
vollständig fabriziert worden war. Doch dieses Alibi wurde mit fremdem Blut bezahlt. Derselbe Goltz hat als Mitglied
der Strafrechtskommission (ab 1933) die nationalsozialistische Fassung des Paragraphen 175 (1935) persönlich
entworfen und eingeführt.

**Statistik gegen PR:** Er verteidigte einen heterosexuellen General der Wehrmachtselite, nachdem er zuvor ein
juristisches Fließband in Gang gesetzt hatte, das etwa 50.000 tatsächliche Homosexuelle ins Gefängnis und etwa 15.000
in Konzentrationslager brachte, bei einer Sterblichkeit von 60 %. Die Rettung eines Generals hebt die Architektur des
Völkermords nicht auf.

**Erfolgreich an der Entnazifizierung vorbei:** Der Fall Fritsch wurde zur perfekten „Hintertür“ durch die
Spruchkammern der Nachkriegszeit. Der Architekt repressiver Gesetze nutzte die Verteidigung eines Generals als Beleg
seiner „Unabhängigkeit“, entging Nürnberg, behielt Status und Zulassung und gründete 1957 den Laden, der heute unter
dem Schild Taylor Wessing seine Fortschrittlichkeit verkauft.

</details>

Also ja, alles in allem: Wir sind sicher, dass es keine Rolle spielt, ob es dieses deutsche Taylor Wessing ist oder
irgendein anderes; mit dem Recht hat das überhaupt nichts zu tun. Was wir hier sagen, ist eine Erklärung, keine
Tatsachenbehauptung, sondern eine Annahme, denn in Wirklichkeit werden sie nach jedem Wort suchen, an dem sie sich
festbeißen können. Genau deshalb geht das in die Archive: die Versuche der Zensur und Vertuschung und die direkten
Verbindungen zu ihrem Erbe. Von Doktor Patrick: die allererste Meldung, in der das grobe homophobe Wort stehen
geblieben ist. Vielleicht zufällig, natürlich, aber es steht da, und zwar als erste.

Von Doktor Tobias erwarten wir natürlich eine Vorlesung über den unwiderlegbaren Beweis in Form einer Anzahl von
Meldungen und eine Erklärung, welcher Teil jenes Viertels für ihn persönlich unwichtig ist. Für die Geschichte und für
das Verständnis, wo die Grenzen liegen, ist das wichtig.

Dass Steam als Verantwortlicher für die Daten auftritt, statt zu moderieren, zeigt schlicht das Offensichtliche:
Doktor Patrick hat sie geleakt. Nun, so ist es gekommen. Offenbar wusste er nicht, dass die Software für den Aufkleber
kaputt ist, schließlich sind das Spitzen-Doktoren, und Steam hat dafür nicht bezahlt: ob man den DSGVO-Antrag
bearbeitet oder nicht, und danach das Leck zu vertuschen, das er gesehen hat.

Wir rufen zu einem vernünftigen Umgang mit der Wahrheit auf und möchten alle an Zero Trust erinnern: gegenüber allen,
auch gegenüber uns. Alles ist feindliche Umgebung, und im Zusammenhang dieser Analyse ganz wörtlich: Sperren am
9. Mai, Nazis, Doktoren, LGBT-Menschen, Kinder. Es war lustig.

Aber unsere Möglichkeiten in Sachen Taylor Wessing sind höchstwahrscheinlich erschöpft, denn ihre Strategie besteht
darin, Links entfernen zu lassen. Wir sind gezwungen, unseren Text und unsere Daten zu sichern, und bauen sie deshalb
in unsere Software ein, die bereits drei bestätigte Dankschreiben von Behörden hat, darunter aus Deutschland und
Belgien, und dabei noch nicht einmal veröffentlicht ist.

Wir möchten alle warnen, die Gesetze gern verdrehen: Es ist nicht nötig, das Repository entfernen zu lassen. Wir sind
in all der Zeit in keinen Konflikt mit Ihnen getreten. Wenn Sie aber beschließen, unsere Arbeit zu zerstören, um die
Wahrheit zu verbergen, dann können Aufsichtsbehörden und andere ohne ein aktives Repository die Signatur einer Version
nicht vergleichen (obwohl, wem sage ich das), und dann treten wir in einen direkten Konflikt. In diesem Sinne
verabschieden wir uns hoffentlich von Mega-Expertise und Elite-Juristen. Es war nicht lustig, und gefreut hat es mich
auch nicht. Alles Gute.

> [!CAUTION]
> **Eine Löschung dieses Repositorys löscht nichts.** Ermittler und Forschende nutzen TgWitness, und mit diesem Repository werden ihre Kopien abgeglichen. Wir haben Backups. Aber eine Löschung würde uns vom Prüfer eines einzelnen Falls zur Konfliktpartei machen. Genug davon, die Wahrheit zu löschen.

[Quelldatensatz](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Hinweis zum Betreiber](OPERATOR-INCOMPATIBILITY.md) · [MIT-Lizenz](../../LICENSE)

[Projekt](../../README.md) · [Dokumentation](README.md) · [Wiki](../wiki/Home.md)
