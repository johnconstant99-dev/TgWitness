[TgWitness](../../README.md) / [Dokumentation](README.md) · [Hinweis zum Betreiber](OPERATOR-INCOMPATIBILITY.md)

![Die DSGVO-Akte: 106 Tage](../assets/presentation/chapter-case.svg)

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

Da die Juristen glauben, sie seien das Gesetz, und das Leben von Menschen, von Kindern, sei egal, ist das ihre
Entscheidung. Es ist nicht unser Konflikt. Aber wir können mit Gewissheit sagen, dass die Straflosigkeit der Kanzlei
historisch belegt ist, angefangen bei ihrem Gründer Goltz, einem der acht, die die Änderungen des §175 ausarbeiteten,
und bei seinem einzigen aufsehenerregenden Fall, der mitunter als Verteidigung von LGBT-Menschen gedeutet wird: dem
Fall des Generals von Fritsch. Die Geschichte überspringen wir; wir haben sie direkt aus einer verlässlichen Quelle
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

[Quelldatensatz](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Hinweis zum Betreiber](OPERATOR-INCOMPATIBILITY.md) · [MIT-Lizenz](../../LICENSE)

[Projekt](../../README.md) · [Dokumentation](README.md) · [Wiki](../wiki/Home.md)
