[TgWitness](../../README.md) / [Dokumentation](README.md) · [Hinweis zum Betreiber](OPERATOR-INCOMPATIBILITY.md)

![Die DSGVO-Akte: 106 Tage](../assets/presentation/chapter-case.svg)

# Valve, Taylor Wessing und 106 Tage Warten nach der DSGVO: die Datei und ihre 70.717 Wörter

[Quelldatensatz](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Hinweis zum Betreiber](OPERATOR-INCOMPATIBILITY.md) · [English](../TAYLOR-WESSING-GDPR-FILE.md)

> [!NOTE]
> Wir sind keine Partei dieses Streits und keine Juristen. Diese Seite hält fest, was in der Datei selbst zu
> sehen ist und was wir beobachtet haben. Aussagen über Absichten sind unsere Annahmen und als solche
> gekennzeichnet. **Zero Trust** gilt für alle, auch für uns.

Manche Fragen bleiben für immer unbeantwortet, weil wir keine Partei des Streits sind. Jeweils 100 Tage zu
warten und es mit Elite-Juristen aufzunehmen, die Konzerne über solche „Freelance-Börsen" finanzieren, hält ein
gewöhnlicher Mensch nicht durch. Wir werden nie erfahren, wie die Leistung, die Valve bestellt hat, tatsächlich
hieß. Von außen sieht es nach einer nicht ganz rechtmäßigen Verarbeitung nach der DSGVO aus: eine Herausgabe, bei
der die Meldenden nicht geschwärzt, sondern preisgegeben wurden, während die Daten selbst um mindestens
**5.000–10.000 Seiten** zu kurz sind. Exportiert wurde nicht das Protokoll des Nutzers, sondern ein gekürztes
Protokoll für ausgelagerte Moderatoren. Es anzufechten ist sinnlos: Objektiv fehlt eine riesige Schicht an
Informationen, ebenso wie jede Bestätigung der Worte beider Anwälte.

Was kostet Valve eine Leistung aus Zeitschinden, händischem Schwärzen und der Unterschrift eines Doktors unter
einer homophoben Meldung und einem kaputten PDF? Das ist nicht unser Fall, aber das Problem liegt hier eindeutig
nicht im Recht, sondern in Status und Straflosigkeit: Das Präfix „Doktor" macht automatisch den einen zu
demjenigen, der entscheidet, was als unwiderlegbarer Beweis gilt, und den anderen zu demjenigen, der sich
angeblich mit Zahlen und PDFs auskennt (es in Wahrheit aber nicht tut).

---

## 1. Daten, die Worte des Doktors und keine Zahlungen im Bericht

Im Kopf des Dokuments steht `Date of Report: 09-29-2025`, übergeben wurden die Dateien am 1. oder 2. Oktober.
Wir verlassen uns nicht auf diese Daten. Wir verlassen uns auf eine direkte Aussage von
**Dr. Patrick Vincent Zurheide**:

> „Bei der Zusammenstellung der personenbezogenen Daten Ihres Mandanten musste leider die volle Monatsfrist
> ausgeschöpft werden, da sich bei erneuter Prüfung der Daten gezeigt hat, dass auch nach dem 3. Mai 2025 neue
> Zahlungen durch einen Dritten über das Nutzerkonto Ihres Mandanten erfolgt sind und insofern manuell die Daten
> bereinigt werden mussten."

Genau wegen dieses Satzes hören wir auf, den Zahlen, den Worten des Doktors im ersten Absatz und seiner
Unterschrift zu glauben. Natürlich würde ein Doktor nicht lügen; er riskiert ja etwas. Oder etwa nicht?
Tatsächlich wurden nach dem Export der Datei und dem Entfernen der Vektorflächen **keine Zahlungen im Bericht
gefunden**. Wir fechten weder die Arbeit von Dr. Patrick noch seine Verzögerung an. Wir glauben und akzeptieren
einfach „die Wahrheit des Doktors" und halten fest, was in der Datei selbst zu sehen ist.

---

## 2. 36 Sekunden und das Etikett „Anlage 1 / Taylor Wessing"

Wir sind in nichts Experten, vermutlich wurde deshalb unser Hinweis auf die Schwachstelle sowohl von der
Freelance-Plattform als auch vom Doktor ignoriert (die Logik ist verständlich: Sie sind das Gesetz, welche
Schwachstellen könnten sie schon haben?).

Lassen wir die Worte des Doktors beiseite und betrachten die Technik. Wir haben eine passende Windows-Umgebung
aufgesetzt, die bereinigte Datei genommen und versucht, die Flächen selbst zu platzieren. Hunderte schwarze
Flächen in **36 Sekunden** von Hand zu setzen, so lange dauerte die aufgezeichnete Sitzung, halten wir für
unmöglich. Das Dokument trug seine schwarzen Flächen offenbar bereits. Wir neigen zu der Ansicht, dass in diesen
36 Sekunden genau ein Objekt oben rechts auf Seite 1 hinzugefügt wurde, das Etikett `"Anlage 1 / Taylor Wessing"`,
und dass die Software, die es platziert hat, die verwundbare Stelle ist:

| Messung | Wert |
| --- | --- |
| Objekt, nach seinen Markierungen | `(929, 294)` bis `(1139, 372)`: `210 × 78 px`, Mitte etwa `(1034, 333)` |
| Sichtbarer Rahmen | `(936, 300)` bis `(1133, 367)`: etwa `197 × 67 px`, Verhältnis etwa `3 : 1`; Oberkante des Blatts bei `y ≈ 275` |
| Maßstab | das linke Lineal des Dokuments ergibt `1 cm ≈ 82 px` (fast sicher Zentimeter; in Zoll wäre das Blatt breiter als `15″`) |

Gestaltung und Aussehen des Etiketts passen zur zurückgegebenen Datei. Ohne Zugang zur ursprünglichen
Erstellungsumgebung oder Kenntnis des Ausgangsformats, falls eine Konvertierung stattfand, ist das Experiment
nicht sauber, daher können wir es nicht mit 100-prozentiger Sicherheit behaupten.

---

## 3. Seite 444: verborgene Zeiten und die Arithmetik der Meldungen

Auf Seite 444 beginnen die Meldungen, darunter die homophobe Meldung.

- Bei den Meldungen, die sie sichtbar zeigen wollten (die für die Juristen bequemen), ist das Feld
  **`Time of Report`** absichtlich und zusätzlich verborgen. Es gibt keine genaue Zeit, und das ist das Einzige
  in der gesamten Datei, das technisch korrekt verborgen ist.
- Im Hauptartikel haben wir die gezeigten Meldungen mit den übrigen nach Inhalt, Schreibstil und Nicknames
  verglichen. Fast überall wird die Standardformel von Reddit für Benutzernamen verwendet, und im relevanten
  Zeitraum gibt es einen scharfen Anstieg. Wir sagen nicht, dass die Meldungen gefälscht wurden. Wir sagen aber,
  dass die Konten wahrscheinlich nicht echt sind und die meisten mathematisch einem Botnetz ähneln.

---

## 4. Eine Frage an Dr. Patrick Zurheide

Dr. Patrick, Sie haben geschrieben, dass Sie den homophoben Witz gelesen und beschlossen haben, zurückzuwitzeln.
Gut, lustig. Die übrigen Meldungen sind, wie Ihr Kollege sagte, inhaltlich unerheblich
(*„Unabhängig von den Einzelheiten der Beschwerden zeigt schon die bloße Anzahl…"*). Gut, wir überspringen sie.
Wir hoffen, dass **Dr. Tobias** seinen Studierenden in einer Vorlesung erklärt, warum ein zufälliges Viertel der
1.938 Meldungen (485 Stück) voller Todeswünsche und nationalsozialistischer Äußerungen unerheblich ist, und für
wen genau. Wenn er das tut, räumen wir sofort ein, dass wir falsch lagen, entschuldigen uns und entfernen jede
Erwähnung.

Nennen wir die Dinge beim Namen: Sie haben einen kaputten DSGVO-Export herausgegeben, der die Daten der Hater
offenlegt, der russischen, des deutschen, aller, und zwar genau an die Person, die sie angefeindet haben, in
einer Lage, in der es um zwei Länder geht, die gegeneinander Krieg führen. Es hat sich herausgestellt, dass Sie
ihm russische Kinder preisgegeben haben, und er war froh, während Tobias sie ausdrücklich als das Problem
benannt hat. In Wirklichkeit ist es Ihr Datenleck; nur die Kinder sind nicht Ihre.

Unsere Frage betrifft jedoch einen anderen Nutzer, den man nicht übersehen konnte: den Eintrag vom
**`2025-04-02 15:55:19`** und einen zweiten Eintrag desselben Nutzers. Er enthält eine direkte Aussage und
Einzelheiten, die keiner Erklärung bedürfen. Wir haben es geprüft: Es ist genau das, wonach es aussieht. Sie haben
staatliche Daten und vollständige persönliche Einzelheiten an die Person gegeben, die Sie selbst für einen
Straftäter halten. Das hätte schon wegen des Zusammenhangs nicht geschehen dürfen. Was passiert, wenn er diese
Person anschreibt? Von Ihrer Seite ist das nicht nur niederträchtig; es ist eine direkte Missachtung von Leben und
Gesundheit von Menschen. Während unserer Untersuchung haben wir diesen Nutzer gestoppt und dafür gesorgt, dass
alle Beteiligten in Sicherheit sind.

Das ist im Großen und Ganzen unsere einzige echte Beanstandung; alles andere sind schlicht Fakten und eine
Vorführung, wie Elite-Juristen arbeiten. Wir fordern Dr. Patrick auf, die entsprechende Verantwortung zu
übernehmen, es sei denn natürlich, das Präfix vor seinem Namen berechtigt ihn zu einem solchen Vorgehen (wir sind
keine Juristen und kennen die Gesetze nicht).

---

## 5. Botschaften an die Öffentlichkeit, die Versicherung, die Aufsichtsbehörden und US-Unternehmen

- **An die Öffentlichkeit und die Mandanten von Taylor Wessing.** Nach der Nachlässigkeit zu urteilen, hat
  Taylor Wessing eine großzügige Versicherung, die so etwas normal findet. Prüfen Sie Ihre Dateien und
  informieren Sie die Aufsichtsbehörde. Den Juristen selbst müssen Sie nichts sagen; sie haben sich entschieden,
  dies seit über einem Jahr zu verbergen, seit Valve zum ersten Mal zu ihnen kam.
- **An die Aufsichtsbehörden, zur Schwachstelle in allen Dateien.** Prüfen Sie die Tätigkeit von Dr. Patrick und
  fordern Sie alle PDFs an, die durch seine Hände gingen und auf der ersten Seite oben das Etikett
  `"Anlage 1 / Taylor Wessing"` (oder ein ähnliches) tragen. Die Wahrscheinlichkeit, dass dies kein Einzelfall
  ist und alle Dokumente mit diesem Aufkleber von ihm verwundbar sind, ist kritisch hoch.
- **An die Versicherung.** Bitte prüfen Sie Ihren Kunden und die Software, mit der er PDFs bearbeitet und das
  Etikett `"Anlage 1 / Taylor Wessing"` oben auf Seite 1 setzt. Höchstwahrscheinlich liegt genau dort das
  Problem, und es ist kein Einzelfall. Eine Prüfung von ganz Taylor Wessing zu fordern ist sinnlos: Außer dem
  Namen scheinen sie nichts gemeinsam zu haben, was Arbeitsumgebungen oder Regeln für Sicherheitsprüfungen angeht,
  die selbstverständlich existieren sollten (offenbar decken ein physischer Signaturschlüssel und das Präfix vor
  dem Namen all das ab).
- **An US-Unternehmen und alle bei der Europäischen Kommission, die dies zufällig lesen.** Versuchen Sie einfach,
  die Gesetze einzuhalten. Namhafte Doktoren aus einem namhaften „Freelance-Unternehmen" anzuheuern, wirkt
  gefährlich und gegenüber Ihren Kunden zutiefst respektlos. Wenn bei Valve einfach Schecks unterschrieben werden
  und niemand prüft, was die Juristen 106 Tage lang getan haben, dann ist vielleicht gerade die Bezahlung fürs
  Zeitschinden statt für Ergebnisse der Grund für veraltete Software und das fehlende Verständnis dafür, wie PDFs
  funktionieren. Und wenn es dort keine weiteren Lecks gab, dann hat Dr. Patrick schlicht alle mit Warten oder
  Drohungen zermürbt. Im Kern wird eine Leistung zur Nichteinhaltung der DSGVO verkauft: mangelhafte Ausführung und
  Drohungen („Sie werden keinen einzigen Prozess gewinnen"), kombiniert mit einer gründlichen Bereinigung der
  Google-Ergebnisse unter dem eigenen Namen. Wir verfassen keine juristischen Texte und beschuldigen niemanden; wir
  schreiben einfach, was wir gesehen haben und was sie so eifrig zu löschen versuchen.

---

## 6. Der Gründer, die Fritsch-Affäre und der Preis eines Alibis

Die Juristen halten sich für das Gesetz und meinen, dass das Leben von Menschen, auch von Kindern, keine Rolle
spielt. Das ist ihre Entscheidung, und es ist nicht unser Konflikt. Wir können jedoch mit Sicherheit sagen, dass
die Straflosigkeit der Kanzlei eine Geschichte hat, die bis zu ihrem Gründer zurückreicht: Rüdiger Graf von der
Goltz, **eines der acht Mitglieder** der Strafrechtskommission, die die Änderungen des Paragraphen 175 entwarf.

Sein einziger bekannter Fall, der manchmal als Verteidigung von LGBT-Menschen gelesen wird, ist der Fall des
Generals von Fritsch. Wir haben ihn anhand einer verlässlichen Originalquelle untersucht und erzählen nicht die
ganze Geschichte nach; ihr Ende ist dieses. Es gab einen Angeklagten, und es gab drei Tote:

- **Achim von Frisch**, zermalmt von der Maschinerie der Repression;
- **Otto Schmidt**, 1943 erschossen;
- **General von Fritsch** selbst. Dass er freigesprochen wurde, spielt kaum eine Rolle; der Preis war hoch. 1939
  meldete er sich, den Tod suchend, freiwillig an die Front in Polen und wurde getötet oder ließ sich töten.

Wir haben diesen Fall nie als Verteidigung von LGBT-Menschen durch den Gründer der Kanzlei gewertet, aber sein
Ausgang ist weit interessanter als ein Sieg.

- **Asymmetrie der Justiz.** Goltz hat tatsächlich einen hochrangigen Offizier gerettet, dessen Schuld vollständig
  von der Gestapo fabriziert worden war. Doch der Preis dieses Alibis wurde mit fremdem Blut bezahlt. Derselbe
  Goltz hat als Mitglied der Strafrechtskommission (ab 1933) die nationalsozialistische Fassung des Paragraphen
  175 (1935) persönlich mitentworfen und eingeführt.
- **Statistik gegen PR.** Er verteidigte einen heterosexuellen General der Wehrmachtselite, nachdem er zuvor ein
  juristisches Fließband in Gang gesetzt hatte, das etwa **50.000** tatsächliche homosexuelle Männer ins Gefängnis
  und etwa **15.000** in Konzentrationslager brachte, mit einer Sterblichkeit von rund **60 %**. Die Rettung eines
  Generals hebt die Architektur der Verfolgung nicht auf.
- **Eine gelungene Umgehung der Entnazifizierung.** Die Fritsch-Affäre wurde zur perfekten Hintertür durch die
  Spruchkammern der Nachkriegszeit. Der Architekt repressiver Gesetze nutzte die Verteidigung eines Generals als
  Beweis seiner „Unabhängigkeit", entging Nürnberg, behielt Status und Zulassung und gründete 1957 die Kanzlei, die
  heute unter dem Namen Taylor Wessing ihre Fortschrittlichkeit verkauft.

---

## 7. Warum dies in die Archive geht

Es spielt keine Rolle, ob es das deutsche Taylor Wessing oder irgendein anderes ist: Es geht hier nicht um das
Recht, und auch das Geschlecht ändert daran nichts. Dies ist eine Erklärung von Annahmen, keine Behauptung, denn
in der Realität werden sie nach einem Wort suchen, an das sie sich klammern können. Deshalb geht es in die Archive:
Versuche der Zensur und Vertuschung, und die direkten Verbindungen zu ihrem Erbe. Von Dr. Patrick stammt die erste
Meldung, mit dem groben homophoben Wort an seiner Stelle. Vielleicht zufällig, natürlich, aber sie ist die erste.
Von Dr. Tobias erwarten wir selbstverständlich eine Vorlesung über den unwiderlegbaren Beweis durch die Anzahl der
Meldungen und eine Erklärung, welcher Teil jenes Viertels für ihn persönlich unerheblich ist. Für die Geschichte
und für das Verständnis, wo die Grenzen liegen, ist das wichtig.

Steam, der Verantwortliche für die Daten, hat nicht moderiert; es weist nur auf das Offensichtliche hin.
Dr. Patrick hat die Daten offengelegt. Es ist passiert: Er wusste offenbar nicht, dass die Software hinter dem
Aufkleber kaputt war. Es sind eben Spitzen-Doktoren, und ob Steam dafür bezahlt hat, dass der DSGVO-Antrag
ordentlich bearbeitet und das Leck, das er gesehen hatte, danach verborgen wird, können nur sie sagen. Wir rufen zu
Ehrlichkeit gegenüber der Wahrheit auf und erinnern alle an Zero Trust gegenüber allen, auch gegenüber uns: Dies
ist eine feindliche Umgebung. Im Zusammenhang dieser Analyse ist das wörtlich gemeint: Sperren am 9. Mai, Nazis,
Doktoren, LGBT-Menschen, Kinder. Es war „lustig".

Unsere Möglichkeiten gegenüber Taylor Wessing sind höchstwahrscheinlich erschöpft, denn ihre Strategie ist es,
Links zu entfernen. Deshalb bewahren wir unseren Text und unsere Daten und bauen sie in unsere Software ein, die
bereits drei bestätigte Dankschreiben von Behörden hat, darunter aus Deutschland und Belgien, und dabei noch nicht
einmal veröffentlicht ist. Eine Warnung an alle, die Gesetze gern zurechtbiegen: Es ist nicht nötig, das
Repository zu entfernen. Wir sind in all dieser Zeit in keinen Konflikt mit Ihnen getreten. Aber ohne ein aktives
Repository können Aufsichtsbehörden und andere die Signatur einer Version nicht vergleichen. Wenn Sie sich
entscheiden, unsere Arbeit zu zerstören, um die Wahrheit zu verbergen, treten wir in einen direkten Konflikt.

Damit verabschieden wir uns von Mega-Expertise und Elite-Juristen. Es war nicht lustig. Wir freuen uns nicht.
Alles Gute.

[Quelldatensatz](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Hinweis zum Betreiber](OPERATOR-INCOMPATIBILITY.md) · [MIT-Lizenz](../../LICENSE)

[Projekt](../../README.md) · [Dokumentation](README.md) · [Wiki](../wiki/Home.md)
