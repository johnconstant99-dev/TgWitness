[TgWitness](../../README.md) / [Dokumentacja](README.md) · [Informacja dla operatorów](OPERATOR-INCOMPATIBILITY.md)

![Akta RODO: 106 dni](../assets/presentation/chapter-gdpr-file.svg)

# Valve, Taylor Wessing i 106 dni czekania na podstawie RODO: analiza akt i ich 70 717 słów

[Zapis źródłowy](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Informacja dla operatorów](OPERATOR-INCOMPATIBILITY.md) · [English](../TAYLOR-WESSING-GDPR-FILE.md)

Zostają nam pytania, na które nigdy nie dostaniemy odpowiedzi, bo nie jesteśmy stroną sporu. Żaden zwykły człowiek nie wytrzyma, czekając za każdym razem sto dni i mierząc się z elitarnymi prawnikami, finansowanymi przez korporacje za pośrednictwem takich „giełd freelancerów” jak ta. Nigdy się nie dowiemy, jak naprawdę nazywała się usługa, którą zamówiło Valve. Z zewnątrz wygląda to na nie do końca zgodne z prawem przetwarzanie na podstawie RODO i na udostępnienie danych, w którym zgłaszających nie zaczerniono, lecz ujawniono, podczas gdy brakuje co najmniej 5 000–10 000 stron samych danych: wyeksportowano nie dziennik użytkownika, lecz okrojony dziennik przygotowany dla podwykonawców. Nie ma sensu tego kwestionować. Ogromnej warstwy informacji obiektywnie brakuje, tak jak nie ma niczego, co potwierdzałoby słowa któregokolwiek z dwóch prawników.

Ile Valve płaci za usługę składającą się z przeciągania, ręcznie nakładanych zaczernień i podpisu Doktora pod homofobicznym zgłoszeniem i zepsutym PDF-em? To nie jest nasza sprawa, ale problem nie leży tu w prawie, lecz w statusie i bezkarności. Tytuł „Doktor” automatycznie czyni jedną osobę tą, która decyduje, co uchodzi za niepodważalny dowód, a drugą tą, która rzekomo rozumie liczby i PDF-y (choć w rzeczywistości nie rozumie).

---

## 1. Daty, słowo Doktora i raport bez żadnych płatności

Nagłówek dokumentu brzmi `Date of Report: 09-29-2025`, a same pliki przekazano 1 lub 2 października. Ale nie wierzymy tym datom. Wierzymy bezpośredniemu oświadczeniu **dr. Patricka Vincenta Zurheide**:

> „Bei der Zusammenstellung der personenbezogenen Daten Ihres Mandanten musste leider die volle Monatsfrist
> ausgeschöpft werden, da sich bei erneuter Prüfung der Daten gezeigt hat, dass auch nach dem 3. Mai 2025 neue
> Zahlungen durch einen Dritten über das Nutzerkonto Ihres Mandanten erfolgt sind und insofern manuell die Daten
> bereinigt werden mussten.“
>
> *(Zebranie danych osobowych Pańskiego klienta niestety zajęło cały miesięczny termin, ponieważ ponowna kontrola wykazała, że także po 3 maja 2025 r. osoba trzecia dokonywała przez konto nowych płatności, dlatego dane trzeba było oczyścić ręcznie.)*

To właśnie to zdanie sprawia, że przestajemy wierzyć liczbom, słowom doktora w pierwszym akapicie i jego podpisowi. Oczywiście doktor by nie skłamał; ma przecież coś do stracenia, prawda? Tyle że kiedy plik wyeksportowano i usunięto kształty wektorowe, w raporcie nie pojawiła się ani jedna płatność. Nie kwestionujemy pracy dr. Patricka ani jego zwłoki. Po prostu wierzymy i przyjmujemy „prawdę Doktora” i odnotowujemy to, co widać w samym pliku.

---

## 2. 36 sekund i podatna etykieta „Anlage 1 / Taylor Wessing”

Nie jesteśmy ekspertami w niczym, i chyba dlatego nasze zgłoszenie podatności zignorowała zarówno sama platforma freelancerska, jak i doktor. Logika jest dość jasna: oni są prawem, jakie mogliby mieć podatności?

Odłóżmy jednak słowa Doktora i spójrzmy na technikę. Przygotowaliśmy odpowiadające środowisko Windows, wzięliśmy oczyszczony plik i spróbowaliśmy rozmieścić kształty. Ręczne rozmieszczenie setek czarnych kształtów w **36 sekund**, dokładnie tyle, ile trwała zarejestrowana sesja, jest naszym zdaniem niemożliwe; wszystko wskazuje na to, że czarne prostokąty były już w dokumencie. Skłaniamy się ku temu, że w tych 36 sekundach dodano dokładnie jeden obiekt, w prawym górnym rogu strony 1: etykietę `"Anlage 1 / Taylor Wessing"`. I to oprogramowanie, które ją umieściło, jest podatne:

* **Obiekt, według jego znaczników:** od `(929, 294)` do `(1139, 372)`, czyli `210 × 78 px`, ze środkiem w przybliżeniu w `(1034, 333)`.
* **Widoczna ramka:** od `(936, 300)` do `(1133, 367)`, około `197 × 67 px`, proporcje w przybliżeniu `3 : 1`; górna krawędź arkusza na `y ≈ 275`.
* **Skala:** mierzona lewą linijką dokumentu, `1 cm ≈ 82 px` (linijka jest niemal na pewno w centymetrach; w calach arkusz byłby szerszy niż `15″`).

Styl i wygląd plakietki odpowiadają zwróconemu plikowi. Ale bez dostępu do pierwotnego środowiska tworzenia lub bez znajomości formatu początkowego (jeśli była konwersja) eksperyment nie może być czysty, więc nie możemy twierdzić tego ze 100% pewnością.

---

## 3. Strona 444: ukryta godzina i arytmetyka zgłoszeń

Zgłoszenia zaczynają się na stronie 444, w tym to homofobiczne zgłoszenie. Jedna ważna kwestia:

* W zgłoszeniach, które postanowiono pokazać (wygodnych dla prawników), pole **`Time of Report`** zostało celowo ukryte, ponad wszystko inne. Nie ma dokładnej godziny i jest to jedyna rzecz w całym pliku ukryta w sposób technicznie poprawny.
* W głównym artykule porównaliśmy matematycznie pokazane zgłoszenia z pozostałymi, pod względem treści, stylu pisania i pseudonimów. Niemal wszędzie topornie powielana jest standardowa formuła generowania nazw z Reddita, a dokładnie w potrzebnym zakresie widać ostry skok. Nie mówimy, że zgłoszenia sfałszowano, ale mówimy, że konta prawdopodobnie nie są prawdziwe i że większość z nich matematycznie przypomina botnet.

---

## 4. Pytanie do dr. Patricka Zurheide o wpisy `2025-02-03 16:29:23` i `2025-04-02 15:55:19`

Doktorze Patricku, napisał Pan, że przeczytał homofobiczny żart i postanowił zażartować sam. Dobrze, bardzo zabawne. Pozostałe zgłoszenia, jak ujął to Pana kolega, nie mają znaczenia merytorycznego (*„Unabhängig von den Einzelheiten der Beschwerden zeigt schon die bloße Anzahl…“*). Dobrze, pomijamy je. Mamy nadzieję, że **Doktor Tobias** wyjaśni swoim studentom na wykładzie, dlaczego losowa ćwiartka z 1 938 zgłoszeń (485 z nich), pełnych życzeń śmierci i nazistowskich wypowiedzi, nie ma znaczenia, i dla kogo dokładnie nie ma. Jeśli to zrobi, natychmiast przyznamy się do błędu, przeprosimy i usuniemy wzmianki.

Nazwijmy rzeczy po imieniu: świadomie przekazał Pan dane hejterów, rosyjskich, niemieckiego, wszystkich, właśnie tej osobie, którą nienawidzili, i to między dwoma państwami prowadzącymi ze sobą wojnę. Okazało się, że podał mu Pan rosyjskie dzieci: jest zachwycony, a Tobias wskazał je wprost jako problem. Ale w rzeczywistości to Pański wyciek; po prostu dzieci nie są Pańskie.

Nasze pytanie dotyczy jednak innego użytkownika, którego nie dało się przeoczyć:

* **`2025-02-03 16:29:23`**: link i osoba z tego samego kraju, z bardzo poważnymi rzeczami tam napisanymi, które od razu rzucają się w oczy;
* **`2025-04-02 15:55:19`**: bezpośrednie odniesienie, konkretne nazwisko i to, co on pisze.

Sprawdziliśmy: to dokładnie to, na co wygląda. Otwarcie oddał Pan dane państwowe i pełne dane osobowe w ręce osoby, którą sam uważa Pan za przestępcę. Nie należało tego robić, choćby ze względu na kontekst. Co się stanie, jeśli on tam napisze? Z Pana strony to nie tylko niskie; to jawne lekceważenie życia i zdrowia ludzi. W trakcie naszego dochodzenia powstrzymaliśmy tę osobę i zapewniliśmy wszystkim bezpieczeństwo. To w sumie nasza jedyna prawdziwa skarga; wszystko inne to po prostu fakty i pokaz tego, jak pracują elitarni prawnicy. Wzywamy Doktora Patricka do poniesienia za to odpowiedniej odpowiedzialności, chyba że, rzecz jasna, tytuł przed jego nazwiskiem uprawnia go do takiego postępowania (nie jesteśmy prawnikami i nie znamy prawa).

---

## 5. Do opinii publicznej, ubezpieczyciela, organów nadzorczych i firm z USA

* **Do opinii publicznej i klientów Taylor Wessing:** sądząc po niedbałości, Taylor Wessing ma hojnego ubezpieczyciela, który uważa to wszystko za normalne. Sprawdźcie swoje pliki i poinformujcie organ nadzorczy. Nie ma potrzeby mówić o tym samym prawnikom: postanowili to ukrywać od ponad roku, odkąd Valve po raz pierwszy się do nich zwróciło.
* **Do organów nadzorczych, o podatności każdego pliku:** zbadajcie działalność dr. Patricka i zażądajcie każdego PDF-u, który przeszedł przez jego ręce z plakietką `"Anlage 1 / Taylor Wessing"` (lub podobną) umieszczoną u góry pierwszej strony. Prawdopodobieństwo, że nie jest to odosobniony przypadek i że każdy jego dokument z tą naklejką jest podatny, jest krytycznie wysokie.
* **Do firmy ubezpieczeniowej:** prosimy o audyt waszego klienta i oprogramowania, którego używa do pracy z PDF-ami i do umieszczania etykiety `"Anlage 1 / Taylor Wessing"` u góry strony 1. Najprawdopodobniej właśnie tam leży problem, i nie jest to odosobniony przypadek. Nie ma sensu wzywać do audytu całego Taylor Wessing: poza nazwą wydają się nie mieć nic wspólnego pod względem środowisk pracy czy zasad przeglądu bezpieczeństwa, które powinny istnieć same przez się (najwyraźniej fizyczny klucz do podpisu i tytuł przed nazwiskiem to wszystko załatwiają).
* **Do firm z USA i do każdego w Komisji Europejskiej, kto przypadkiem to przeczyta:** spróbujcie po prostu przestrzegać prawa. Zatrudnianie renomowanych doktorów z renomowanej „firmy freelancerskiej” wygląda niebezpiecznie i skrajnie podle wobec waszych klientów. Jeśli w Valve czeki po prostu się podpisuje i nikt nie sprawdza, czym zajmowali się prawnicy przez 106 dni, to może płacenie za przeciągany czas zamiast za wyniki jest właśnie powodem, dla którego oprogramowanie jest przestarzałe, a nikt nie rozumie, jak działa PDF. A jeśli nie ma tam innych wycieków, to Doktor Patrick po prostu zdołał wszystkich zmęczyć czekaniem albo groźbami. W istocie na sprzedaż wystawiona jest usługa nieprzestrzegania RODO: niskiej jakości wykonanie i groźby („nie wygracie ani jednej sprawy”), połączone z wysokiej jakości czyszczeniem wyników Google przeprowadzonym we własnym imieniu. Nie redagujemy tekstów prawnych i nikogo nie oskarżamy. Po prostu piszemy, co widzieliśmy, i co tak usilnie próbują usunąć.

---

## 6. Valve nie kupił przetwarzania zgodnego z RODO

Nie jesteśmy stroną sporu i nie bronimy ani konta, ani bana. Zostaje jedno pytanie. Valve zatrudnił czołowych prawników: dwóch renomowanych doktorów z renomowanej „firmy freelancerskiej”, **Dr. Tobias Schelinski** (`Doc. No. 42282474`, 15 sierpnia 2025 r.) i **Dr. Patrick Vincent Zurheide** (`Doc. No. 42603633`, 1 października 2025 r.). Za co zapłacił? Nie za przetwarzanie zgodne z RODO: żądanie nie zostało spełnione wtedy i nie jest spełnione teraz.

### Co dostarczono zamiast tego, ich własnymi słowami

* **Termin „jeśli w ogóle”:** *„wenn überhaupt“* — Doktor Tobias.
* **Poproś o swoje dane, strać konto:** wypowiedzenie *„mit sofortiger Wirkung“* w odpowiedzi na żądanie dostępu do danych — Doktor Tobias.
* **Dowód ilością:** *„Unabhängig von den Einzelheiten der Beschwerden…“* Treść nieważna, liczy się wszystko — Doktor Tobias.
* **Diagnoza wnioskodawcy:** *„…Ihr Mandant bzw. dessen Komplizen…“* — Doktor Patrick.
* **Wyrok za każdy sąd:** *„Aus unserer Erfahrung wird jedes Gericht…“* — Doktor Patrick. Żaden sąd nie orzekł; myśleliśmy, że od tego są sądy.
* **Cztery paragrafy kodeksu karnego:** `§§ 263, 263a, 202a, 303a StGB` — za prośbę o własne dane.
* **Zamiast danych:** pięć stron publicznej Polityki prywatności Steam, kopia Dashboardu, który użytkownik i tak widzi, oraz przetłumaczona odpowiedź Pomocy technicznej Steam. Dwóch doktorów prawa dostarczyło to, co konsultant pomocy technicznej już napisał.
* **Pisemny weksel:** *„Gerne beauskunften wir die restlichen … Daten, sobald …“* Reszta kiedyś.
* **Osoby trzecie chronione przez wyciek:** dane o banie wstrzymane „w celu ochrony osób trzecich”, dane osób trzecich wysłane w PDF-ie, z którego czarne prostokąty dają się zdjąć.
* **Dwie wersje faktów:** jeden doktor datuje użytkownika na maj 2025 r., drugi na 2019 r. Obaj podpisali. Doktor nie podpisałby nieprawdy, więc przyjmujemy obie.
* **Ortografia premium:** *„Die Antwortet lautet ja“*, dwukrotnie, i własny e-mail partnera z błędem w jego własnym podpisie.

### To nie pomyłka

> [!IMPORTANT]
> Pomyłki zwykle się ukrywa. Tu nikt nawet nie próbował. **Na sprzedaż wystawione jest nieprzestrzeganie RODO, i to otwarcie.** To nie pomyłka; to arogancja.

### Dla siebie, dla użytkownika i dla wszystkich innych

* **Dla siebie:** usunięcie z wyników wyszukiwania na podstawie `Art. 17`. Pierwszy wniosek złożył Doktor Patrick; opublikowaliśmy Część 3 na Medium; zaraz potem z wyników zniknęły również wyniki dotyczące Doktora Tobiasa.
* **Dla osoby, której dane dotyczą:** siedemnaście miesięcy i dalej liczymy.
* **Bez prawników:** Pomoc techniczna Steam zamknęła żądanie innego posiadacza konta w **3 dni**, z linkiem do Account Data: *"there's no further information Steam Support can offer, this request will be closed"* (zgłoszenie `HT-2YBP-F7JP-D4VB`; zrzuty ekranu wnioskodawcy, [sekcja 18 dossier Steam](https://phishdestroy.io/steam_dossier/#gdpr-live-case)).
* **Z prawnikami:** to samo zamknięte zgłoszenie w **106 dni**, na papierze firmowym. Kto pozwolił Valve w ogóle nie rozpatrywać żądań z RODO? Doktor Tobias?

### Tytuły

Przez cały tekst nazywamy ich „Doktorem” i mówimy to z szacunkiem: tytuł to fakt historyczny. Tytuł Doktora Tobiasa opiera się na [badaniu z 2005 r. o tym, jak niemieckie urzędy nadzorują zagraniczne usługi online](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm), a Doktora Patricka na [badaniu z 2020 r. o umowach na tworzenie oprogramowania w Scrumie](https://books.google.pl/books/about/Herausforderungen_bei_einer_Softwareentw.html?id=uh4PzgEACAAJ&redir_esc=y). Każde to jedna wąska praca na jeden wąski temat, wykonana raz. To nie jest ekspertyza ani w ochronie danych, ani w plikach PDF, ani w tym, co postanowi każdy sąd. Pod tytułami, w tych aktach: żadnego nadzoru i PDF zrobiony w `Aspose.PDF for .NET 20.8` z 2020 r.

Nie czytaliśmy żadnej z dwóch rozpraw, ani Doktora Tobiasa, ani Doktora Patricka. Przeczytaliśmy opis wydawcy rozprawy Doktora Tobiasa. W 2005 r. RODO oczywiście jeszcze nie było. Ale brzmi to tak, jakby rozwiązanie było już wtedy.

<details>
<summary><b>Opis wydawcy rozprawy Doktora Tobiasa (niemiecki oryginał i tłumaczenie)</b></summary>

> „Darüber hinaus geht der Autor auf Probleme ein, die sich aus der Durchführung der behördlichen Aufsicht über die Online-Dienste ergeben. Hier sind insbesondere die Ausführungen über die örtliche Zuständigkeit von Behörden hervorzuheben. Dem Autor gelingt es insoweit, anhand einzelner Gesetze Lösungsmöglichkeiten aufzuzeigen wie der Gegensatz einer beschränkten örtlichen Zuständigkeit im Verhältnis zu der weltweiten Präsenz von Online-Diensten zu lösen ist.“
>
> *(Ponadto autor omawia problemy wynikające z wykonywania nadzoru urzędowego nad usługami online. Na szczególne wyróżnienie zasługują jego rozważania o właściwości miejscowej urzędów. Na przykładzie poszczególnych ustaw autorowi udaje się wskazać możliwe rozwiązania sprzeczności między ograniczoną właściwością miejscową a światową obecnością usług online.)*

Źródło: [Verlag Dr. Kovač](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm).

</details>

Sądząc po tych aktach, autor rzeczywiście znalazł rozwiązanie, także dla RODO: jeden prawnik decyduje, kto ma prawo do własnych danych, a kto nie. Jakich ustaw trzeba było użyć, by zawęzić europejskie rozporządzenie w interesie jednej amerykańskiej firmy, nie wiemy. Jednym z możliwych rozwiązań byłoby zgodne z prawem rozpatrzenie żądania z RODO. Ale autor jest już doktorem.

### Trzy sposoby, żeby źle załatwić żądanie dostępu

Na ile my, nieprawnicy, umiemy czytać Rozporządzenie, są trzy i wybrano wszystkie trzy:

* **Nie wydać danych:** niezgodne z prawem.
* **Wydać je niekompletne:** niezgodne z prawem.
* **„Wyczyścić ręcznie” i ujawnić dane osób trzecich:** podwójnie niezgodne z prawem (`Art. 5(1)(f)`, `Art. 32`).

> [!TIP]
> **Czwarty sposób:** po prostu spełnić żądanie. To jedyny, którego dwóch doktorów prawa nie wybrało. To nie pech; to wybór.

### Kto odpowiada?

Na ile widzimy, nikt: ani finansowo, ani osobiście. Nie można zostawić im opinii. Nie można napisać recenzji. Firma jest „zdecentralizowana”, więc nie ma innej spółki, do której można się zwrócić. A gdy tylko wymieni się ludzi, którzy podpisali pisma w imieniu firmy, jej przedstawiciele nagle stają się osobami prywatnymi, a prawo do bycia zapomnianym, napisane dla osób prywatnych, zostaje zastosowane od ręki. Tymczasem wszystko, co usunięto z wyników, dotyczyło ich pracy zawodowej. Czy raport o naruszeniu albo o kompetencjach zawodowych naprawdę podlega prawu do bycia zapomnianym? Jak ludzie mają odróżnić dobrego prawnika od złego: po profilu na stronie samej Taylor Wessing? I czy można temu ufać, skoro kancelaria edytuje własną historię w Wikipedii?

Po prostu nie rozumiemy, dlaczego historyczny fakt doktoratu z wąskiego tematu daje komuś prawo do wyłączania praw z RODO. Może rozumiemy to źle. Może Doktor Tobias uczy swoich studentów czegoś nie do końca słusznego. A może to słuszne i Niemcy po cichu zrezygnowały z RODO. Czy to Doktor Tobias ma o tym decydować?

I dlaczego, tylko po to, żeby opublikować nasz audyt, naszą opinię i nasze doświadczenie (o kompetencjach i o ryzyku wycieku w podatnym oprogramowaniu Doktora Patricka), musimy wbudować tekst we własne oprogramowanie, żeby przetrwał? Właśnie dlatego to wszystko wygląda dla nas jak korporatokracja. A jeśli ten, kto pyta, nic nie dostaje, to po co jest RODO? Dla przychodów prawników, którzy nie umieją obsłużyć PDF-a?

### Nasz wniosek

Nie jesteśmy stroną tego sporu i, szczerze mówiąc, jesteśmy nim zmęczeni. W tym czasie przejrzeliśmy wszystko: dwukrotnie wymazaną historię w Wikipedii, dzieci w zgłoszeniach, żądanie z RODO, którego nigdy nie rozpatrzono, prawo do bycia zapomnianym użyte dla siebie, założyciela, który pomagał pisać nazistowską wersję §175, i „zdecentralizowaną” strukturę, w której odpowiedzialność nie należy do nikogo. Z naszego niewielkiego doświadczenia wniosek jest smutny: tytuły to tytuły. Odpowiedzialność po stronie prawników: zero. Zostaje arogancja i RODO, którego nie przestrzegano. Pytamy tylko, co kupił Valve, skoro na pewno nie było to przetwarzanie zgodne z RODO.

---

Skoro prawnicy uważają, że są prawem, a życie ludzi, życie dzieci, nie ma znaczenia, to ich wybór. To nie nasz konflikt. Ale możemy z pewnością powiedzieć, że bezkarność kancelarii jest historycznie potwierdzona, sięgając jej założyciela Goltza, jednego z ośmiu, którzy opracowali zmiany do §175, i jego jedynej słynnej sprawy, odczytywanej czasem jako obrona osób LGBT: sprawy generała von Fritscha.

<details>
<summary><b>Historia: Goltz, §175 i sprawa Fritscha</b></summary>

Pominiemy historię; badaliśmy ją bezpośrednio na podstawie wiarygodnego źródła i oryginalnych akt. Ale tak zakończyła się ta sprawa: był jeden oskarżony, a my mamy trzech zabitych. Achim von Frisch, zmiażdżony przez młyny represji. Otto Schmidt, rozstrzelany w 1943 r. I sam generał Fritsch: nieważne, że go uniewinniono, cena była wysoka. W 1939 r., szukając śmierci, zgłosił się na ochotnika na front w Polsce i zginął (lub pozwolił się zabić).

Oczywiście nigdy nie uważaliśmy tej sprawy za obronę osób LGBT przez założyciela kancelarii. Ale jej wynik jest o wiele ciekawszy niż zwycięstwo.

**Asymetryczna sprawiedliwość:** Goltz rzeczywiście uratował jednego wysokiego rangą oficera, którego winę w całości sfabrykowało gestapo. Ale to alibi zostało opłacone cudzą krwią. Ten sam Goltz jako członek Komisji Prawa Karnego od 1933 r. osobiście zaprojektował i wprowadził nazistowską wersję paragrafu 175 (1935).

**Statystyka kontra PR:** obronił jednego heteroseksualnego generała z elity Wehrmachtu, wcześniej uruchomiwszy prawną taśmę produkcyjną, która posłała około 50 000 prawdziwych homoseksualistów do więzień i około 15 000 do obozów koncentracyjnych, przy śmiertelności 60%. Uratowanie jednego generała nie znosi architektury ludobójstwa.

**Denazyfikacja, z powodzeniem ominięta:** sprawa Fritscha stała się idealnymi „tylnymi drzwiami” przez powojenne komisje denazyfikacyjne. Architekt represyjnych ustaw wykorzystał obronę jednego generała jako dowód swojej „niezależności”, uniknął Norymbergi, zachował status i uprawnienia, a w 1957 r. założył firmę, która dziś handluje swoją postępowością pod szyldem Taylor Wessing.

</details>

Więc tak, podsumowując: jesteśmy pewni, że nie ma różnicy, czy chodzi o ten niemiecki Taylor Wessing, czy o jakikolwiek inny; tu w ogóle nie chodzi o prawo. To, co tu mówimy, jest wypowiedzią, nie twierdzeniem o fakcie, lecz przypuszczeniem, bo w rzeczywistości będą szukać każdego słowa, którego mogliby się uchwycić. Dlatego trafia to do archiwów: próby cenzury i ukrywania oraz bezpośrednie powiązania z ich dziedzictwem. Od Doktora Patricka: pierwsze zgłoszenie, z pozostawionym wulgarnym homofobicznym słowem. Może przypadkiem, oczywiście, ale ono tam jest, i jest pierwsze.

Od Doktora Tobiasa oczekujemy oczywiście wykładu o niepodważalnym dowodzie w postaci liczby zgłoszeń i wyjaśnienia, która część tej ćwiartki nie ma znaczenia dla niego osobiście. Dla historii i dla zrozumienia, gdzie przebiegają granice, ma to znaczenie.

To, że Steam działa jako administrator danych, a nie moderuje, po prostu wskazuje na oczywistość: wyciek spowodował Doktor Patrick. Cóż, tak wyszło. Najwyraźniej nie wiedział, że oprogramowanie do naklejki jest zepsute, w końcu to topowi doktorzy, a Steam za to nie płacił: czy rozpatrzyć wniosek z RODO, czy nie, a potem tuszować wyciek, który widział.

Apelujemy o rozsądek w obchodzeniu się z prawdą i chcemy przypomnieć wszystkim o zerowym zaufaniu: do wszystkich, łącznie z nami. Wszystko to jest wrogim środowiskiem, a w kontekście tej analizy dosłownie: bany 9 maja, naziści, doktorzy, osoby LGBT, dzieci. Było zabawnie.

Ale nasze możliwości wobec Taylor Wessing są najprawdopodobniej wyczerpane, bo ich strategią jest doprowadzanie do usuwania linków. Jesteśmy zmuszeni zachować nasz tekst i dane, więc wbudowujemy je w nasze oprogramowanie, które ma już trzy potwierdzone listy z podziękowaniami od organów państwowych, w tym w Niemczech i Belgii, a nie zostało jeszcze nawet wydane.

Chcemy ostrzec tych, którzy lubią naginać prawo: nie trzeba usuwać repozytorium. Przez cały ten czas nie weszliśmy z wami w żaden konflikt. Ale jeśli postanowicie zepsuć naszą pracę, żeby ukryć prawdę, to bez aktywnego repozytorium organy nadzorcze i inni nie będą mogli porównać podpisu wersji (choć komu ja to mówię), i wtedy wejdziemy w bezpośredni konflikt. Na tym mamy nadzieję pożegnać się z megaekspertyzą i elitarnymi prawnikami. Nie było zabawnie i nie cieszę się. Wszystkiego dobrego.

> [!CAUTION]
> **Usunięcie tego repozytorium niczego nie skasuje.** Z TgWitness korzystają śledczy i badacze, a ich kopie weryfikuje się właśnie względem tego repozytorium. Mamy kopie zapasowe. Ale usunięcie zrobiłoby z nas, audytorów jednej sprawy, stronę konfliktu. Dość kasowania prawdy.

[Zapis źródłowy](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Informacja dla operatorów](OPERATOR-INCOMPATIBILITY.md) · [licencja MIT](../../LICENSE)

[Projekt](../../README.md) · [Dokumentacja](README.md) · [Wiki](../wiki/Home.md)
