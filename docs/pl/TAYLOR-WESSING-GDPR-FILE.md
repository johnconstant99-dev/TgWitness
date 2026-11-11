[TgWitness](../../README.md) / [Dokumentacja](README.md) · [Informacja dla operatorów](OPERATOR-INCOMPATIBILITY.md)

![Akta RODO: 106 dni](../assets/presentation/chapter-case.svg)

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

Skoro prawnicy uważają, że są prawem, a życie ludzi, życie dzieci, nie ma znaczenia, to ich wybór. To nie nasz konflikt. Ale możemy z pewnością powiedzieć, że bezkarność kancelarii jest historycznie potwierdzona, sięgając jej założyciela Goltza, jednego z ośmiu, którzy opracowali zmiany do §175, i jego jedynej słynnej sprawy, odczytywanej czasem jako obrona osób LGBT: sprawy generała von Fritscha. Pominiemy historię; badaliśmy ją bezpośrednio na podstawie wiarygodnego źródła i oryginalnych akt. Ale tak zakończyła się ta sprawa: był jeden oskarżony, a my mamy trzech zabitych. Achim von Frisch, zmiażdżony przez młyny represji. Otto Schmidt, rozstrzelany w 1943 r. I sam generał Fritsch: nieważne, że go uniewinniono, cena była wysoka. W 1939 r., szukając śmierci, zgłosił się na ochotnika na front w Polsce i zginął (lub pozwolił się zabić).

Oczywiście nigdy nie uważaliśmy tej sprawy za obronę osób LGBT przez założyciela kancelarii. Ale jej wynik jest o wiele ciekawszy niż zwycięstwo.

**Asymetryczna sprawiedliwość:** Goltz rzeczywiście uratował jednego wysokiego rangą oficera, którego winę w całości sfabrykowało gestapo. Ale to alibi zostało opłacone cudzą krwią. Ten sam Goltz jako członek Komisji Prawa Karnego od 1933 r. osobiście zaprojektował i wprowadził nazistowską wersję paragrafu 175 (1935).

**Statystyka kontra PR:** obronił jednego heteroseksualnego generała z elity Wehrmachtu, wcześniej uruchomiwszy prawną taśmę produkcyjną, która posłała około 50 000 prawdziwych homoseksualistów do więzień i około 15 000 do obozów koncentracyjnych, przy śmiertelności 60%. Uratowanie jednego generała nie znosi architektury ludobójstwa.

**Denazyfikacja, z powodzeniem ominięta:** sprawa Fritscha stała się idealnymi „tylnymi drzwiami” przez powojenne komisje denazyfikacyjne. Architekt represyjnych ustaw wykorzystał obronę jednego generała jako dowód swojej „niezależności”, uniknął Norymbergi, zachował status i uprawnienia, a w 1957 r. założył firmę, która dziś handluje swoją postępowością pod szyldem Taylor Wessing.

Więc tak, podsumowując: jesteśmy pewni, że nie ma różnicy, czy chodzi o ten niemiecki Taylor Wessing, czy o jakikolwiek inny; tu w ogóle nie chodzi o prawo. To, co tu mówimy, jest wypowiedzią, nie twierdzeniem o fakcie, lecz przypuszczeniem, bo w rzeczywistości będą szukać każdego słowa, którego mogliby się uchwycić. Dlatego trafia to do archiwów: próby cenzury i ukrywania oraz bezpośrednie powiązania z ich dziedzictwem. Od Doktora Patricka: pierwsze zgłoszenie, z pozostawionym wulgarnym homofobicznym słowem. Może przypadkiem, oczywiście, ale ono tam jest, i jest pierwsze.

Od Doktora Tobiasa oczekujemy oczywiście wykładu o niepodważalnym dowodzie w postaci liczby zgłoszeń i wyjaśnienia, która część tej ćwiartki nie ma znaczenia dla niego osobiście. Dla historii i dla zrozumienia, gdzie przebiegają granice, ma to znaczenie.

To, że Steam działa jako administrator danych, a nie moderuje, po prostu wskazuje na oczywistość: wyciek spowodował Doktor Patrick. Cóż, tak wyszło. Najwyraźniej nie wiedział, że oprogramowanie do naklejki jest zepsute, w końcu to topowi doktorzy, a Steam za to nie płacił: czy rozpatrzyć wniosek z RODO, czy nie, a potem tuszować wyciek, który widział.

Apelujemy o rozsądek w obchodzeniu się z prawdą i chcemy przypomnieć wszystkim o zerowym zaufaniu: do wszystkich, łącznie z nami. Wszystko to jest wrogim środowiskiem, a w kontekście tej analizy dosłownie: bany 9 maja, naziści, doktorzy, osoby LGBT, dzieci. Było zabawnie.

Ale nasze możliwości wobec Taylor Wessing są najprawdopodobniej wyczerpane, bo ich strategią jest doprowadzanie do usuwania linków. Jesteśmy zmuszeni zachować nasz tekst i dane, więc wbudowujemy je w nasze oprogramowanie, które ma już trzy potwierdzone listy z podziękowaniami od organów państwowych, w tym w Niemczech i Belgii, a nie zostało jeszcze nawet wydane.

Chcemy ostrzec tych, którzy lubią naginać prawo: nie trzeba usuwać repozytorium. Przez cały ten czas nie weszliśmy z wami w żaden konflikt. Ale jeśli postanowicie zepsuć naszą pracę, żeby ukryć prawdę, to bez aktywnego repozytorium organy nadzorcze i inni nie będą mogli porównać podpisu wersji (choć komu ja to mówię), i wtedy wejdziemy w bezpośredni konflikt. Na tym mamy nadzieję pożegnać się z megaekspertyzą i elitarnymi prawnikami. Nie było zabawnie i nie cieszę się. Wszystkiego dobrego.

[Zapis źródłowy](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Informacja dla operatorów](OPERATOR-INCOMPATIBILITY.md) · [licencja MIT](../../LICENSE)

[Projekt](../../README.md) · [Dokumentacja](README.md) · [Wiki](../wiki/Home.md)
