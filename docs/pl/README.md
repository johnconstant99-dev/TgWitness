<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">Inne języki</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Podążaj tropem. Zabezpiecz dowody. Podpisany dziennik powiązany hashami, osobno przechowywany punkt kontrolny i weryfikowalne archiwum dowodów.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=pl"><b>Otwórz demo&nbsp;↗</b></a><br><sub>Prawdziwy interfejs z fikcyjnymi zapisami</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>Pobierz i uruchom&nbsp;↓</b></a><br><sub>Jedno polecenie dla Linuksa, macOS i Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Przeczytaj podręcznik&nbsp;↗</b></a><br><sub>Przewodniki dochodzeniowe krok po kroku</sub></td>
</tr>
</table>

<p align="center"><strong>Samodzielnie hostowane środowisko do dochodzeń w Telegramie.</strong><br>Zapisuj czaty, zachowuj edycje i usunięcia, sprawdzaj, kto jest z kim powiązany,<br>i przekazuj podpisane eksporty, które każdy może zweryfikować.</p>

<p align="center"><strong>ZERO ZAUFANIA.</strong> TgWitness nie staje po żadnej stronie: te same kontrole obowiązują operatora, PhishDestroy i każdego innego.<br>Liczy się tylko to, co potwierdza strona trzecia albo matematyka. <a href="../QUESTIONS-AND-CHECKS.md">Pytania i weryfikacja</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.2 · wersja przedpremierowa"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">Przetestowane środowiska</a> · 25 języków interfejsu · 26 języków przewodników</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=pl">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="Demo TgWitness w działaniu: przechwycone wiadomości, zapisane wersje i treść zachowana po usunięciu. Fikcyjne zapisy demonstracyjne.">
</picture>
</a>

<p align="center"><sub>Poznaj prawdziwy interfejs na fikcyjnych zapisach. Kliknij obszar roboczy, aby go wypróbować.</sub></p>

## Co robi TgWitness

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">Każda edycja i każde usunięcie zachowane</a></b><br><sub>Każda wersja wiadomości jest zapisywana, a jej tekst zostaje także po powiadomieniu o usunięciu.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">Dowód, który każdy może sprawdzić</a></b><br><sub>Podpisane zapisy połączone łańcuchem hashy. Odbiorca weryfikuje archiwum offline jednym poleceniem.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">Pochodzenie, które można wykazać</a></b><br><sub>Wiadomości przychodzą przez uwierzytelnioną sesję MTProto konta i są podpisywane w chwili odbioru; GitHub Actions i Intel TDX dodają atestację.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">Zmierzone na dużą skalę</a></b><br><sub>48 zweryfikowanych archiwów z 3 598 381 zapisami; osiem kont pobrało 768 007 zapisów historii z szybkością 687,5 zapisu/s.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">Stworzone do dochodzeń</a></b><br><sub>Listy obserwacyjne obejmujące tekst, kody QR i OCR, sprawdzanie portfeli, karty podmiotów, „Tablica sprawy” i pakiet dla sądu.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">Pod Twoją kontrolą</a></b><br><sub>Hostowane samodzielnie, bez telemetrii. Sesje są w zaszyfrowanym sejfie; panel nasłuchuje na localhost.</sub></td>
</tr>
</table>

<p align="center"><sub>Opracowywano i testowano przez około sześć miesięcy: najpierw moduł zbierający, podpisany dziennik i moduł weryfikujący, a następnie panel oraz moduły dodatkowe. Niniejsze repozytorium zostało utworzone 29 października 2026 r. w celu publikacji, więc jego wiek nie odpowiada wiekowi projektu.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## Instalacja

Python jest w zestawie. Te same polecenia służą do aktualizacji.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell lub CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Serwer Ubuntu: uruchom jako root. Komputer stacjonarny: uruchom jako zwykły użytkownik. `-ExecutionPolicy Bypass` dotyczy tylko tego jednego procesu PowerShell.</sub>

Podpisane kompilacje pochodzą z publicznego [przepływu pracy Installer](../../.github/workflows/installer.yml), a instalator przed instalacją sprawdza SHA-256 i podpis RSA każdego pakietu.

[Najpierw zweryfikuj skrypt](../INSTALLATION.md#verify-before-running) · [Pierwsza konfiguracja](../SETTINGS.md) · [Wydania](https://github.com/phishdestroy/TgWitness/releases) · [Docker](../DEPLOYMENT.md)

<details>
<summary><strong>Ochrona instalatora i Twoich danych</strong></summary>

`get.destroy.tools` to strona pobierania projektu. Publiczny
[przepływ pracy Installer](../../.github/workflows/installer.yml) buduje ją z
[`deploy/installer/`](../../deploy/installer/README.md) dla konkretnej rewizji `main`,
publikuje po pomyślnych testach instalacji na Linuksie i Windows oraz podpisuje
skrypty instalatora i pakiety aplikacji kluczem wydania z
[`release-signing.pub`](../../deploy/installer/release-signing.pub). Przed instalacją instalator sprawdza
SHA-256 i podpis RSA pakietu oraz pliku blokady zależności.
Aby najpierw sprawdzić sam skrypt, pobierz go wraz z podpisem i wykonaj
[polecenia wstępnej weryfikacji](../INSTALLATION.md#verify-before-running). Nieudana kompilacja
pozostawia poprzednią wersję do pobrania; zainstalowane panele aktualizują się po ponownym uruchomieniu instalatora.
[Wydania](https://github.com/phishdestroy/TgWitness/releases) w serwisie GitHub, kod źródłowy i
[Docker](../DEPLOYMENT.md) to pozostałe sposoby instalacji.

**Twoje sesje i dane.** TgWitness działa na Twoim komputerze lub serwerze, a panel
domyślnie nasłuchuje na localhost. Sesje Telegram, dane logowania do proxy i hashe
tokenów dostępu są przechowywane w zaszyfrowanym sejfie każdego obszaru roboczego, z opcjonalnym
[zewnętrznym kluczem głównym](../SECURITY-MODEL.md#external-master-key). Aplikacja
nie ma telemetrii. Łączy się z Telegramem i z usługami wskazanymi w jej ustawieniach:
publicznymi listami MTProxy, Twoimi proxy, magazynem S3, botem-świadkiem, urzędami
znaczników czasu, dostawcami AI i webhookami. [Mapa systemu](../SYSTEM-MAP.md) wymienia
połączenia nawiązywane przez proces aplikacji.
Do obserwacji używaj [dedykowanego konta Telegram](https://phishdestroy.github.io/TgWitness/pl/docs/dedicated-account/).

Odznaka wersji opisuje to drzewo źródeł. Kompilacje do zainstalowania są wymienione w sekcji
[Wydania](https://github.com/phishdestroy/TgWitness/releases); funkcja scalona z
`main` trafia do nich wraz z następnym wydaniem.

[Konfiguracja i dostęp do panelu](../INSTALLATION.md) ·
[Podpisy i SHA-256](https://get.destroy.tools/#verification) ·
[Aktualizacja](../INSTALLATION.md#update-an-existing-installation) ·
[Bieżące możliwości i kwalifikacja](../STATUS.md) ·
[Wybór metody zbierania](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## Zapis, który może sprawdzić ktoś inny

Sprawdź bez konta i instalacji. Opublikowana próbka zawiera własny weryfikator:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # weryfikator jest dołączony do archiwum
python verify.py tgwitness-demo.zip          # Python 3.11+, potrzebuje tylko `cryptography`
```

Wypisuje podpisane zapisy, hash najnowszego zapisu i odcisk klucza podpisującego, po czym kończy działanie z kodem `0`.
Próbka jest fikcyjna; ten sam weryfikator działa na każdym prawdziwym eksporcie.

Eksport zawiera wiadomości, pliki i weryfikator. Przekaż odbiorcy odcisk
swojego klucza innym kanałem, a będzie mógł sam go sprawdzić:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

Weryfikator sprawdza podpisy, łańcuch dziennika, listę plików i załączniki.
Aby eksport miał wartość dowodową, potrzebny jest odcisk Twojego klucza i znacznik czasu strony trzeciej obejmujący ostatni
zapis, na przykład znacznik czasu RFC 3161 sprawdzony względem certyfikatu głównego urzędu.

**Skąd pochodzą wiadomości.** TgWitness odbiera je z Telegrama przez
zaszyfrowaną sesję MTProto konta, tak jak oficjalne aplikacje, i w chwili nadejścia
podpisuje każdą z nich i zapisuje w dzienniku. [Zbieranie przez GitHub Actions](../SEALED-ACTIONS.md) i
[Phala Intel TDX](../HIGH-ASSURANCE.md) dodatkowo atestują kolektor, który je odebrał.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="Nowe wiadomości, zapisane edycje i zaobserwowane usunięcia tworzą powiązany, podpisany dziennik. Zweryfikuj go kluczem, któremu ufasz niezależnie.">
</picture>

[Weryfikacja archiwum](../wiki/Exports-and-Verification.md) · [Format dowodów](../EVIDENCE.md) · [Niezależny świadek](../WITNESS.md) · [Zewnętrzne znaczniki czasu](../TIMESTAMP.md) · [Kontrole i przetestowana skala](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Od rozmowy do sprawy

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="Trzy animowane procesy: eksport czatu do HTML i JSON, wyszukanie udostępnionego linku we wszystkich zarejestrowanych czatach oraz zachowanie przechwyconych wersji po powiadomieniu o usunięciu.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>Eksport czatu&nbsp;↗</b></a><br><sub>Jeden czat do podpisanych HTML i JSON</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>Dochodzenie&nbsp;↗</b></a><br><sub>Podążaj za tropem przez zarejestrowane czaty</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>Zapisane wersje&nbsp;↗</b></a><br><sub>Edycje i powiadomienia o usunięciu — zachowane</sub></td>
</tr>
</table>

Dwa sposoby użycia: jednorazowo [wyeksportuj swoje konto](../ACCOUNT-EXPORT.md) albo
[prowadź dochodzenie](../INVESTIGATION.md) i stale zapisuj zmiany.
Wybierz kilka czatów, folder Telegram lub całe konto. Każde konto ma
własny obszar roboczy, sesję i klucz podpisujący.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Więcej

<details>
<summary><strong>Zmierzone eksporty · 6 listopada 2026</strong> · 56 329 wiadomości, oba archiwa zweryfikowane</summary>

**56 329 wiadomości wyeksportowanych w dwóch nowych przebiegach.** Oba podpisane archiwa przeszły weryfikację z przypiętymi kluczami kolektora.

[![Zmierzona szybkość zbierania i pełnego eksportu](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/pl/docs/validation/)

| Przebieg | Wiadomości | Czas zbierania | Szybkość zbierania | Pełny eksport | Szybkość od początku do końca |
| --- | ---: | ---: | ---: | ---: | ---: |
| Serwer A | 27 030 | 189,043 s | **142,983 wiad./s** | 211,647 s | 127,713 wiad./s |
| Serwer B | 29 299 | 182,513 s | **160,531 wiad./s** | 206,650 s | 141,781 wiad./s |

Tekst i metadane przez WARP, dwa konta na serwer, bez załączników i ponownie użytych zapisów.
Zmierzono na rewizji [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e).
Każdy opublikowany przebieg podaje rewizję źródeł, obciążenie, czasy i wynik weryfikacji:
[obciążenie, czasy i weryfikacja](../EXPORT-BENCHMARK-2026-11-06.md). Zmiany w `main`
przechodzą przez publiczne [przepływy pracy CI](../../.github/workflows/README.md), w tym testy instalatora
na Linuksie i Windows oraz kompilację samodzielnego weryfikatora.

[**Otwórz demo →**](https://phishdestroy.github.io/TgWitness/demo/?lang=pl) ·
[**Pomiary, daty i metoda →**](https://phishdestroy.github.io/TgWitness/pl/docs/validation/) ·
[Pobierz fikcyjny przykładowy eksport](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[Podpisany audyt w języku angielskim](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>Zacznij prosto. Zobacz każdą trasę.</strong> · pierwsze uruchomienie i mapa systemu</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="Przy pierwszym uruchomieniu do wyboru są „Po prostu pobierz”, „Obserwuj czaty” lub „Dowody w sprawie”, a panel pokazuje tylko pasujące sekcje. Mapa systemu łączy panel, kolektor, Telegram, dziennik, świadka i usługi zewnętrzne wraz z obserwacjami sieci. Wartości fikcyjne.">
</picture>

Przy pierwszym uruchomieniu pada jedno pytanie: **Po prostu pobierz**, **Obserwuj czaty** czy
**Dowody w sprawie**. Odpowiedź ustala cel i poziom interfejsu, więc
panel pokazuje tylko sekcje potrzebne do tego zadania. Połączenie, logowanie do Telegrama i
wybór czatów odbywają się w pięciu etapach. Test połączenia uruchamia się sam, a
opcje trasy otwierają się tylko wtedy, gdy się nie powiedzie. Narzędzia eksperckie są o jeden przełącznik dalej.

**Mapa systemu** pokazuje, jak instalacja dociera do Telegrama i usług
zewnętrznych: dostęp do panelu, trasę i cel w Telegramie dla każdego konta, ścieżkę dziennika i
świadka oraz najnowsze obserwacje sieci. Brakująca obserwacja jest
oznaczona jako brakująca.

[Pierwsza konfiguracja](../SETTINGS.md) · [Mapa systemu](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>Do całej reszty dochodzenia</strong> · karty podmiotów, listy obserwacyjne, portfele, obserwacja aktywności online, dokumenty dla sądu</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Śledź wyświetlane nazwy i nazwy użytkowników według Telegram ID. Rejestruj obsługiwane interakcje z botami z podpisanymi potwierdzeniami. Przeszukuj zarchiwizowane wiadomości i podłączaj klientów MCP tylko do odczytu. Wdrażaj kolektor z zamaskowanym SSH i zapisami dostawcy do przeglądu. Dokumentuj rozmowę krok po kroku z odwołaniami do dziennika. Przekazuj pakiet sprawy BagIt z szablonami sądowymi. Przykładowe procesy.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>Osoby i dossier&nbsp;↗</b></a><br><sub>Wyświetlane nazwy i nazwy użytkowników według Telegram ID</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>Dochodzenie wobec botów&nbsp;↗</b></a><br><sub>Interakcje z botami z podpisanymi potwierdzeniami</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/pl/docs/archive/"><b>Wyszukiwanie w archiwum, AI i MCP&nbsp;↗</b></a><br><sub>Przeszukuj archiwum, podłączaj klientów tylko do odczytu</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>Zapieczętowane wdrożenie w chmurze&nbsp;↗</b></a><br><sub>Kolektor wewnątrz Intel TDX</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="Trzy animowane kroki: karta podmiotu, której późniejsza migawka rejestruje zmianę nazwy; plan rozmowy, którego cele zamykają zapisy dziennika; oraz płatniczy kod QR zdekodowany do portfela z poprawną sumą kontrolną, który wywołuje trafienie na liście obserwacyjnej. Wartości fikcyjne.">
</picture>

**Dokumentuj rozmowę.** Rozpocznij dokumentowanie czatu w panelu bocznym **Dokumentacja**,
a każdy krok zapisze się sam: działania w panelu, odpowiedzi wraz z opóźnieniem przed
nimi, edycje, powiadomienia o usunięciu, notatki i szkice AI. Każdy krok wskazuje swój zapis
w dzienniku i SHA-256. Zatwierdzenie dokumentu podpisuje go i zapisuje hash protokołu
w dzienniku.

| | |
| --- | --- |
| [Karty podmiotów](../INVESTIGATION-MODE.md#subject-cards) | Migawki profilu bota, osoby, kanału lub grupy z etykietami Telegram BOT, VERIFIED, SCAM i FAKE; późniejsza migawka pokazuje, co się zmieniło |
| [Plany rozmowy](../INVESTIGATION-MODE.md#conversation-plans) | Cele dotyczące ścieżki płatności, infrastruktury lub osób, przygotowane wiadomości, czasy odpowiedzi, aktywność według godzin i styl pisania drugiej strony |
| [Tłumaczenie](../INVESTIGATION-MODE.md#machine-translation) | Wyświetlane pod oryginałem z językami, modelem i zapisem w dzienniku |
| [Listy obserwacyjne](../INVESTIGATION-MODE.md#watchlists) | Słowa, wzorce, portfele, @nazwy użytkowników, ID, domeny, telefony i linki, dopasowywane w tekście, edycjach, ukrytych celach linków, przyciskach botów, kodach QR i OCR |
| [Obserwacja aktywności online](../INVESTIGATION-MODE.md#online-watch) | Sprawdzanie co 1–60 minut, do 100 kont na zapytanie, z rozkładem według godzin i dni tygodnia |
| [Kody i portfele](../INVESTIGATION-MODE.md#codes-in-images) | Płatnicze kody QR; adresy EVM sprawdzane według EIP-55, TON w postaci surowej, sumy kontrolne XRP Ledger, linki płatnicze z siecią, kwotą i tokenem |
| [Ślady klienta](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-show) | Ślady kodera w okrągłych wideo i wiadomościach głosowych; porównanie czasu przesłania z czasem wysłania ujawnia wcześniej nagrane dowody „na żywo” |
| [Przykrywka i upoważnienia](../INVESTIGATION-MODE.md#cover-and-authority) | Persony, upoważnienia i rejestr działań pod przykryciem, który oznacza wiadomości spoza upoważnionych czatów lub okresu |
| [Kontrola konta](../INVESTIGATION-MODE.md#account-control) | Edycja profilu i prywatności z zapisami przed/po, kontrolą ekspozycji i przejściem offline zaraz po każdej czynności |
| [Dokumenty dla sądu](../INVESTIGATION-MODE.md#documents-for-court) | Pakiet sprawy BagIt z szablonem certyfikacji Rule 902(13)/(14), wykazem dowodów, załącznikiem do wniosku i napisami WebVTT/SRT do nagrań ekranu |

Treści oznaczone jako 18+, przemoc lub dane osobowe pozostają w kopii dla sądu, zapieczętowane
AES-256-GCM; klucze przekazuje się osobno.

[Ustawienia eksportu](../EXPORT_HASHES.md) obejmują pozyskiwanie przez zwykłe API i Takeout,
pobieranie historii wiadomości przed załącznikami, pobieranie plików lub hashe serwera oraz zgodne
widoki JSON/HTML z Telegram Desktop. [Rozproszony eksport czatów](../DISTRIBUTED-EXPORT.md#history-acquisition)
oferuje opcjonalną ścieżkę Takeout dla historii publicznej, podpisane punkty kontrolne co 100 wiadomości
oraz wznawianie w obrębie zakresu z tym samym kontem; jego
[projekt wydajności](../FAST-ACQUISITION.md) opisuje przetestowane zachowanie pozyskiwania
i planowane pomiary na żywo.

</details>

<details>
<summary><strong>Wszystko inne</strong> · historia, konta, proxy, AI, integracje</summary>

| | |
| --- | --- |
| [Wczytywanie starszych wiadomości](../HISTORY.md) | Pobieraj historię wybranych czatów, wstrzymuj i wznawiaj w dowolnej chwili |
| [Kilka kont](../ACCOUNTS.md#multiple-accounts) | Oddzielne obszary robocze, każdy z własną sesją Telegram, dziennikiem i kluczem podpisującym |
| [Import zbiorczy](../ACCOUNTS.md#bulk-import-and-account-groups) | Wrzuć cały stos plików sesji i posortuj konta w grupy ze wspólnymi ustawieniami |
| [Pula MTProxy](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping, kraje, filtry, własne listy |
| [Istniejące sesje](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key lub linia `key:DC`; opcjonalna niezależna autoryzacja QR z zaimportowanego konta-dawcy |
| [Bezpieczeństwo konta](../ACCOUNTS.md#create-an-independent-authorization) | Alerty o nowych sesjach, kończenie innych sesji, tryb jedynej sesji, który ustawia też hasło weryfikacji dwuetapowej, oraz [sonda świadka](../ACCOUNTS.md#witness-probe), która wykrywa, kiedy aktualizacje na żywo przestają docierać do tej sesji |
| [Wznawialny eksport czatu](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | Zatrzymany eksport zachowuje podpisaną częściową kopię: wznów go, zacznij od nowa lub pobierz to, co zapisano |
| [Proxy](../CONNECTION-SECURITY.md#ip-modes) | SOCKS5, HTTP CONNECT lub MTProxy dla każdego obszaru roboczego. **Ukryj adres IP** nigdy nie przełącza się na połączenie bezpośrednie |
| [Wyszukiwanie i AI](../ANALYSIS.md) | Wyszukiwanie lokalne, opcjonalne AI ze źródłami, które możesz sprawdzić |
| [Wyszukiwanie pełnotekstowe](../SEARCH.md) | Formy wyrazów, dokładne frazy, domeny, @nazwy użytkowników i chiński bez spacji, najlepsze dopasowania najpierw (**wersja wstępna**) |
| [MCP](../MCP.md) | Dostęp tylko do odczytu dla klientów MCP, ograniczony do wybranych przez Ciebie czatów |
| [Wiersz poleceń](../CLI.md) | `search`, `context`, `messages`, `stats` i `export` w JSON Lines z `--json` dla skryptów i agentów, lokalnie lub z tokenem o ograniczonym zakresie (**wersja wstępna**) |
| [OCR i transkrypcja](../MEDIA-ANALYSIS.md) | Działa lokalnie, oryginały pozostają nienaruszone |
| [Niezależne przechwytywanie](../OPTIONAL-CAPTURE.md) | Opcjonalne rejestratory przeglądarki/AyuGram w **Więcej narzędzi → Dodatki** (wersja wstępna, domyślnie wyłączone) |
| [Trusted Live](../TRUSTED-LIVE.md) | Sesja oficjalnego Desktop/Web, chronione nagranie wideo i analiza ciągłości względem natywnego eksportu (wersja wstępna; kwalifikacja na żywo jeszcze nieprzeprowadzona) |
| [Zapieczętowany oficjalny Web](../OFFICIAL-WITNESS.md) | Świeża oficjalna przeglądarka w GitHub Actions, ograniczone sterowanie, podpisane wideo i niezależnie oczekiwane źródła/ustawienia |
| [Webhooki](../WEBHOOKS.md) | Podpisane zdarzenia wychodzące z ponawianiem, przykład dla n8n w zestawie |
| [Współdzielony dostęp](../ACCESS.md) | Udostępnij komuś tylko wybrane czaty, z terminem ważności i limitami IP |
| [Brakujące numery wiadomości](../EVIDENCE.md#missing-message-numbers-gap_summary) | Numery nadane przez Telegram, których nigdy nie zaobserwowano, dla każdego kanału i całego konta, w pokryciu, raportach i MCP (**wersja wstępna**) |
| [Migawki stanu czatu](../COLLECTION.md) | Okresowe podpisane migawki tytułu, opisu, przypięć, administratorów i prezentów, ze wskazaniem zmian (**wersja wstępna**) |
| [Mapa systemu](../SYSTEM-MAP.md) | Mapa na żywo dostępu do panelu, tras kont, celów w Telegramie i usług zewnętrznych, z ostatnimi 200 z maksymalnie 2000 obserwacji sieci |

</details>

<details>
<summary><strong>Wybierz, co potwierdza zapis</strong> · lokalnie, audytowana chmura, GitHub Actions lub Intel TDX</summary>

Uruchom lokalnie, dodaj audytowane wdrożenie w chmurze albo zbieraj dane wewnątrz **poufnej maszyny wirtualnej Phala Cloud
z Intel TDX**. Każda opcja zachowuje podpisany dziennik; dodatkowe
kontrole dotyczą środowiska, w którym go zebrano.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="Trzy warianty wdrożenia: lokalna weryfikacja dziennika; audytowana maszyna wirtualna z zapisami dostawcy i dostępu; Phala Intel TDX ze zweryfikowanym raportem atestacyjnym, zmierzonym systemem i aplikacją oraz powiązanym kluczem kolektora.">
</picture>

Weryfikator TDX sprawdza raport atestacyjny względem przypiętego certyfikatu głównego Intel i danych o unieważnieniach,
wiąże go z podpisanym oświadczeniem kolektora i świeżym wyzwaniem oraz porównuje
zmierzony system i aplikację z niezależnie oczekiwanymi danymi wejściowymi. Raport końcowy
podaje każdy wynik osobno, dzięki czemu zmierzone środowisko, tożsamość kolektora, zapisy
zbierania i pokrycie można ocenić łącznie.

**Zbieranie z poświadczeniem pochodzenia GitHub** (wersja wstępna). Zbierz czat na runnerze hostowanym przez GitHub
z przypiętą wersją TgWitness i świeżą sesją Telegram, a następnie pobierz zaszyfrowane
archiwum wraz z atestacją GitHub. Weryfikator sprawdza zatwierdzony przepływ pracy i
wersję kolektora, hash archiwum, dziennik i załączniki. Dostępne też
w sekcji **Eksporty** w panelu.
[Otwórz stronę zbierania](https://phishdestroy.github.io/TgWitness/pl/docs/capture/) · [Instrukcja](../SEALED-ACTIONS.md)

Do obserwacji na żywo, pobrania historii lub jednorazowego eksportu wybierz
[metodę zbierania](../COLLECTION-MODES.md). Prywatne czaty w chmurze są dostępne,
jeśli podłączone konto ma do nich dostęp. Opublikowana aplikacja zawiera też
[integrację z czatami sekretnymi](../PSEUDO-SECRET.md): zainstaluj opcjonalną zależność
protokołu i włącz ją dla konta, aby rejestrować utworzone lub zaakceptowane w nim czaty.
Dostępne ścieżki pozyskiwania opisuje [zakres zbierania](../COLLECTION.md).

[Phala / Intel TDX i audytowane wdrożenia](../HIGH-ASSURANCE.md) ·
[Kwalifikacja Phala na żywo](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[Granice zaufania](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>Sprawdź zbieranie i zachowany zapis</strong> · co weryfikuje odbiorca i Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="Przechwyć rozmowę. Zweryfikuj zapis. Zachowuj wiadomości, edycje i pliki, sprawdzaj podpisy i punkty kontrolne oraz przeglądaj proces zbierania.">
</picture>

TgWitness rejestruje treści dostarczone na podłączone konto Telegram wraz z
identyfikatorami czatu, wiadomości i nadawcy, przechwyconymi wersjami i metadanymi zbierania.
Archiwum łączy te zapisy, zachowane załączniki i dane weryfikacyjne
w jedną całość do przeglądu.

| Kontrola | Co weryfikuje odbiorca |
| --- | --- |
| Podpisany dziennik i manifest | Podpisy zapisów, łańcuch hashy i dostarczone pliki względem oczekiwanego klucza podpisującego. |
| Osobno przechowywany punkt kontrolny | Dziennik względem wcześniej zarejestrowanej długości i hasha najnowszego zapisu. |
| Niezależny świadek | Dziennik względem punktów kontrolnych przechowywanych przez osobnego świadka. |
| Zbieranie przez GitHub Actions | Archiwum względem jego atestacji, zatwierdzonego przepływu pracy hostowanego przez GitHub i wersji kolektora. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
pokazuje rozmowę w Telegramie obok celowo zmienionych plików eksportu z Desktop.
Porównaj wersje, przejrzyj zmiany i prześledź kroki zbierania oraz
weryfikacji podpisanego archiwum TgWitness.

[Kroki weryfikacji](../wiki/Exports-and-Verification.md) ·
[Zbieranie przez GitHub](../SEALED-ACTIONS.md) ·
[Techniczny model zaufania](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>Utrzymaj dochodzenie w ruchu</strong> · powiadomienia, przechowywanie i odzyskiwanie</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="Animowane procesy: Apprise wysyła skonfigurowane alerty; kopie zewnętrzne są szyfrowane przed przesłaniem do magazynu zgodnego z S3.">
</picture>

[Powiadomienia](../OPERATIONS.md#notifications) · [Zaszyfrowana kopia zewnętrzna](../wiki/Off-site-Copy.md) · [Kopie zapasowe i odzyskiwanie](../wiki/Backup-and-Recovery.md) · [Rozwiązywanie problemów](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/pl/docs/start/"><b>Przewodnik konfiguracji&nbsp;↗</b></a><br><sub>Od instalacji do pierwszego czatu</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/pl/docs/dedicated-account/"><b>Przygotuj konto&nbsp;↗</b></a><br><sub>Dedykowane konto Telegram</sub></td>
<td width="33%" align="center"><a href="../DEPLOYMENT.md"><b>Docker i serwery&nbsp;↗</b></a><br><sub>HTTPS, restarty i aktualizacje</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>Poznaj repozytorium</strong> · gdzie są kod, dokumentacja i narzędzia</summary>

| Katalog | Zacznij tutaj |
| --- | --- |
| [docs/](../README.md) | Konfiguracja, procesy dochodzeniowe i dokumentacja techniczna |
| [tgwitness/](../../tgwitness/README.md) | Główna aplikacja, kolektor, dziennik i panel webowy |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | Niezależne rejestratory i ich kod weryfikacyjny |
| [addons/](../../addons/README.md) | Instalacja, konfiguracja i testy opcjonalnego zbierania |
| [deploy/](../../deploy/README.md) | Instalatory, kontenery i usługi działające w tle |
| [examples/](../../examples/README.md) | Konfiguracje eksportu konta i zapieczętowanego zbierania |
| [integrations/](../../integrations/README.md) | Podpisane webhooki i odbiornik n8n |
| [.agents/](../../.agents/README.md) | Instrukcje zadań do odczytu archiwum przez CLI |
| [scripts/](../../scripts/README.md) | Skrypty uruchomieniowe i narzędzia CI |
| [tools/](../../tools/README.md) | Kompilacje, kontrole i pakowanie |
| [website/](../../website/README.md) | Publiczna strona, przetłumaczone przewodniki i interaktywne demo |
| [.github/](../../.github/AUTOMATION.md) | Przepływy pracy, zasady współpracy i wsparcie |

[Pełny przewodnik po projekcie](../PROJECT-GUIDE.md) ·
[Współtworzenie](../../.github/CONTRIBUTING.md) · [Pomoc](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ Informacja dotycząca etyki i ciągłości historycznej</strong></summary>

Stanowisko autorów i informacja dla operatorów po polsku:

[Informacja dla operatorów](OPERATOR-INCOMPATIBILITY.md) · [Licencja MIT](../../LICENSE) · [Oryginalny NOTICE](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>Przeczytaj omówienie projektu w swoim języku</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · **Polski** · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>Dokumentacja techniczna</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Podręcznik dochodzeniowy</b></a> ·
  <a href="https://github.com/phishdestroy"><b>Stworzone przez PhishDestroy</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>Współtwórz</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>Uzyskaj pomoc</b></a> ·
  <a href="../../.github/SECURITY.md"><b>Zgłoś podatność</b></a>
</p>

[Indeks projektu do odczytu maszynowego](../../llms.txt) · [Pełny podręcznik w formie tekstu](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [Zasady repozytorium dla agentów](../../AGENTS.md)
