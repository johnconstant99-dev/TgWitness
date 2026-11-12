[TgWitness](../README.md) / [Documentation](README.md) · [Operator notice](OPERATOR-INCOMPATIBILITY.md)

![The 106-day GDPR file](assets/presentation/chapter-gdpr-file.svg)

# Valve, Taylor Wessing and 106 days of waiting under the GDPR: a breakdown of the file and its 70,717 words

[Source record](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Operator notice](OPERATOR-INCOMPATIBILITY.md)

**English** · [Русский](ru/TAYLOR-WESSING-GDPR-FILE.md) · [Українська](uk/TAYLOR-WESSING-GDPR-FILE.md) · [Español](es/TAYLOR-WESSING-GDPR-FILE.md) · [Português (Brasil)](pt/TAYLOR-WESSING-GDPR-FILE.md) · [Türkçe](tr/TAYLOR-WESSING-GDPR-FILE.md) · [العربية](ar/TAYLOR-WESSING-GDPR-FILE.md) · [فارسی](fa/TAYLOR-WESSING-GDPR-FILE.md) · [اردو](ur/TAYLOR-WESSING-GDPR-FILE.md) · [हिन्दी](hi/TAYLOR-WESSING-GDPR-FILE.md) · [Bahasa Indonesia](id/TAYLOR-WESSING-GDPR-FILE.md) · [Tiếng Việt](vi/TAYLOR-WESSING-GDPR-FILE.md) · [简体中文](zh/TAYLOR-WESSING-GDPR-FILE.md) · [繁體中文](zh-Hant/TAYLOR-WESSING-GDPR-FILE.md) · [Français](fr/TAYLOR-WESSING-GDPR-FILE.md) · [Deutsch](de/TAYLOR-WESSING-GDPR-FILE.md) · [Italiano](it/TAYLOR-WESSING-GDPR-FILE.md) · [Polski](pl/TAYLOR-WESSING-GDPR-FILE.md) · [O‘zbekcha](uz/TAYLOR-WESSING-GDPR-FILE.md) · [한국어](ko/TAYLOR-WESSING-GDPR-FILE.md) · [日本語](ja/TAYLOR-WESSING-GDPR-FILE.md) · [Bahasa Melayu](ms/TAYLOR-WESSING-GDPR-FILE.md) · [ไทย](th/TAYLOR-WESSING-GDPR-FILE.md) · [עברית](he/TAYLOR-WESSING-GDPR-FILE.md) · [বাংলা](bn/TAYLOR-WESSING-GDPR-FILE.md) · [አማርኛ](am/TAYLOR-WESSING-GDPR-FILE.md)

We are left with questions that will never be answered, because we are not a party to the dispute. No ordinary
person can hold out waiting a hundred days at a time and taking on elite lawyers, bankrolled by corporations through
"freelance exchanges" like this one. We will never learn what the service Valve ordered was actually called. From
the outside it looks like GDPR processing that was not entirely lawful, and a data disclosure in which the reporters
were not blacked out but leaked, while at least 5,000–10,000 pages of the data itself are missing: what was exported
was not the user log but a trimmed log made for outsourcers. There is no point in contesting it. An enormous layer
of information is objectively missing, just as there is nothing to confirm what either lawyer said.

What does Valve pay for a service made of stalling, hand-applied blackouts and a Doctor's signature under a
homophobic report and a broken PDF? This is not our case, but the problem here is clearly not the law; it is status
and impunity. The title "Doctor" automatically makes one person the one who decides what counts as irrefutable
proof, and another the one who supposedly understands numbers and PDFs (although in reality he does not).

---

## 1. The dates, the Doctor's word and a report with no payments in it

The document header reads `Date of Report: 09-29-2025`, and the files themselves were handed over on 1 or 2 October.
But we do not believe these dates. We believe the direct statement of **Dr. Patrick Vincent Zurheide**:

> „Bei der Zusammenstellung der personenbezogenen Daten Ihres Mandanten musste leider die volle Monatsfrist
> ausgeschöpft werden, da sich bei erneuter Prüfung der Daten gezeigt hat, dass auch nach dem 3. Mai 2025 neue
> Zahlungen durch einen Dritten über das Nutzerkonto Ihres Mandanten erfolgt sind und insofern manuell die Daten
> bereinigt werden mussten.“
>
> *(Compiling your client's personal data unfortunately took the full one-month period, because a renewed review
> showed that new payments had been made by a third party through the account after 3 May 2025 as well, which is
> why the data had to be cleaned manually.)*

It is precisely this sentence that makes us stop believing the figures, the doctor's words in the first paragraph and
his signature. Of course, a doctor would not lie; he has something at stake, doesn't he? It is just that once the
file was exported and the vector shapes were removed, not a single payment turned up in the report. We do not dispute
Dr. Patrick's work or his delay. We simply believe and accept "the Doctor's truth", and record what can be seen in the
file itself.

---

## 2. 36 seconds and the vulnerable "Anlage 1 / Taylor Wessing" label

We are not experts in anything, which is apparently why our vulnerability notice was ignored both by the freelance
platform itself and by the doctor. The logic is clear enough: they are the law, so what vulnerabilities could they
possibly have?

But set the Doctor's words aside and look at the technology. We set up a matching Windows environment, took the
cleaned file and tried to place the shapes. Placing hundreds of black shapes by hand in **36 seconds**, exactly as
long as the recorded session lasted, is in our view impossible; by all appearances, the black boxes were already on
the document. We lean towards the view that in those 36 seconds exactly one object was added, at the top right of
page 1: the label `"Anlage 1 / Taylor Wessing"`. And it is the software that placed it that is vulnerable:

* **Object, by its markers:** from `(929, 294)` to `(1139, 372)`, i.e. `210 × 78 px`, centred at roughly `(1034, 333)`.
* **Visible frame:** from `(936, 300)` to `(1133, 367)`, about `197 × 67 px`, proportions of roughly `3 : 1`; the top edge of the sheet is at `y ≈ 275`.
* **Scale:** measured against the document's left ruler, `1 cm ≈ 82 px` (the ruler is almost certainly in centimetres; in inches the sheet would be wider than `15″`).

The style and look of the badge match the returned file. But without access to the original authoring environment,
or knowledge of the initial format (if there was a conversion), the experiment cannot be clean, so we cannot claim
this with 100% certainty.

---

## 3. Page 444: the hidden time and the arithmetic of the reports

The reports start on page 444, including that homophobic report. One important point:

* On the reports they chose to show (the ones convenient for the lawyers), the **`Time of Report`** field has been
  deliberately hidden on top of everything else. There is no exact time, and this is the only thing in the entire
  file that has been hidden in a technically correct way.
* In the main article we compared the reports shown with the rest mathematically, by content, writing style and
  nicknames. Almost everywhere, Reddit's standard name-generation formula is crudely reused, and there is a sharp
  spike in exactly the range that was needed. We are not saying the reports were falsified, but we are saying that
  the accounts are probably not real, and that most of them are mathematically similar to a botnet.

---

## 4. A question for Dr. Patrick Zurheide about the entries `2025-02-03 16:29:23` and `2025-04-02 15:55:19`

Doctor Patrick, you wrote that you read the homophobic joke and decided to make a joke of your own. Fine, very funny.
The other reports, as your colleague put it, do not matter in substance (*„Unabhängig von den Einzelheiten der
Beschwerden zeigt schon die bloße Anzahl…“*). Fine, we skip them. We hope **Doctor Tobias** will explain to his
students in a lecture why a random quarter of the 1,938 reports (485 of them), full of death wishes and Nazi
statements, does not matter, and to whom exactly it does not matter. If he does, we will immediately admit we were
wrong, apologise and delete the mentions.

Let us call things by their proper names: you knowingly fed the haters' data, the Russian ones, the German one, all
of them, to the very person they were hating, and this between two countries at war with each other. It turned out
that you fed him Russian children: he is delighted, and Tobias pointed to them directly as the problem. But in
reality this is your leak; it is just that the children are not yours.

Our question, however, concerns another user, one who could not have been missed:

* **`2025-02-03 16:29:23`**: a link and a person from the same country, with very serious things written there that
  stand out immediately;
* **`2025-04-02 15:55:19`**: a direct reference, a specific name and what he writes.

We checked: it is exactly what it looks like. You openly placed state data and full personal details in the hands of
a person whom you yourselves consider a criminal. This should not have been done, if only because of the context.
What happens if he writes there? On your part this is not merely low; it is outright disregard for people's life and
health. While we were investigating, we stopped this person and made everyone safe. This is, on the whole, our only
real complaint; everything else is simply facts and a demonstration of how elite lawyers work. We call on Doctor
Patrick to bear the appropriate responsibility for it, unless, of course, the title in front of his name entitles him
to act this way (we are not lawyers and do not know the law).

---

## 5. To the public, the insurer, regulators and US companies

* **To the public and Taylor Wessing's clients:** Judging by the carelessness, Taylor Wessing has a generous insurer
  that considers all this normal. Check your files and inform the regulator. There is no need to tell the lawyers
  themselves: they have chosen to hide this for more than a year, ever since Valve first came to them.
* **To regulators, on the vulnerability of every file:** Review Dr. Patrick's activity and request every PDF that
  passed through him with the `"Anlage 1 / Taylor Wessing"` badge (or a similar one) placed at the top of the first
  page. The probability that this is not an isolated case, and that every document from him bearing this sticker is
  vulnerable, is critically high.
* **To the insurance company:** Please audit your client and the software he uses to work with PDFs and to place the
  `"Anlage 1 / Taylor Wessing"` label at the top of page 1. That is most likely exactly where the problem lies, and
  it is not an isolated case. There is no point in calling for an audit of all of Taylor Wessing: apart from the
  name, they seem to share nothing in terms of working environments or security review rules, which ought to exist
  as a matter of course (apparently a physical signing key and the title in front of a name cover all of that).
* **To US companies, and to anyone at the European Commission who happens to read this:** Try simply obeying the law.
  Hiring renowned doctors from a renowned "freelance company" looks dangerous and utterly vile towards your
  customers. If at Valve cheques simply get signed and nobody checks what the lawyers were doing for 106 days, then
  perhaps paying for dragged-out time rather than for results is exactly why the software is outdated and nobody
  understands how a PDF works. And if there are no other leaks there, then Doctor Patrick simply managed to wear
  everyone down with waiting or threats. In essence, what is on sale is a GDPR non-compliance service: poor-quality
  execution and threats ("you will not win a single case"), combined with a high-quality clean-up of Google results
  carried out in their own name. We do not draft legal texts and we accuse no one. We simply write what we saw, and
  what they are trying so hard to delete.

---

## 6. What Valve bought was not GDPR processing

We are not a party to the dispute and we do not defend the account or the ban. One question is left. Valve hired top lawyers: two renowned doctors from a renowned "freelance company", **Dr. Tobias Schelinski** (`Doc. No. 42282474`, 15 August 2025) and **Dr. Patrick Vincent Zurheide** (`Doc. No. 42603633`, 1 October 2025). What did it pay for? Not GDPR processing: the request was not fulfilled then and is not fulfilled now.

### What was delivered instead, in their own words

* **A deadline "if at all":** *„wenn überhaupt“* — Doctor Tobias.
* **Ask for your data, lose your account:** terminated *„mit sofortiger Wirkung“*, in reply to a data access request — Doctor Tobias.
* **Proof by quantity:** *„Unabhängig von den Einzelheiten der Beschwerden…“* Content irrelevant, count everything — Doctor Tobias.
* **A diagnosis of the requester:** *„…Ihr Mandant bzw. dessen Komplizen…“* — Doctor Patrick.
* **A verdict for every court:** *„Aus unserer Erfahrung wird jedes Gericht…“* — Doctor Patrick. No court has ruled; we thought that is what courts are for.
* **Four sections of the Criminal Code:** `§§ 263, 263a, 202a, 303a StGB`, for asking for one's own data.
* **Instead of the data:** five pages of Steam's public Privacy Policy, a copy of the Dashboard the user already sees, and a translated Steam Support reply. Two doctors of law delivered what a support agent had already written.
* **A written IOU:** *„Gerne beauskunften wir die restlichen … Daten, sobald …“* The rest, some day.
* **Third parties protected by leaking them:** the ban data withheld "to protect third parties", third parties' data shipped in a PDF whose black boxes come off.
* **Two versions of the facts:** one doctor dates the user from May 2025, the other from 2019. Both signed. A doctor would not sign something untrue, so we accept both.
* **Premium spelling:** *„Die Antwortet lautet ja“*, twice, and the partner's own e-mail misspelled in his own signature.

### Not a mistake

> [!IMPORTANT]
> Mistakes are usually hidden. Here nobody even tried. **What is on sale is GDPR non-compliance, and it is sold openly.** That is not a mistake; that is arrogance.

### For themselves, for the user, and for everyone else

* **For themselves:** `Art. 17` delisting. Doctor Patrick filed first; we published Part 3 on Medium; right after it, the results about Doctor Tobias were delisted too.
* **For the data subject:** seventeen months and counting.
* **Without lawyers:** Steam Support closed another account holder's request in **3 days**, with a link to Account Data: *"there's no further information Steam Support can offer, this request will be closed"* (ticket `HT-2YBP-F7JP-D4VB`; the requester's screenshots, [Section 18 of the Steam dossier](https://phishdestroy.io/steam_dossier/#gdpr-live-case)).
* **With lawyers:** the same closed ticket in **106 days**, on letterhead. Who allowed Valve not to process GDPR requests at all? Doctor Tobias?

### Titles

We call them "Doctor" throughout, and we mean it respectfully: the title is a historical fact. Doctor Tobias's rests on [a 2005 study of how German authorities supervise foreign online services](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm); Doctor Patrick's on [a 2020 study of software development contracts in Scrum](https://books.google.pl/books/about/Herausforderungen_bei_einer_Softwareentw.html?id=uh4PzgEACAAJ&redir_esc=y). Each is one narrow piece of research, on one narrow topic, done once. It is not expertise in data protection, in PDF files, or in what every court will decide. Under the titles, in this file: no supervision, and a PDF made with `Aspose.PDF for .NET 20.8`, from 2020.

We have not read either dissertation, Doctor Tobias's or Doctor Patrick's. We have read the publisher's description of Doctor Tobias's. In 2005 there was no GDPR, of course. But it sounds as if the solution was already there.

<details>
<summary><b>The publisher's description of Doctor Tobias's thesis (German original and translation)</b></summary>

> „Darüber hinaus geht der Autor auf Probleme ein, die sich aus der Durchführung der behördlichen Aufsicht über die Online-Dienste ergeben. Hier sind insbesondere die Ausführungen über die örtliche Zuständigkeit von Behörden hervorzuheben. Dem Autor gelingt es insoweit, anhand einzelner Gesetze Lösungsmöglichkeiten aufzuzeigen wie der Gegensatz einer beschränkten örtlichen Zuständigkeit im Verhältnis zu der weltweiten Präsenz von Online-Diensten zu lösen ist.“
>
> *(The author also addresses problems arising from carrying out official supervision of online services. His remarks on the local jurisdiction of authorities deserve particular mention. Using individual laws, the author succeeds in showing possible solutions to the contrast between limited local jurisdiction and the worldwide presence of online services.)*

Source: [Verlag Dr. Kovač](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm).

</details>

Judging by this file, the author did find a solution, for the GDPR too: one lawyer decides who is entitled to their own data and who is not. Which laws had to be used to narrow a European regulation in the interest of a single American company, we do not know. One possible solution would have been to process the GDPR request lawfully. But the author is already a doctor.

### Three ways to get an access request wrong

As far as we, not lawyers, can read the Regulation, there are three, and all three were taken:

* **Not handing the data over:** unlawful.
* **Handing it over incomplete:** unlawful.
* **"Cleaning it manually" and leaking third parties' data:** unlawful twice over (`Art. 5(1)(f)`, `Art. 32`).

> [!TIP]
> **The fourth way:** simply fulfilling the request. It is the only one two doctors of law did not take. That is not bad luck; that is a choice.

### Who is accountable?

As far as we can see, nobody, not financially and not personally. You cannot leave them a review. You cannot write an opinion. The company is "decentralised", so there is no other company to address. And the moment you name the people who signed the letters on the company's behalf, the company's representatives suddenly become private individuals, with a right to be forgotten written for private individuals, applied at once. Yet everything that was delisted was about their professional work. Does a report on a violation, or on professional competence, really fall under the right to be forgotten? How are people supposed to tell a good lawyer from a bad one: from the profile on Taylor Wessing's own website? And can that be trusted, when the firm edits its own Wikipedia history?

We simply do not understand why the historical fact of a doctorate on a narrow topic gives anyone the right to switch off GDPR rights. Perhaps we understand it wrongly. Perhaps Doctor Tobias teaches his students something not quite right. Or perhaps it is right, and Germany has quietly given up on the GDPR. Or is that for Doctor Tobias to decide?

And why, just to publish our audit, our opinion and our experience (about competence, and about the leak risk in Doctor Patrick's vulnerable software), do we have to build the text into our own software so that it survives? That is exactly why all of this looks to us like corporatocracy. And if the person who asks gets nothing, what is the GDPR for? Revenue for lawyers who cannot use a PDF?

### Our conclusion

We are not a party to this dispute, and frankly we are tired of it. In the time it took, we have looked at everything: the Wikipedia history erased twice, the children in the reports, a GDPR request that was never processed, the right to be forgotten used for themselves, a founder who helped write the Nazi version of §175, and a "decentralised" structure in which responsibility belongs to no one. From our small experience, the conclusion is a sad one: titles are titles. Responsibility on the lawyers' side: zero. What remains is arrogance, and a GDPR that was not complied with. We only ask what Valve bought, since it clearly was not GDPR processing.

---

Since the lawyers think they are the law, and that people's lives, children's lives, do not matter, that is their
choice. It is not our conflict. But we can say with confidence that the firm's impunity is historically confirmed,
going back to its founder Goltz, one of the eight who drafted the amendments to §175, and to his only famous case,
which is sometimes read as a defence of LGBT people: the case of General von Fritsch.

<details>
<summary><b>History: Goltz, §175 and the Fritsch case</b></summary>

We will skip the history; we
studied it straight from a reliable source and the original record. But this is how the case ended: there was one
defendant, and we have three dead. Achim von Frisch, crushed by the millstones of repression. Otto Schmidt, shot in
1943. And General Fritsch himself: it does not matter that he was acquitted, the price was high. In 1939, seeking
death, he volunteered for the front in Poland and was killed (or let himself be killed).

Of course, we never counted this case as the firm's founder defending LGBT people. But the outcome is far more
interesting than a victory.

**Asymmetric justice:** Goltz did save one high-ranking officer, whose guilt had been entirely fabricated by the
Gestapo. But this alibi was paid for in other people's blood. The same Goltz, as a member of the Criminal Law
Commission from 1933, personally designed and introduced the Nazi version of Paragraph 175 (1935).

**Statistics versus PR:** He defended one heterosexual general of the Wehrmacht elite after first setting in motion
a legal conveyor belt that sent about 50,000 real homosexuals to prison and about 15,000 to concentration camps, with
a mortality rate of 60%. Saving one general does not cancel out the architecture of genocide.

**Denazification, successfully bypassed:** The Fritsch case became the perfect "backdoor" through the post-war
denazification panels. The architect of repressive laws used his defence of one general as proof of his
"independence", escaped Nuremberg, kept his status and his licence, and in 1957 founded the outfit that today trades
on its progressiveness under the Taylor Wessing sign.

</details>

So yes, all in all: we are sure it makes no difference whether it is this German Taylor Wessing or any other; this is
not about the law at all. What we say here is a statement, not an assertion of fact but an assumption, because in
reality they will look for any word to latch on to. That is why this is going to the archives: the attempts at
censorship and concealment, and the direct links to their heritage. From Doctor Patrick: the very first report, with
the crude homophobic word left in. Perhaps by accident, of course, but it is there, and it is the first.

From Doctor Tobias we naturally expect a lecture on irrefutable proof in the form of a report count, and an
explanation of which part of that quarter does not matter to him personally. For history, and for understanding where
the limits lie, this matters.

That Steam acts as the data controller rather than moderating simply points to the obvious: Doctor Patrick leaked
them. Well, so it went. Apparently he did not know that the software for the sticker was broken, these being top
doctors, and Steam did not pay for it: whether to process the GDPR request or not, and then to cover up the leak he
had seen.

We call for sanity in dealing with the truth, and we want to remind everyone of zero trust: towards everyone,
including us. It is all a hostile environment, and in the context of this review quite literally so: bans on 9 May,
Nazis, doctors, LGBT people, children. It was fun.

But our options regarding Taylor Wessing are most likely exhausted, since their strategy is to get links removed. We
are forced to preserve our text and data, so we are building them into our software, which already has three
confirmed letters of thanks from government bodies, including in Germany and Belgium, and has not even been released
yet.

We want to warn those who like to bend the law: there is no need to take the repository down. We have not entered
into any conflict with you in all this time. But if you decide to break our work in order to hide the truth, then
without an active repository regulators and others will not be able to compare the signature of a version (though who
am I telling), and then we will enter into direct conflict. On that note, we hope to take our leave of mega-expertise
and elite lawyers. It was not fun, and I am not glad. All the best.

> [!CAUTION]
> **Taking this repository down will not delete anything.** Investigators and researchers use TgWitness, and this repository is what their copies are verified against. We keep backups. But a takedown would turn us from the auditor of one case into a party to a conflict. Enough deleting the truth.

[Source record](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Operator notice](OPERATOR-INCOMPATIBILITY.md) · [MIT License](../LICENSE)

[Project](../README.md) · [Documentation](README.md) · [Wiki](wiki/Home.md)
