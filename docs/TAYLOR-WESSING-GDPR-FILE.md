[TgWitness](../README.md) / [Documentation](README.md) · [Operator notice](OPERATOR-INCOMPATIBILITY.md)

![The 106-day GDPR file](assets/presentation/chapter-case.svg)

# Valve, Taylor Wessing and 106 days of waiting under the GDPR: the file and its 70,717 words

[Source record](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Operator notice](OPERATOR-INCOMPATIBILITY.md) · [Deutsch](de/TAYLOR-WESSING-GDPR-FILE.md)

> [!NOTE]
> We are not a party to this dispute and we are not lawyers. This page records what is visible in the file
> itself and what we observed. Statements about intent are our assumptions, marked as such. **Zero Trust**
> applies to everyone, including us.

Some questions will stay unanswered for good, because we are not a party to the dispute. Waiting 100 days at a
time and taking on elite lawyers, financed by corporations through "freelance exchanges" like this one, is more
than an ordinary person can carry. We will never learn what the service Valve ordered was actually called. From
the outside it looks like processing under the GDPR that is not entirely lawful: a disclosure in which the
reporters were not redacted but exposed, while the data itself falls short by at least **5,000–10,000 pages**.
What was exported was not the user's log but a trimmed log made for outsourced moderators. There is no point in
contesting it: a huge layer of information is objectively missing, and so is any confirmation of what either
lawyer said.

How much does Valve pay for a service of running out the clock, redacting by hand and a Doctor's signature under
a homophobic report and a broken PDF? This is not our case, but the problem here is clearly not the law; it is
status and impunity. The prefix "Doctor" automatically makes one person the one who decides what counts as
irrefutable proof, and another the one who supposedly understands numbers and PDFs (but in fact does not).

---

## 1. Dates, the Doctor's words and no payments in the report

The document header reads `Date of Report: 09-29-2025`; the files themselves were handed over on 1 or 2 October.
We do not rely on those dates. We rely on a direct statement by **Dr. Patrick Vincent Zurheide**:

> „Bei der Zusammenstellung der personenbezogenen Daten Ihres Mandanten musste leider die volle Monatsfrist
> ausgeschöpft werden, da sich bei erneuter Prüfung der Daten gezeigt hat, dass auch nach dem 3. Mai 2025 neue
> Zahlungen durch einen Dritten über das Nutzerkonto Ihres Mandanten erfolgt sind und insofern manuell die Daten
> bereinigt werden mussten."
>
> *Compiling your client's personal data unfortunately required the full one-month period, because a renewed
> review showed that new payments had been made by a third party through your client's user account after
> 3 May 2025 as well, so the data had to be cleaned manually.*

That sentence is why we stop trusting the figures, the Doctor's words in the first paragraph and his signature.
Of course a Doctor would not lie; he has something at stake. Or does he? In fact, after exporting the file and
removing the vector boxes, **no payments were found in the report**. We do not contest Dr. Patrick's work or his
delay. We simply accept "the Doctor's truth" and record what can be seen in the file itself.

---

## 2. 36 seconds and the "Anlage 1 / Taylor Wessing" sticker

We are not experts in anything, which is presumably why our vulnerability notice was ignored by the freelance
platform and by the Doctor alike (the logic is understandable: they are the law, so how could they have a
vulnerability?).

Leave the Doctor's words aside and look at the technology. We set up a matching Windows environment, took the
cleaned file and tried to place the boxes ourselves. Placing hundreds of black boxes by hand in **36 seconds**,
the length of the recorded session, we consider impossible. The document had evidently already carried its black
boxes. We lean towards the view that those 36 seconds added exactly one object, at the top right of page 1, the
`"Anlage 1 / Taylor Wessing"` label, and that the software which placed it is the vulnerable part:

| Measurement | Value |
| --- | --- |
| Object, by its markers | `(929, 294)` to `(1139, 372)`: `210 × 78 px`, centre about `(1034, 333)` |
| Visible frame | `(936, 300)` to `(1133, 367)`: about `197 × 67 px`, ratio about `3 : 1`; top edge of the sheet at `y ≈ 275` |
| Scale | the document's left ruler gives `1 cm ≈ 82 px` (almost certainly centimetres; in inches the sheet would be wider than `15″`) |

The styling and appearance of the badge match the returned file. Without access to the original authoring
environment, or knowing the starting format if a conversion took place, the experiment cannot be clean, so we
cannot claim this with 100% certainty.

---

## 3. Page 444: hidden times and the arithmetic of the reports

The reports begin on page 444, including the homophobic report.

- On the reports they chose to show visually (the ones convenient for the lawyers), the **`Time of Report`**
  field is deliberately and additionally hidden. No exact time is given, and this is the only thing in the whole
  file that is technically hidden correctly.
- In the main article we compared the shown reports with the others by content, writing style and nicknames.
  Almost all of them use Reddit's standard username formula, and there is a sharp spike in the relevant period.
  We do not say the reports were fabricated. We do say the accounts are probably not real, and most of them are
  mathematically similar to a botnet.

---

## 4. A question to Dr. Patrick Zurheide

Dr. Patrick, you wrote that you read the homophobic joke and decided to joke back. Fine, funny. The other
reports, as your colleague put it, do not matter in substance (*„Unabhängig von den Einzelheiten der Beschwerden
zeigt schon die bloße Anzahl…"*). Fine, we skip them. We hope **Dr. Tobias** will explain to his students in a
lecture why a random quarter of the 1,938 reports (485 of them), full of death wishes and Nazi statements, does
not matter, and to whom exactly it does not matter. If he does, we will immediately admit we were wrong,
apologise and remove every mention.

Let us call things by their names: you handed over a broken GDPR export that exposed the data of the haters, the
Russian ones, the German one, all of them, to the very person they were hating, in a situation that involves two
countries at war with each other. It turned out that you exposed Russian children to him, and he was pleased,
while Tobias explicitly cited them as the problem. In reality it is your leak; the children just are not yours.

Our question, however, concerns another user who could not be overlooked: the entry of **`2025-04-02 15:55:19`**
and a second entry by the same user. It contains a direct statement and details that need no explanation. We
checked: it is exactly what it appears to be. You handed state data and full personal details to the person you
yourselves regard as a criminal. That should not have happened, if only because of the context. What happens if
he writes to that person? On your side this is not merely low; it is a direct disregard for people's life and
health. While we investigated, we stopped this user and made sure everyone involved was safe.

This is, on the whole, our only real complaint; everything else is simply facts and a demonstration of how elite
lawyers work. We call on Dr. Patrick to bear the appropriate responsibility, unless, of course, the prefix in
front of his name entitles him to act this way (we are not lawyers and do not know the laws).

---

## 5. Messages to the public, the insurer, regulators and US companies

- **To the public and to Taylor Wessing's clients.** Judging by the carelessness, Taylor Wessing has a generous
  insurer that finds this normal. Check your files and inform the regulator. There is no need to tell the lawyers
  themselves; they have chosen to keep this hidden for more than a year since Valve first came to them.
- **To regulators, on the vulnerability in every file.** Review Dr. Patrick's work and request every PDF that
  passed through him with the `"Anlage 1 / Taylor Wessing"` badge (or a similar one) placed at the top of the first
  page. The likelihood that this is not a one-off case, and that every document carrying this sticker from him is
  vulnerable, is critically high.
- **To the insurance company.** Please audit your client and the software used to work with PDFs and to place the
  `"Anlage 1 / Taylor Wessing"` badge at the top of page 1. That is most likely where the problem lies, and it is
  not a one-off case. There is no point in calling for an audit of all of Taylor Wessing: apart from the name, they
  seem to share nothing in terms of working environments or security review rules, which should exist as a
  matter of course (apparently a physical signing key and the prefix in front of a name cover all of that).
- **To US companies, and to anyone at the European Commission who happens to read this.** Try simply complying
  with the law. Hiring renowned doctors from a renowned "freelance company" looks dangerous and utterly
  disrespectful towards your customers. If Valve simply signs the cheques and nobody checks what the lawyers did
  for 106 days, then perhaps payment for running out the clock, rather than for results, is the reason behind
  outdated software and a lack of understanding of how PDFs work. And if there were no other leaks, then
  Dr. Patrick simply managed to wear everyone down with waiting or threats. In effect, what is being sold is a
  service of not complying with the GDPR: poor execution and threats ("you will not win a single case"), combined
  with a thorough clean-up of Google results under their own names. We do not draft legal texts and we accuse no
  one; we simply write what we saw, and what they are trying so hard to delete.

---

## 6. The founder, the Fritsch affair and the price of an alibi

The lawyers think they are the law and that people's lives, children's included, do not matter. That is their
choice, and it is not our conflict. We can, however, say with confidence that the firm's impunity has a history
reaching back to its founder, Rüdiger Graf von der Goltz, **one of the eight members** of the Criminal Law
Commission who drafted the amendments to Paragraph 175.

His one famous case, sometimes read as a defence of LGBT people, is the case of General von Fritsch. We studied
it from a reliable original source and will not retell the whole story; its ending is this. There was one
accused, and there were three dead:

- **Achim von Frisch**, crushed by the machinery of repression;
- **Otto Schmidt**, shot in 1943;
- **General von Fritsch** himself. It hardly matters that he was acquitted; the price was high. In 1939, seeking
  death, he volunteered for the front in Poland and was killed, or let himself be killed.

We never counted this case as the firm's founder defending LGBT people, but its outcome is far more interesting
than a victory.

- **Asymmetric justice.** Goltz did save one high-ranking officer, whose guilt had been entirely fabricated by
  the Gestapo. But the price of that alibi was paid in other people's blood. The same Goltz, as a member of the
  Criminal Law Commission from 1933, personally designed and introduced the Nazi revision of Paragraph 175
  (1935).
- **Statistics against PR.** He defended one heterosexual general of the Wehrmacht elite after first setting in
  motion a legal conveyor belt that sent about **50,000** real homosexual men to prison and about **15,000** to
  concentration camps, where mortality was around **60%**. Saving one general does not undo the architecture of
  persecution.
- **A successful bypass of denazification.** The Fritsch case became the perfect back door through the post-war
  denazification panels. The architect of repressive laws used his defence of one general as proof of his
  "independence", escaped Nuremberg, kept his status and licence, and in 1957 founded the office that today sells
  its progressiveness under the Taylor Wessing name.

---

## 7. Why this goes to the archives

It does not matter whether this is the German Taylor Wessing or any other: this is not about the law, and
gender does not change it either. This is a statement of assumptions, not an assertion, because in reality they
will look for a word to cling to. That is why it goes to the archives: attempts at censorship and concealment,
and the direct links to their heritage. From Dr. Patrick there is the first report, with the crude homophobic
word left in place. Perhaps by accident, of course, but it is the first one. From Dr. Tobias we of course expect a
lecture on irrefutable proof by number of reports, and an explanation of which part of that quarter does not
matter to him personally. For history, and for understanding where the limits lie, this matters.

Steam, the data controller, did not moderate; it simply points to the obvious. Dr. Patrick exposed the data. It
happened: he apparently did not know that the software behind the sticker was broken. These are top doctors,
after all, and whether Steam paid for the GDPR request to be handled properly, and then for the leak he had seen
to be hidden, only they can say. We call for honesty about the truth, and we remind everyone of zero trust
towards everyone, including us: this is a hostile environment. In the context of this review that is meant
literally: bans on 9 May, Nazis, doctors, LGBT people, children. It was "fun".

Our options regarding Taylor Wessing are most likely exhausted, since their strategy is to remove links. We are
therefore preserving our text and data and building them into our software, which already has three confirmed
letters of thanks from public authorities, including in Germany and Belgium, and it has not even been released
yet. A warning to those who like to bend the law: there is no need to take down the repository. We have not
entered into any conflict with you in all this time. But without an active repository, regulators and others
cannot compare the signature of a version. If you decide to break our work in order to hide the truth, we will
enter into direct conflict.

On that note we take our leave of mega-expertise and elite lawyers. It was not fun. We are not glad. All the
best.

[Source record](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Operator notice](OPERATOR-INCOMPATIBILITY.md) · [MIT License](../LICENSE)

[Project](../README.md) · [Documentation](README.md) · [Wiki](wiki/Home.md)
