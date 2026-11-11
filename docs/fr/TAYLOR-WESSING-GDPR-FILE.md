[TgWitness](../../README.md) / [Documentation](README.md) · [Avis à l’opérateur](OPERATOR-INCOMPATIBILITY.md)

![Le dossier RGPD de 106 jours](../assets/presentation/chapter-case.svg)

# Valve, Taylor Wessing et 106 jours d’attente au titre du RGPD : analyse du dossier et de ses 70 717 mots

[Enregistrement source](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Avis à l’opérateur](OPERATOR-INCOMPATIBILITY.md) · [English](../TAYLOR-WESSING-GDPR-FILE.md)

Il nous reste des questions qui n’auront jamais de réponse, parce que nous ne sommes pas partie au litige. Aucune personne ordinaire ne peut tenir en attendant cent jours à chaque fois et en affrontant des avocats d’élite, financés par des entreprises au travers de « bourses de freelances » comme celle-ci. Nous ne saurons jamais comment s’appelait réellement la prestation commandée par Valve. Vu de l’extérieur, cela ressemble à un traitement RGPD pas tout à fait licite, et à une communication de données dans laquelle les signalants n’ont pas été masqués mais divulgués, alors qu’il manque au moins 5 000 à 10 000 pages des données elles-mêmes : ce qui a été exporté n’est pas le journal de l’utilisateur, mais un journal tronqué fait pour des sous-traitants. Il est inutile de le contester. Une immense couche d’informations manque objectivement, de même que rien ne confirme ce qu’a dit l’un ou l’autre des deux avocats.

Combien Valve paie-t-il pour une prestation faite de manœuvres dilatoires, de caviardages appliqués à la main et de la signature d’un Docteur sous un signalement homophobe et un PDF cassé ? Ce n’est pas notre affaire, mais le problème ici n’est clairement pas le droit ; c’est le statut et l’impunité. Le titre de « Docteur » fait automatiquement d’une personne celle qui décide de ce qui vaut preuve irréfutable, et d’une autre celle qui est censée comprendre les chiffres et les PDF (alors qu’en réalité non).

---

## 1. Les dates, la parole du Docteur et un rapport sans aucun paiement

L’en-tête du document indique `Date of Report: 09-29-2025`, et les fichiers eux-mêmes ont été remis le 1er ou le 2 octobre. Mais nous ne croyons pas ces dates. Nous croyons la déclaration directe du **Dr Patrick Vincent Zurheide** :

> „Bei der Zusammenstellung der personenbezogenen Daten Ihres Mandanten musste leider die volle Monatsfrist
> ausgeschöpft werden, da sich bei erneuter Prüfung der Daten gezeigt hat, dass auch nach dem 3. Mai 2025 neue
> Zahlungen durch einen Dritten über das Nutzerkonto Ihres Mandanten erfolgt sind und insofern manuell die Daten
> bereinigt werden mussten.“
>
> *(La compilation des données personnelles de votre client a malheureusement nécessité tout le délai d’un mois, car un nouvel examen a montré que de nouveaux paiements avaient aussi été effectués par un tiers via le compte après le 3 mai 2025, raison pour laquelle les données ont dû être nettoyées manuellement.)*

C’est précisément cette phrase qui nous fait cesser de croire les chiffres, les mots du docteur au premier paragraphe et sa signature. Bien sûr, un docteur ne mentirait pas ; il a quelque chose à perdre, n’est-ce pas ? Simplement, une fois le fichier exporté et les formes vectorielles retirées, pas un seul paiement n’est apparu dans le rapport. Nous ne contestons ni le travail du Dr Patrick ni son retard. Nous croyons et acceptons simplement « la vérité du Docteur », et nous consignons ce que l’on voit dans le fichier lui-même.

---

## 2. 36 secondes et l’étiquette vulnérable « Anlage 1 / Taylor Wessing »

Nous ne sommes experts en rien, ce qui explique apparemment pourquoi notre signalement de vulnérabilité a été ignoré à la fois par la plateforme de freelances elle-même et par le docteur. La logique est assez claire : ils sont le droit, quelles vulnérabilités pourraient-ils bien avoir ?

Mais laissons de côté les paroles du Docteur et regardons la technique. Nous avons monté un environnement Windows équivalent, pris le fichier nettoyé et essayé de placer les formes. Placer à la main des centaines de formes noires en **36 secondes**, exactement la durée de la session enregistrée, est à notre avis impossible ; selon toute apparence, les cadres noirs se trouvaient déjà sur le document. Nous penchons pour l’idée qu’en ces 36 secondes un seul objet a été ajouté, en haut à droite de la page 1 : l’étiquette `"Anlage 1 / Taylor Wessing"`. Et c’est le logiciel qui l’a placée qui est vulnérable :

* **Objet, d’après ses marqueurs :** de `(929, 294)` à `(1139, 372)`, soit `210 × 78 px`, centré à peu près en `(1034, 333)`.
* **Cadre visible :** de `(936, 300)` à `(1133, 367)`, environ `197 × 67 px`, proportions d’environ `3 : 1` ; le bord supérieur de la feuille est à `y ≈ 275`.
* **Échelle :** mesurée sur la règle gauche du document, `1 cm ≈ 82 px` (la règle est presque certainement en centimètres ; en pouces, la feuille serait plus large que `15″`).

Le style et l’aspect du badge correspondent au fichier renvoyé. Mais sans accès à l’environnement de création d’origine, ou sans connaître le format initial (s’il y a eu une conversion), l’expérience ne peut pas être propre ; nous ne pouvons donc pas l’affirmer avec une certitude de 100 %.

---

## 3. Page 444 : l’heure cachée et l’arithmétique des signalements

Les signalements commencent à la page 444, y compris ce signalement homophobe. Un point important :

* Sur les signalements qu’ils ont choisi de montrer (ceux qui arrangent les avocats), le champ **`Time of Report`** a été délibérément masqué en plus de tout le reste. Il n’y a pas d’heure exacte, et c’est la seule chose de tout le fichier qui ait été masquée de manière techniquement correcte.
* Dans l’article principal, nous avons comparé mathématiquement les signalements montrés avec les autres, par contenu, style d’écriture et pseudonymes. Presque partout, la formule standard de génération de noms de Reddit est grossièrement réutilisée, et il y a un pic net exactement dans la plage qui était nécessaire. Nous ne disons pas que les signalements ont été falsifiés, mais nous disons que les comptes ne sont probablement pas réels, et que la plupart d’entre eux ressemblent mathématiquement à un botnet.

---

## 4. Une question au Dr Patrick Zurheide sur les entrées `2025-02-03 16:29:23` et `2025-04-02 15:55:19`

Docteur Patrick, vous avez écrit que vous aviez lu la blague homophobe et décidé d’en faire une vous-même. Soit, très drôle. Les autres signalements, comme l’a dit votre collègue, n’ont pas d’importance sur le fond (*„Unabhängig von den Einzelheiten der Beschwerden zeigt schon die bloße Anzahl…“*). Soit, nous les passons. Nous espérons que le **Docteur Tobias** expliquera à ses étudiants, lors d’un cours, pourquoi un quart pris au hasard des 1 938 signalements (485), remplis de souhaits de mort et de déclarations nazies, n’a pas d’importance, et pour qui exactement il n’en a pas. S’il le fait, nous reconnaîtrons immédiatement notre erreur, nous présenterons nos excuses et supprimerons les mentions.

Appelons les choses par leur nom : vous avez sciemment livré les données des haineux, les russes, l’allemand, tous, à la personne même qu’ils haïssaient, et ce entre deux pays en guerre l’un contre l’autre. Il s’est avéré que vous lui avez livré des enfants russes : il est ravi, et Tobias les a directement désignés comme le problème. Mais en réalité, c’est votre fuite ; simplement, les enfants ne sont pas les vôtres.

Notre question porte toutefois sur un autre utilisateur, qu’on ne pouvait pas manquer :

* **`2025-02-03 16:29:23`** : un lien et une personne du même pays, avec des choses très graves écrites là, qui sautent aux yeux immédiatement ;
* **`2025-04-02 15:55:19`** : une référence directe, un nom précis et ce qu’il écrit.

Nous avons vérifié : c’est exactement ce que cela paraît. Vous avez ouvertement mis des données étatiques et des informations personnelles complètes entre les mains d’une personne que vous considérez vous-mêmes comme un criminel. Cela n’aurait pas dû être fait, ne serait-ce qu’en raison du contexte. Que se passe-t-il s’il écrit là ? De votre part, ce n’est pas seulement bas ; c’est un mépris pur et simple de la vie et de la santé des personnes. Pendant notre enquête, nous avons arrêté cette personne et mis tout le monde en sécurité. C’est, dans l’ensemble, notre seul vrai grief ; tout le reste n’est que faits et démonstration de la façon dont travaillent les avocats d’élite. Nous appelons le Docteur Patrick à en assumer la responsabilité qui convient, à moins, bien sûr, que le titre devant son nom ne l’autorise à agir ainsi (nous ne sommes pas juristes et ne connaissons pas le droit).

---

## 5. Au public, à l’assureur, aux régulateurs et aux entreprises américaines

* **Au public et aux clients de Taylor Wessing :** à en juger par la négligence, Taylor Wessing a un assureur généreux qui trouve tout cela normal. Vérifiez vos fichiers et informez le régulateur. Inutile de le dire aux avocats eux-mêmes : ils ont choisi de le cacher depuis plus d’un an, depuis que Valve s’est adressé à eux pour la première fois.
* **Aux régulateurs, sur la vulnérabilité de chaque fichier :** examinez l’activité du Dr Patrick et demandez chaque PDF passé par lui avec le badge `"Anlage 1 / Taylor Wessing"` (ou un badge similaire) placé en haut de la première page. La probabilité que ce ne soit pas un cas isolé, et que chaque document de sa part portant cet autocollant soit vulnérable, est extrêmement élevée.
* **À la compagnie d’assurance :** veuillez auditer votre client et le logiciel qu’il utilise pour travailler avec les PDF et placer l’étiquette `"Anlage 1 / Taylor Wessing"` en haut de la page 1. C’est très probablement exactement là que se situe le problème, et ce n’est pas un cas isolé. Il est inutile de demander un audit de tout Taylor Wessing : à part le nom, ils ne semblent rien partager en matière d’environnements de travail ou de règles de revue de sécurité, qui devraient exister d’office (apparemment, une clé de signature physique et le titre devant un nom couvrent tout cela).
* **Aux entreprises américaines, et à quiconque à la Commission européenne lira ceci par hasard :** essayez simplement de respecter la loi. Engager des docteurs renommés d’une « société de freelances » renommée paraît dangereux et parfaitement méprisable envers vos clients. Si chez Valve les chèques sont simplement signés et que personne ne vérifie ce que les avocats ont fait pendant 106 jours, alors peut-être que payer pour du temps étiré plutôt que pour des résultats est exactement la raison pour laquelle le logiciel est obsolète et que personne ne comprend comment fonctionne un PDF. Et s’il n’y a pas d’autres fuites là-bas, alors le Docteur Patrick a simplement réussi à épuiser tout le monde par l’attente ou les menaces. Au fond, ce qui est vendu, c’est un service de non-conformité au RGPD : une exécution de mauvaise qualité et des menaces (« vous ne gagnerez pas une seule affaire »), combinées à un nettoyage de haute qualité des résultats Google effectué en leur propre nom. Nous ne rédigeons pas de textes juridiques et n’accusons personne. Nous écrivons simplement ce que nous avons vu, et ce qu’ils s’efforcent tant d’effacer.

Puisque les avocats pensent qu’ils sont le droit, et que la vie des gens, la vie des enfants, n’a pas d’importance, c’est leur choix. Ce n’est pas notre conflit. Mais nous pouvons dire avec assurance que l’impunité du cabinet est historiquement confirmée, depuis son fondateur Goltz, l’un des huit qui ont rédigé les modifications du §175, et depuis sa seule affaire célèbre, parfois lue comme une défense des personnes LGBT : l’affaire du général von Fritsch. Nous passerons sur l’histoire ; nous l’avons étudiée directement à partir d’une source fiable et du dossier original. Mais voici comment l’affaire s’est terminée : il y avait un accusé, et nous avons trois morts. Achim von Frisch, broyé par les meules de la répression. Otto Schmidt, fusillé en 1943. Et le général Fritsch lui-même : peu importe qu’il ait été acquitté, le prix fut élevé. En 1939, cherchant la mort, il s’est porté volontaire pour le front en Pologne et a été tué (ou s’est laissé tuer).

Bien sûr, nous n’avons jamais compté cette affaire comme une défense des personnes LGBT par le fondateur du cabinet. Mais l’issue est bien plus intéressante qu’une victoire.

**Justice asymétrique :** Goltz a bien sauvé un officier de haut rang, dont la culpabilité avait été entièrement fabriquée par la Gestapo. Mais cet alibi a été payé du sang des autres. Le même Goltz, en tant que membre de la Commission de droit pénal à partir de 1933, a personnellement conçu et introduit la version nazie du paragraphe 175 (1935).

**Statistiques contre relations publiques :** il a défendu un général hétérosexuel de l’élite de la Wehrmacht après avoir d’abord mis en marche une chaîne juridique qui a envoyé environ 50 000 homosexuels réels en prison et environ 15 000 en camps de concentration, avec un taux de mortalité de 60 %. Sauver un général n’annule pas l’architecture du génocide.

**Dénazification, contournée avec succès :** l’affaire Fritsch est devenue la « porte dérobée » parfaite à travers les commissions de dénazification d’après-guerre. L’architecte des lois répressives a utilisé sa défense d’un général comme preuve de son « indépendance », a échappé à Nuremberg, a conservé son statut et sa licence, et a fondé en 1957 la structure qui aujourd’hui fait commerce de son progressisme sous l’enseigne Taylor Wessing.

Alors oui, au bout du compte : nous sommes sûrs que peu importe qu’il s’agisse de ce Taylor Wessing allemand ou d’un autre ; il ne s’agit pas du tout du droit. Ce que nous disons ici est une déclaration, non pas l’affirmation d’un fait mais une supposition, parce qu’en réalité ils chercheront n’importe quel mot auquel s’accrocher. C’est pourquoi cela part aux archives : les tentatives de censure et de dissimulation, et les liens directs avec leur héritage. Du Docteur Patrick : le tout premier signalement, avec le mot homophobe grossier laissé tel quel. Peut-être par accident, bien sûr, mais il est là, et c’est le premier.

Du Docteur Tobias, nous attendons naturellement un cours sur la preuve irréfutable sous forme de nombre de signalements, et une explication de la partie de ce quart qui n’a pas d’importance pour lui personnellement. Pour l’histoire, et pour comprendre où se situent les limites, cela compte.

Que Steam agisse comme responsable du traitement plutôt que de modérer montre simplement l’évidence : c’est le Docteur Patrick qui les a divulgués. Eh bien, c’est ainsi que cela s’est passé. Apparemment, il ne savait pas que le logiciel de l’autocollant était cassé, s’agissant de docteurs de premier plan, et Steam n’a pas payé pour cela : traiter ou non la demande RGPD, puis couvrir la fuite qu’il avait vue.

Nous appelons à la raison dans le rapport à la vérité, et nous voulons rappeler à chacun la confiance zéro : envers tout le monde, nous compris. Tout cela est un environnement hostile, et dans le contexte de cette analyse, littéralement : des bannissements le 9 mai, des nazis, des docteurs, des personnes LGBT, des enfants. C’était amusant.

Mais nos options concernant Taylor Wessing sont très probablement épuisées, puisque leur stratégie consiste à faire supprimer les liens. Nous sommes contraints de préserver notre texte et nos données, et nous les intégrons donc à notre logiciel, qui compte déjà trois lettres de remerciement confirmées d’organismes publics, notamment en Allemagne et en Belgique, et qui n’est même pas encore sorti.

Nous voulons prévenir ceux qui aiment tordre la loi : inutile de faire tomber le dépôt. Pendant tout ce temps, nous ne sommes entrés dans aucun conflit avec vous. Mais si vous décidez de casser notre travail pour cacher la vérité, alors sans dépôt actif, les régulateurs et d’autres ne pourront pas comparer la signature d’une version (mais à qui je le dis), et nous entrerons alors en conflit direct. Sur ce, nous espérons prendre congé de la méga-expertise et des avocats d’élite. Ce n’était pas amusant, et je n’en suis pas content. Bonne continuation.

[Enregistrement source](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Avis à l’opérateur](OPERATOR-INCOMPATIBILITY.md) · [licence MIT](../../LICENSE)

[Projet](../../README.md) · [Documentation](README.md) · [Wiki](../wiki/Home.md)
