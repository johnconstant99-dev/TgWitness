<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">Autres langues</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Suivez la piste. Préservez les preuves. Un journal signé et chaîné par hachage, un point de contrôle conservé séparément et une archive de preuves vérifiable.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=fr"><b>Explorer la démo&nbsp;↗</b></a><br><sub>La véritable interface avec des enregistrements fictifs</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>Télécharger et démarrer&nbsp;↓</b></a><br><sub>Une seule commande pour Linux, macOS et Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Lire le manuel&nbsp;↗</b></a><br><sub>Guides d'enquête pas à pas</sub></td>
</tr>
</table>

<p align="center"><strong>Environnement auto-hébergé pour les enquêtes sur Telegram.</strong><br>Enregistrez les discussions, conservez les modifications et les suppressions, voyez qui est lié à qui<br>et remettez des exports signés que chacun peut vérifier.</p>

<p align="center"><strong>CONFIANCE ZÉRO.</strong> TgWitness ne prend parti pour personne : les mêmes vérifications s'appliquent à l'opérateur, à PhishDestroy et à tous les autres.<br>Seul compte ce qu'un tiers ou les mathématiques confirment. <a href="../LIMITS-AND-OBJECTIONS.md">Limites et objections</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.2 · préversion"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">Environnements testés</a> · 25 langues d'interface · 26 langues de guides</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=fr">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="La démo de TgWitness en action : messages capturés, versions enregistrées et contenu conservé après suppression. Enregistrements de démonstration fictifs.">
</picture>
</a>

<p align="center"><sub>Explorez la véritable interface avec des enregistrements fictifs. Cliquez sur l'espace de travail pour l'essayer.</sub></p>

## Ce que fait TgWitness

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">Chaque modification et chaque suppression conservées</a></b><br><sub>Chaque version d'un message est enregistrée, et son texte reste après un avis de suppression.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">Une preuve vérifiable par tous</a></b><br><sub>Des enregistrements signés et chaînés par hachage. Le destinataire vérifie l'archive hors ligne en une commande.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">Une origine démontrable</a></b><br><sub>Les messages sont reçus via la session MTProto authentifiée du compte et signés dès leur arrivée ; GitHub Actions et Intel TDX ajoutent une attestation.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">Mesuré à grande échelle</a></b><br><sub>48 archives vérifiées totalisant 3 598 381 enregistrements ; huit comptes ont acquis 768 007 enregistrements d'historique à 687,5 enregistrements/s.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">Conçu pour les enquêtes</a></b><br><sub>Listes de surveillance sur le texte, les codes QR et l'OCR, vérification de portefeuilles, fiches de sujets, Tableau de l'affaire et dossier pour le tribunal.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">Sous votre contrôle</a></b><br><sub>Auto-hébergé, sans télémétrie. Les sessions sont stockées dans un coffre-fort chiffré ; le panneau écoute sur localhost.</sub></td>
</tr>
</table>

<p align="center"><sub>Développement et tests menés pendant environ six mois : d’abord le collecteur, le journal signé et le vérificateur, puis le panneau et les modules complémentaires. Ce dépôt a été créé le 29 octobre 2026 en vue de sa publication ; son âge ne correspond donc pas à celui du projet.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## Installation

Python est inclus. Les mêmes commandes servent à la mise à jour.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell ou CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Serveur Ubuntu : exécutez en tant que root. Poste de travail : exécutez avec votre utilisateur habituel. `-ExecutionPolicy Bypass` ne s'applique qu'à ce processus PowerShell.</sub>

Les builds signés proviennent du [workflow Installer](../../.github/workflows/installer.yml) public, et le programme d'installation vérifie le SHA-256 et la signature RSA de chaque paquet avant l'installation.

[Vérifier d'abord le script](../INSTALLATION.md#verify-before-running) · [Première configuration](../SETTINGS.md) · [Versions](https://github.com/phishdestroy/TgWitness/releases) · [Docker](../DEPLOYMENT.md)

<details>
<summary><strong>Comment le programme d'installation et vos données sont protégés</strong></summary>

`get.destroy.tools` est le site de téléchargement du projet. Le
[workflow Installer](../../.github/workflows/installer.yml) public le construit à partir de
[`deploy/installer/`](../../deploy/installer/README.md) pour la révision exacte de `main`,
le publie une fois les tests d'installation Linux et Windows réussis, et signe les
scripts d'installation et les paquets de l'application avec la clé de publication de
[`release-signing.pub`](../../deploy/installer/release-signing.pub). Le programme d'installation vérifie
le SHA-256 et la signature RSA du paquet et du verrou des dépendances avant l'installation.
Pour vérifier d'abord le script lui-même, téléchargez-le avec sa signature et exécutez les
[commandes de vérification préalable](../INSTALLATION.md#verify-before-running). En cas d'échec d'un build,
le téléchargement précédent reste en place ; les panneaux installés se mettent à jour lorsque vous relancez le programme d'installation.
Les [Versions](https://github.com/phishdestroy/TgWitness/releases) GitHub, les sources et
[Docker](../DEPLOYMENT.md) sont les autres moyens d'installation.

**Vos sessions et vos données.** TgWitness s'exécute sur votre ordinateur ou votre serveur, et le panneau
écoute sur localhost par défaut. Les sessions Telegram, les identifiants de proxy et les hachages
des jetons d'accès sont stockés dans le coffre-fort chiffré de chaque espace de travail, avec une
[clé maîtresse externe](../SECURITY-MODEL.md#external-master-key) en option. L'application
n'a aucune télémétrie. Elle se connecte à Telegram et aux services utilisés par ses paramètres :
listes MTProxy publiques, vos proxys, stockage S3, bot témoin, autorités
d'horodatage, fournisseurs d'IA et webhooks. La [Carte du système](../SYSTEM-MAP.md) répertorie
les connexions établies par le processus de l'application.
Observez avec un [compte Telegram dédié](https://phishdestroy.github.io/TgWitness/fr/docs/dedicated-account/).

Le badge de version décrit cette arborescence source. Les builds installables sont listés dans
[Versions](https://github.com/phishdestroy/TgWitness/releases) ; une fonctionnalité fusionnée dans
`main` arrive dans ces téléchargements avec la version suivante.

[Configuration et accès au panneau](../INSTALLATION.md) ·
[Signatures et SHA-256](https://get.destroy.tools/#verification) ·
[Mise à jour](../INSTALLATION.md#update-an-existing-installation) ·
[Capacités actuelles et qualification](../STATUS.md) ·
[Choisir une méthode de collecte](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## Un enregistrement que quelqu'un d'autre peut vérifier

Vérifiez-le sans compte ni installation. L'échantillon publié contient son propre vérificateur :

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # le vérificateur est fourni dans l'archive
python verify.py tgwitness-demo.zip          # Python 3.11+, seul `cryptography` est requis
```

Il affiche les enregistrements signés, le hachage du dernier enregistrement et l'empreinte du signataire, puis se termine avec le code `0`.
L'échantillon est fictif ; le même vérificateur fonctionne sur n'importe quel export réel.

Un export contient les messages, les fichiers et le vérificateur. Envoyez au destinataire l'empreinte de votre
clé par un autre canal, et il pourra le vérifier lui-même :

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

Le vérificateur contrôle les signatures, la chaîne du journal, la liste des fichiers et les pièces jointes.
Pour qu'un export ait valeur de preuve, il faut l'empreinte de votre clé et un horodatage tiers couvrant le dernier
enregistrement, par exemple un horodatage RFC 3161 vérifié par rapport au certificat racine de l'autorité.

**D'où viennent les messages.** TgWitness les reçoit de Telegram via la
session MTProto chiffrée du compte, comme les applications officielles, et inscrit chacun dans le
journal avec sa signature dès son arrivée. La [collecte via GitHub Actions](../SEALED-ACTIONS.md) et
[Phala Intel TDX](../HIGH-ASSURANCE.md) attestent en outre le collecteur qui les a reçus.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="Les nouveaux messages, les modifications enregistrées et les suppressions observées forment un journal signé et chaîné. Vérifiez-le à l'aide d'une clé à laquelle vous faites confiance de manière indépendante.">
</picture>

[Vérification de l'archive](../wiki/Exports-and-Verification.md) · [Format des preuves](../EVIDENCE.md) · [Témoin indépendant](../WITNESS.md) · [Horodatages externes](../TIMESTAMP.md) · [Contrôles et échelle testée](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## De la conversation au dossier

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="Trois flux animés : exporter une discussion en HTML et JSON, retrouver un lien partagé dans les discussions enregistrées et conserver les versions capturées après un avis de suppression.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>Export de discussion&nbsp;↗</b></a><br><sub>Une discussion en HTML et JSON signés</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>Enquête&nbsp;↗</b></a><br><sub>Suivez une piste à travers les discussions enregistrées</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>Versions enregistrées&nbsp;↗</b></a><br><sub>Modifications et avis de suppression, conservés</sub></td>
</tr>
</table>

Deux façons de l'utiliser : [exporter votre compte](../ACCOUNT-EXPORT.md) une fois, ou
[suivre une enquête](../INVESTIGATION.md) et continuer à enregistrer les changements.
Choisissez quelques discussions, un dossier Telegram ou le compte entier. Chaque compte dispose de
son propre espace de travail, de sa session et de sa clé de signature.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## En savoir plus

<details>
<summary><strong>Exports mesurés · 6 novembre 2026</strong> · 56 329 messages, les deux archives vérifiées</summary>

**56 329 messages exportés en deux nouvelles exécutions.** Les deux archives signées ont passé la vérification avec des clés de collecteur épinglées.

[![Vitesse mesurée de la collecte et de l'export complet](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/fr/docs/validation/)

| Exécution | Messages | Durée de collecte | Vitesse de collecte | Export complet | Vitesse de bout en bout |
| --- | ---: | ---: | ---: | ---: | ---: |
| Serveur A | 27 030 | 189,043 s | **142,983 messages/s** | 211,647 s | 127,713 messages/s |
| Serveur B | 29 299 | 182,513 s | **160,531 messages/s** | 206,650 s | 141,781 messages/s |

Texte et métadonnées via WARP, deux comptes par serveur, sans pièces jointes ni enregistrements réutilisés.
Mesuré sur la révision [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e).
Chaque exécution publiée indique sa révision source, sa charge de travail, ses durées et son résultat de vérification :
[charge, durées et vérification](../EXPORT-BENCHMARK-2026-11-06.md). Les modifications de `main`
déclenchent les [workflows CI](../../.github/workflows/README.md) publics, y compris les tests du programme d'installation sous Linux et Windows
et la compilation du vérificateur autonome.

[**Explorer la démo →**](https://phishdestroy.github.io/TgWitness/demo/?lang=fr) ·
[**Mesures, dates et méthode →**](https://phishdestroy.github.io/TgWitness/fr/docs/validation/) ·
[Télécharger un export d'exemple fictif](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[Audit signé en anglais](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>Démarrez simplement. Voyez chaque route.</strong> · premier démarrage et carte du système</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="Le premier démarrage propose « Simplement télécharger », « Suivre des discussions » ou « Éléments de preuve à l'appui d'une affaire » et n'affiche que les sections correspondantes. La carte du système relie le panneau, le collecteur, Telegram, le journal, le témoin et les services externes, avec les observations réseau. Valeurs fictives.">
</picture>

Le premier démarrage pose une seule question : **Simplement télécharger**, **Suivre des discussions** ou
**Éléments de preuve à l'appui d'une affaire**. La réponse fixe l'objectif et le niveau d'interface, de sorte que le
panneau n'affiche que les sections utiles à cette tâche. La connexion, l'authentification Telegram et
le choix des discussions suivent en cinq étapes. Le test de connexion s'exécute de lui-même, et
les options de route ne s'ouvrent qu'en cas d'échec. Un seul interrupteur suffit pour accéder aux outils experts.

La **Carte du système** montre comment l'installation atteint Telegram et les services
externes : accès au panneau, route et cible Telegram de chaque compte, chemin du journal et du
témoin, et dernières observations réseau. Une observation manquante est
signalée comme manquante.

[Première configuration](../SETTINGS.md) · [Carte du système](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>Conçu pour le reste de l'enquête</strong> · fiches de sujets, listes de surveillance, portefeuilles, suivi en ligne, documents judiciaires</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Suivez les noms et noms d'utilisateur par ID Telegram. Enregistrez les interactions prises en charge avec des bots, avec des reçus signés. Recherchez dans les messages archivés et connectez des clients MCP en lecture seule. Déployez un collecteur avec SSH masqué et des enregistrements du fournisseur pour examen. Documentez une conversation étape par étape avec des références au journal. Remettez un dossier BagIt avec des modèles pour le tribunal. Flux illustratifs.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>Personnes et dossiers&nbsp;↗</b></a><br><sub>Noms et noms d'utilisateur suivis par ID Telegram</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>Enquête sur les bots&nbsp;↗</b></a><br><sub>Interactions avec des bots, avec reçus signés</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/fr/docs/archive/"><b>Recherche dans l'archive, IA et MCP&nbsp;↗</b></a><br><sub>Cherchez dans l'archive, connectez des clients en lecture seule</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>Déploiement cloud scellé&nbsp;↗</b></a><br><sub>Un collecteur dans Intel TDX</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="Trois étapes animées : une fiche de sujet dont un instantané ultérieur enregistre un changement de nom, un plan de conversation dont les objectifs se ferment par des enregistrements du journal, et un code QR de paiement décodé en un portefeuille à somme de contrôle valide qui déclenche une correspondance dans une liste de surveillance. Valeurs fictives.">
</picture>

**Documentez la conversation.** Démarrez un compte rendu pour une discussion dans le volet **Documentation**
et chaque étape est consignée automatiquement : actions du panneau, réponses avec le délai qui les
précède, modifications, avis de suppression, notes et brouillons d'IA. Chaque étape cite son enregistrement
du journal et son SHA-256. La finalisation du document le signe et inscrit le hachage de la déclaration dans
le journal.

| | |
| --- | --- |
| [Fiches de sujets](../INVESTIGATION-MODE.md#subject-cards) | Instantanés du profil d'un bot, d'une personne, d'un canal ou d'un groupe avec les libellés Telegram BOT, VERIFIED, SCAM et FAKE ; un instantané ultérieur liste ce qui a changé |
| [Plans de conversation](../INVESTIGATION-MODE.md#conversation-plans) | Objectifs concernant le circuit de paiement, l'infrastructure ou les personnes, messages préparés, délais de réponse, activité par heure et style d'écriture de l'interlocuteur |
| [Traduction](../INVESTIGATION-MODE.md#machine-translation) | Affichée sous l'original avec les langues, le modèle et l'enregistrement du journal |
| [Listes de surveillance](../INVESTIGATION-MODE.md#watchlists) | Mots, motifs, portefeuilles, @noms d'utilisateur, ID, domaines, téléphones et liens, recherchés dans le texte, les modifications, les cibles de liens masquées, les boutons de bots, les codes QR et l'OCR |
| [Suivi en ligne](../INVESTIGATION-MODE.md#online-watch) | Vérification toutes les 1–60 minutes, jusqu'à 100 comptes par requête, avec une répartition par heure et par jour de la semaine |
| [Codes et portefeuilles](../INVESTIGATION-MODE.md#codes-in-images) | Codes QR de paiement ; adresses EVM vérifiées selon EIP-55, TON sous forme brute, sommes de contrôle XRP Ledger, liens de paiement avec chaîne, montant et jeton |
| [Traces du client](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-can-and-cannot-show) | Traces d'encodeur des vidéos rondes et des messages vocaux ; comparer l'heure de téléversement à l'heure d'envoi révèle une preuve « en direct » préenregistrée |
| [Couverture et autorisation](../INVESTIGATION-MODE.md#cover-and-authority) | Identités d'emprunt, autorisations et registre d'activité sous couverture qui signale les messages hors des discussions ou de la période autorisées |
| [Contrôle du compte](../INVESTIGATION-MODE.md#account-control) | Modification du profil et de la confidentialité avec enregistrements avant/après, contrôle d'exposition et passage hors ligne juste après chaque action |
| [Documents pour le tribunal](../INVESTIGATION-MODE.md#documents-for-court) | Dossier BagIt avec modèle de certification Rule 902(13)/(14), index des pièces, annexe de requête et sous-titres WebVTT/SRT pour les enregistrements d'écran |

Les contenus marqués 18+, violence ou données personnelles restent dans la copie destinée au tribunal, scellés avec
AES-256-GCM ; les clés sont transmises séparément.

Les [paramètres d'export](../EXPORT_HASHES.md) couvrent l'acquisition par l'API standard et par Takeout,
l'historique des messages avant les pièces jointes, le téléchargement des fichiers ou les hachages serveur, ainsi que des
vues JSON/HTML compatibles avec Telegram Desktop. L'[export distribué de discussions](../DISTRIBUTED-EXPORT.md#history-acquisition)
propose une voie Takeout facultative pour l'historique public, des points de contrôle signés tous les 100 messages
et une reprise dans une plage avec le même compte ; sa
[conception des performances](../FAST-ACQUISITION.md) décrit le comportement d'acquisition testé
et les mesures en conditions réelles prévues.

</details>

<details>
<summary><strong>Tout le reste</strong> · historique, comptes, proxys, IA, intégrations</summary>

| | |
| --- | --- |
| [Charger les anciens messages](../HISTORY.md) | Récupérez l'historique des discussions choisies, mettez en pause et reprenez à tout moment |
| [Plusieurs comptes](../ACCOUNTS.md#multiple-accounts) | Espaces de travail séparés, chacun avec sa session Telegram, son journal et sa clé de signature |
| [Import par lots](../ACCOUNTS.md#bulk-import-and-account-groups) | Déposez une pile de fichiers de session, classez les comptes en groupes aux paramètres partagés |
| [Pool MTProxy](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping, pays, filtres, vos propres listes |
| [Sessions existantes](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key ou une ligne `key:DC` ; autorisation QR indépendante facultative depuis un compte donneur importé |
| [Sécurité du compte](../ACCOUNTS.md#create-an-independent-authorization) | Alertes pour les nouvelles sessions, fermeture des autres sessions, mode session unique qui définit aussi un mot de passe de validation en deux étapes, et une [sonde témoin](../ACCOUNTS.md#witness-probe) qui détecte quand les mises à jour en direct n'atteignent plus cette session |
| [Export de discussion reprenable](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | Un export interrompu conserve une copie partielle signée : reprenez-le, recommencez ou téléchargez ce qui a été enregistré |
| [Proxys](../CONNECTION-SECURITY.md#ip-modes) | SOCKS5, HTTP CONNECT ou MTProxy par espace de travail. **Masquer l'adresse IP** ne revient jamais à une connexion directe |
| [Recherche et IA](../ANALYSIS.md) | Recherche locale, IA facultative avec des sources vérifiables |
| [Recherche plein texte](../SEARCH.md) | Formes fléchies, expressions exactes, domaines, @noms d'utilisateur et chinois sans espaces, meilleurs résultats en premier (**version préliminaire**) |
| [MCP](../MCP.md) | Accès en lecture seule pour les clients MCP, limité aux discussions que vous choisissez |
| [Ligne de commande](../CLI.md) | `search`, `context`, `messages`, `stats` et `export` en JSON Lines avec `--json` pour les scripts et les agents, en local ou avec un jeton à portée limitée (**version préliminaire**) |
| [OCR et transcription](../MEDIA-ANALYSIS.md) | S'exécute localement, les originaux restent intacts |
| [Capture indépendante](../OPTIONAL-CAPTURE.md) | Enregistreurs optionnels navigateur/AyuGram dans **Autres outils → Suppléments** (version préliminaire, désactivés par défaut) |
| [Trusted Live](../TRUSTED-LIVE.md) | Session Desktop/Web officielle, vidéo protégée et analyse de continuité avec l'export natif (version préliminaire ; qualification en conditions réelles en attente) |
| [Web officiel scellé](../OFFICIAL-WITNESS.md) | Navigateur officiel neuf sur GitHub Actions, commandes restreintes, vidéo signée et source/paramètres attendus de manière indépendante |
| [Webhooks](../WEBHOOKS.md) | Événements sortants signés avec nouvelles tentatives, exemple n8n inclus |
| [Accès partagé](../ACCESS.md) | Donnez à quelqu'un l'accès à certaines discussions seulement, avec expiration et restrictions d'IP |
| [Numéros de messages manquants](../EVIDENCE.md#missing-message-numbers-gap_summary) | Numéros attribués par Telegram mais jamais observés, par canal et pour tout le compte, dans la couverture, les rapports et MCP (**version préliminaire**) |
| [Instantanés de l'état des discussions](../COLLECTION.md) | Instantanés signés périodiques du titre, de la description, des épinglages, des administrateurs et des cadeaux, avec ce qui a changé (**version préliminaire**) |
| [Carte du système](../SYSTEM-MAP.md) | Carte en direct de l'accès au panneau, des routes des comptes, des cibles Telegram et des services externes, avec les 200 dernières observations réseau sur 2 000 au maximum |

</details>

<details>
<summary><strong>Choisissez ce qui étaye l'enregistrement</strong> · local, cloud audité, GitHub Actions ou Intel TDX</summary>

Exécutez en local, ajoutez un déploiement cloud audité ou collectez dans une **VM confidentielle Phala Cloud
avec Intel TDX**. Chaque option conserve le journal signé ; les contrôles
supplémentaires portent sur l'environnement où il a été collecté.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="Trois choix de déploiement : vérification locale du journal ; VM auditée avec enregistrements du fournisseur et des accès ; Phala Intel TDX avec rapport d'attestation vérifié, OS et application mesurés, et clé de collecteur liée.">
</picture>

Le vérificateur TDX confronte le rapport d'attestation à la racine Intel épinglée et aux données de révocation,
le lie à une déclaration signée du collecteur et à un nouveau défi, et compare
l'OS et l'application mesurés à des entrées attendues de manière indépendante. Le compte rendu final
liste chaque résultat séparément, afin que l'environnement mesuré, l'identité du collecteur, les enregistrements
de capture et la couverture puissent être examinés ensemble.

**Collecte avec provenance GitHub** (version préliminaire). Collectez une discussion sur un runner hébergé par GitHub
avec une version épinglée de TgWitness et une nouvelle session Telegram, puis téléchargez l'archive
chiffrée avec son attestation GitHub. Le vérificateur contrôle le workflow approuvé et la
version du collecteur, le condensé de l'archive, le journal et les pièces jointes. Également disponible
sous **Exportations** dans le panneau.
[Ouvrir la page de collecte](https://phishdestroy.github.io/TgWitness/fr/docs/capture/) · [Instructions](../SEALED-ACTIONS.md)

Pour l'observation en direct, l'historique ou un export ponctuel, choisissez une
[méthode de collecte](../COLLECTION-MODES.md). Les discussions cloud privées sont disponibles
lorsque le compte connecté y a accès. L'application publiée inclut aussi
l'[intégration des discussions secrètes](../PSEUDO-SECRET.md) : installez la dépendance de protocole
facultative et activez-la par compte pour enregistrer les discussions créées ou acceptées depuis ce compte.
Consultez le [périmètre de collecte](../COLLECTION.md) pour les voies d'acquisition disponibles.

[Phala / Intel TDX et déploiements audités](../HIGH-ASSURANCE.md) ·
[Qualification Phala en conditions réelles](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[Frontières de confiance](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>Vérifiez la capture et l'enregistrement conservé</strong> · ce que vérifie le destinataire et l'Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="Capturez la conversation. Vérifiez l'enregistrement. Conservez messages, modifications et fichiers, contrôlez signatures et points de contrôle, et examinez le processus de capture.">
</picture>

TgWitness enregistre le contenu remis au compte Telegram connecté, avec les
identifiants de discussion, de message et d'expéditeur, les versions capturées et les métadonnées de collecte.
L'archive réunit ces enregistrements, les pièces jointes conservées et les données de vérification
pour examen.

| Contrôle | Ce que vérifie le destinataire |
| --- | --- |
| Journal signé et manifeste | Les signatures des enregistrements, la chaîne de hachage et les fichiers remis, par rapport à la clé de signature attendue. |
| Point de contrôle conservé séparément | Le journal par rapport à une longueur et un hachage du dernier enregistrement relevés auparavant. |
| Témoin indépendant | Le journal par rapport aux points de contrôle conservés par un témoin distinct. |
| Collecte via GitHub Actions | L'archive par rapport à son attestation, au workflow hébergé approuvé et à la version du collecteur. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
montre une conversation Telegram à côté de fichiers d'export Desktop délibérément modifiés.
Comparez les versions, examinez les changements et suivez les étapes de collecte et de
vérification d'une archive TgWitness signée.

[Étapes de vérification](../wiki/Exports-and-Verification.md) ·
[Collecte GitHub](../SEALED-ACTIONS.md) ·
[Modèle de confiance technique](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>Assurer la continuité de l'enquête</strong> · notifications, stockage et récupération</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="Flux animés : Apprise envoie les alertes configurées ; les copies hors site sont chiffrées avant l'envoi vers un stockage compatible S3.">
</picture>

[Notifications](../OPERATIONS.md#notifications) · [Copie hors site chiffrée](../wiki/Off-site-Copy.md) · [Sauvegarde et restauration](../wiki/Backup-and-Recovery.md) · [Dépannage](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/fr/docs/start/"><b>Guide de configuration&nbsp;↗</b></a><br><sub>De l'installation à la première discussion</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/fr/docs/dedicated-account/"><b>Préparer votre compte&nbsp;↗</b></a><br><sub>Un compte Telegram dédié</sub></td>
<td width="33%" align="center"><a href="../DEPLOYMENT.md"><b>Docker et serveurs&nbsp;↗</b></a><br><sub>HTTPS, redémarrages et mises à jour</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>Explorer le dépôt</strong> · où se trouvent le code, la documentation et les outils</summary>

| Répertoire | Commencer ici |
| --- | --- |
| [docs/](../README.md) | Configuration, procédures d'enquête et référence technique |
| [tgwitness/](../../tgwitness/README.md) | Application principale, collecteur, journal et panneau web |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | Enregistreurs indépendants et leur code de vérification |
| [addons/](../../addons/README.md) | Installation, configuration et tests de la capture facultative |
| [deploy/](../../deploy/README.md) | Programmes d'installation, conteneurs et services d'arrière-plan |
| [examples/](../../examples/README.md) | Configurations d'export de compte et de capture scellée |
| [integrations/](../../integrations/README.md) | Webhooks signés et récepteur n8n |
| [.agents/](../../.agents/README.md) | Instructions de tâches pour lire l'archive via la CLI |
| [scripts/](../../scripts/README.md) | Lanceurs et utilitaires CI |
| [tools/](../../tools/README.md) | Compilations, contrôles et empaquetage |
| [website/](../../website/README.md) | Site public, guides traduits et démo interactive |
| [.github/](../../.github/AUTOMATION.md) | Workflows, règles de contribution et assistance |

[Guide complet du projet](../PROJECT-GUIDE.md) ·
[Contribuer](../../.github/CONTRIBUTING.md) · [Obtenir de l'aide](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ Avis éthique et continuité historique</strong></summary>

La position des auteurs et l'avis aux opérateurs, en français :

[Avis aux opérateurs](OPERATOR-INCOMPATIBILITY.md) · [Licence MIT](../../LICENSE) · [NOTICE d'origine](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>Lire la présentation du projet dans votre langue</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · **Français** · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>Documentation technique</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Manuel d'enquête</b></a> ·
  <a href="https://github.com/phishdestroy"><b>Conçu par PhishDestroy</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>Contribuer</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>Obtenir de l'aide</b></a> ·
  <a href="../../.github/SECURITY.md"><b>Signaler une vulnérabilité</b></a>
</p>

[Index du projet lisible par machine](../../llms.txt) · [Manuel complet au format texte](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [Règles du dépôt pour les agents](../../AGENTS.md)
