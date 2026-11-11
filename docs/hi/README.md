<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">अन्य भाषाएँ</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — सुराग का पीछा करें। सबूत सुरक्षित रखें। हैश से जुड़ा हस्ताक्षरित जर्नल, अलग से रखा गया चेकपॉइंट और सत्यापन-योग्य सबूत आर्काइव।">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=hi"><b>डेमो देखें&nbsp;↗</b></a><br><sub>असली इंटरफ़ेस, काल्पनिक रिकॉर्ड के साथ</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>डाउनलोड करें और शुरू करें&nbsp;↓</b></a><br><sub>Linux, macOS और Windows के लिए एक ही कमांड</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>हैंडबुक पढ़ें&nbsp;↗</b></a><br><sub>जाँच की गाइड, चरण-दर-चरण</sub></td>
</tr>
</table>

<p align="center"><strong>Telegram जाँच के लिए सेल्फ़-होस्टेड कार्यक्षेत्र।</strong><br>चैट सहेजें, संपादन और हटाए गए संदेश सुरक्षित रखें, देखें कि कौन किससे जुड़ा है<br>और ऐसे हस्ताक्षरित निर्यात सौंपें जिन्हें कोई भी जाँच सके।</p>

<p align="center"><strong>ZERO TRUST.</strong> TgWitness किसी का पक्ष नहीं लेता: ऑपरेटर, PhishDestroy और किसी भी अन्य पर एक जैसी जाँच लागू होती है।<br>मान्य वही है जिसकी पुष्टि कोई तीसरा पक्ष या गणित करे। <a href="../QUESTIONS-AND-CHECKS.md">प्रश्न और जाँच</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.2 · प्री-रिलीज़"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">परीक्षित परिवेश</a> · 25 इंटरफ़ेस भाषाएँ · 26 गाइड भाषाएँ</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=hi">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="TgWitness डेमो चलते हुए: कैप्चर किए गए संदेश, सहेजे गए संस्करण और हटाए जाने के बाद भी बची सामग्री। काल्पनिक प्रदर्शन रिकॉर्ड।">
</picture>
</a>

<p align="center"><sub>काल्पनिक रिकॉर्ड के साथ असली इंटरफ़ेस देखें। आज़माने के लिए कार्यक्षेत्र पर क्लिक करें।</sub></p>

## TgWitness क्या करता है

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">हर संपादन और हटाया गया संदेश सुरक्षित</a></b><br><sub>संदेश का हर संस्करण सहेजा जाता है, और हटाने की सूचना के बाद भी उसका टेक्स्ट बना रहता है।</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">ऐसा प्रमाण जिसे कोई भी जाँच सके</a></b><br><sub>हस्ताक्षरित, हैश-शृंखला से जुड़े रिकॉर्ड। प्राप्तकर्ता एक कमांड से आर्काइव को ऑफ़लाइन सत्यापित करता है।</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">स्रोत, जिसे आप दिखा सकें</a></b><br><sub>खाते के प्रमाणित MTProto सत्र से प्राप्त और आते ही हस्ताक्षरित; GitHub Actions और Intel TDX अटेस्टेशन जोड़ते हैं।</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">बड़े पैमाने पर मापा गया</a></b><br><sub>48 सत्यापित आर्काइव में 3,598,381 रिकॉर्ड; आठ खातों ने 687.5 रिकॉर्ड/सेकंड की गति से इतिहास के 768,007 रिकॉर्ड प्राप्त किए।</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">जाँच के लिए बना</a></b><br><sub>टेक्स्ट, QR कोड और OCR पर वॉचलिस्ट, वॉलेट जाँच, प्रोफ़ाइल कार्ड, केस बोर्ड और अदालती पैकेज।</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">आपके नियंत्रण में</a></b><br><sub>सेल्फ़-होस्टेड, बिना टेलीमेट्री। सत्र एन्क्रिप्टेड वॉल्ट में रहते हैं; पैनल localhost पर सुनता है।</sub></td>
</tr>
</table>

<p align="center"><sub>लगभग छह महीनों तक विकसित और परीक्षण किया गया: पहले कलेक्टर, हस्ताक्षरित जर्नल और सत्यापनकर्ता, फिर पैनल और ऐड-ऑन मॉड्यूल। यह रिपॉजिटरी 29 अक्टूबर 2026 को प्रकाशन के लिए बनाई गई थी, इसलिए इसकी आयु परियोजना की आयु नहीं है।</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## इंस्टॉल करें

Python साथ में शामिल है। अपडेट के लिए भी यही कमांड चलाएँ।

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell या CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Ubuntu सर्वर: root के रूप में चलाएँ। डेस्कटॉप: अपने सामान्य उपयोगकर्ता के रूप में चलाएँ। `-ExecutionPolicy Bypass` केवल इसी एक PowerShell प्रक्रिया पर लागू होता है।</sub>

हस्ताक्षरित बिल्ड सार्वजनिक [इंस्टॉलर वर्कफ़्लो](../../.github/workflows/installer.yml) से आते हैं, और इंस्टॉलर हर पैकेज को इंस्टॉल करने से पहले उसका SHA-256 और RSA हस्ताक्षर जाँचता है।

[पहले स्क्रिप्ट सत्यापित करें](../INSTALLATION.md#verify-before-running) · [पहला सेटअप](../SETTINGS.md) · [रिलीज़](https://github.com/phishdestroy/TgWitness/releases) · [Docker](DEPLOYMENT.md)

<details>
<summary><strong>इंस्टॉलर और आपका डेटा कैसे सुरक्षित रहते हैं</strong></summary>

`get.destroy.tools` प्रोजेक्ट की डाउनलोड साइट है। सार्वजनिक
[इंस्टॉलर वर्कफ़्लो](../../.github/workflows/installer.yml) इसे `main` के ठीक उसी संशोधन के लिए
[`deploy/installer/`](../../deploy/installer/README.md) से बनाता है,
Linux और Windows इंस्टॉलेशन टेस्ट पास होने के बाद प्रकाशित करता है, और इंस्टॉलर
स्क्रिप्ट व एप्लिकेशन पैकेजों पर रिलीज़ कुंजी से हस्ताक्षर करता है, जो
[`release-signing.pub`](../../deploy/installer/release-signing.pub) में है। इंस्टॉलर
इंस्टॉल करने से पहले पैकेज और डिपेंडेंसी लॉक का SHA-256 और RSA हस्ताक्षर जाँचता है।
अगर पहले स्क्रिप्ट को ही जाँचना है, तो उसे हस्ताक्षर के साथ डाउनलोड करें और
[पहले-सत्यापन कमांड](../INSTALLATION.md#verify-before-running) चलाएँ। बिल्ड विफल होने पर
पिछला डाउनलोड बना रहता है; इंस्टॉलर दोबारा चलाने पर इंस्टॉल किए गए पैनल अपडेट हो जाते हैं।
GitHub [रिलीज़](https://github.com/phishdestroy/TgWitness/releases), सोर्स कोड और
[Docker](DEPLOYMENT.md) इंस्टॉल करने के अन्य तरीके हैं।

**आपके सत्र और डेटा।** TgWitness आपके कंप्यूटर या सर्वर पर चलता है, और पैनल
डिफ़ॉल्ट रूप से localhost पर सुनता है। Telegram सत्र, प्रॉक्सी क्रेडेंशियल और एक्सेस-टोकन
के हैश हर कार्यक्षेत्र के एन्क्रिप्टेड वॉल्ट में रखे जाते हैं, वैकल्पिक
[बाहरी मास्टर कुंजी](../SECURITY-MODEL.md#external-master-key) के साथ। एप्लिकेशन में
कोई टेलीमेट्री नहीं है। यह Telegram से और उन सेवाओं से जुड़ता है जो इसकी सेटिंग्स में चुनी गई हैं:
सार्वजनिक MTProxy सूचियाँ, आपके प्रॉक्सी, S3 स्टोरेज, गवाह बॉट, टाइमस्टैम्प
प्राधिकरण, AI प्रदाता और वेबहुक। [सिस्टम मानचित्र](../SYSTEM-MAP.md) उन
कनेक्शनों की सूची देता है जो एप्लिकेशन प्रक्रिया बनाती है।
निगरानी के लिए [अलग Telegram खाते](https://phishdestroy.github.io/TgWitness/hi/docs/dedicated-account/) का उपयोग करें।

संस्करण बैज इसी सोर्स ट्री का वर्णन करता है। इंस्टॉल करने योग्य बिल्ड
[रिलीज़](https://github.com/phishdestroy/TgWitness/releases) में सूचीबद्ध हैं; `main` में मर्ज की गई
सुविधा अगली रिलीज़ के साथ इन डाउनलोड में पहुँचती है।

[सेटअप और पैनल एक्सेस](../INSTALLATION.md) ·
[हस्ताक्षर और SHA-256](https://get.destroy.tools/#verification) ·
[अपडेट](../INSTALLATION.md#update-an-existing-installation) ·
[वर्तमान क्षमताएँ और योग्यता-परीक्षण](../STATUS.md) ·
[संग्रह का तरीका चुनें](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## ऐसा रिकॉर्ड जिसे कोई और जाँच सके

बिना खाते और बिना इंस्टॉलेशन के जाँचें। प्रकाशित नमूने में उसका अपना सत्यापनकर्ता शामिल है:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # सत्यापनकर्ता आर्काइव के अंदर ही आता है
python verify.py tgwitness-demo.zip          # Python 3.11+, केवल `cryptography` चाहिए
```

यह हस्ताक्षरित रिकॉर्ड, नवीनतम रिकॉर्ड का हैश और हस्ताक्षरकर्ता का फ़िंगरप्रिंट दिखाता है और कोड `0` के साथ समाप्त होता है।
नमूना काल्पनिक है; यही सत्यापनकर्ता किसी भी वास्तविक निर्यात पर चलता है।

निर्यात में संदेश, फ़ाइलें और सत्यापनकर्ता होते हैं। प्राप्तकर्ता को अपनी
कुंजी का फ़िंगरप्रिंट किसी दूसरे चैनल से भेजें, और वह इसे स्वयं जाँच सकता है:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

सत्यापनकर्ता हस्ताक्षर, जर्नल शृंखला, फ़ाइल सूची और अटैचमेंट जाँचता है।
सबूत के स्तर के लिए उसे आपकी कुंजी का फ़िंगरप्रिंट और अंतिम रिकॉर्ड को कवर करने वाला
किसी तीसरे पक्ष का टाइमस्टैम्प चाहिए, जैसे प्राधिकरण के रूट प्रमाणपत्र से जाँचा गया RFC 3161 टाइमस्टैम्प।

**संदेश कहाँ से आते हैं।** TgWitness उन्हें Telegram से खाते के एन्क्रिप्टेड
MTProto सत्र के ज़रिए प्राप्त करता है, जैसे आधिकारिक ऐप करते हैं, और हर संदेश के आते ही उस पर
हस्ताक्षर करके उसे जर्नल में दर्ज करता है। [GitHub Actions कैप्चर](../SEALED-ACTIONS.md) और
[Phala Intel TDX](../HIGH-ASSURANCE.md) उन्हें प्राप्त करने वाले संग्रहकर्ता का अटेस्टेशन भी देते हैं।

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="नए संदेश, सहेजे गए संपादन और हटाने के अवलोकन मिलकर एक जुड़ा हुआ, हस्ताक्षरित जर्नल बनाते हैं। इसे स्वतंत्र रूप से भरोसेमंद कुंजी के विरुद्ध सत्यापित करें।">
</picture>

[आर्काइव सत्यापन](../wiki/Exports-and-Verification.md) · [सबूत का प्रारूप](../EVIDENCE.md) · [स्वतंत्र गवाह](../WITNESS.md) · [बाहरी टाइमस्टैम्प](../TIMESTAMP.md) · [जाँचें और परीक्षित पैमाना](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## बातचीत से मामले तक

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="तीन एनिमेटेड वर्कफ़्लो: चैट को HTML और JSON में निर्यात करना, रिकॉर्ड की गई चैटों में साझा लिंक ढूँढना, और हटाने की सूचना के बाद कैप्चर किए गए संस्करण बनाए रखना।">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>चैट निर्यात&nbsp;↗</b></a><br><sub>एक चैट से हस्ताक्षरित HTML और JSON</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>जाँच&nbsp;↗</b></a><br><sub>रिकॉर्ड की गई चैटों में सुराग का पीछा करें</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>सहेजे गए संस्करण&nbsp;↗</b></a><br><sub>संपादन और हटाने की सूचनाएँ, सुरक्षित</sub></td>
</tr>
</table>

इस्तेमाल के दो तरीके: एक बार [अपना खाता निर्यात करें](../ACCOUNT-EXPORT.md), या
[जाँच पर लगातार नज़र रखें](../INVESTIGATION.md) और बदलाव सहेजते रहें।
कुछ चैट, कोई Telegram फ़ोल्डर या पूरा खाता चुनें। हर खाते को अपना
कार्यक्षेत्र, सत्र और हस्ताक्षर कुंजी मिलती है।

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## और जानें

<details>
<summary><strong>मापे गए निर्यात · 6 नवंबर 2026</strong> · 56,329 संदेश, दोनों आर्काइव सत्यापित</summary>

**दो नए रन में 56,329 संदेश निर्यात किए गए।** दोनों हस्ताक्षरित आर्काइव पिन की गई संग्रहकर्ता कुंजियों के साथ सत्यापन में सफल रहे।

[![मापी गई संग्रह गति और पूर्ण निर्यात की गति](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/hi/docs/validation/)

| रन | संदेश | संग्रह समय | संग्रह गति | पूर्ण निर्यात | शुरू से अंत तक गति |
| --- | ---: | ---: | ---: | ---: | ---: |
| सर्वर A | 27,030 | 189.043 s | **142.983 संदेश/s** | 211.647 s | 127.713 संदेश/s |
| सर्वर B | 29,299 | 182.513 s | **160.531 संदेश/s** | 206.650 s | 141.781 संदेश/s |

WARP के ज़रिए टेक्स्ट और मेटाडेटा, प्रति सर्वर दो खाते, बिना अटैचमेंट और बिना दोबारा इस्तेमाल किए गए रिकॉर्ड के।
संशोधन [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e) पर मापा गया।
हर प्रकाशित रन में उसका सोर्स संशोधन, वर्कलोड, समय और सत्यापन परिणाम दर्ज है:
[वर्कलोड, समय और सत्यापन](../EXPORT-BENCHMARK-2026-11-06.md)। `main` में बदलाव होने पर
सार्वजनिक [CI वर्कफ़्लो](../../.github/workflows/README.md) चलते हैं, जिनमें Linux और Windows
इंस्टॉलर टेस्ट और स्टैंडअलोन सत्यापनकर्ता का बिल्ड शामिल हैं।

[**डेमो देखें →**](https://phishdestroy.github.io/TgWitness/demo/?lang=hi) ·
[**माप, तिथियाँ और पद्धति →**](https://phishdestroy.github.io/TgWitness/hi/docs/validation/) ·
[काल्पनिक नमूना निर्यात डाउनलोड करें](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[हस्ताक्षरित अंग्रेज़ी ऑडिट](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>सरल शुरुआत। हर मार्ग सामने।</strong> · पहली शुरुआत और सिस्टम मानचित्र</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="पहली शुरुआत में ‘बस डाउनलोड करें’, ‘चैट पर नज़र रखें’ या ‘मामले के लिए सबूत’ का विकल्प मिलता है और केवल उससे जुड़े अनुभाग दिखते हैं। सिस्टम मानचित्र पैनल, संग्रहकर्ता, Telegram, जर्नल, गवाह और बाहरी सेवाओं को नेटवर्क अवलोकनों के साथ जोड़कर दिखाता है। काल्पनिक मान।">
</picture>

पहली शुरुआत में एक ही सवाल पूछा जाता है: **बस डाउनलोड करें**, **चैट पर नज़र रखें** या
**मामले के लिए सबूत**। जवाब से लक्ष्य और इंटरफ़ेस स्तर तय होते हैं, इसलिए
पैनल केवल वही अनुभाग दिखाता है जो उस काम के लिए ज़रूरी हैं। कनेक्शन, Telegram साइन-इन और
चैट का चुनाव पाँच चरणों में होते हैं। कनेक्शन जाँच अपने-आप चलती है, और
मार्ग के विकल्प तभी खुलते हैं जब वह विफल हो। विशेषज्ञ उपकरण बस एक स्विच दूर रहते हैं।

**सिस्टम मानचित्र** दिखाता है कि इंस्टॉलेशन Telegram और बाहरी
सेवाओं तक कैसे पहुँचता है: पैनल एक्सेस, हर खाते का मार्ग और Telegram लक्ष्य, जर्नल और
गवाह का पथ, और नवीनतम नेटवर्क अवलोकन। जो अवलोकन मौजूद नहीं है, उसे
अनुपलब्ध के रूप में चिह्नित किया जाता है।

[पहला सेटअप](../SETTINGS.md) · [सिस्टम मानचित्र](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>बाकी जाँच के लिए भी तैयार</strong> · प्रोफ़ाइल कार्ड, वॉचलिस्ट, वॉलेट, ऑनलाइन निगरानी, अदालती दस्तावेज़</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Telegram ID के आधार पर नाम और यूज़रनेम ट्रैक करें। समर्थित बॉट इंटरैक्शन हस्ताक्षरित रसीदों के साथ रिकॉर्ड करें। आर्काइव किए गए संदेश खोजें और केवल-पढ़ने वाले MCP क्लाइंट जोड़ें। SSH को मास्क करके और समीक्षा के लिए प्रदाता के रिकॉर्ड के साथ संग्रहकर्ता तैनात करें। जर्नल संदर्भों के साथ बातचीत को चरण-दर-चरण दर्ज करें। अदालती टेम्पलेट के साथ BagIt केस पैकेज सौंपें। उदाहरण के लिए वर्कफ़्लो।">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>लोग और डोज़ियर&nbsp;↗</b></a><br><sub>Telegram ID के आधार पर ट्रैक किए गए नाम और यूज़रनेम</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>बॉट की जाँच&nbsp;↗</b></a><br><sub>हस्ताक्षरित रसीदों के साथ बॉट इंटरैक्शन</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/hi/docs/archive/"><b>आर्काइव खोज, AI और MCP&nbsp;↗</b></a><br><sub>आर्काइव में खोजें, केवल-पढ़ने वाले क्लाइंट जोड़ें</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>सीलबंद क्लाउड डिप्लॉयमेंट&nbsp;↗</b></a><br><sub>Intel TDX के भीतर संग्रहकर्ता</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="तीन एनिमेटेड चरण: एक प्रोफ़ाइल कार्ड, जिसका बाद का स्नैपशॉट नाम बदलने को दर्ज करता है; बातचीत की एक योजना, जिसके लक्ष्य जर्नल रिकॉर्ड के साथ पूरे होते हैं; और एक भुगतान QR कोड, जो वैध चेकसम वाले वॉलेट में डिकोड होकर वॉचलिस्ट मिलान ट्रिगर करता है। काल्पनिक मान।">
</picture>

**बातचीत का दस्तावेज़ बनाएँ।** **दस्तावेज़ीकरण** साइड पैनल में किसी चैट का रिकॉर्ड शुरू करें
और हर चरण अपने-आप दर्ज होता है: पैनल की कार्रवाइयाँ, जवाब और उनसे पहले की
देरी, संपादन, हटाने की सूचनाएँ, नोट्स और AI ड्राफ़्ट। हर चरण अपने जर्नल
रिकॉर्ड और SHA-256 का हवाला देता है। दस्तावेज़ को अंतिम रूप देने पर उस पर हस्ताक्षर होता है और कथन का हैश
जर्नल में दर्ज हो जाता है।

| | |
| --- | --- |
| [प्रोफ़ाइल कार्ड](../INVESTIGATION-MODE.md#subject-cards) | बॉट, व्यक्ति, चैनल या समूह की प्रोफ़ाइल के स्नैपशॉट, Telegram के BOT, VERIFIED, SCAM और FAKE लेबल सहित; बाद का स्नैपशॉट बताता है कि क्या बदला |
| [बातचीत की योजनाएँ](../INVESTIGATION-MODE.md#conversation-plans) | भुगतान मार्ग, इन्फ्रास्ट्रक्चर या लोगों से जुड़े लक्ष्य, पहले से तैयार संदेश, जवाब का समय, घंटेवार गतिविधि और दूसरे पक्ष की लेखन शैली |
| [अनुवाद](../INVESTIGATION-MODE.md#machine-translation) | मूल के नीचे दिखता है, भाषाओं, मॉडल और जर्नल रिकॉर्ड के साथ |
| [वॉचलिस्ट](../INVESTIGATION-MODE.md#watchlists) | शब्द, पैटर्न, वॉलेट, @यूज़रनेम, ID, डोमेन, फ़ोन नंबर और लिंक; मिलान टेक्स्ट, संपादनों, छिपे लिंक गंतव्यों, बॉट बटनों, QR कोड और OCR में |
| [ऑनलाइन निगरानी](../INVESTIGATION-MODE.md#online-watch) | हर 1–60 मिनट में जाँच, प्रति अनुरोध 100 खातों तक, घंटे और सप्ताह के दिन के अनुसार पैटर्न के साथ |
| [कोड और वॉलेट](../INVESTIGATION-MODE.md#codes-in-images) | भुगतान QR कोड; EIP-55 के अनुसार जाँचे गए EVM पते, raw रूप में TON, XRP Ledger चेकसम, चेन, राशि और टोकन सहित भुगतान लिंक |
| [क्लाइंट के निशान](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-show) | गोल वीडियो और वॉइस संदेशों में एन्कोडर के निशान; अपलोड समय की भेजने के समय से तुलना पहले से रिकॉर्ड किए गए “लाइव” प्रमाण को उजागर करती है |
| [कवर और अधिकार](../INVESTIGATION-MODE.md#cover-and-authority) | पर्सोना, प्राधिकरण और गुप्त गतिविधि का रिकॉर्ड, जो अधिकृत चैटों या अवधि के बाहर के संदेशों को चिह्नित करता है |
| [खाता नियंत्रण](../INVESTIGATION-MODE.md#account-control) | पहले/बाद के रिकॉर्ड के साथ प्रोफ़ाइल और गोपनीयता संपादन, एक्सपोज़र जाँच, और हर कार्रवाई के तुरंत बाद ऑफ़लाइन होना |
| [अदालत के लिए दस्तावेज़](../INVESTIGATION-MODE.md#documents-for-court) | BagIt केस पैकेज, जिसमें Rule 902(13)/(14) प्रमाणन टेम्पलेट, प्रदर्शों की सूची, अनुरोध परिशिष्ट और स्क्रीन रिकॉर्डिंग के लिए WebVTT/SRT कैप्शन हैं |

18+, हिंसा या व्यक्तिगत डेटा के रूप में चिह्नित सामग्री अदालती प्रति में रहती है, जो AES-256-GCM से
सील होती है; कुंजियाँ अलग से भेजी जाती हैं।

[निर्यात सेटिंग्स](../EXPORT_HASHES.md) में सामान्य API और Takeout से प्राप्ति,
अटैचमेंट से पहले संदेश इतिहास, फ़ाइल डाउनलोड या सर्वर हैश, और संगत
Telegram Desktop JSON/HTML दृश्य शामिल हैं। [वितरित चैट निर्यात](../DISTRIBUTED-EXPORT.md#history-acquisition)
सार्वजनिक इतिहास के लिए स्वयं चालू किया जाने वाला Takeout मार्ग, हर 100 संदेशों पर हस्ताक्षरित चेकपॉइंट,
और उसी खाते से किसी रेंज के भीतर पुनर्प्राप्ति देता है; इसका
[प्रदर्शन डिज़ाइन](../FAST-ACQUISITION.md) परीक्षित प्राप्ति व्यवहार
और नियोजित लाइव मापों की सूची देता है।

</details>

<details>
<summary><strong>बाकी सब कुछ</strong> · इतिहास, खाते, प्रॉक्सी, AI, इंटीग्रेशन</summary>

| | |
| --- | --- |
| [पुराने संदेश लोड करें](../HISTORY.md) | चुनी गई चैटों का पिछला इतिहास लाएँ, कभी भी रोकें और फिर से शुरू करें |
| [कई खाते](../ACCOUNTS.md#multiple-accounts) | अलग-अलग कार्यक्षेत्र, हर एक का अपना Telegram सत्र, जर्नल और हस्ताक्षर कुंजी |
| [बैच इम्पोर्ट](../ACCOUNTS.md#bulk-import-and-account-groups) | ढेर सारी सत्र फ़ाइलें एक साथ डालें, खातों को साझा सेटिंग्स वाले समूहों में बाँटें |
| [MTProxy पूल](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | पिंग, देश, फ़िल्टर, आपकी अपनी सूचियाँ |
| [मौजूदा सत्र](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key या `key:DC` पंक्ति; इम्पोर्ट किए गए डोनर से वैकल्पिक स्वतंत्र QR प्राधिकरण |
| [खाता सुरक्षा](../ACCOUNTS.md#create-an-independent-authorization) | नए सत्रों की चेतावनी, अन्य सत्र समाप्त करना, एकमात्र-सत्र मोड जो दो-चरणीय पासवर्ड भी सेट करता है, और [गवाह प्रोब](../ACCOUNTS.md#witness-probe), जो पहचानता है कि लाइव अपडेट इस सत्र तक पहुँचना कब बंद हो गए |
| [फिर से शुरू होने वाला चैट निर्यात](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | रुका हुआ निर्यात हस्ताक्षरित आंशिक प्रति रखता है: उसे आगे बढ़ाएँ, नए सिरे से शुरू करें या जो सहेजा गया है उसे डाउनलोड करें |
| [प्रॉक्सी](../CONNECTION-SECURITY.md#ip-modes) | हर कार्यक्षेत्र के लिए SOCKS5, HTTP CONNECT या MTProxy। **IP छिपाएँ** कभी सीधे कनेक्शन पर नहीं लौटता |
| [खोज और AI](../ANALYSIS.md) | स्थानीय खोज, ऐसे स्रोतों के साथ वैकल्पिक AI जिन्हें आप जाँच सकें |
| [पूर्ण-पाठ खोज](../SEARCH.md) | शब्द रूप, सटीक वाक्यांश, डोमेन, @यूज़रनेम और बिना स्पेस वाली चीनी, सबसे अच्छे मिलान पहले (**पूर्वावलोकन संस्करण**) |
| [MCP](../MCP.md) | MCP क्लाइंट के लिए केवल-पढ़ने की पहुँच, आपकी चुनी हुई चैटों तक सीमित |
| [कमांड लाइन](../CLI.md) | स्क्रिप्ट और एजेंटों के लिए `--json` के साथ `search`, `context`, `messages`, `stats` और JSON Lines `export`, स्थानीय रूप से या सीमित दायरे वाले टोकन से (**पूर्वावलोकन संस्करण**) |
| [OCR और ट्रांसक्रिप्शन](../MEDIA-ANALYSIS.md) | स्थानीय रूप से चलता है, मूल फ़ाइलें अछूती रहती हैं |
| [स्वतंत्र कैप्चर](../OPTIONAL-CAPTURE.md) | **अधिक उपकरण → अतिरिक्त सुविधाएँ** में वैकल्पिक ब्राउज़र/AyuGram रिकॉर्डर (पूर्वावलोकन, डिफ़ॉल्ट रूप से बंद) |
| [Trusted Live](../TRUSTED-LIVE.md) | आधिकारिक Desktop/Web सत्र, सुरक्षित वीडियो और मूल निर्यात से निरंतरता का विश्लेषण (पूर्वावलोकन; लाइव योग्यता-परीक्षण बाकी) |
| [सीलबंद आधिकारिक Web](../OFFICIAL-WITNESS.md) | GitHub Actions पर नया आधिकारिक ब्राउज़र, सीमित नियंत्रण, हस्ताक्षरित वीडियो और स्वतंत्र रूप से अपेक्षित सोर्स/सेटिंग्स |
| [वेबहुक](../WEBHOOKS.md) | दोबारा प्रयास के साथ हस्ताक्षरित आउटगोइंग इवेंट, n8n उदाहरण शामिल |
| [साझा पहुँच](../ACCESS.md) | किसी को केवल चुनी गई चैटों की पहुँच दें, समाप्ति समय और IP सीमाओं के साथ |
| [छूटे हुए संदेश नंबर](../EVIDENCE.md#missing-message-numbers-gap_summary) | Telegram द्वारा दिए गए वे नंबर जो कभी देखे नहीं गए, हर चैनल और पूरे खाते के लिए, कवरेज, रिपोर्टों और MCP में (**पूर्वावलोकन संस्करण**) |
| [चैट स्थिति के स्नैपशॉट](../COLLECTION.md) | शीर्षक, विवरण, पिन, एडमिनिस्ट्रेटर और गिफ़्ट के नियमित हस्ताक्षरित स्नैपशॉट, बदलावों के साथ (**पूर्वावलोकन संस्करण**) |
| [सिस्टम मानचित्र](../SYSTEM-MAP.md) | पैनल एक्सेस, खातों के मार्गों, Telegram लक्ष्यों और बाहरी सेवाओं का लाइव मानचित्र, अधिकतम 2,000 नेटवर्क अवलोकनों में से नवीनतम 200 के साथ |

</details>

<details>
<summary><strong>चुनें कि रिकॉर्ड का आधार क्या हो</strong> · स्थानीय, ऑडिट किया गया क्लाउड, GitHub Actions या Intel TDX</summary>

स्थानीय रूप से चलाएँ, ऑडिट किया गया क्लाउड डिप्लॉयमेंट जोड़ें, या **Intel TDX वाले Phala Cloud
गोपनीय VM** के भीतर संग्रह करें। हर विकल्प में हस्ताक्षरित जर्नल बना रहता है; अतिरिक्त
जाँचें उस परिवेश से संबंधित हैं जहाँ संग्रह हुआ।

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="डिप्लॉयमेंट के तीन विकल्प: स्थानीय जर्नल सत्यापन; प्रदाता और एक्सेस रिकॉर्ड के साथ ऑडिट किया गया VM; सत्यापित quote, मापे गए OS और एप्लिकेशन, और बंधी हुई संग्रहकर्ता कुंजी के साथ Phala Intel TDX।">
</picture>

TDX सत्यापनकर्ता quote को Intel के पिन किए गए रूट और निरस्तीकरण डेटा के विरुद्ध जाँचता है,
उसे संग्रहकर्ता के हस्ताक्षरित कथन और नए चैलेंज से बाँधता है, और मापे गए
OS और एप्लिकेशन की तुलना स्वतंत्र रूप से अपेक्षित इनपुट से करता है। रिपोर्ट
हर परिणाम अलग से दिखाती है, ताकि मापे गए परिवेश, संग्रहकर्ता की पहचान, कैप्चर
रिकॉर्ड और कवरेज की एक साथ समीक्षा की जा सके।

**GitHub उत्पत्ति-प्रमाण के साथ कैप्चर** (पूर्वावलोकन)। GitHub-होस्टेड रनर पर पिन किए गए TgWitness
और नए Telegram सत्र के साथ चैट का संग्रह करें, फिर एन्क्रिप्टेड
आर्काइव को उसके GitHub अटेस्टेशन के साथ डाउनलोड करें। सत्यापनकर्ता स्वीकृत वर्कफ़्लो और
संग्रहकर्ता संस्करण, आर्काइव डाइजेस्ट, जर्नल और अटैचमेंट जाँचता है। यह पैनल में
**निर्यात** के अंतर्गत भी उपलब्ध है।
[कैप्चर पेज खोलें](https://phishdestroy.github.io/TgWitness/hi/docs/capture/) · [निर्देश](../SEALED-ACTIONS.md)

लाइव अवलोकन, इतिहास या एक बार के निर्यात के लिए
[संग्रह का तरीका](../COLLECTION-MODES.md) चुनें। निजी क्लाउड चैट तब उपलब्ध होती हैं
जब जुड़े हुए खाते की उन तक पहुँच हो। प्रकाशित एप्लिकेशन में
[सीक्रेट चैट इंटीग्रेशन](../PSEUDO-SECRET.md) भी शामिल है: वैकल्पिक प्रोटोकॉल
डिपेंडेंसी इंस्टॉल करें और वहाँ बनाई या स्वीकार की गई चैट रिकॉर्ड करने के लिए इसे हर खाते के लिए अलग से चालू करें।
उपलब्ध प्राप्ति मार्गों के लिए [संग्रह का दायरा](../COLLECTION.md) देखें।

[Phala / Intel TDX और ऑडिट किए गए डिप्लॉयमेंट](../HIGH-ASSURANCE.md) ·
[Phala पर लाइव योग्यता-परीक्षण](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[भरोसे की सीमाएँ](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>कैप्चर और सहेजा गया रिकॉर्ड जाँचें</strong> · प्राप्तकर्ता क्या सत्यापित करता है और Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="बातचीत कैप्चर करें। रिकॉर्ड सत्यापित करें। संदेश, संपादन और फ़ाइलें सहेजें, हस्ताक्षर और चेकपॉइंट जाँचें, और कैप्चर प्रक्रिया की समीक्षा करें।">
</picture>

TgWitness जुड़े हुए Telegram खाते तक पहुँचाई गई सामग्री रिकॉर्ड करता है, साथ में
चैट, संदेश और प्रेषक के पहचानकर्ता, कैप्चर किए गए संस्करण और संग्रह का मेटाडेटा।
आर्काइव इन रिकॉर्ड, सुरक्षित रखे गए अटैचमेंट और सत्यापन डेटा को
समीक्षा के लिए एक साथ लाता है।

| जाँच | प्राप्तकर्ता क्या सत्यापित करता है |
| --- | --- |
| हस्ताक्षरित जर्नल और मैनिफ़ेस्ट | अपेक्षित हस्ताक्षर कुंजी के विरुद्ध रिकॉर्ड के हस्ताक्षर, हैश शृंखला और सौंपी गई फ़ाइलें। |
| अलग से रखा गया चेकपॉइंट | पहले दर्ज की गई लंबाई और नवीनतम रिकॉर्ड के हैश के विरुद्ध जर्नल। |
| स्वतंत्र गवाह | किसी अलग गवाह द्वारा रखे गए चेकपॉइंट के विरुद्ध जर्नल। |
| GitHub Actions कैप्चर | उसके अटेस्टेशन, स्वीकृत होस्टेड वर्कफ़्लो और संग्रहकर्ता संस्करण के विरुद्ध आर्काइव। |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
एक Telegram बातचीत को जानबूझकर बदली गई Desktop निर्यात फ़ाइलों के साथ-साथ दिखाता है।
संस्करणों की तुलना करें, बदलावों की जाँच करें, और हस्ताक्षरित TgWitness आर्काइव के
संग्रह और सत्यापन के चरणों का पालन करें।

[सत्यापन के चरण](../wiki/Exports-and-Verification.md) ·
[GitHub कैप्चर](../SEALED-ACTIONS.md) ·
[तकनीकी भरोसा मॉडल](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>जाँच को चालू रखें</strong> · सूचनाएँ, स्टोरेज और पुनर्प्राप्ति</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="एनिमेटेड वर्कफ़्लो: Apprise कॉन्फ़िगर किए गए अलर्ट भेजता है; ऑफ़-साइट प्रतियाँ S3-संगत स्टोरेज पर अपलोड होने से पहले एन्क्रिप्ट की जाती हैं।">
</picture>

[सूचनाएँ](../OPERATIONS.md#notifications) · [एन्क्रिप्टेड ऑफ़-साइट प्रति](../wiki/Off-site-Copy.md) · [बैकअप और पुनर्प्राप्ति](../wiki/Backup-and-Recovery.md) · [समस्या निवारण](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/hi/docs/start/"><b>सेटअप गाइड&nbsp;↗</b></a><br><sub>इंस्टॉलेशन से पहली चैट तक</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/hi/docs/dedicated-account/"><b>अपना खाता तैयार करें&nbsp;↗</b></a><br><sub>अलग Telegram खाता</sub></td>
<td width="33%" align="center"><a href="DEPLOYMENT.md"><b>Docker और सर्वर&nbsp;↗</b></a><br><sub>HTTPS, रीस्टार्ट और अपडेट</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>रिपॉज़िटरी देखें</strong> · कोड, दस्तावेज़ और टूल कहाँ हैं</summary>

| डायरेक्टरी | यहाँ से शुरू करें |
| --- | --- |
| [docs/](../README.md) | सेटअप, जाँच वर्कफ़्लो और तकनीकी संदर्भ |
| [tgwitness/](../../tgwitness/README.md) | मुख्य एप्लिकेशन, संग्रहकर्ता, जर्नल और वेब पैनल |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | स्वतंत्र रिकॉर्डर और उनका सत्यापन कोड |
| [addons/](../../addons/README.md) | वैकल्पिक कैप्चर का इंस्टॉलेशन, कॉन्फ़िगरेशन और टेस्ट |
| [deploy/](../../deploy/README.md) | इंस्टॉलर, कंटेनर और बैकग्राउंड सेवाएँ |
| [examples/](../../examples/README.md) | खाता-निर्यात और सीलबंद कैप्चर के कॉन्फ़िगरेशन |
| [integrations/](../../integrations/README.md) | हस्ताक्षरित वेबहुक और n8n रिसीवर |
| [.agents/](../../.agents/README.md) | CLI के ज़रिए आर्काइव पढ़ने के लिए कार्य-निर्देश |
| [scripts/](../../scripts/README.md) | लॉन्चर और CI यूटिलिटी |
| [tools/](../../tools/README.md) | बिल्ड, जाँच और पैकेजिंग |
| [website/](../../website/README.md) | सार्वजनिक साइट, अनूदित गाइड और इंटरैक्टिव डेमो |
| [.github/](../../.github/AUTOMATION.md) | वर्कफ़्लो, योगदान के दिशानिर्देश और सहायता |

[पूरी प्रोजेक्ट गाइड](../PROJECT-GUIDE.md) ·
[योगदान](../../.github/CONTRIBUTING.md) · [सहायता पाएँ](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ नैतिक सूचना और ऐतिहासिक निरंतरता</strong></summary>

लेखकों की स्थिति और ऑपरेटर सूचना, इस भाषा में:

[ऑपरेटर सूचना](OPERATOR-INCOMPATIBILITY.md) · [MIT लाइसेंस](../../LICENSE) · [मूल NOTICE](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>प्रोजेक्ट का परिचय अपनी भाषा में पढ़ें</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · **हिन्दी** · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>तकनीकी दस्तावेज़ीकरण</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>जाँच हैंडबुक</b></a> ·
  <a href="https://github.com/phishdestroy"><b>PhishDestroy द्वारा निर्मित</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>योगदान दें</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>सहायता पाएँ</b></a> ·
  <a href="../../.github/SECURITY.md"><b>कमज़ोरी की रिपोर्ट करें</b></a>
</p>

[मशीन-पठनीय प्रोजेक्ट इंडेक्स](../../llms.txt) · [पूरी टेक्स्ट हैंडबुक](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [एजेंटों के लिए रिपॉज़िटरी नियम](../../AGENTS.md)
