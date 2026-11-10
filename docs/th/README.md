<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">ภาษาอื่น ๆ</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — ตามรอย เก็บรักษาหลักฐาน สมุดบันทึกที่ลงนามและเชื่อมโยงกันด้วยแฮช จุดตรวจสอบที่เก็บแยกไว้ต่างหาก และไฟล์เก็บถาวรหลักฐานที่ตรวจสอบได้">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=th"><b>ลองใช้เดโม&nbsp;↗</b></a><br><sub>อินเทอร์เฟซจริงพร้อมรายการบันทึกสมมติ</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>ดาวน์โหลดและเริ่มใช้งาน&nbsp;↓</b></a><br><sub>คำสั่งเดียวสำหรับ Linux, macOS และ Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>อ่านคู่มือ&nbsp;↗</b></a><br><sub>คู่มือการสืบสวนทีละขั้นตอน</sub></td>
</tr>
</table>

<p align="center"><strong>พื้นที่ทำงานแบบโฮสต์เองสำหรับการสืบสวนบน Telegram</strong><br>บันทึกแชท เก็บการแก้ไขและการลบไว้ ดูว่าใครเชื่อมโยงกับใคร<br>และส่งมอบไฟล์ส่งออกที่ลงนามแล้วซึ่งใครก็ตรวจสอบได้</p>

<p align="center"><strong>ZERO TRUST</strong> TgWitness ไม่เข้าข้างฝ่ายใด การตรวจสอบแบบเดียวกันใช้กับผู้ดำเนินการ กับ PhishDestroy และกับทุกคน<br>นับเฉพาะสิ่งที่บุคคลที่สามหรือคณิตศาสตร์ยืนยันได้ <a href="../LIMITS-AND-OBJECTIONS.md">ข้อจำกัดและข้อโต้แย้ง</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.2 · รุ่นก่อนเผยแพร่"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">สภาพแวดล้อมที่ทดสอบแล้ว</a> · อินเทอร์เฟซ 25 ภาษา · คู่มือ 26 ภาษา</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=th">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="เดโม TgWitness ขณะทำงาน: ข้อความที่เก็บได้ เวอร์ชันที่บันทึกไว้ และเนื้อหาที่ยังคงอยู่หลังการลบ รายการบันทึกสาธิตที่สมมติขึ้น">
</picture>
</a>

<p align="center"><sub>สำรวจอินเทอร์เฟซจริงพร้อมรายการบันทึกสมมติ คลิกที่พื้นที่ทำงานเพื่อทดลองใช้</sub></p>

## TgWitness ทำอะไรได้บ้าง

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">เก็บทุกการแก้ไขและการลบ</a></b><br><sub>ทุกเวอร์ชันของข้อความถูกบันทึกไว้ และเนื้อหายังคงอยู่แม้มีประกาศการลบ</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">หลักฐานที่ใครก็ตรวจสอบได้</a></b><br><sub>รายการบันทึกที่ลงนามและร้อยต่อกันเป็นสายแฮช ผู้รับตรวจสอบไฟล์เก็บถาวรแบบออฟไลน์ได้ด้วยคำสั่งเดียว</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">แสดงที่มาได้</a></b><br><sub>รับผ่านเซสชัน MTProto ที่ยืนยันตัวตนแล้วของบัญชีและลงนามทันทีที่มาถึง GitHub Actions และ Intel TDX เพิ่มการรับรอง</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">วัดผลในระดับใหญ่</a></b><br><sub>ไฟล์เก็บถาวรที่ตรวจสอบแล้ว 48 ชุด รวม 3,598,381 รายการบันทึก บัญชีแปดบัญชีดึงรายการบันทึกประวัติได้ 768,007 รายการ ด้วยความเร็ว 687.5 รายการต่อวินาที</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">สร้างมาเพื่อการสืบสวน</a></b><br><sub>รายการเฝ้าระวังที่ครอบคลุมข้อความ คิวอาร์โค้ด และ OCR การตรวจสอบวอลเล็ต การ์ดโปรไฟล์ กระดานคดี และชุดเอกสารสำหรับศาล</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">ควบคุมได้เอง</a></b><br><sub>โฮสต์เองและไม่มีเทเลเมทรี เซสชันอยู่ในห้องนิรภัยที่เข้ารหัส แผงควบคุมรับการเชื่อมต่อบน localhost</sub></td>
</tr>
</table>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## ติดตั้ง

มี Python มาในตัว ใช้คำสั่งเดียวกันนี้เพื่ออัปเดต

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell หรือ CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>เซิร์ฟเวอร์ Ubuntu: รันในฐานะ root เดสก์ท็อป: รันในฐานะผู้ใช้ปกติของคุณ `-ExecutionPolicy Bypass` มีผลเฉพาะกับโปรเซส PowerShell นี้เพียงโปรเซสเดียว</sub>

บิลด์ที่ลงนามแล้วมาจาก[เวิร์กโฟลว์ตัวติดตั้ง](../../.github/workflows/installer.yml)แบบสาธารณะ และตัวติดตั้งจะตรวจสอบ SHA-256 และลายเซ็น RSA ของทุกแพ็กเกจก่อนติดตั้ง

[ตรวจสอบสคริปต์ก่อน](../INSTALLATION.md#verify-before-running) · [ตั้งค่าครั้งแรก](../SETTINGS.md) · [รุ่นเผยแพร่](https://github.com/phishdestroy/TgWitness/releases) · [Docker](../DEPLOYMENT.md)

<details>
<summary><strong>ตัวติดตั้งและข้อมูลของคุณได้รับการปกป้องอย่างไร</strong></summary>

`get.destroy.tools` คือเว็บไซต์ดาวน์โหลดของโปรเจกต์
[เวิร์กโฟลว์ตัวติดตั้ง](../../.github/workflows/installer.yml)แบบสาธารณะสร้างไซต์นี้จาก
[`deploy/installer/`](../../deploy/installer/README.md) สำหรับรีวิชันที่ระบุแน่นอนของ `main`
แล้วเผยแพร่หลังผ่านการทดสอบการติดตั้งบน Linux และ Windows พร้อมลงนามสคริปต์ตัวติดตั้ง
และแพ็กเกจแอปพลิเคชันด้วยกุญแจรุ่นเผยแพร่ใน
[`release-signing.pub`](../../deploy/installer/release-signing.pub) ตัวติดตั้งจะตรวจสอบ
SHA-256 และลายเซ็น RSA ของแพ็กเกจและไฟล์ล็อก dependency ก่อนติดตั้ง
หากต้องการตรวจสอบตัวสคริปต์เองก่อน ให้ดาวน์โหลดสคริปต์พร้อมลายเซ็น
แล้วรัน[คำสั่งตรวจสอบก่อนรัน](../INSTALLATION.md#verify-before-running) หากบิลด์ล้มเหลว
ไฟล์ดาวน์โหลดเดิมจะยังคงอยู่ แผงควบคุมที่ติดตั้งแล้วจะอัปเดตเมื่อคุณรันตัวติดตั้งอีกครั้ง
[รุ่นเผยแพร่](https://github.com/phishdestroy/TgWitness/releases)บน GitHub ซอร์สโค้ด และ
[Docker](../DEPLOYMENT.md) เป็นวิธีติดตั้งอื่น ๆ

**เซสชันและข้อมูลของคุณ** TgWitness ทำงานบนคอมพิวเตอร์หรือเซิร์ฟเวอร์ของคุณ
และโดยค่าเริ่มต้นแผงควบคุมจะรับการเชื่อมต่อบน localhost เซสชัน Telegram ข้อมูลรับรองพร็อกซี
และแฮชของโทเค็นการเข้าถึงจะถูกเก็บในห้องนิรภัยที่เข้ารหัสของแต่ละพื้นที่ทำงาน
โดยเลือกใช้[กุญแจหลักภายนอก](../SECURITY-MODEL.md#external-master-key)ร่วมด้วยได้
แอปพลิเคชันไม่มีเทเลเมทรี และเชื่อมต่อกับ Telegram และบริการที่ใช้ตามการตั้งค่า ได้แก่
รายการ MTProxy สาธารณะ พร็อกซีของคุณ ที่เก็บข้อมูล S3 บอตพยาน หน่วยงานประทับเวลา
ผู้ให้บริการ AI และเว็บฮุก
[แผนผังระบบ](../SYSTEM-MAP.md) แสดงรายการการเชื่อมต่อที่โปรเซสของแอปพลิเคชันสร้างขึ้น
ใช้[บัญชี Telegram แยกต่างหาก](https://phishdestroy.github.io/TgWitness/th/docs/dedicated-account/)สำหรับการเฝ้าสังเกต

ป้ายเวอร์ชันอธิบายซอร์สทรีชุดนี้
บิลด์ที่ติดตั้งได้แสดงอยู่ใน[รุ่นเผยแพร่](https://github.com/phishdestroy/TgWitness/releases) ฟีเจอร์ที่ผสานเข้า
`main` แล้วจะไปถึงไฟล์ดาวน์โหลดเหล่านั้นในรุ่นเผยแพร่ถัดไป

[การตั้งค่าและการเข้าถึงแผงควบคุม](../INSTALLATION.md) ·
[ลายเซ็นและ SHA-256](https://get.destroy.tools/#verification) ·
[อัปเดต](../INSTALLATION.md#update-an-existing-installation) ·
[ความสามารถปัจจุบันและการทดสอบคุณสมบัติ](../STATUS.md) ·
[เลือกวิธีเก็บข้อมูล](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## รายการบันทึกที่ผู้อื่นตรวจสอบได้

ตรวจสอบได้โดยไม่ต้องมีบัญชีหรือติดตั้งอะไร ตัวอย่างที่เผยแพร่มีตัวตรวจสอบของตัวเองมาด้วย:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # ตัวตรวจสอบมาพร้อมอยู่ในไฟล์เก็บถาวร
python verify.py tgwitness-demo.zip          # Python 3.11+ ต้องใช้เพียง `cryptography`
```

คำสั่งนี้แสดงรายการบันทึกที่ลงนาม แฮชของรายการบันทึกล่าสุด และลายนิ้วมือของผู้ลงนาม แล้วจบการทำงานด้วยรหัส `0`
ตัวอย่างนี้เป็นข้อมูลสมมติ ตัวตรวจสอบเดียวกันนี้ใช้ได้กับไฟล์ส่งออกจริงทุกไฟล์

ไฟล์ส่งออกประกอบด้วยข้อความ ไฟล์ และตัวตรวจสอบ
ส่งลายนิ้วมือกุญแจของคุณให้ผู้รับผ่านช่องทางอื่น แล้วผู้รับจะตรวจสอบได้ด้วยตนเอง:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

ตัวตรวจสอบจะตรวจลายเซ็น สายโซ่ของสมุดบันทึก รายการไฟล์ และไฟล์แนบ
หากจะใช้เป็นหลักฐาน ต้องมีลายนิ้วมือกุญแจของคุณ และการประทับเวลาจากบุคคลที่สามที่ครอบคลุมรายการบันทึกสุดท้าย
เช่น การประทับเวลาตาม RFC 3161 ที่ตรวจสอบกับใบรับรองรากของหน่วยงานผู้ออก

**ข้อความมาจากไหน** TgWitness รับข้อความจาก Telegram ผ่านเซสชัน MTProto ที่เข้ารหัสของบัญชี
เช่นเดียวกับแอปทางการ และลงนามแต่ละข้อความลงในสมุดบันทึกทันทีที่มาถึง
[การเก็บข้อมูลผ่าน GitHub Actions](../SEALED-ACTIONS.md) และ
[Phala Intel TDX](../HIGH-ASSURANCE.md) ยังรับรองตัวเก็บข้อมูลที่รับข้อความเหล่านั้นด้วย

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="ข้อความใหม่ การแก้ไขที่บันทึกไว้ และการสังเกตการลบ รวมกันเป็นสมุดบันทึกที่เชื่อมโยงกันและลงนามแล้ว ตรวจสอบเทียบกับกุญแจที่ได้รับความเชื่อถืออย่างเป็นอิสระ">
</picture>

[การตรวจสอบไฟล์เก็บถาวร](../wiki/Exports-and-Verification.md) · [รูปแบบหลักฐาน](../EVIDENCE.md) · [พยานอิสระ](../WITNESS.md) · [การประทับเวลาภายนอก](../TIMESTAMP.md) · [การตรวจสอบและขนาดที่ทดสอบแล้ว](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## จากบทสนทนาสู่คดี

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="เวิร์กโฟลว์แบบเคลื่อนไหวสามแบบ: ส่งออกแชทเป็น HTML และ JSON ค้นหาลิงก์ที่แชร์กันในแชทที่บันทึกไว้ และเก็บเวอร์ชันที่บันทึกได้ไว้หลังมีประกาศการลบ">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>การส่งออกแชท&nbsp;↗</b></a><br><sub>แชทเดียวเป็น HTML และ JSON ที่ลงนามแล้ว</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>การสืบสวน&nbsp;↗</b></a><br><sub>ตามเบาะแสข้ามแชทที่บันทึกไว้</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>เวอร์ชันที่บันทึกไว้&nbsp;↗</b></a><br><sub>เก็บการแก้ไขและประกาศการลบไว้</sub></td>
</tr>
</table>

ใช้งานได้สองแบบ: [ส่งออกบัญชีของคุณ](../ACCOUNT-EXPORT.md)ครั้งเดียว หรือ
[ติดตามการสืบสวน](../INVESTIGATION.md)และบันทึกการเปลี่ยนแปลงอย่างต่อเนื่อง
เลือกบางแชท โฟลเดอร์ Telegram หรือทั้งบัญชี
แต่ละบัญชีมีพื้นที่ทำงาน เซสชัน และกุญแจลงนามของตัวเอง

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## สำรวจเพิ่มเติม

<details>
<summary><strong>การส่งออกที่วัดผลแล้ว · 6 พฤศจิกายน 2026</strong> · 56,329 ข้อความ ไฟล์เก็บถาวรทั้งสองชุดผ่านการตรวจสอบ</summary>

**ส่งออก 56,329 ข้อความจากการรันใหม่สองครั้ง** ไฟล์เก็บถาวรที่ลงนามทั้งสองชุดผ่านการตรวจสอบด้วยกุญแจตัวเก็บข้อมูลที่ปักหมุดไว้

[![ความเร็วการเก็บรวบรวมและความเร็วการส่งออกทั้งหมดที่วัดได้](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/th/docs/validation/)

| การรัน | ข้อความ | เวลาเก็บรวบรวม | ความเร็วเก็บรวบรวม | ส่งออกครบ | ความเร็วตั้งแต่ต้นจนจบ |
| --- | ---: | ---: | ---: | ---: | ---: |
| เซิร์ฟเวอร์ A | 27,030 | 189.043 s | **142.983 ข้อความ/s** | 211.647 s | 127.713 ข้อความ/s |
| เซิร์ฟเวอร์ B | 29,299 | 182.513 s | **160.531 ข้อความ/s** | 206.650 s | 141.781 ข้อความ/s |

ข้อความและเมทาดาทาผ่าน WARP สองบัญชีต่อเซิร์ฟเวอร์ ไม่มีไฟล์แนบหรือรายการบันทึกที่ใช้ซ้ำ
วัดบนรีวิชัน [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e)
การรันที่เผยแพร่แต่ละครั้งระบุรีวิชันของซอร์ส ปริมาณงาน เวลา และผลการตรวจสอบ:
[ปริมาณงาน เวลา และการตรวจสอบ](../EXPORT-BENCHMARK-2026-11-06.md) การเปลี่ยนแปลงใน `main`
จะรัน[เวิร์กโฟลว์ CI](../../.github/workflows/README.md)สาธารณะ รวมถึงการทดสอบตัวติดตั้งบน Linux และ Windows
และการบิลด์ตัวตรวจสอบแบบสแตนด์อโลน

[**ลองใช้เดโม →**](https://phishdestroy.github.io/TgWitness/demo/?lang=th) ·
[**การวัดผล วันที่ และวิธีการ →**](https://phishdestroy.github.io/TgWitness/th/docs/validation/) ·
[ดาวน์โหลดตัวอย่างไฟล์ส่งออกสมมติ](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[รายงานการตรวจประเมินฉบับภาษาอังกฤษที่ลงนามแล้ว](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>เริ่มง่าย เห็นทุกเส้นทาง</strong> · การเริ่มต้นครั้งแรกและแผนผังระบบ</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="การเริ่มต้นครั้งแรกมีตัวเลือก “ดาวน์โหลดอย่างเดียว” “ติดตามแชท” หรือ “หลักฐานในคดี” และแสดงเฉพาะส่วนที่ตรงกัน แผนผังระบบเชื่อมแผงควบคุม ตัวเก็บข้อมูล Telegram สมุดบันทึก พยาน และบริการภายนอก พร้อมข้อมูลสังเกตการณ์เครือข่าย ค่าสมมติ">
</picture>

การเริ่มต้นครั้งแรกถามเพียงคำถามเดียว: **ดาวน์โหลดอย่างเดียว** **ติดตามแชท** หรือ
**หลักฐานในคดี** คำตอบจะกำหนดเป้าหมายและระดับอินเทอร์เฟซ
แผงควบคุมจึงแสดงเฉพาะส่วนที่งานนั้นต้องใช้ การเชื่อมต่อ การลงชื่อเข้าใช้ Telegram
และการเลือกแชทตามมาในห้าขั้นตอน การตรวจสอบการเชื่อมต่อทำงานเอง
และตัวเลือกเส้นทางจะเปิดขึ้นเฉพาะเมื่อการตรวจสอบล้มเหลว เครื่องมือสำหรับผู้เชี่ยวชาญอยู่ห่างไปเพียงสวิตช์เดียว

**แผนผังระบบ** แสดงว่าการติดตั้งเข้าถึง Telegram และบริการภายนอกอย่างไร:
การเข้าถึงแผงควบคุม เส้นทางและปลายทาง Telegram ของแต่ละบัญชี เส้นทางของสมุดบันทึกและพยาน
และข้อมูลสังเกตการณ์เครือข่ายล่าสุด ข้อมูลสังเกตการณ์ที่ขาดหายจะถูกระบุว่าขาดหาย

[ตั้งค่าครั้งแรก](../SETTINGS.md) · [แผนผังระบบ](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>พร้อมสำหรับงานสืบสวนส่วนที่เหลือ</strong> · การ์ดโปรไฟล์ รายการเฝ้าระวัง วอลเล็ต การเฝ้าดูสถานะออนไลน์ เอกสารสำหรับศาล</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="ติดตามชื่อและชื่อผู้ใช้ด้วย Telegram ID บันทึกการโต้ตอบกับบอตที่รองรับพร้อมใบรับที่ลงนาม ค้นหาข้อความที่เก็บถาวรและเชื่อมต่อไคลเอนต์ MCP แบบอ่านอย่างเดียว ติดตั้งตัวเก็บข้อมูลโดยปิดบัง SSH และมีรายการบันทึกของผู้ให้บริการไว้ตรวจทาน บันทึกบทสนทนาทีละขั้นตอนพร้อมการอ้างอิงสมุดบันทึก ส่งมอบชุดคดี BagIt พร้อมแม่แบบเอกสารศาล เวิร์กโฟลว์ตัวอย่าง">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>บุคคลและแฟ้มประวัติ&nbsp;↗</b></a><br><sub>ชื่อและชื่อผู้ใช้ที่ติดตามด้วย Telegram ID</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>การสืบสวนบอต&nbsp;↗</b></a><br><sub>การโต้ตอบกับบอตพร้อมใบรับที่ลงนาม</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/th/docs/archive/"><b>ค้นหาไฟล์เก็บถาวร AI และ MCP&nbsp;↗</b></a><br><sub>ค้นหาในไฟล์เก็บถาวร เชื่อมต่อไคลเอนต์แบบอ่านอย่างเดียว</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>การติดตั้งบนคลาวด์แบบปิดผนึก&nbsp;↗</b></a><br><sub>ตัวเก็บข้อมูลภายใน Intel TDX</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="สามขั้นตอนแบบเคลื่อนไหว: การ์ดโปรไฟล์ที่สแนปช็อตภายหลังบันทึกการเปลี่ยนชื่อ แผนการสนทนาที่เป้าหมายปิดลงด้วยรายการบันทึกในสมุดบันทึก และคิวอาร์โค้ดชำระเงินที่ถอดรหัสได้เป็นวอลเล็ตที่ checksum ถูกต้องและทำให้เกิดการตรงกับรายการเฝ้าระวัง ค่าสมมติ">
</picture>

**บันทึกบทสนทนาเป็นเอกสาร** เริ่มบันทึกสำหรับแชทในแผงด้านข้าง **เอกสาร**
แล้วทุกขั้นตอนจะถูกเขียนลงเอง: การกระทำในแผงควบคุม คำตอบพร้อมระยะเวลาก่อนตอบ
การแก้ไข ประกาศการลบ บันทึกย่อ และร่างจาก AI แต่ละขั้นตอนอ้างอิงรายการบันทึกในสมุดบันทึกและ SHA-256 ของตน
เมื่อปิดเอกสารเป็นฉบับสุดท้าย ระบบจะลงนามเอกสารและเขียนแฮชของคำแถลงลงในสมุดบันทึก

| | |
| --- | --- |
| [การ์ดโปรไฟล์](../INVESTIGATION-MODE.md#subject-cards) | สแนปช็อตโปรไฟล์ของบอต บุคคล ช่อง หรือกลุ่ม พร้อมป้าย BOT, VERIFIED, SCAM และ FAKE ของ Telegram สแนปช็อตที่ถ่ายภายหลังจะแสดงรายการสิ่งที่เปลี่ยนไป |
| [แผนการสนทนา](../INVESTIGATION-MODE.md#conversation-plans) | เป้าหมายเกี่ยวกับเส้นทางการชำระเงิน โครงสร้างพื้นฐาน หรือบุคคล ข้อความที่เตรียมไว้ เวลาตอบกลับ กิจกรรมรายชั่วโมง และสไตล์การเขียนของอีกฝ่าย |
| [การแปล](../INVESTIGATION-MODE.md#machine-translation) | แสดงใต้ต้นฉบับ พร้อมภาษา โมเดล และรายการบันทึกในสมุดบันทึก |
| [รายการเฝ้าระวัง](../INVESTIGATION-MODE.md#watchlists) | คำ รูปแบบ วอลเล็ต @ชื่อผู้ใช้ ID โดเมน หมายเลขโทรศัพท์ และลิงก์ ที่ตรวจจับในข้อความ การแก้ไข ปลายทางลิงก์ที่ซ่อนอยู่ ปุ่มบอต คิวอาร์โค้ด และ OCR |
| [การเฝ้าดูสถานะออนไลน์](../INVESTIGATION-MODE.md#online-watch) | ตรวจทุก 1–60 นาที สูงสุด 100 บัญชีต่อคำขอ พร้อมรูปแบบตามชั่วโมงและวันในสัปดาห์ |
| [โค้ดและวอลเล็ต](../INVESTIGATION-MODE.md#codes-in-images) | คิวอาร์โค้ดชำระเงิน ที่อยู่ EVM ที่ตรวจตาม EIP-55 ที่อยู่ TON แบบ raw checksum ของ XRP Ledger และลิงก์ชำระเงินพร้อมเชน จำนวน และโทเค็น |
| [ร่องรอยของไคลเอนต์](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-can-and-cannot-show) | ร่องรอยของตัวเข้ารหัสในวิดีโอวงกลมและข้อความเสียง การเทียบเวลาอัปโหลดกับเวลาส่งจะเผยหลักฐาน “สด” ที่อัดไว้ล่วงหน้า |
| [การแฝงตัวและอำนาจดำเนินการ](../INVESTIGATION-MODE.md#cover-and-authority) | ตัวตนสมมติ การอนุญาต และรายการบันทึกกิจกรรมแฝงตัวที่ทำเครื่องหมายข้อความนอกแชทหรือช่วงเวลาที่ได้รับอนุญาต |
| [การควบคุมบัญชี](../INVESTIGATION-MODE.md#account-control) | แก้ไขโปรไฟล์และความเป็นส่วนตัวพร้อมรายการบันทึกก่อน/หลัง การตรวจการเปิดเผยข้อมูล และออฟไลน์ทันทีหลังแต่ละการกระทำ |
| [เอกสารสำหรับศาล](../INVESTIGATION-MODE.md#documents-for-court) | ชุดคดี BagIt พร้อมแม่แบบหนังสือรับรองตาม Rule 902(13)/(14) ดัชนีพยานเอกสาร ภาคผนวกคำขอ และคำบรรยาย WebVTT/SRT สำหรับการบันทึกหน้าจอ |

เนื้อหาที่ถูกทำเครื่องหมายว่า 18+ ความรุนแรง หรือข้อมูลส่วนบุคคล จะอยู่ในสำเนาสำหรับศาลซึ่งปิดผนึกด้วย
AES-256-GCM ส่วนกุญแจจะส่งแยกต่างหาก

[การตั้งค่าการส่งออก](../EXPORT_HASHES.md) ครอบคลุมการดึงข้อมูลผ่าน API ปกติและ Takeout
ประวัติข้อความก่อนไฟล์แนบ การดาวน์โหลดไฟล์หรือแฮชจากเซิร์ฟเวอร์ และมุมมอง JSON/HTML
ที่เข้ากันได้กับ Telegram Desktop [การส่งออกแชทแบบกระจาย](../DISTRIBUTED-EXPORT.md#history-acquisition)
มีเส้นทาง Takeout แบบเลือกเปิดใช้สำหรับประวัติสาธารณะ จุดตรวจสอบที่ลงนามทุก 100 ข้อความ
และการกู้คืนภายในช่วงที่กำหนดโดยใช้บัญชีเดิม
ส่วน[การออกแบบด้านประสิทธิภาพ](../FAST-ACQUISITION.md)ระบุพฤติกรรมการดึงข้อมูลที่ทดสอบแล้ว
และการวัดผลในสภาพใช้งานจริงที่วางแผนไว้

</details>

<details>
<summary><strong>ทุกอย่างที่เหลือ</strong> · ประวัติ บัญชี พร็อกซี AI การผสานระบบ</summary>

| | |
| --- | --- |
| [โหลดข้อความเก่า](../HISTORY.md) | ดึงประวัติย้อนหลังของแชทที่เลือก หยุดชั่วคราวและทำต่อได้ทุกเมื่อ |
| [หลายบัญชี](../ACCOUNTS.md#multiple-accounts) | พื้นที่ทำงานแยกกัน แต่ละแห่งมีเซสชัน Telegram สมุดบันทึก และกุญแจลงนามของตัวเอง |
| [นำเข้าเป็นชุด](../ACCOUNTS.md#bulk-import-and-account-groups) | ใส่ไฟล์เซสชันจำนวนมากพร้อมกัน จัดบัญชีเป็นกลุ่มที่ใช้การตั้งค่าร่วมกัน |
| [พูล MTProxy](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | ปิง ประเทศ ตัวกรอง และรายการของคุณเอง |
| [เซสชันที่มีอยู่](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key หรือบรรทัด `key:DC` และเลือกสร้างการอนุญาตแบบอิสระผ่าน QR จากเซสชันต้นทางที่นำเข้าได้ |
| [ความปลอดภัยของบัญชี](../ACCOUNTS.md#create-an-independent-authorization) | การแจ้งเตือนเซสชันใหม่ การยุติเซสชันอื่น โหมดเซสชันเดียวที่ตั้งรหัสผ่านสองขั้นตอนด้วย และ[การตรวจสอบโดยพยาน](../ACCOUNTS.md#witness-probe)ที่สังเกตได้เมื่ออัปเดตสดหยุดมาถึงเซสชันนี้ |
| [การส่งออกแชทที่ทำต่อได้](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | การส่งออกที่หยุดไปจะเก็บสำเนาบางส่วนที่ลงนามไว้: ทำต่อ เริ่มใหม่ หรือดาวน์โหลดส่วนที่บันทึกไว้ |
| [พร็อกซี](../CONNECTION-SECURITY.md#ip-modes) | SOCKS5, HTTP CONNECT หรือ MTProxy ต่อพื้นที่ทำงาน **ซ่อน IP** จะไม่ย้อนกลับไปเชื่อมต่อโดยตรง |
| [การค้นหาและ AI](../ANALYSIS.md) | ค้นหาภายในเครื่อง และ AI แบบเลือกใช้พร้อมแหล่งที่มาที่ตรวจสอบได้ |
| [การค้นหาข้อความเต็ม](../SEARCH.md) | รูปคำ วลีตรงตัว โดเมน @ชื่อผู้ใช้ และภาษาจีนที่ไม่มีช่องว่าง เรียงผลที่ตรงที่สุดก่อน (**รุ่นทดลอง**) |
| [MCP](../MCP.md) | การเข้าถึงแบบอ่านอย่างเดียวสำหรับไคลเอนต์ MCP จำกัดเฉพาะแชทที่คุณเลือก |
| [บรรทัดคำสั่ง](../CLI.md) | `search`, `context`, `messages`, `stats` และ `export` แบบ JSON Lines พร้อม `--json` สำหรับสคริปต์และเอเจนต์ ใช้ภายในเครื่องหรือด้วยโทเค็นที่จำกัดขอบเขต (**รุ่นทดลอง**) |
| [OCR และการถอดเสียง](../MEDIA-ANALYSIS.md) | ทำงานภายในเครื่อง ไฟล์ต้นฉบับไม่ถูกแตะต้อง |
| [การเก็บข้อมูลอิสระ](../OPTIONAL-CAPTURE.md) | ตัวบันทึกเบราว์เซอร์/AyuGram แบบเลือกใช้ใน **เครื่องมือเพิ่มเติม → ส่วนเสริม** (รุ่นทดลอง ปิดไว้โดยค่าเริ่มต้น) |
| [Trusted Live](../TRUSTED-LIVE.md) | เซสชัน Desktop/Web ทางการ วิดีโอที่มีการป้องกัน และการวิเคราะห์ความต่อเนื่องกับการส่งออกแบบเนทีฟ (รุ่นทดลอง รอการทดสอบคุณสมบัติในสภาพจริง) |
| [Web ทางการแบบปิดผนึก](../OFFICIAL-WITNESS.md) | เบราว์เซอร์ทางการที่เปิดใหม่บน GitHub Actions การควบคุมแบบจำกัด วิดีโอที่ลงนาม และซอร์ส/การตั้งค่าที่คาดหมายไว้อย่างเป็นอิสระ |
| [เว็บฮุก](../WEBHOOKS.md) | อีเวนต์ขาออกที่ลงนามพร้อมการลองใหม่ มีตัวอย่าง n8n |
| [การเข้าถึงร่วม](../ACCESS.md) | ให้ผู้อื่นเข้าถึงเฉพาะแชทที่เลือก พร้อมวันหมดอายุและข้อจำกัด IP |
| [หมายเลขข้อความที่ขาดหาย](../EVIDENCE.md#missing-message-numbers-gap_summary) | หมายเลขที่ Telegram กำหนดแต่ไม่เคยถูกสังเกตเห็น แยกตามช่องและทั้งบัญชี แสดงในขอบเขตการครอบคลุม รายงาน และ MCP (**รุ่นทดลอง**) |
| [สแนปช็อตสถานะแชท](../COLLECTION.md) | สแนปช็อตที่ลงนามเป็นระยะของชื่อ คำอธิบาย ข้อความที่ปักหมุด ผู้ดูแล และของขวัญ พร้อมสิ่งที่เปลี่ยนไป (**รุ่นทดลอง**) |
| [แผนผังระบบ](../SYSTEM-MAP.md) | แผนผังสดของการเข้าถึงแผงควบคุม เส้นทางของบัญชี ปลายทาง Telegram และบริการภายนอก พร้อมข้อมูลสังเกตการณ์เครือข่ายล่าสุด 200 รายการจากสูงสุด 2,000 รายการ |

</details>

<details>
<summary><strong>เลือกสิ่งที่รองรับรายการบันทึก</strong> · ภายในเครื่อง คลาวด์ที่ผ่านการตรวจประเมิน GitHub Actions หรือ Intel TDX</summary>

รันภายในเครื่อง เพิ่มการติดตั้งบนคลาวด์ที่ผ่านการตรวจประเมิน หรือเก็บข้อมูลภายใน **Confidential VM
ของ Phala Cloud ที่ใช้ Intel TDX** ทุกตัวเลือกยังคงมีสมุดบันทึกที่ลงนาม
ส่วนการตรวจสอบเพิ่มเติมจะครอบคลุมสภาพแวดล้อมที่ใช้เก็บข้อมูล

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="ตัวเลือกการติดตั้งสามแบบ: การตรวจสอบสมุดบันทึกภายในเครื่อง VM ที่ผ่านการตรวจประเมินพร้อมรายการบันทึกของผู้ให้บริการและการเข้าถึง และ Phala Intel TDX พร้อม quote ที่ตรวจสอบแล้ว OS และแอปพลิเคชันที่วัดค่าแล้ว และกุญแจตัวเก็บข้อมูลที่ผูกไว้">
</picture>

ตัวตรวจสอบ TDX ตรวจ quote เทียบกับรากและข้อมูลการเพิกถอนของ Intel ที่ปักหมุดไว้
ผูก quote เข้ากับคำแถลงที่ลงนามของตัวเก็บข้อมูลและ challenge ใหม่ แล้วเปรียบเทียบ
OS และแอปพลิเคชันที่วัดค่าแล้วกับอินพุตที่คาดหมายไว้อย่างเป็นอิสระ
รายงานแสดงผลแต่ละรายการแยกกัน จึงตรวจทานสภาพแวดล้อมที่วัดค่า ตัวตนของตัวเก็บข้อมูล
รายการบันทึกการเก็บข้อมูล และความครอบคลุมไปพร้อมกันได้

**การเก็บข้อมูลพร้อมหลักฐานที่มาจาก GitHub** (รุ่นทดลอง) เก็บแชทบน runner ที่ GitHub โฮสต์
โดยใช้ TgWitness ที่ปักหมุดเวอร์ชันและเซสชัน Telegram ใหม่ แล้วดาวน์โหลดไฟล์เก็บถาวรที่เข้ารหัสพร้อมการรับรองจาก GitHub
ตัวตรวจสอบจะตรวจเวิร์กโฟลว์ที่อนุมัติและเวอร์ชันตัวเก็บข้อมูล ไดเจสต์ของไฟล์เก็บถาวร สมุดบันทึก และไฟล์แนบ
ใช้งานได้จาก **การส่งออก** ในแผงควบคุมด้วย
[เปิดหน้าการเก็บข้อมูล](https://phishdestroy.github.io/TgWitness/th/docs/capture/) · [คำแนะนำ](../SEALED-ACTIONS.md)

สำหรับการเฝ้าสังเกตแบบสด ประวัติ หรือการส่งออกครั้งเดียว ให้เลือก[วิธีเก็บข้อมูล](../COLLECTION-MODES.md)
แชทส่วนตัวบนคลาวด์ใช้ได้เมื่อบัญชีที่เชื่อมต่อเข้าถึงแชทนั้นได้
แอปพลิเคชันที่เผยแพร่ยังมี[การผสานรวมแชทลับ](../PSEUDO-SECRET.md)ด้วย: ติดตั้ง dependency
ของโปรโตคอลที่เป็นตัวเลือก แล้วเปิดใช้แยกตามบัญชีเพื่อบันทึกแชทที่สร้างหรือยอมรับที่นั่น
ดู[ขอบเขตการเก็บข้อมูล](../COLLECTION.md)สำหรับเส้นทางการดึงข้อมูลที่มีให้ใช้

[Phala / Intel TDX และการติดตั้งที่ผ่านการตรวจประเมิน](../HIGH-ASSURANCE.md) ·
[การทดสอบคุณสมบัติบน Phala ในสภาพจริง](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[ขอบเขตความเชื่อถือ](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>ตรวจสอบการเก็บข้อมูลและรายการบันทึกที่เก็บไว้</strong> · สิ่งที่ผู้รับตรวจสอบ และ Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="เก็บบทสนทนาไว้ ตรวจสอบรายการบันทึก บันทึกข้อความ การแก้ไข และไฟล์ ตรวจลายเซ็นและจุดตรวจสอบ และตรวจทานกระบวนการเก็บข้อมูล">
</picture>

TgWitness บันทึกเนื้อหาที่ส่งถึงบัญชี Telegram ที่เชื่อมต่อ พร้อมตัวระบุของแชท ข้อความ และผู้ส่ง
เวอร์ชันที่เก็บได้ และเมทาดาทาการเก็บข้อมูล
ไฟล์เก็บถาวรรวบรวมรายการบันทึกเหล่านั้น ไฟล์แนบที่เก็บรักษาไว้ และข้อมูลสำหรับการตรวจสอบไว้ด้วยกันเพื่อการตรวจทาน

| การตรวจสอบ | สิ่งที่ผู้รับตรวจสอบ |
| --- | --- |
| สมุดบันทึกและแมนิเฟสต์ที่ลงนาม | ลายเซ็นของรายการบันทึก สายแฮช และไฟล์ที่ส่งมอบ เทียบกับกุญแจลงนามที่คาดหมาย |
| จุดตรวจสอบที่เก็บแยกไว้ต่างหาก | สมุดบันทึก เทียบกับความยาวและแฮชของรายการบันทึกล่าสุดที่บันทึกไว้ก่อนหน้า |
| พยานอิสระ | สมุดบันทึก เทียบกับจุดตรวจสอบที่พยานแยกต่างหากเก็บไว้ |
| การเก็บข้อมูลผ่าน GitHub Actions | ไฟล์เก็บถาวร เทียบกับการรับรอง เวิร์กโฟลว์โฮสต์ที่อนุมัติ และเวอร์ชันตัวเก็บข้อมูล |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
แสดงบทสนทนา Telegram เคียงข้างไฟล์ส่งออกของ Desktop ที่ถูกดัดแปลงโดยเจตนา
เปรียบเทียบเวอร์ชัน ตรวจดูการเปลี่ยนแปลง และทำตามขั้นตอนการเก็บข้อมูลและการตรวจสอบสำหรับไฟล์เก็บถาวร TgWitness ที่ลงนาม

[ขั้นตอนการตรวจสอบ](../wiki/Exports-and-Verification.md) ·
[การเก็บข้อมูลผ่าน GitHub](../SEALED-ACTIONS.md) ·
[โมเดลความเชื่อถือทางเทคนิค](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>ให้การสืบสวนดำเนินต่อไป</strong> · การแจ้งเตือน ที่เก็บข้อมูล และการกู้คืน</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="เวิร์กโฟลว์แบบเคลื่อนไหว: Apprise ส่งการแจ้งเตือนตามที่ตั้งค่าไว้ สำเนานอกสถานที่จะถูกเข้ารหัสก่อนอัปโหลดไปยังที่เก็บข้อมูลที่เข้ากันได้กับ S3">
</picture>

[การแจ้งเตือน](../OPERATIONS.md#notifications) · [สำเนานอกสถานที่ที่เข้ารหัส](../wiki/Off-site-Copy.md) · [การสำรองและกู้คืนข้อมูล](../wiki/Backup-and-Recovery.md) · [การแก้ไขปัญหา](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/th/docs/start/"><b>คู่มือการตั้งค่า&nbsp;↗</b></a><br><sub>ตั้งแต่ติดตั้งจนถึงแชทแรก</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/th/docs/dedicated-account/"><b>เตรียมบัญชีของคุณ&nbsp;↗</b></a><br><sub>บัญชี Telegram แยกต่างหาก</sub></td>
<td width="33%" align="center"><a href="../DEPLOYMENT.md"><b>Docker และเซิร์ฟเวอร์&nbsp;↗</b></a><br><sub>HTTPS การรีสตาร์ต และการอัปเดต</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>สำรวจรีโพซิทอรี</strong> · โค้ด เอกสาร และเครื่องมืออยู่ที่ไหน</summary>

| ไดเรกทอรี | เริ่มที่นี่ |
| --- | --- |
| [docs/](../README.md) | การตั้งค่า เวิร์กโฟลว์การสืบสวน และเอกสารอ้างอิงทางเทคนิค |
| [tgwitness/](../../tgwitness/README.md) | แอปพลิเคชันหลัก ตัวเก็บข้อมูล สมุดบันทึก และแผงควบคุมบนเว็บ |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | ตัวบันทึกอิสระและโค้ดตรวจสอบของตัวบันทึกเหล่านั้น |
| [addons/](../../addons/README.md) | การติดตั้ง การกำหนดค่า และการทดสอบส่วนเก็บข้อมูลเสริม |
| [deploy/](../../deploy/README.md) | ตัวติดตั้ง คอนเทนเนอร์ และบริการเบื้องหลัง |
| [examples/](../../examples/README.md) | การกำหนดค่าสำหรับการส่งออกบัญชีและการเก็บข้อมูลแบบปิดผนึก |
| [integrations/](../../integrations/README.md) | เว็บฮุกที่ลงนามและตัวรับสำหรับ n8n |
| [.agents/](../../.agents/README.md) | คำสั่งงานสำหรับอ่านไฟล์เก็บถาวรผ่าน CLI |
| [scripts/](../../scripts/README.md) | ตัวเรียกใช้งานและยูทิลิตี CI |
| [tools/](../../tools/README.md) | การบิลด์ การตรวจสอบ และการแพ็กเกจ |
| [website/](../../website/README.md) | เว็บไซต์สาธารณะ คู่มือที่แปลแล้ว และเดโมแบบโต้ตอบ |
| [.github/](../../.github/AUTOMATION.md) | เวิร์กโฟลว์ แนวทางการมีส่วนร่วม และการสนับสนุน |

[คู่มือโปรเจกต์ฉบับสมบูรณ์](../PROJECT-GUIDE.md) ·
[การมีส่วนร่วม](../../.github/CONTRIBUTING.md) · [ขอความช่วยเหลือ](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ ประกาศด้านจริยธรรมและความต่อเนื่องทางประวัติศาสตร์</strong></summary>

จุดยืนของผู้เขียนและประกาศถึงผู้ดำเนินการ ในภาษานี้:

[ประกาศเรื่องใบอนุญาตและความไม่เข้ากันทางสถาปัตยกรรม](TAYLOR-WESSING-EXCLUSION.md) · [ประกาศถึงผู้ดำเนินการ](OPERATOR-INCOMPATIBILITY.md) · [สัญญาอนุญาต MIT](../../LICENSE) · [NOTICE ฉบับดั้งเดิม](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>อ่านภาพรวมของโปรเจกต์ในภาษาของคุณ</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · **ไทย** · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>เอกสารทางเทคนิค</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>คู่มือการสืบสวน</b></a> ·
  <a href="https://github.com/phishdestroy"><b>สร้างโดย PhishDestroy</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>ร่วมพัฒนา</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>ขอความช่วยเหลือ</b></a> ·
  <a href="../../.github/SECURITY.md"><b>รายงานช่องโหว่</b></a>
</p>

[ดัชนีโปรเจกต์ที่เครื่องอ่านได้](../../llms.txt) · [คู่มือฉบับข้อความเต็ม](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [กฎของรีโพซิทอรีสำหรับเอเจนต์](../../AGENTS.md)
