<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">다른 언어</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — 흔적을 따라가고, 증거를 보존합니다. 해시로 연결된 서명된 저널, 별도로 보관되는 체크포인트, 검증 가능한 증거 아카이브.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=ko"><b>데모 둘러보기&nbsp;↗</b></a><br><sub>가상의 기록으로 보는 실제 인터페이스</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>다운로드하고 시작하기&nbsp;↓</b></a><br><sub>Linux, macOS, Windows용 명령 한 줄</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>핸드북 읽기&nbsp;↗</b></a><br><sub>단계별 조사 가이드</sub></td>
</tr>
</table>

<p align="center"><strong>Telegram 조사를 위한 자체 호스팅 작업 공간.</strong><br>채팅을 저장하고, 수정과 삭제를 보존하고, 누가 누구와 연결되어 있는지 파악하고,<br>누구나 확인할 수 있는 서명된 내보내기 파일을 넘겨줄 수 있습니다.</p>

<p align="center"><strong>제로 트러스트.</strong> TgWitness는 어느 편도 들지 않습니다. 운영자에게도, PhishDestroy에도, 그 밖의 누구에게도 같은 검사를 적용합니다.<br>제3자나 수학이 확인해 주는 것만 인정됩니다. <a href="../LIMITS-AND-OBJECTIONS.md">한계와 반론</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.2 · 사전 릴리스"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">테스트된 환경</a> · 인터페이스 25개 언어 · 가이드 26개 언어</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=ko">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="작동 중인 TgWitness 데모: 캡처된 메시지, 저장된 버전, 삭제 후에도 보존된 내용. 가상의 시연용 기록.">
</picture>
</a>

<p align="center"><sub>가상의 기록으로 실제 인터페이스를 살펴보세요. 작업 공간을 클릭하면 직접 사용해 볼 수 있습니다.</sub></p>

## TgWitness가 하는 일

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">모든 수정과 삭제를 보존</a></b><br><sub>메시지의 모든 버전이 저장되며, 삭제 알림 후에도 텍스트가 남습니다.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">누구나 확인할 수 있는 증명</a></b><br><sub>서명되고 해시 체인으로 연결된 기록. 받는 사람은 명령 하나로 아카이브를 오프라인에서 검증합니다.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">보여 줄 수 있는 출처</a></b><br><sub>계정의 인증된 MTProto 세션으로 수신하고 도착 즉시 서명합니다. GitHub Actions와 Intel TDX가 어테스테이션을 더합니다.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">대규모로 측정</a></b><br><sub>검증된 아카이브 48개, 기록 3,598,381건. 계정 8개가 히스토리 기록 768,007건을 초당 687.5건의 속도로 가져왔습니다.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">조사를 위한 설계</a></b><br><sub>텍스트, QR 코드, OCR을 아우르는 감시 목록, 지갑 확인, 대상 카드, 사건 보드, 법원 제출 패키지.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">직접 운영</a></b><br><sub>텔레메트리 없는 자체 호스팅. 세션은 암호화된 볼트에 저장되고, 패널은 localhost에서 수신 대기합니다.</sub></td>
</tr>
</table>

<p align="center"><sub>약 6개월 동안 개발 및 테스트를 진행했습니다: 먼저 수집기, 서명된 저널, 검증기를 개발하고 테스트한 뒤, 패널과 추가 모듈을 개발 및 테스트했습니다. 이 저장소는 2026년 10월 29일 공개를 위해 생성되었으므로, 저장소의 생성일은 프로젝트의 개발 기간과 일치하지 않습니다.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## 설치

Python이 포함되어 있습니다. 업데이트할 때도 같은 명령을 사용합니다.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell 또는 CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Ubuntu 서버: root로 실행합니다. 데스크톱: 일반 사용자로 실행합니다. `-ExecutionPolicy Bypass`는 이 PowerShell 프로세스 하나에만 적용됩니다.</sub>

서명된 빌드는 공개 [Installer 워크플로](../../.github/workflows/installer.yml)에서 만들어지며, 설치 프로그램은 설치 전에 모든 패키지의 SHA-256과 RSA 서명을 확인합니다.

[먼저 스크립트 검증하기](../INSTALLATION.md#verify-before-running) · [첫 설정](../SETTINGS.md) · [릴리스](https://github.com/phishdestroy/TgWitness/releases) · [Docker](../DEPLOYMENT.md)

<details>
<summary><strong>설치 프로그램과 데이터를 보호하는 방법</strong></summary>

`get.destroy.tools`는 프로젝트의 다운로드 사이트입니다. 공개
[Installer 워크플로](../../.github/workflows/installer.yml)가
[`deploy/installer/`](../../deploy/installer/README.md)에서 정확한 `main` 리비전을 기준으로 사이트를 빌드하고,
Linux와 Windows 설치 테스트를 통과하면 게시하며,
[`release-signing.pub`](../../deploy/installer/release-signing.pub)의 릴리스 키로 설치 스크립트와
애플리케이션 패키지에 서명합니다. 설치 프로그램은 설치 전에 패키지와 의존성 잠금 파일의
SHA-256 및 RSA 서명을 확인합니다. 스크립트 자체를 먼저 확인하려면 서명과 함께 내려받은 뒤
[먼저 검증하는 명령](../INSTALLATION.md#verify-before-running)을 실행하세요. 빌드가 실패하면
이전 다운로드가 그대로 유지되며, 설치된 패널은 설치 프로그램을 다시 실행하면 업데이트됩니다.
GitHub [릴리스](https://github.com/phishdestroy/TgWitness/releases), 소스 코드,
[Docker](../DEPLOYMENT.md)로도 설치할 수 있습니다.

**세션과 데이터.** TgWitness는 사용자의 컴퓨터나 서버에서 실행되며, 패널은
기본적으로 localhost에서 수신 대기합니다. Telegram 세션, 프록시 자격 증명, 액세스 토큰
해시는 각 작업 공간의 암호화된 볼트에 저장되며, 선택적으로
[외부 마스터 키](../SECURITY-MODEL.md#external-master-key)를 사용할 수 있습니다. 애플리케이션에는
텔레메트리가 없습니다. 애플리케이션은 Telegram과 설정에서 사용하는 서비스에 연결합니다:
공개 MTProxy 목록, 사용자의 프록시, S3 스토리지, 증인 봇, 타임스탬프
기관, AI 제공업체, 웹훅. [시스템 지도](../SYSTEM-MAP.md)에는
애플리케이션 프로세스가 맺는 연결이 나열되어 있습니다.
관찰에는 [전용 Telegram 계정](https://phishdestroy.github.io/TgWitness/ko/docs/dedicated-account/)을 사용하세요.

버전 배지는 이 소스 트리를 기준으로 합니다. 설치 가능한 빌드는
[릴리스](https://github.com/phishdestroy/TgWitness/releases)에 나와 있으며, `main`에 병합된
기능은 다음 릴리스 때 해당 다운로드에 포함됩니다.

[설정과 패널 접속](../INSTALLATION.md) ·
[서명과 SHA-256](https://get.destroy.tools/#verification) ·
[업데이트](../INSTALLATION.md#update-an-existing-installation) ·
[현재 기능과 적격성 평가](../STATUS.md) ·
[수집 방법 선택](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## 다른 사람이 확인할 수 있는 기록

계정도 설치도 없이 확인할 수 있습니다. 공개된 샘플에는 자체 검증 도구가 들어 있습니다:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # 검증 도구는 아카이브 안에 들어 있습니다
python verify.py tgwitness-demo.zip          # Python 3.11+, `cryptography`만 있으면 됩니다
```

서명된 기록, 가장 최근 기록의 해시, 서명자 지문을 출력하고 `0`으로 종료합니다.
샘플은 가상의 데이터이며, 같은 검증 도구를 실제 내보내기 파일에도 그대로 사용할 수 있습니다.

내보내기 파일에는 메시지, 파일, 검증 도구가 들어 있습니다. 키 지문을 다른 채널로
받는 사람에게 보내면 받는 사람이 직접 확인할 수 있습니다:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

검증 도구는 서명, 저널 체인, 파일 목록, 첨부 파일을 확인합니다.
증거로 쓰려면 키 지문과 함께 마지막 기록까지 포함하는 제3자 타임스탬프가 필요합니다.
타임스탬프 기관의 루트 인증서로 확인한 RFC 3161 타임스탬프가 그 예입니다.

**메시지의 출처.** TgWitness는 공식 앱과 마찬가지로 계정의 암호화된 MTProto 세션을 통해
Telegram에서 메시지를 받고, 도착하는 메시지를 하나씩 서명해 저널에
기록합니다. [GitHub Actions 캡처](../SEALED-ACTIONS.md)와
[Phala Intel TDX](../HIGH-ASSURANCE.md)는 메시지를 받은 수집기에 대한 어테스테이션도 제공합니다.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="새 메시지, 저장된 수정 내역, 삭제 관찰 기록이 서로 연결된 서명된 저널을 이룹니다. 독립적으로 신뢰가 확인된 키로 검증하세요.">
</picture>

[아카이브 검증](../wiki/Exports-and-Verification.md) · [증거 형식](../EVIDENCE.md) · [독립적인 증인](../WITNESS.md) · [외부 타임스탬프](../TIMESTAMP.md) · [검사 항목과 테스트 규모](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## 대화에서 사건으로

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="애니메이션 워크플로 세 가지: 채팅을 HTML과 JSON으로 내보내기, 기록된 채팅 전체에서 공유된 링크 찾기, 삭제 알림 후에도 캡처된 버전 보존하기.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>채팅 내보내기&nbsp;↗</b></a><br><sub>채팅 하나를 서명된 HTML과 JSON으로</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>조사&nbsp;↗</b></a><br><sub>기록된 채팅 전반에서 단서 추적</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>저장된 버전&nbsp;↗</b></a><br><sub>수정과 삭제 알림을 그대로 보존</sub></td>
</tr>
</table>

사용 방법은 두 가지입니다. [계정 내보내기](../ACCOUNT-EXPORT.md)를 한 번 실행하거나,
[조사를 이어 가며](../INVESTIGATION.md) 변경 사항을 계속 저장할 수 있습니다.
채팅 몇 개, Telegram 폴더 하나 또는 계정 전체를 선택하세요. 계정마다
별도의 작업 공간, 세션, 서명 키가 주어집니다.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## 더 살펴보기

<details>
<summary><strong>내보내기 측정 · 2026년 11월 6일</strong> · 메시지 56,329건, 두 아카이브 모두 검증 완료</summary>

**새로 실행한 두 번의 작업에서 메시지 56,329건을 내보냈습니다.** 두 서명된 아카이브 모두 고정된 수집기 키로 검증을 통과했습니다.

[![측정된 수집 속도와 전체 내보내기 속도](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/ko/docs/validation/)

| 실행 | 메시지 | 수집 시간 | 수집 속도 | 전체 내보내기 | 엔드투엔드 속도 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 서버 A | 27,030 | 189.043초 | **142.983 메시지/초** | 211.647초 | 127.713 메시지/초 |
| 서버 B | 29,299 | 182.513초 | **160.531 메시지/초** | 206.650초 | 141.781 메시지/초 |

WARP를 통한 텍스트와 메타데이터, 서버당 계정 2개, 첨부 파일이나 재사용된 기록은 없습니다.
측정 리비전은 [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e)입니다.
공개된 각 실행에는 소스 리비전, 작업량, 소요 시간, 검증 결과가 나와 있습니다:
[작업량, 소요 시간, 검증](../EXPORT-BENCHMARK-2026-11-06.md). `main`에 대한 변경 사항은
Linux 및 Windows 설치 프로그램 테스트와 독립 실행형 검증 도구 빌드를 포함한
공개 [CI 워크플로](../../.github/workflows/README.md)를 거칩니다.

[**데모 둘러보기 →**](https://phishdestroy.github.io/TgWitness/demo/?lang=ko) ·
[**측정값, 날짜, 방법 →**](https://phishdestroy.github.io/TgWitness/ko/docs/validation/) ·
[가상의 샘플 내보내기 파일 다운로드](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[서명된 영문 감사 보고서](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>간단하게 시작하고, 모든 경로를 확인하세요.</strong> · 첫 시작과 시스템 지도</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="첫 시작 화면에서 ‘다운로드만’, ‘채팅 지켜보기’, ‘사건에 대한 증거’ 중 하나를 고르면 해당하는 섹션만 표시됩니다. 시스템 지도는 패널, 수집기, Telegram, 저널, 증인, 외부 서비스의 연결을 네트워크 관찰 기록과 함께 보여 줍니다. 가상의 값입니다.">
</picture>

첫 시작에서는 질문이 하나뿐입니다. **다운로드만**, **채팅 지켜보기**,
**사건에 대한 증거** 중 하나를 고르세요. 답에 따라 목표와 인터페이스 수준이 정해지고, 패널에는
그 작업에 필요한 섹션만 표시됩니다. 이어서 연결, Telegram 로그인,
채팅 선택이 다섯 단계로 진행됩니다. 연결 확인은 자동으로 실행되며, 실패했을 때만
경로 옵션이 열립니다. 전문가용 도구는 스위치 하나로 켤 수 있습니다.

**시스템 지도**는 설치 환경이 Telegram과 외부 서비스에 어떻게 연결되는지 보여 줍니다:
패널 접속, 각 계정의 경로와 Telegram 대상, 저널과
증인 경로, 최신 네트워크 관찰 기록. 관찰 기록이 없으면
없다고 표시됩니다.

[첫 설정](../SETTINGS.md) · [시스템 지도](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>나머지 조사 과정까지</strong> · 대상 카드, 감시 목록, 지갑, 온라인 감시, 법원 제출 문서</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Telegram ID로 이름과 사용자 이름을 추적합니다. 지원되는 봇과의 상호작용을 서명된 영수증과 함께 기록합니다. 보관된 메시지를 검색하고 읽기 전용 MCP 클라이언트를 연결합니다. SSH를 가리고 제공업체 기록을 검토용으로 남긴 채 수집기를 배포합니다. 저널 참조와 함께 대화를 단계별로 기록합니다. 법원 템플릿이 포함된 BagIt 사건 패키지를 넘겨줍니다. 예시 워크플로입니다.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>인물과 신상 파일&nbsp;↗</b></a><br><sub>Telegram ID로 추적하는 이름과 사용자 이름</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>봇 조사&nbsp;↗</b></a><br><sub>서명된 영수증이 남는 봇 상호작용</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/ko/docs/archive/"><b>아카이브 검색, AI, MCP&nbsp;↗</b></a><br><sub>아카이브 검색, 읽기 전용 클라이언트 연결</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>봉인된 클라우드 배포&nbsp;↗</b></a><br><sub>Intel TDX 안에서 실행되는 수집기</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="애니메이션 단계 세 가지: 이후 스냅샷에 이름 변경이 기록되는 대상 카드, 저널 기록으로 목표가 하나씩 완료되는 대화 계획, 체크섬이 유효한 지갑으로 디코딩되어 감시 목록 일치를 일으키는 결제 QR 코드. 가상의 값입니다.">
</picture>

**대화 기록하기.** **문서** 드로어에서 채팅 기록을 시작하면
모든 단계가 자동으로 기록됩니다: 패널 작업, 답장과 그 전까지의 지연 시간,
수정, 삭제 알림, 메모, AI 초안. 각 단계에는 해당 저널 기록과 SHA-256이 인용됩니다.
문서를 확정하면 서명되고 진술서 해시가
저널에 기록됩니다.

| | |
| --- | --- |
| [대상 카드](../INVESTIGATION-MODE.md#subject-cards) | 봇, 사람, 채널, 그룹의 프로필 스냅샷과 Telegram의 BOT, VERIFIED, SCAM, FAKE 라벨. 이후 스냅샷에는 바뀐 점이 표시됩니다 |
| [대화 계획](../INVESTIGATION-MODE.md#conversation-plans) | 결제 경로, 인프라, 관련 인물에 관한 목표, 미리 준비한 메시지, 답장 시간, 시간대별 활동, 상대방의 문체 |
| [번역](../INVESTIGATION-MODE.md#machine-translation) | 원문 아래에 언어, 모델, 저널 기록과 함께 표시 |
| [감시 목록](../INVESTIGATION-MODE.md#watchlists) | 단어, 패턴, 지갑, @사용자 이름, ID, 도메인, 전화번호, 링크를 텍스트, 수정 내역, 숨겨진 링크 대상, 봇 버튼, QR 코드, OCR에서 찾아냄 |
| [온라인 감시](../INVESTIGATION-MODE.md#online-watch) | 1–60분마다 확인, 요청당 최대 100개 계정, 시간대와 요일별 패턴 제공 |
| [코드와 지갑](../INVESTIGATION-MODE.md#codes-in-images) | 결제 QR 코드. EIP-55로 확인하는 EVM 주소, 원시 형식의 TON, XRP Ledger 체크섬, 체인·금액·토큰이 담긴 결제 링크 |
| [클라이언트 흔적](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-can-and-cannot-show) | 원형 동영상과 음성 메시지의 인코더 흔적. 업로드 시각과 전송 시각을 비교하면 미리 녹화한 ‘라이브’ 증거가 드러납니다 |
| [위장 신분과 권한](../INVESTIGATION-MODE.md#cover-and-authority) | 페르소나, 승인 문서, 그리고 승인된 채팅이나 기간을 벗어난 메시지를 표시하는 잠입 활동 기록 |
| [계정 관리](../INVESTIGATION-MODE.md#account-control) | 변경 전후 기록이 남는 프로필 및 개인정보 설정 편집, 노출 점검, 각 작업 직후 오프라인 전환 |
| [법원 제출 문서](../INVESTIGATION-MODE.md#documents-for-court) | Rule 902(13)/(14) 인증서 템플릿, 증거물 색인, 요청서 부속서, 화면 녹화용 WebVTT/SRT 자막이 포함된 BagIt 사건 패키지 |

18+, 폭력, 개인 데이터로 표시된 콘텐츠는 법원 제출용 사본에 남으며
AES-256-GCM으로 봉인되고, 키는 따로 전달됩니다.

[내보내기 설정](../EXPORT_HASHES.md)은 일반 API와 Takeout 수집,
첨부 파일보다 메시지 히스토리를 먼저 가져오는 방식, 파일 다운로드 또는 서버 해시, 호환되는
Telegram Desktop JSON/HTML 보기를 다룹니다. [분산 채팅 내보내기](../DISTRIBUTED-EXPORT.md#history-acquisition)는
공개 히스토리에 대한 선택형 Takeout 경로, 100개 메시지마다 서명되는 체크포인트,
같은 계정을 사용한 범위 내 복구를 제공합니다.
[성능 설계](../FAST-ACQUISITION.md) 문서에는 테스트된 수집 동작과
예정된 실환경 측정이 정리되어 있습니다.

</details>

<details>
<summary><strong>그 밖의 기능</strong> · 히스토리, 계정, 프록시, AI, 연동</summary>

| | |
| --- | --- |
| [이전 메시지 불러오기](../HISTORY.md) | 선택한 채팅의 과거 히스토리를 가져오며, 언제든 일시 중지하고 재개 가능 |
| [여러 계정](../ACCOUNTS.md#multiple-accounts) | 각자 Telegram 세션, 저널, 서명 키를 갖춘 별도의 작업 공간 |
| [일괄 가져오기](../ACCOUNTS.md#bulk-import-and-account-groups) | 세션 파일을 한꺼번에 넣고, 설정을 공유하는 그룹으로 계정을 분류 |
| [MTProxy 풀](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | 핑, 국가, 필터, 직접 만든 목록 |
| [기존 세션](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key 또는 `key:DC` 형식의 줄. 가져온 기증 계정을 통한 독립 QR 인증(선택) |
| [계정 보안](../ACCOUNTS.md#create-an-independent-authorization) | 새 세션 알림, 다른 세션 종료, 2단계 인증 비밀번호도 설정하는 단독 세션 모드, 그리고 실시간 업데이트가 이 세션에 더 이상 도달하지 않으면 이를 알아차리는 [증인 프로브](../ACCOUNTS.md#witness-probe) |
| [재개 가능한 채팅 내보내기](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | 중단된 내보내기는 서명된 부분 사본으로 남으며, 이어서 진행하거나 처음부터 다시 하거나 저장된 부분을 내려받을 수 있음 |
| [프록시](../CONNECTION-SECURITY.md#ip-modes) | 작업 공간별 SOCKS5, HTTP CONNECT 또는 MTProxy. **IP 숨기기**는 절대 직접 연결로 전환하지 않음 |
| [검색과 AI](../ANALYSIS.md) | 로컬 검색, 출처를 확인할 수 있는 선택형 AI |
| [전체 텍스트 검색](../SEARCH.md) | 어형 변화, 정확한 구문, 도메인, @사용자 이름, 띄어쓰기 없는 중국어, 관련도 높은 결과 우선(**프리뷰**) |
| [MCP](../MCP.md) | 선택한 채팅으로 제한된 MCP 클라이언트용 읽기 전용 접근 |
| [명령줄](../CLI.md) | `search`, `context`, `messages`, `stats`, JSON Lines `export`와 스크립트 및 에이전트용 `--json`. 로컬에서 또는 범위가 지정된 토큰으로 사용(**프리뷰**) |
| [OCR과 음성 텍스트 변환](../MEDIA-ANALYSIS.md) | 로컬에서 실행되며 원본은 그대로 유지 |
| [독립적인 캡처](../OPTIONAL-CAPTURE.md) | **기타 도구 → 부가 기능**에 있는 선택형 브라우저/AyuGram 레코더(미리 보기, 기본값은 꺼짐) |
| [Trusted Live](../TRUSTED-LIVE.md) | 공식 Desktop/Web 세션, 보호된 동영상, 네이티브 내보내기 연속성 분석(미리 보기, 실환경 적격성 평가는 진행 전) |
| [봉인된 공식 Web](../OFFICIAL-WITNESS.md) | GitHub Actions에서 새로 실행하는 공식 브라우저, 제한된 조작, 서명된 동영상, 독립적으로 정한 기댓값과 대조하는 소스/설정 |
| [웹훅](../WEBHOOKS.md) | 재시도 기능이 있는 서명된 발신 이벤트, n8n 예제 포함 |
| [공유 접근](../ACCESS.md) | 만료 기간과 IP 제한을 두고 선택한 채팅만 다른 사람에게 공개 |
| [누락된 메시지 번호](../EVIDENCE.md#missing-message-numbers-gap_summary) | Telegram이 할당했지만 한 번도 관찰되지 않은 번호를 채널별, 계정 전체 기준으로 커버리지, 보고서, MCP에 표시(**프리뷰**) |
| [채팅 상태 스냅샷](../COLLECTION.md) | 제목, 설명, 고정 메시지, 관리자, 선물의 서명된 스냅샷을 주기적으로 남기고 변경 사항을 표시(**프리뷰**) |
| [시스템 지도](../SYSTEM-MAP.md) | 패널 접속, 계정 경로, Telegram 대상, 외부 서비스를 보여 주는 실시간 지도. 최대 2,000건의 네트워크 관찰 기록 중 최신 200건 표시 |

</details>

<details>
<summary><strong>기록의 근거 선택하기</strong> · 로컬, 감사받은 클라우드, GitHub Actions 또는 Intel TDX</summary>

로컬에서 실행하거나, 감사받은 클라우드 배포를 추가하거나, **Intel TDX 기반 Phala Cloud
기밀 VM** 안에서 수집할 수 있습니다. 어떤 방식이든 서명된 저널은 유지되며, 추가
검사는 수집이 이루어진 환경을 다룹니다.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="세 가지 배포 방식: 로컬 저널 검증, 제공업체 및 접근 기록이 남는 감사받은 VM, 검증된 quote와 측정된 OS 및 애플리케이션, 바인딩된 수집기 키를 갖춘 Phala Intel TDX.">
</picture>

TDX 검증 도구는 고정된 Intel 루트와 폐기 데이터로 quote를 확인하고,
이를 서명된 수집기 진술서와 새로운 챌린지에 바인딩한 뒤, 측정된 OS와 애플리케이션을
독립적으로 정한 기대 입력값과 비교합니다. 보고서는 각 결과를 따로 나열하므로,
측정된 환경, 수집기 신원, 캡처 기록, 커버리지를
함께 검토할 수 있습니다.

**GitHub 출처 증명이 붙은 캡처**(미리 보기). 고정된 버전의 TgWitness와 새 Telegram 세션으로
GitHub 호스팅 러너에서 채팅을 수집한 뒤, 암호화된 아카이브를 GitHub 어테스테이션과 함께
내려받습니다. 검증 도구는 승인된 워크플로와 수집기 버전, 아카이브 다이제스트, 저널, 첨부 파일을
확인합니다. 패널의 **내보내기**에서도 사용할 수 있습니다.
[캡처 페이지 열기](https://phishdestroy.github.io/TgWitness/ko/docs/capture/) · [안내](../SEALED-ACTIONS.md)

실시간 관찰, 히스토리, 일회성 내보내기 중 목적에 맞는
[수집 방법](../COLLECTION-MODES.md)을 선택하세요. 연결된 계정이 접근할 수 있다면
비공개 클라우드 채팅도 수집할 수 있습니다. 배포된 애플리케이션에는
[Secret Chat 연동](../PSEUDO-SECRET.md)도 포함되어 있습니다. 선택형 프로토콜
의존성을 설치하고 계정별로 활성화하면 그 계정에서 만들거나 수락한 채팅을 기록합니다.
사용 가능한 수집 경로는 [수집 범위](../COLLECTION.md)를 참고하세요.

[Phala / Intel TDX와 감사받은 배포](../HIGH-ASSURANCE.md) ·
[Phala 실환경 적격성 평가](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[신뢰 경계](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>캡처와 저장된 기록 확인하기</strong> · 받는 사람이 검증하는 내용과 Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="대화를 캡처하고 기록을 검증합니다. 메시지, 수정 내역, 파일을 저장하고, 서명과 체크포인트를 확인하고, 캡처 과정을 검토하세요.">
</picture>

TgWitness는 연결된 Telegram 계정에 전달된 콘텐츠를
채팅, 메시지, 발신자 식별자, 캡처된 버전, 수집 메타데이터와 함께 기록합니다.
아카이브는 이 기록들과 보존된 첨부 파일, 검증 데이터를 한데 모아
검토할 수 있게 합니다.

| 검사 | 받는 사람이 검증하는 내용 |
| --- | --- |
| 서명된 저널과 매니페스트 | 예상 서명 키를 기준으로 한 기록 서명, 해시 체인, 전달된 파일. |
| 별도로 보관된 체크포인트 | 이전에 기록된 길이와 가장 최근 기록의 해시를 기준으로 한 저널. |
| 독립적인 증인 | 별도의 증인이 보관한 체크포인트를 기준으로 한 저널. |
| GitHub Actions 캡처 | 어테스테이션, 승인된 호스팅 워크플로, 수집기 버전을 기준으로 한 아카이브. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)은
Telegram 대화와 의도적으로 변조한 Desktop 내보내기 파일을 나란히 보여 줍니다.
버전을 비교하고 변경 사항을 살펴본 뒤, 서명된 TgWitness 아카이브의 수집 및
검증 단계를 따라가 보세요.

[검증 단계](../wiki/Exports-and-Verification.md) ·
[GitHub 캡처](../SEALED-ACTIONS.md) ·
[기술적 신뢰 모델](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>조사를 계속 이어 가기</strong> · 알림, 저장소, 복구</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="애니메이션 워크플로: Apprise가 설정된 알림을 보내고, 외부 보관 사본은 S3 호환 스토리지에 업로드하기 전에 암호화됩니다.">
</picture>

[알림](../OPERATIONS.md#notifications) · [암호화된 외부 보관 사본](../wiki/Off-site-Copy.md) · [백업과 복구](../wiki/Backup-and-Recovery.md) · [문제 해결](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/ko/docs/start/"><b>설정 가이드&nbsp;↗</b></a><br><sub>설치부터 첫 채팅까지</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/ko/docs/dedicated-account/"><b>계정 준비하기&nbsp;↗</b></a><br><sub>전용 Telegram 계정</sub></td>
<td width="33%" align="center"><a href="../DEPLOYMENT.md"><b>Docker와 서버&nbsp;↗</b></a><br><sub>HTTPS, 재시작, 업데이트</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>저장소 둘러보기</strong> · 코드, 문서, 도구의 위치</summary>

| 디렉터리 | 시작 지점 |
| --- | --- |
| [docs/](../README.md) | 설정, 조사 워크플로, 기술 참고 자료 |
| [tgwitness/](../../tgwitness/README.md) | 메인 애플리케이션, 수집기, 저널, 웹 패널 |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | 독립 레코더와 그 검증 코드 |
| [addons/](../../addons/README.md) | 선택형 캡처의 설치, 구성, 테스트 |
| [deploy/](../../deploy/README.md) | 설치 프로그램, 컨테이너, 백그라운드 서비스 |
| [examples/](../../examples/README.md) | 계정 내보내기와 봉인된 캡처 구성 |
| [integrations/](../../integrations/README.md) | 서명된 웹훅과 n8n 수신기 |
| [.agents/](../../.agents/README.md) | CLI로 아카이브를 읽기 위한 작업 지침 |
| [scripts/](../../scripts/README.md) | 실행 스크립트와 CI 유틸리티 |
| [tools/](../../tools/README.md) | 빌드, 검사, 패키징 |
| [website/](../../website/README.md) | 공개 사이트, 번역된 가이드, 대화형 데모 |
| [.github/](../../.github/AUTOMATION.md) | 워크플로, 기여 지침, 지원 |

[전체 프로젝트 가이드](../PROJECT-GUIDE.md) ·
[기여하기](../../.github/CONTRIBUTING.md) · [도움 받기](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ 윤리 공지 및 역사적 연속성</strong></summary>

저자들의 입장과 운영자 공지의 한국어판:

[운영자 공지](OPERATOR-INCOMPATIBILITY.md) · [MIT 라이선스](../../LICENSE) · [원본 NOTICE](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>프로젝트 개요를 원하는 언어로 읽기</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · **한국어** · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>기술 문서</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>조사 핸드북</b></a> ·
  <a href="https://github.com/phishdestroy"><b>PhishDestroy 제작</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>기여하기</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>도움 받기</b></a> ·
  <a href="../../.github/SECURITY.md"><b>취약점 신고</b></a>
</p>

[기계 판독용 프로젝트 색인](../../llms.txt) · [전체 텍스트 핸드북](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [에이전트용 저장소 규칙](../../AGENTS.md)
