<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">其他語言</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — 追查線索，保全證據。雜湊鏈結的簽名日誌、另行保存的檢查點，以及可驗證的證據存檔。">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=zh-Hant"><b>瀏覽示範&nbsp;↗</b></a><br><sub>真實介面，虛構記錄</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>下載並啟動&nbsp;↓</b></a><br><sub>一行指令，適用於 Linux、macOS 和 Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>閱讀手冊&nbsp;↗</b></a><br><sub>逐步說明的調查指南</sub></td>
</tr>
</table>

<p align="center"><strong>自行架設的 Telegram 調查工作區。</strong><br>儲存聊天，保留編輯與刪除，看清誰和誰有關聯，<br>並交付任何人都能查驗的簽名匯出檔。</p>

<p align="center"><strong>零信任。</strong>TgWitness 不偏袒任何一方：同樣的檢查適用於營運者、PhishDestroy 以及其他任何人。<br>只有第三方或數學能夠證實的內容才算數。<a href="../QUESTIONS-AND-CHECKS.md">問題與查核</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.3 · 預發行版"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">已測試的環境</a> · 25 種介面語言 · 26 種指南語言</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=zh-Hant">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="TgWitness 示範動畫：已擷取的訊息、儲存的版本，以及刪除後仍保留的內容。虛構的示範記錄。">
</picture>
</a>

<p align="center"><sub>以虛構記錄體驗真實介面。點選工作區即可試用。</sub></p>

## TgWitness 能做什麼

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">每次編輯與刪除都留存</a></b><br><sub>訊息的每個版本都會儲存，收到刪除通知後其文字依然保留。</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">人人可查驗的證明</a></b><br><sub>簽名的雜湊鏈結記錄。接收方只要一行指令就能離線驗證存檔。</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">可以證明的來源</a></b><br><sub>透過帳戶經驗證的 MTProto 會話接收，送達時即簽名；GitHub Actions 和 Intel TDX 還會附加證明。</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">大規模實測</a></b><br><sub>48 個已驗證的存檔，共 3,598,381 筆記錄；八個帳戶以每秒 687.5 筆的速度取得 768,007 筆歷史記錄。</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">專為調查打造</a></b><br><sub>涵蓋文字、QR Code 與 OCR 的觀察清單、錢包檢查、對象卡片、案件看板和法庭資料包。</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">由您自行運作</a></b><br><sub>自行架設，沒有遙測。會話保存在加密金庫中；面板監聽 localhost。</sub></td>
</tr>
</table>

<p align="center"><sub>開發與測試歷時約六個月：首先是收集器、簽名日誌和驗證器，接著是控制面板與附加模組。此儲存庫於 2026 年 10 月 29 日建立以供發布，因此其建立時間不代表專案的開發時間。</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## 安裝

內建 Python。更新時執行相同的指令即可。

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell 或 CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Ubuntu 伺服器：以 root 身分執行。桌面系統：以一般使用者身分執行。`-ExecutionPolicy Bypass` 只套用於這一個 PowerShell 處理程序。</sub>

簽名的建置版本來自公開的 [Installer 工作流程](../../.github/workflows/installer.yml)，安裝程式會在安裝前檢查每個套件的 SHA-256 和 RSA 簽名。

[先驗證指令碼](../INSTALLATION.md#verify-before-running) · [初次設定](../SETTINGS.md) · [發行版本](https://github.com/phishdestroy/TgWitness/releases) · [Docker](../DEPLOYMENT.md)

<details>
<summary><strong>安裝程式與您的資料如何受到保護</strong></summary>

`get.destroy.tools` 是本專案的下載網站。公開的 [Installer 工作流程](../../.github/workflows/installer.yml)會針對確切的 `main` 修訂版本，從 [`deploy/installer/`](../../deploy/installer/README.md) 建置該網站，在 Linux 和 Windows 安裝測試通過後發布，並以 [`release-signing.pub`](../../deploy/installer/release-signing.pub) 中的發行金鑰為安裝指令碼和應用程式套件簽名。安裝程式在安裝前會檢查套件與相依套件鎖定檔的 SHA-256 和 RSA 簽名。若想先檢查指令碼本身，請連同簽名一起下載，再執行[先驗證的指令](../INSTALLATION.md#verify-before-running)。建置失敗時，原有的下載內容維持不變；重新執行安裝程式即可更新已安裝的面板。GitHub [發行版本](https://github.com/phishdestroy/TgWitness/releases)、原始碼和 [Docker](../DEPLOYMENT.md) 是其他幾種安裝方式。

**您的會話與資料。** TgWitness 在您的電腦或伺服器上執行，面板預設監聽 localhost。Telegram 會話、代理伺服器認證資訊和存取權杖雜湊值都儲存在各工作區的加密金庫中，也可選用[外部主金鑰](../SECURITY-MODEL.md#external-master-key)。應用程式沒有遙測功能。它會連線到 Telegram 以及設定中使用的服務：公開的 MTProxy 清單、您的代理伺服器、S3 儲存空間、見證機器人、時間戳記機構、AI 供應商和 webhook。[系統地圖](../SYSTEM-MAP.md)列出了應用程式處理程序建立的連線。請使用[專用的 Telegram 帳戶](https://phishdestroy.github.io/TgWitness/zh-Hant/docs/dedicated-account/)進行觀察。

版本徽章描述的是這份原始碼樹。可安裝的建置版本列於[發行版本](https://github.com/phishdestroy/TgWitness/releases)；合併到 `main` 的功能會隨下一個版本進入這些下載內容。

[設定與面板存取](../INSTALLATION.md) ·
[簽名與 SHA-256](https://get.destroy.tools/#verification) ·
[更新](../INSTALLATION.md#update-an-existing-installation) ·
[目前功能與鑑定狀態](../STATUS.md) ·
[選擇蒐集方法](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## 他人也能查驗的記錄

不需要帳戶，也不必安裝就能查驗。公開的範例自帶驗證器：

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # 驗證器就附在存檔裡
python verify.py tgwitness-demo.zip          # Python 3.11+，只需要 `cryptography`
```

它會輸出簽名記錄、最新記錄的雜湊值和簽署者指紋，並以 `0` 結束。範例為虛構內容；同一個驗證器也適用於任何真實的匯出。

匯出內含訊息、檔案和驗證器。透過另一個管道把您的金鑰指紋交給接收方，對方就能自行查驗：

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

驗證器會檢查簽名、日誌鏈、檔案清單和附件。若要達到證據等級，還需要您的金鑰指紋，以及涵蓋最後一筆記錄的第三方時間戳記，例如對照時間戳記機構根憑證檢查的 RFC 3161 時間戳記。

**訊息從何而來。** TgWitness 和官方應用程式一樣，透過帳戶的加密 MTProto 會話從 Telegram 接收訊息，並在每則訊息送達時將其簽名寫入日誌。[GitHub Actions 擷取](../SEALED-ACTIONS.md)和 [Phala Intel TDX](../HIGH-ASSURANCE.md) 還會為接收這些訊息的蒐集器提供證明。

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="新訊息、儲存的編輯與刪除觀測記錄構成一條相互鏈結的簽名日誌。以經獨立管道確認可信的金鑰加以驗證。">
</picture>

[存檔驗證](../wiki/Exports-and-Verification.md) · [證據格式](../EVIDENCE.md) · [獨立見證人](../WITNESS.md) · [外部時間戳記](../TIMESTAMP.md) · [檢查項目與測試規模](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## 從一段對話到一件案件

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="三個動畫工作流程：將聊天匯出為 HTML 和 JSON、在已記錄的聊天中找出共用連結，以及在收到刪除通知後保留已擷取的版本。">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>聊天匯出&nbsp;↗</b></a><br><sub>把一個聊天匯出為簽名的 HTML 和 JSON</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>調查&nbsp;↗</b></a><br><sub>在已記錄的聊天中追查線索</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>儲存的版本&nbsp;↗</b></a><br><sub>編輯與刪除通知都會保留</sub></td>
</tr>
</table>

兩種用法：一次性[匯出您的帳戶](../ACCOUNT-EXPORT.md)，或是[追蹤一項調查](../INVESTIGATION.md)並持續儲存變更。可以選擇幾個聊天、一個 Telegram 資料夾或整個帳戶。每個帳戶都有自己的工作區、會話和簽名金鑰。

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## 深入了解

<details>
<summary><strong>匯出實測 · 2026 年 11 月 6 日</strong> · 56,329 則訊息，兩份存檔皆通過驗證</summary>

**兩次全新執行共匯出 56,329 則訊息。** 兩份簽名存檔皆以固定的蒐集器金鑰通過驗證。

[![實測蒐集速度與完整匯出速度](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/zh-Hant/docs/validation/)

| 執行 | 訊息數 | 蒐集時間 | 蒐集速度 | 完整匯出 | 端對端速度 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 伺服器 A | 27,030 | 189.043 秒 | **142.983 則訊息/秒** | 211.647 秒 | 127.713 則訊息/秒 |
| 伺服器 B | 29,299 | 182.513 秒 | **160.531 則訊息/秒** | 206.650 秒 | 141.781 則訊息/秒 |

透過 WARP 傳輸文字和中繼資料，每台伺服器兩個帳戶，不含附件，也沒有重複使用的記錄。量測基於修訂版本 [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e)。每次公布的執行都會列出原始碼修訂版本、工作負載、耗時和驗證結果：[工作負載、耗時與驗證](../EXPORT-BENCHMARK-2026-11-06.md)。對 `main` 的變更會執行公開的 [CI 工作流程](../../.github/workflows/README.md)，其中包括 Linux 和 Windows 安裝程式測試，以及獨立驗證器的建置。

[**瀏覽示範 →**](https://phishdestroy.github.io/TgWitness/demo/?lang=zh-Hant) ·
[**量測數據、日期與方法 →**](https://phishdestroy.github.io/TgWitness/zh-Hant/docs/validation/) ·
[下載虛構的範例匯出](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[簽名的英文稽核報告](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>從簡單開始，看清每條路徑。</strong> · 初次啟動與系統地圖</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="初次啟動提供「只要下載」「關注聊天」和「案件的證據」三個選項，並只顯示對應的區塊。系統地圖把面板、蒐集器、Telegram、日誌、見證人和外部服務串連起來，並附上網路觀測記錄。數值均為虛構。">
</picture>

初次啟動只問一個問題：**只要下載**、**關注聊天**還是**案件的證據**。答案決定目標和介面層級，面板只顯示該任務需要的區塊。接著分五個階段完成連線、Telegram 登入和聊天選擇。連線檢查會自動執行，只有檢查失敗時才會出現路徑選項。專家工具只要切換一個開關就能開啟。

**系統地圖**顯示這套安裝如何連到 Telegram 與外部服務：面板存取、每個帳戶的路徑和 Telegram 目標、日誌與見證人路徑，以及最新的網路觀測記錄。缺少的觀測記錄會標示為缺少。

[初次設定](../SETTINGS.md) · [系統地圖](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>涵蓋調查的其他環節</strong> · 對象卡片、觀察清單、錢包、上線狀態監測、法庭文件</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="依 Telegram ID 追蹤名稱和使用者名稱。以簽名回條記錄受支援的機器人互動。搜尋存檔中的訊息，並連接唯讀的 MCP 用戶端。部署蒐集器：遮蔽 SSH，並保留供應商記錄以供審查。透過日誌參照逐步記錄一段對話。交付附有法庭範本的 BagIt 案件包。示意工作流程。">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>人物與檔案&nbsp;↗</b></a><br><sub>依 Telegram ID 追蹤名稱和使用者名稱</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>機器人調查&nbsp;↗</b></a><br><sub>附簽名回條的機器人互動</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/zh-Hant/docs/archive/"><b>存檔搜尋、AI 與 MCP&nbsp;↗</b></a><br><sub>搜尋存檔，連接唯讀用戶端</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>密封雲端部署&nbsp;↗</b></a><br><sub>在 Intel TDX 內執行的蒐集器</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="三個動畫步驟：對象卡片的後續快照記下一次改名；對話計畫的目標隨日誌記錄逐一完成；付款 QR Code 解碼為檢查碼有效的錢包位址，並觸發觀察清單命中。數值均為虛構。">
</picture>

**記錄對話。** 在**文件說明**抽屜中為某個聊天開始記錄後，每個步驟都會自動寫入：面板操作、回覆及回覆前的延遲、編輯、刪除通知、備註和 AI 草稿。每個步驟都會引用對應的日誌記錄及其 SHA-256。定稿時，文件會被簽名，聲明雜湊值會寫入日誌。

| | |
| --- | --- |
| [對象卡片](../INVESTIGATION-MODE.md#subject-cards) | 機器人、個人、頻道或群組的個人檔案快照，附 Telegram 的 BOT、VERIFIED、SCAM 和 FAKE 標籤；後續快照會列出變動之處 |
| [對話計畫](../INVESTIGATION-MODE.md#conversation-plans) | 針對付款路徑、基礎架構或相關人員的目標、預先準備的訊息、回覆時間、每小時活動量，以及對方的寫作風格 |
| [翻譯](../INVESTIGATION-MODE.md#machine-translation) | 顯示在原文下方，並註明語言、模型和日誌記錄 |
| [觀察清單](../INVESTIGATION-MODE.md#watchlists) | 字詞、模式、錢包、@使用者名稱、ID、網域、電話號碼和連結，可在文字、編輯、隱藏的連結目標、機器人按鈕、QR Code 和 OCR 中比對 |
| [上線狀態監測](../INVESTIGATION-MODE.md#online-watch) | 每 1–60 分鐘檢查一次，每次請求最多 100 個帳戶，並依小時和星期整理出規律 |
| [條碼與錢包](../INVESTIGATION-MODE.md#codes-in-images) | 付款 QR Code；依 EIP-55 檢查的 EVM 位址、原始格式的 TON 位址、XRP Ledger 檢查碼，以及含鏈、金額和代幣的付款連結 |
| [用戶端痕跡](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-show) | 圓形影片和語音訊息的編碼器痕跡；比對上傳時間與傳送時間，可揭穿預先錄製的「即時」證明 |
| [掩護身分與授權](../INVESTIGATION-MODE.md#cover-and-authority) | 人設、授權，以及臥底活動記錄，後者會標記授權聊天範圍或授權期間以外的訊息 |
| [帳戶控制](../INVESTIGATION-MODE.md#account-control) | 編輯個人檔案和隱私設定並留下變更前後的記錄、曝光檢查，每次操作後立即離線 |
| [法庭文件](../INVESTIGATION-MODE.md#documents-for-court) | BagIt 案件包，附 Rule 902(13)/(14) 認證範本、證物索引、請求附件，以及螢幕錄影的 WebVTT/SRT 字幕 |

標示為 18+、暴力或個人資料的內容會保留在法庭副本中，以 AES-256-GCM 密封；金鑰另行傳遞。

[匯出設定](../EXPORT_HASHES.md)涵蓋一般 API 與 Takeout 取得方式、先取得訊息歷史再取得附件、下載檔案或使用伺服器雜湊值，以及相容於 Telegram Desktop 的 JSON/HTML 檢視。[分散式聊天匯出](../DISTRIBUTED-EXPORT.md#history-acquisition)為公開歷史提供需自行啟用的 Takeout 路徑、每 100 則訊息一個簽名檢查點，以及以同一帳戶在指定範圍內復原；其[效能設計](../FAST-ACQUISITION.md)列出了已測試的取得行為和規劃中的實際量測。

</details>

<details>
<summary><strong>其他功能</strong> · 歷史記錄、帳戶、代理伺服器、AI、整合</summary>

| | |
| --- | --- |
| [載入較早的訊息](../HISTORY.md) | 拉取所選聊天的歷史訊息，可隨時暫停和繼續 |
| [多個帳戶](../ACCOUNTS.md#multiple-accounts) | 彼此獨立的工作區，各自擁有 Telegram 會話、日誌和簽名金鑰 |
| [批次匯入](../ACCOUNTS.md#bulk-import-and-account-groups) | 一次放入大量會話檔案，將帳戶分組並共用設定 |
| [MTProxy 代理池](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping 延遲、國家、篩選條件、自訂清單 |
| [現有會話](../ACCOUNTS.md) | TData、Telethon、Pyrogram、StringSession、auth key 或 `key:DC` 字串；可選擇透過匯入的來源帳戶進行獨立的 QR Code 授權 |
| [帳戶安全性](../ACCOUNTS.md#create-an-independent-authorization) | 新會話警示、終止其他會話、會一併設定兩步驟驗證密碼的唯一會話模式，以及[見證探針](../ACCOUNTS.md#witness-probe)：即時更新不再送達此會話時會察覺 |
| [可續傳的聊天匯出](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | 中斷的匯出會保留一份簽名的部分副本：可以繼續、重新開始或下載已儲存的內容 |
| [代理伺服器](../CONNECTION-SECURITY.md#ip-modes) | 每個工作區可使用 SOCKS5、HTTP CONNECT 或 MTProxy。**隱藏 IP** 絕不會退回直接連線 |
| [搜尋與 AI](../ANALYSIS.md) | 本機搜尋，可選用的 AI 並附可查證的來源 |
| [全文搜尋](../SEARCH.md) | 詞形變化、完整片語、網域、@使用者名稱以及不含空格的中文，最佳相符結果優先（**預覽版**） |
| [MCP](../MCP.md) | 為 MCP 用戶端提供唯讀存取，僅限您選取的聊天 |
| [命令列](../CLI.md) | `search`、`context`、`messages`、`stats` 以及 JSON Lines 格式的 `export`，搭配 `--json` 供指令碼和 AI 代理程式使用，可在本機執行或使用限定範圍的權杖（**預覽版**） |
| [OCR 與轉錄](../MEDIA-ANALYSIS.md) | 在本機執行，原始檔案保持不變 |
| [獨立擷取](../OPTIONAL-CAPTURE.md) | 可選用的瀏覽器/AyuGram 錄製器，位於**更多工具 → 擴充功能**（預覽，預設關閉） |
| [Trusted Live](../TRUSTED-LIVE.md) | 官方 Desktop/Web 會話、受保護的影片錄製，以及原生匯出連續性分析（預覽；實測鑑定尚待完成） |
| [密封的官方 Web](../OFFICIAL-WITNESS.md) | 在 GitHub Actions 上執行全新的官方瀏覽器，控制項受限，影片經過簽名，來源與設定有獨立給出的預期值 |
| [Webhooks](../WEBHOOKS.md) | 具重試機制的簽名傳出事件，附 n8n 範例 |
| [共用存取](../ACCESS.md) | 只開放選定的聊天給他人，並設定到期時間和 IP 限制 |
| [缺少訊息編號](../EVIDENCE.md#missing-message-numbers-gap_summary) | Telegram 已指派但從未觀測到的編號，依頻道和整個帳戶統計，呈現在涵蓋率、報告和 MCP 中（**預覽版**） |
| [聊天狀態快照](../COLLECTION.md) | 定期為標題、說明、置頂訊息、管理員和禮物建立簽名快照，並列出變動（**預覽版**） |
| [系統地圖](../SYSTEM-MAP.md) | 即時呈現面板存取、帳戶路徑、Telegram 目標和外部服務，並顯示最多 2,000 筆網路觀測記錄中的最新 200 筆 |

</details>

<details>
<summary><strong>選擇記錄的信任基礎</strong> · 本機、經稽核的雲端、GitHub Actions 或 Intel TDX</summary>

可以在本機執行、加上經稽核的雲端部署，或在**搭載 Intel TDX 的 Phala Cloud 機密虛擬機器**內蒐集。每種方式都會保留簽名日誌；額外的檢查針對的是蒐集時所在的環境。

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="三種部署選擇：本機日誌驗證；附供應商與存取記錄的經稽核虛擬機器；Phala Intel TDX，含已驗證的 quote、經量測的作業系統與應用程式，以及綁定的蒐集器金鑰。">
</picture>

TDX 驗證器會對照固定的 Intel 根憑證和撤銷資料檢查 quote，將其綁定到簽名的蒐集器聲明和新產生的挑戰值，並把經量測的作業系統與應用程式和獨立得出的預期輸入相比對。報告會逐項列出每個結果，因此可以將經量測的環境、蒐集器身分、擷取記錄和涵蓋範圍放在一起審查。

**附 GitHub 來源證明的擷取**（預覽）。在 GitHub 代管的執行器上，以固定版本的 TgWitness 和全新的 Telegram 會話蒐集聊天，然後下載加密存檔及其 GitHub 證明。驗證器會檢查核准的工作流程和蒐集器版本、存檔摘要、日誌和附件。也可以在面板的**匯出**中使用。[開啟擷取頁面](https://phishdestroy.github.io/TgWitness/zh-Hant/docs/capture/) · [使用說明](../SEALED-ACTIONS.md)

如需即時觀察、取得歷史或一次性匯出，請選擇合適的[蒐集方法](../COLLECTION-MODES.md)。只要連接的帳戶能存取，私人雲端聊天就能蒐集。發布的應用程式也包含 [Secret Chat 整合](../PSEUDO-SECRET.md)：安裝選用的協定相依套件並依帳戶啟用後，即可記錄在該帳戶建立或接受的聊天。可用的取得途徑請參閱[蒐集範圍](../COLLECTION.md)。

[Phala / Intel TDX 與經稽核的部署](../HIGH-ASSURANCE.md) ·
[Phala 線上實測鑑定](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[信任邊界](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>查驗擷取過程與儲存的記錄</strong> · 接收方驗證的內容與 Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="擷取對話，驗證記錄。儲存訊息、編輯和檔案，檢查簽名與檢查點，並審查擷取過程。">
</picture>

TgWitness 會記錄傳送到所連接 Telegram 帳戶的內容，包括聊天、訊息和傳送者識別碼、已擷取的版本以及蒐集中繼資料。存檔把這些記錄、保留的附件和驗證資料彙整在一起，以供審查。

| 檢查項目 | 接收方驗證的內容 |
| --- | --- |
| 簽名日誌與資訊清單 | 對照預期的簽名金鑰，驗證記錄簽名、雜湊鏈和交付的檔案。 |
| 另行保存的檢查點 | 對照先前記錄的長度和最新記錄的雜湊值驗證日誌。 |
| 獨立見證人 | 對照另一位見證人保存的檢查點驗證日誌。 |
| GitHub Actions 擷取 | 對照存檔的證明、核准的代管工作流程和蒐集器版本驗證存檔。 |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/) 將一段 Telegram 對話與刻意竄改過的 Desktop 匯出檔並排呈現。您可以比較各個版本、檢視變動之處，並依步驟了解簽名 TgWitness 存檔的蒐集與驗證流程。

[驗證步驟](../wiki/Exports-and-Verification.md) ·
[GitHub 擷取](../SEALED-ACTIONS.md) ·
[技術信任模型](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>讓調查持續運作</strong> · 通知、儲存空間與復原</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="動畫工作流程：Apprise 傳送已設定的警示；異地副本在上傳到 S3 相容儲存空間之前先加密。">
</picture>

[通知](../OPERATIONS.md#notifications) · [加密的異地副本](../wiki/Off-site-Copy.md) · [備份與復原](../wiki/Backup-and-Recovery.md) · [疑難排解](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/zh-Hant/docs/start/"><b>設定指南&nbsp;↗</b></a><br><sub>從安裝到第一個聊天</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/zh-Hant/docs/dedicated-account/"><b>準備帳戶&nbsp;↗</b></a><br><sub>專用的 Telegram 帳戶</sub></td>
<td width="33%" align="center"><a href="../DEPLOYMENT.md"><b>Docker 與伺服器&nbsp;↗</b></a><br><sub>HTTPS、重新啟動與更新</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>瀏覽儲存庫</strong> · 程式碼、文件和工具的位置</summary>

| 目錄 | 從這裡開始 |
| --- | --- |
| [docs/](../README.md) | 設定、調查工作流程和技術參考 |
| [tgwitness/](../../tgwitness/README.md) | 主要應用程式、蒐集器、日誌和網頁面板 |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | 獨立錄製器及其驗證程式碼 |
| [addons/](../../addons/README.md) | 選用擷取功能的安裝、設定和測試 |
| [deploy/](../../deploy/README.md) | 安裝程式、容器和背景服務 |
| [examples/](../../examples/README.md) | 帳戶匯出和密封擷取的設定 |
| [integrations/](../../integrations/README.md) | 簽名 webhook 和 n8n 接收端 |
| [.agents/](../../.agents/README.md) | 透過 CLI 讀取存檔的任務說明 |
| [scripts/](../../scripts/README.md) | 啟動器和 CI 工具 |
| [tools/](../../tools/README.md) | 建置、檢查和封裝 |
| [website/](../../website/README.md) | 公開網站、翻譯版指南和互動式示範 |
| [.github/](../../.github/AUTOMATION.md) | 工作流程、貢獻指南和支援 |

[完整專案指南](../PROJECT-GUIDE.md) ·
[參與貢獻](../../.github/CONTRIBUTING.md) · [取得協助](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ 道德聲明與歷史延續性</strong></summary>

作者立場聲明與營運者聲明的繁體中文版本：

[營運者聲明](OPERATOR-INCOMPATIBILITY.md) · [MIT 授權條款](../../LICENSE) · [原始 NOTICE](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>以您的語言閱讀專案概覽</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · **繁體中文** · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>技術文件</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>調查手冊</b></a> ·
  <a href="https://github.com/phishdestroy"><b>由 PhishDestroy 打造</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>參與貢獻</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>取得協助</b></a> ·
  <a href="../../.github/SECURITY.md"><b>回報安全漏洞</b></a>
</p>

[機器可讀的專案索引](../../llms.txt) · [完整純文字手冊](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [給 AI 代理程式的儲存庫規則](../../AGENTS.md)
