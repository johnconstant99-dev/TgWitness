<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">他の言語</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — 痕跡をたどり、証拠を保全する。ハッシュで連結された署名付きジャーナル、別途保管されるチェックポイント、検証可能な証拠アーカイブ。">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=ja"><b>デモを見る&nbsp;↗</b></a><br><sub>架空のレコードで動く実際のインターフェース</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>ダウンロードして開始&nbsp;↓</b></a><br><sub>Linux、macOS、Windows に対応したワンコマンド</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>ハンドブックを読む&nbsp;↗</b></a><br><sub>調査ガイドをステップごとに</sub></td>
</tr>
</table>

<p align="center"><strong>Telegram 調査のためのセルフホスト型ワークスペース。</strong><br>チャットを保存し、編集と削除を残し、誰が誰とつながっているかを把握して、<br>誰でも検証できる署名付きエクスポートを引き渡せます。</p>

<p align="center"><strong>ゼロトラスト。</strong>TgWitness はどの側にも立ちません。オペレーターにも、PhishDestroy にも、それ以外の誰にも同じ検証を適用します。<br>認められるのは、第三者または数学が裏付けるものだけです。<a href="../QUESTIONS-AND-CHECKS.md">質問と検証</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.3 · プレリリース"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">テスト済みの環境</a> · インターフェース 25 言語 · ガイド 26 言語</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=ja">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="動作中の TgWitness デモ：キャプチャされたメッセージ、保存されたバージョン、削除後も保持された内容。架空のデモ用レコード。">
</picture>
</a>

<p align="center"><sub>架空のレコードで実際のインターフェースを確かめられます。ワークスペースをクリックして試してください。</sub></p>

## TgWitness でできること

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">編集も削除もすべて保存</a></b><br><sub>メッセージの各バージョンが保存され、削除通知の後もテキストが残ります。</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">誰でも検証できる証明</a></b><br><sub>署名され、ハッシュチェーンでつながったレコード。受信者はコマンド 1 つでアーカイブをオフライン検証できます。</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">示せる出所</a></b><br><sub>アカウントの認証済み MTProto セッション経由で受信し、到着時に署名します。GitHub Actions と Intel TDX がアテステーションを加えます。</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">大規模に実測</a></b><br><sub>検証済みアーカイブ 48 件、レコード 3,598,381 件。8 つのアカウントが 687.5 レコード/秒で履歴レコード 768,007 件を取得しました。</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">調査のための設計</a></b><br><sub>テキスト、QR コード、OCR を対象とするウォッチリスト、ウォレット確認、対象カード、ケースボード、裁判用パッケージ。</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">自分の手で運用</a></b><br><sub>テレメトリなしのセルフホスト。セッションは暗号化された保管庫に保存され、パネルは localhost で待ち受けます。</sub></td>
</tr>
</table>

<p align="center"><sub>約6か月間にわたり開発およびテストが行われました。まずコレクター、署名付きジャーナル、検証ツールが、次にパネルおよびアドオンモジュールが開発・テストされました。このリポジトリは公開のために2026年10月29日に作成されたため、その作成日はプロジェクトの開始時期とは異なります。</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## インストール

Python 同梱。更新にも同じコマンドを使います。

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell または CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Ubuntu サーバー：root で実行します。デスクトップ：通常のユーザーで実行します。`-ExecutionPolicy Bypass` はこの PowerShell プロセスにのみ適用されます。</sub>

署名付きビルドは公開の [Installer ワークフロー](../../.github/workflows/installer.yml)から提供され、インストーラーはインストール前にすべてのパッケージの SHA-256 と RSA 署名を確認します。

[先にスクリプトを検証](../INSTALLATION.md#verify-before-running) · [初期設定](../SETTINGS.md) · [リリース](https://github.com/phishdestroy/TgWitness/releases) · [Docker](../DEPLOYMENT.md)

<details>
<summary><strong>インストーラーとデータの保護</strong></summary>

`get.destroy.tools` はプロジェクトのダウンロードサイトです。公開の [Installer ワークフロー](../../.github/workflows/installer.yml)が [`deploy/installer/`](../../deploy/installer/README.md) から特定の `main` リビジョンを対象にサイトをビルドし、Linux と Windows のインストールテストに合格した後に公開して、インストーラースクリプトとアプリケーションパッケージに [`release-signing.pub`](../../deploy/installer/release-signing.pub) のリリース鍵で署名します。インストーラーはインストール前に、パッケージと依存関係ロックファイルの SHA-256 と RSA 署名を確認します。スクリプト自体を先に確認したい場合は、署名と一緒にダウンロードして[事前検証コマンド](../INSTALLATION.md#verify-before-running)を実行してください。ビルドに失敗した場合は以前のダウンロードがそのまま残ります。インストール済みのパネルは、インストーラーを再実行すると更新されます。GitHub の[リリース](https://github.com/phishdestroy/TgWitness/releases)、ソースコード、[Docker](../DEPLOYMENT.md) でもインストールできます。

**セッションとデータ。** TgWitness はお使いのコンピューターまたはサーバー上で動作し、パネルはデフォルトで localhost で待ち受けます。Telegram セッション、プロキシの認証情報、アクセストークンのハッシュは各ワークスペースの暗号化された保管庫に保存され、オプションで[外部マスターキー](../SECURITY-MODEL.md#external-master-key)も使えます。アプリケーションにテレメトリはありません。接続先は Telegram と、設定で使用するサービスです：公開 MTProxy リスト、お使いのプロキシ、S3 ストレージ、証人ボット、タイムスタンプ局、AI プロバイダー、Webhook。アプリケーションのプロセスが行う接続は[システムマップ](../SYSTEM-MAP.md)に一覧されています。観測には[専用の Telegram アカウント](https://phishdestroy.github.io/TgWitness/ja/docs/dedicated-account/)を使ってください。

バージョンバッジはこのソースツリーを示します。インストール可能なビルドは[リリース](https://github.com/phishdestroy/TgWitness/releases)に掲載されています。`main` にマージされた機能は、次のリリースでそれらのダウンロードに反映されます。

[セットアップとパネルへのアクセス](../INSTALLATION.md) ·
[署名と SHA-256](https://get.destroy.tools/#verification) ·
[更新](../INSTALLATION.md#update-an-existing-installation) ·
[現在の機能と適格性評価](../STATUS.md) ·
[収集方法を選ぶ](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## 他者が検証できる記録

アカウントもインストールも不要で検証できます。公開サンプルには検証ツールが同梱されています：

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # 検証ツールはアーカイブに同梱
python verify.py tgwitness-demo.zip          # Python 3.11+、必要なのは `cryptography` のみ
```

署名付きレコード、最新のレコードのハッシュ、署名者のフィンガープリントを表示し、`0` で終了します。サンプルは架空のものですが、同じ検証ツールで実際のどのエクスポートも検証できます。

エクスポートにはメッセージ、ファイル、検証ツールが含まれます。鍵のフィンガープリントを別の経路で受信者に伝えれば、受信者は自分で検証できます：

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

検証ツールは署名、ジャーナルのチェーン、ファイル一覧、添付ファイルを確認します。証拠として扱うには、鍵のフィンガープリントに加えて、最後のレコードをカバーする第三者のタイムスタンプが必要です。たとえば、タイムスタンプ局のルート証明書と照合した RFC 3161 タイムスタンプです。

**メッセージの出所。** TgWitness は公式アプリと同じく、アカウントの暗号化された MTProto セッションを通じて Telegram からメッセージを受信し、届いたメッセージを 1 件ずつ署名してジャーナルに記録します。[GitHub Actions キャプチャ](../SEALED-ACTIONS.md)と [Phala Intel TDX](../HIGH-ASSURANCE.md) は、メッセージを受信したコレクターについてもアテステーションを提供します。

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="新しいメッセージ、保存された編集、削除の観測が連結され、署名付きジャーナルを形成します。独立に信頼が確認された鍵で検証してください。">
</picture>

[アーカイブの検証](../wiki/Exports-and-Verification.md) · [証拠フォーマット](../EVIDENCE.md) · [独立した証人](../WITNESS.md) · [外部タイムスタンプ](../TIMESTAMP.md) · [チェック項目とテスト規模](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## 会話から事件へ

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="3 つのアニメーションワークフロー：チャットを HTML と JSON にエクスポート、記録済みチャット全体から共有リンクを検索、削除通知の後もキャプチャ済みのバージョンを保持。">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>チャットのエクスポート&nbsp;↗</b></a><br><sub>1 つのチャットを署名付き HTML と JSON に</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>調査&nbsp;↗</b></a><br><sub>記録済みのチャットをまたいで手がかりを追跡</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>保存されたバージョン&nbsp;↗</b></a><br><sub>編集と削除通知をそのまま保持</sub></td>
</tr>
</table>

使い方は 2 通りです。[アカウントのエクスポート](../ACCOUNT-EXPORT.md)を 1 回だけ行うか、[調査を継続](../INVESTIGATION.md)して変更を保存し続けるかです。対象は数件のチャット、Telegram のフォルダー、アカウント全体から選べます。アカウントごとに専用のワークスペース、セッション、署名鍵が用意されます。

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## さらに詳しく

<details>
<summary><strong>エクスポートの実測 · 2026 年 11 月 6 日</strong> · メッセージ 56,329 件、両アーカイブとも検証済み</summary>

**新規の 2 回の実行でメッセージ 56,329 件をエクスポート。** どちらの署名付きアーカイブも、固定したコレクター鍵で検証に合格しました。

[![実測した収集速度と完全エクスポート速度](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/ja/docs/validation/)

| 実行 | メッセージ数 | 収集時間 | 収集速度 | 完全エクスポート | エンドツーエンド速度 |
| --- | ---: | ---: | ---: | ---: | ---: |
| サーバー A | 27,030 | 189.043 秒 | **142.983 メッセージ/秒** | 211.647 秒 | 127.713 メッセージ/秒 |
| サーバー B | 29,299 | 182.513 秒 | **160.531 メッセージ/秒** | 206.650 秒 | 141.781 メッセージ/秒 |

テキストとメタデータを WARP 経由で取得し、サーバーごとに 2 アカウント、添付ファイルなし、レコードの再利用なしで計測しました。計測したリビジョンは [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e) です。公開されている各実行には、ソースリビジョン、ワークロード、所要時間、検証結果が記載されています：[ワークロード、所要時間、検証](../EXPORT-BENCHMARK-2026-11-06.md)。`main` への変更では、Linux と Windows のインストーラーテストやスタンドアロン検証ツールのビルドを含む公開 [CI ワークフロー](../../.github/workflows/README.md)が実行されます。

[**デモを見る →**](https://phishdestroy.github.io/TgWitness/demo/?lang=ja) ·
[**計測値・日付・手法 →**](https://phishdestroy.github.io/TgWitness/ja/docs/validation/) ·
[架空のサンプルエクスポートをダウンロード](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[署名付きの英語版監査レポート](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>シンプルに始めて、すべてのルートを見渡す。</strong> · 初回起動とシステムマップ</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="初回起動では「ダウンロードのみ」「チャットを見守る」「事件の証拠」から選び、該当するセクションだけが表示されます。システムマップは、パネル、コレクター、Telegram、ジャーナル、証人、外部サービスのつながりをネットワーク観測記録とともに示します。値は架空のものです。">
</picture>

初回起動で尋ねるのは 1 つだけです：**ダウンロードのみ**、**チャットを見守る**、**事件の証拠**のどれにするか。この回答で目的とインターフェースのレベルが決まり、パネルにはそのタスクに必要なセクションだけが表示されます。続いて接続、Telegram へのサインイン、チャットの選択を 5 つのステージで進めます。接続チェックは自動で実行され、失敗したときだけルートのオプションが開きます。エキスパート向けツールはスイッチ 1 つで使えます。

**システムマップ**は、インストール環境が Telegram と外部サービスにどう到達しているかを示します：パネルへのアクセス、各アカウントのルートと Telegram の接続先、ジャーナルと証人の経路、最新のネットワーク観測記録。観測記録が欠けている場合は、欠落として表示されます。

[初期設定](../SETTINGS.md) · [システムマップ](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>調査の残りの工程にも対応</strong> · 対象カード、ウォッチリスト、ウォレット、オンライン監視、裁判用書類</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Telegram ID で名前とユーザー名を追跡。対応するボットとのやり取りを署名付きレシートとともに記録。アーカイブされたメッセージを検索し、読み取り専用の MCP クライアントを接続。SSH をマスクし、事業者の記録をレビュー用に残してコレクターをデプロイ。ジャーナル参照を付けて会話を段階的に記録。裁判用テンプレート付きの BagIt 事件パッケージを引き渡し。説明用のワークフロー。">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>人物と調査ファイル&nbsp;↗</b></a><br><sub>Telegram ID で追跡する名前とユーザー名</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>ボット調査&nbsp;↗</b></a><br><sub>署名付きレシートで残すボットとのやり取り</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/ja/docs/archive/"><b>アーカイブ検索、AI、MCP&nbsp;↗</b></a><br><sub>アーカイブを検索し、読み取り専用クライアントを接続</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>封印型クラウドデプロイ&nbsp;↗</b></a><br><sub>Intel TDX 内で動作するコレクター</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="3 つのアニメーションステップ：後のスナップショットで名前の変更を記録する対象カード、ジャーナルレコードで目標が達成されていく会話プラン、チェックサムの正しいウォレットにデコードされてウォッチリストのヒットを発生させる支払い QR コード。値は架空のものです。">
</picture>

**会話を記録する。** **ドキュメント**ドロワーでチャットの記録を開始すると、すべてのステップが自動で書き込まれます：パネル操作、返信とその前の待ち時間、編集、削除通知、メモ、AI の下書き。各ステップには対応するジャーナルレコードと SHA-256 が記されます。文書を確定すると署名され、ステートメントのハッシュがジャーナルに書き込まれます。

| | |
| --- | --- |
| [対象カード](../INVESTIGATION-MODE.md#subject-cards) | ボット、人物、チャンネル、グループのプロフィールスナップショット（Telegram の BOT、VERIFIED、SCAM、FAKE ラベル付き）。後のスナップショットには変更点が一覧されます |
| [会話プラン](../INVESTIGATION-MODE.md#conversation-plans) | 支払いルート、インフラ、関係者に関する目標、準備済みのメッセージ、返信時間、時間帯別のアクティビティ、相手の文体 |
| [翻訳](../INVESTIGATION-MODE.md#machine-translation) | 原文の下に、言語、モデル、ジャーナルレコードとともに表示 |
| [ウォッチリスト](../INVESTIGATION-MODE.md#watchlists) | 単語、パターン、ウォレット、@ユーザー名、ID、ドメイン、電話番号、リンクを、テキスト、編集、隠しリンク先、ボットのボタン、QR コード、OCR から照合 |
| [オンライン監視](../INVESTIGATION-MODE.md#online-watch) | 1–60 分ごとにチェック、1 回のリクエストで最大 100 アカウント、時間帯と曜日ごとのパターン付き |
| [コードとウォレット](../INVESTIGATION-MODE.md#codes-in-images) | 支払い QR コード。EIP-55 で確認する EVM アドレス、raw 形式の TON、XRP Ledger のチェックサム、チェーン・金額・トークンを含む支払いリンク |
| [クライアントの痕跡](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-show) | 丸型動画とボイスメッセージに残るエンコーダーの痕跡。アップロード時刻と送信時刻を比べると、事前に録画された「ライブ」の証拠が明らかになります |
| [偽装身分と権限](../INVESTIGATION-MODE.md#cover-and-authority) | ペルソナ、承認、そして承認されたチャットや期間の外にあるメッセージにフラグを付ける潜入活動記録 |
| [アカウント管理](../INVESTIGATION-MODE.md#account-control) | 変更前後の記録を残すプロフィールとプライバシーの編集、露出チェック、各操作直後のオフライン化 |
| [裁判用書類](../INVESTIGATION-MODE.md#documents-for-court) | Rule 902(13)/(14) 証明書テンプレート、証拠物一覧、要請書の別紙、画面録画用の WebVTT/SRT 字幕を含む BagIt 事件パッケージ |

18+、暴力、個人データとしてマークされたコンテンツは裁判用コピーに残り、AES-256-GCM で封印されます。鍵は別経路で渡します。

[エクスポート設定](../EXPORT_HASHES.md)では、通常の API と Takeout による取得、添付ファイルより先にメッセージ履歴を取得する方式、ファイルのダウンロードまたはサーバーハッシュ、互換性のある Telegram Desktop の JSON/HTML 表示を扱います。[分散チャットエクスポート](../DISTRIBUTED-EXPORT.md#history-acquisition)は、公開履歴向けのオプトイン方式の Takeout 経路、100 メッセージごとの署名付きチェックポイント、同じアカウントを使った範囲内での復旧を提供します。その[パフォーマンス設計](../FAST-ACQUISITION.md)には、テスト済みの取得動作と、予定している実環境での計測が記載されています。

</details>

<details>
<summary><strong>その他の機能</strong> · 履歴、アカウント、プロキシ、AI、連携</summary>

| | |
| --- | --- |
| [古いメッセージの読み込み](../HISTORY.md) | 選択したチャットの過去の履歴を取得。いつでも一時停止・再開が可能 |
| [複数のアカウント](../ACCOUNTS.md#multiple-accounts) | それぞれ専用の Telegram セッション、ジャーナル、署名鍵を持つ個別のワークスペース |
| [一括インポート](../ACCOUNTS.md#bulk-import-and-account-groups) | 大量のセッションファイルをまとめて投入し、設定を共有するグループにアカウントを振り分け |
| [MTProxy プール](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping、国、フィルター、独自のリスト |
| [既存のセッション](../ACCOUNTS.md) | TData、Telethon、Pyrogram、StringSession、auth key、または `key:DC` 形式の行。インポートしたドナーからの独立した QR 認証も可能（オプション） |
| [アカウントのセキュリティ](../ACCOUNTS.md#create-an-independent-authorization) | 新しいセッションの通知、他のセッションの終了、2 段階認証パスワードも設定する単独セッションモード、そしてライブ更新がこのセッションに届かなくなったことに気付く[証人プローブ](../ACCOUNTS.md#witness-probe) |
| [再開可能なチャットエクスポート](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | 中断したエクスポートは署名付きの部分コピーとして残り、再開、やり直し、保存済み分のダウンロードが可能 |
| [プロキシ](../CONNECTION-SECURITY.md#ip-modes) | ワークスペースごとに SOCKS5、HTTP CONNECT、MTProxy を設定。**IPを隠す**は決して直接接続にフォールバックしません |
| [検索と AI](../ANALYSIS.md) | ローカル検索と、確認可能な出典付きのオプションの AI |
| [全文検索](../SEARCH.md) | 語形変化、完全一致フレーズ、ドメイン、@ユーザー名、スペースなしの中国語に対応し、関連度の高い順に表示（**プレビュー版**） |
| [MCP](../MCP.md) | 選択したチャットに限定した、MCP クライアント向けの読み取り専用アクセス |
| [コマンドライン](../CLI.md) | `search`、`context`、`messages`、`stats` と JSON Lines 形式の `export`。`--json` でスクリプトやエージェントから利用でき、ローカルでもスコープ付きトークンでも使用可能（**プレビュー版**） |
| [OCR と文字起こし](../MEDIA-ANALYSIS.md) | ローカルで実行し、原本には手を加えません |
| [独立キャプチャ](../OPTIONAL-CAPTURE.md) | **その他のツール → 拡張機能**にある、ブラウザー/AyuGram 用のオプションのレコーダー（プレビュー、デフォルトはオフ） |
| [Trusted Live](../TRUSTED-LIVE.md) | 公式 Desktop/Web セッション、保護された動画、ネイティブエクスポートの連続性分析（プレビュー。実環境での適格性評価は未完了） |
| [封印型の公式 Web](../OFFICIAL-WITNESS.md) | GitHub Actions 上で起動する新規の公式ブラウザー、制限された操作、署名付き動画、独立に求めた期待値と照合するソース/設定 |
| [Webhooks](../WEBHOOKS.md) | リトライ付きの署名済み送信イベント。n8n のサンプル付き |
| [共有アクセス](../ACCESS.md) | 選択したチャットだけを、有効期限と IP 制限付きで他の人に共有 |
| [欠落しているメッセージ番号](../EVIDENCE.md#missing-message-numbers-gap_summary) | Telegram が割り当てたものの一度も観測されなかった番号を、チャンネル単位とアカウント全体でカバレッジ、レポート、MCP に表示（**プレビュー版**） |
| [チャット状態のスナップショット](../COLLECTION.md) | タイトル、説明、ピン留め、管理者、ギフトの署名付きスナップショットを定期的に取得し、変更点を表示（**プレビュー版**） |
| [システムマップ](../SYSTEM-MAP.md) | パネルへのアクセス、アカウントのルート、Telegram の接続先、外部サービスのライブマップ。最大 2,000 件のネットワーク観測記録のうち最新 200 件を表示 |

</details>

<details>
<summary><strong>記録の裏付けを選ぶ</strong> · ローカル、監査済みクラウド、GitHub Actions、Intel TDX</summary>

ローカルで実行するか、監査済みのクラウドデプロイを追加するか、**Intel TDX 搭載の Phala Cloud 機密 VM** 内で収集できます。どの方式でも署名付きジャーナルは維持され、追加のチェックは収集が行われた環境を対象とします。

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="3 つのデプロイ方式：ローカルでのジャーナル検証、事業者とアクセスの記録を伴う監査済み VM、検証済みの quote、計測済みの OS とアプリケーション、バインドされたコレクター鍵を備えた Phala Intel TDX。">
</picture>

TDX 検証ツールは、固定した Intel のルートと失効データに照らして quote を確認し、署名付きのコレクターステートメントと新しいチャレンジに結び付け、計測された OS とアプリケーションを独立に想定した入力と比較します。レポートは結果を項目ごとに分けて示すため、計測された環境、コレクターの身元、キャプチャ記録、カバレッジをまとめてレビューできます。

**GitHub の来歴付きキャプチャ**（プレビュー）。固定バージョンの TgWitness と新しい Telegram セッションを使って GitHub ホストのランナー上でチャットを収集し、暗号化されたアーカイブを GitHub のアテステーションとともにダウンロードします。検証ツールは承認済みのワークフローとコレクターのバージョン、アーカイブのダイジェスト、ジャーナル、添付ファイルを確認します。パネルの**エクスポート**からも利用できます。[キャプチャページを開く](https://phishdestroy.github.io/TgWitness/ja/docs/capture/) · [手順](../SEALED-ACTIONS.md)

ライブ観測、履歴、1 回限りのエクスポートなど、目的に合った[収集方法](../COLLECTION-MODES.md)を選んでください。接続したアカウントがアクセスできる場合は、プライベートなクラウドチャットも対象になります。公開中のアプリケーションには [Secret Chat 連携](../PSEUDO-SECRET.md)も含まれています。オプションのプロトコル依存関係をインストールしてアカウントごとに有効にすると、そのアカウントで作成または承諾したチャットを記録できます。利用可能な取得経路については[収集範囲](../COLLECTION.md)を参照してください。

[Phala / Intel TDX と監査済みデプロイ](../HIGH-ASSURANCE.md) ·
[Phala の実環境での適格性評価](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[信頼境界](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>キャプチャと保存された記録を検証する</strong> · 受信者が検証する内容と Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="会話をキャプチャし、記録を検証する。メッセージ、編集、ファイルを保存し、署名とチェックポイントを確認して、キャプチャのプロセスをレビューします。">
</picture>

TgWitness は、接続した Telegram アカウントに届いたコンテンツを、チャット・メッセージ・送信者の識別子、キャプチャしたバージョン、収集メタデータとともに記録します。アーカイブは、これらのレコード、保存された添付ファイル、検証データをまとめてレビューできるようにします。

| チェック | 受信者が検証する内容 |
| --- | --- |
| 署名付きジャーナルとマニフェスト | 想定される署名鍵に照らした、レコードの署名、ハッシュチェーン、引き渡されたファイル。 |
| 別途保管されたチェックポイント | 以前に記録された長さと最新のレコードのハッシュに照らしたジャーナル。 |
| 独立した証人 | 別の証人が保管しているチェックポイントに照らしたジャーナル。 |
| GitHub Actions キャプチャ | アテステーション、承認済みのホスト型ワークフロー、コレクターのバージョンに照らしたアーカイブ。 |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/) では、Telegram の会話と、意図的に改ざんした Desktop エクスポートファイルを並べて表示します。バージョンを比較し、変更点を確認しながら、署名付き TgWitness アーカイブの収集と検証の手順をたどれます。

[検証手順](../wiki/Exports-and-Verification.md) ·
[GitHub キャプチャ](../SEALED-ACTIONS.md) ·
[技術的な信頼モデル](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>調査を止めずに続ける</strong> · 通知、ストレージ、復旧</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="アニメーションワークフロー：Apprise が設定済みのアラートを送信し、オフサイトコピーは S3 互換ストレージへのアップロード前に暗号化されます。">
</picture>

[通知](../OPERATIONS.md#notifications) · [暗号化されたオフサイトコピー](../wiki/Off-site-Copy.md) · [バックアップと復旧](../wiki/Backup-and-Recovery.md) · [トラブルシューティング](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/ja/docs/start/"><b>セットアップガイド&nbsp;↗</b></a><br><sub>インストールから最初のチャットまで</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/ja/docs/dedicated-account/"><b>アカウントの準備&nbsp;↗</b></a><br><sub>専用の Telegram アカウント</sub></td>
<td width="33%" align="center"><a href="../DEPLOYMENT.md"><b>Docker とサーバー&nbsp;↗</b></a><br><sub>HTTPS、再起動、更新</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>リポジトリを見る</strong> · コード、ドキュメント、ツールの場所</summary>

| ディレクトリ | ここから始める |
| --- | --- |
| [docs/](../README.md) | セットアップ、調査ワークフロー、技術リファレンス |
| [tgwitness/](../../tgwitness/README.md) | メインアプリケーション、コレクター、ジャーナル、Web パネル |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | 独立したレコーダーとその検証コード |
| [addons/](../../addons/README.md) | オプションのキャプチャのインストール、設定、テスト |
| [deploy/](../../deploy/README.md) | インストーラー、コンテナー、バックグラウンドサービス |
| [examples/](../../examples/README.md) | アカウントエクスポートと封印型キャプチャの設定 |
| [integrations/](../../integrations/README.md) | 署名付き Webhook と n8n レシーバー |
| [.agents/](../../.agents/README.md) | CLI でアーカイブを読むためのタスク手順 |
| [scripts/](../../scripts/README.md) | ランチャーと CI ユーティリティ |
| [tools/](../../tools/README.md) | ビルド、チェック、パッケージング |
| [website/](../../website/README.md) | 公開サイト、翻訳済みガイド、インタラクティブデモ |
| [.github/](../../.github/AUTOMATION.md) | ワークフロー、コントリビューションガイドライン、サポート |

[プロジェクト完全ガイド](../PROJECT-GUIDE.md) ·
[コントリビューション](../../.github/CONTRIBUTING.md) · [ヘルプ](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ 倫理に関する通知および歴史的連続性</strong></summary>

作者の立場とオペレーターに関する通知の日本語版：

[オペレーターに関する通知](OPERATOR-INCOMPATIBILITY.md) · [MIT ライセンス](../../LICENSE) · [元の NOTICE](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>プロジェクト概要を各言語で読む</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · **日本語** · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>技術ドキュメント</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>調査ハンドブック</b></a> ·
  <a href="https://github.com/phishdestroy"><b>開発：PhishDestroy</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>コントリビュート</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>ヘルプ</b></a> ·
  <a href="../../.github/SECURITY.md"><b>脆弱性を報告</b></a>
</p>

[機械可読なプロジェクト索引](../../llms.txt) · [テキスト版ハンドブック全文](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [エージェント向けリポジトリルール](../../AGENTS.md)
