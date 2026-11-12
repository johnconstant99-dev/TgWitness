[TgWitness](../../README.md) / [Документация](../README.md) / [Папка](README.md) · [Доказательства и проверка](../EVIDENCE.md)

![Доказательства и проверка](../assets/presentation/chapter-evidence.svg)

# Независимая проверка

[English](../TRUST.md) · [Политика безопасности](../../.github/SECURITY.md)

Сверьте полученный файл с его публичным рабочим процессом и коммитом исходного кода.
Записи о происхождении предоставляют размещённые раннеры GitHub, OIDC и Sigstore; ваша
политика проверки определяет, каким ревизиям рабочего процесса и кода вы доверяете.

Для архива Telegram начните с раздела [«Запечатанные доказательства»](#запечатанные-доказательства),
а для локального рабочего пространства — с [руководства по подписанному журналу](../wiki/Exports-and-Verification.md).
Для выпуска TgWitness следуйте шагам для архива исходного кода ниже.

## Архив исходного кода выпуска

Установите актуальную версию [GitHub CLI](https://cli.github.com/manual/gh_attestation_verify). Из
релиза скачайте `TgWitness-<ver>.zip`, `.zip.sha256`, `sbom.spdx.json`,
`provenance.sigstore.json` и `sbom.sigstore.json`. ZIP собирается скриптом
`tools/build_source.py` на размещённом GitHub раннере Ubuntu (это отдельный файл, а не старый
ресурс релиза `*-source.zip`).

Возьмите полный SHA проверенного вами коммита и просмотрите `.github/workflows/provenance.yml`,
закреплённые в нём actions и `tools/build_source.py` именно в этом коммите. Не берите SHA
из недоверенного архива и не считайте, что теги никогда не перемещаются. Затем выполните:

```sh
VERSION='<ver>'
COMMIT='<reviewed-release-commit>'
gh attestation verify "TgWitness-${VERSION}.zip" \
  --repo phishdestroy/TgWitness \
  --signer-workflow phishdestroy/TgWitness/.github/workflows/provenance.yml \
  --signer-digest "$COMMIT" --source-digest "$COMMIT" \
  --source-ref "refs/tags/v${VERSION}" --deny-self-hosted-runners
```

Команда проверяет дайджест файла, подпись SLSA provenance, репозиторий, ревизию рабочего
процесса, коммит и ref исходного кода, а также то, что файл собран на размещённом раннере.
Одна контрольная сумма ничего не говорит о том, кто собрал файл. Повторите команду для
`.zip.sha256`. Для сохранённых пакетов аттестации добавьте `--bundle provenance.sigstore.json`;
для автономной проверки заранее получите доверенные корни.

3 ноября 2026 года коммиты были объединены (squash). Теперь теги указывают на коммиты с теми же
файлами, но аттестации более ранних выпусков называют исходные коммиты, которые по-прежнему
доступны на GitHub. Используйте их в качестве `COMMIT`:

| Выпуск | Аттестованный коммит |
| --- | --- |
| 0.8.1 | `5ad1569e0b5bc8fce6920b5439eb3e35418a2193` |
| 0.8.0 | `204e31bd294534574a9ef9428f24a38c81b57e6b` |
| 0.7.1 | `99225f985701b0cdccb333d947c6bb9bad8673aa` |

### Повторная сборка ZIP с исходным кодом

`python tools/build_source.py` сортирует записи и фиксирует метки времени, права доступа
и сжатие, поэтому одни и те же входные байты и одинаковые Python/zlib дают одинаковый ZIP.
Метка времени 1980 года — просто нейтральное значение. Чтобы сравнить результат с ZIP,
собранным на GitHub, соберите архив из проверенного коммита в чистой рабочей копии с теми же
настройками окончаний строк и тем же набором инструментов, затем сравните SHA-256. Окончания
строк и версии компрессора могут изменить результат.

## Запечатанные доказательства

Расшифровав переданный архив по инструкции [SEALED-ACTIONS](SEALED-ACTIONS.md), проверьте
`evidence.zip` по своему форку (`OWNER/TgWitness`):

```sh
gh attestation verify evidence.zip --bundle attestation.jsonl \
  --repo OWNER/TgWitness \
  --signer-workflow phishdestroy/TgWitness/.github/workflows/sealed-collector.yml \
  --signer-digest e8746b675e7d4f74d4317d634ad0ae838b128397 \
  --deny-self-hosted-runners
```

Просмотрите [закреплённый рабочий процесс коллектора](https://github.com/phishdestroy/TgWitness/blob/e8746b675e7d4f74d4317d634ad0ae838b128397/.github/workflows/sealed-collector.yml):
он загружает коммит коллектора `0a6a488fb35a8815cacad2e584fcfdefe7014fab`. Проверенные пары
рабочего процесса и коллектора перечислены в [`tgwitness/sealed_policy.json`](../../tgwitness/sealed_policy.json);
используйте пару, закреплённую вызывающим рабочим процессом вашего форка.
Для проверки журнала, вложений, политики и охвата также запустите верификатор из установки,
которой вы доверяете:

```sh
python -m tgwitness.sealed_verify evidence.zip --bundle attestation.jsonl --repo OWNER/TgWitness
```

## Публичные записи и SBOM

- **Журнал прозрачности.** Сводка шага аттестации в Actions содержит ссылку на Rekor; поле
  `verificationMaterial.tlogEntries` пакета аттестации содержит запись журнала и доказательство
  включения. Просмотреть её можно в [поиске Sigstore](https://search.sigstore.dev/). Запись журнала
  фиксирует время обязательства, а не сообщений Telegram ([Rekor](https://docs.sigstore.dev/logging/overview/)).
- **Scorecard.** [Отчёт OpenSSF Scorecard](https://securityscorecards.dev/viewer/?uri=github.com/phishdestroy/TgWitness)
  формируется каждый понедельник и при push в `main`. Смотрите на дату, коммит и замечания
  вместе с оценкой.
- **Аудит рабочих процессов.** [workflow-audit.yml](../../.github/workflows/workflow-audit.yml) запускает zizmor
  при изменениях рабочих процессов и каждый понедельник; результаты сохраняются в артефакте
  `workflow-audit-sarif`.
- **Зависимости.** `sbom.spdx.json` объединяет найденное Syft с точными версиями Python-пакетов
  из `deploy/requirements.lock`, `deploy/build.lock` и `deploy/constraints-mcp.txt`.
  Рабочий процесс завершается ошибкой при отсутствующих, лишних или несовпадающих пакетах.

  Проверьте подпись SBOM командой проверки выпуска выше (указав файл `sbom.spdx.json`),
  а также его привязку к ZIP с исходным кодом:

  ```sh
  gh attestation verify "TgWitness-${VERSION}.zip" \
    --bundle sbom.sigstore.json \
    --predicate-type https://spdx.dev/Document/v2.3 \
    --repo phishdestroy/TgWitness \
    --signer-workflow phishdestroy/TgWitness/.github/workflows/provenance.yml \
    --signer-digest "$COMMIT" --source-digest "$COMMIT" \
    --source-ref "refs/tags/v${VERSION}" --deny-self-hosted-runners
  ```

  Затем просканируйте его локально:

  ```sh
  grype sbom:sbom.spdx.json
  ```

## Область проверки

Аттестация выпуска связывает указанный файл и его дайджест с записанным рабочим процессом
сборки и ревизией исходного кода. Проверяйте аттестацию, предоставленную именно для
устанавливаемого артефакта; у других форматов пакетов свои способы публикации и проверки.

SBOM описывает заявленные версии пакетов, а сканирование сверяет эти версии со своей
базой уязвимостей. Архивы доказательств проверяются отдельно — по
[процедуре проверки для их режима сбора](../EVIDENCE.md#verification-scope).
