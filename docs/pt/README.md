<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">Outros idiomas</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Siga o rastro. Preserve as provas. Um diário assinado e encadeado por hashes, um ponto de verificação guardado à parte e um arquivo de provas verificável.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=pt"><b>Explore a demo&nbsp;↗</b></a><br><sub>A interface real com registros fictícios</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>Baixe e comece&nbsp;↓</b></a><br><sub>Um único comando para Linux, macOS e Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Leia o manual&nbsp;↗</b></a><br><sub>Guias de investigação, passo a passo</sub></td>
</tr>
</table>

<p align="center"><strong>Espaço de trabalho auto-hospedado para investigações no Telegram.</strong><br>Salve chats, mantenha edições e exclusões, veja quem está ligado a quem<br>e entregue exportações assinadas que qualquer pessoa pode conferir.</p>

<p align="center"><strong>CONFIANÇA ZERO.</strong> O TgWitness não toma partido: as mesmas verificações valem para o operador, para a PhishDestroy e para qualquer outra pessoa.<br>Só conta o que um terceiro ou a matemática confirma. <a href="../LIMITS-AND-OBJECTIONS.md">Limites e objeções</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.2 · pré-lançamento"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">Ambientes testados</a> · 25 idiomas de interface · 26 idiomas de guias</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=pt">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="A demo do TgWitness em ação: mensagens capturadas, versões salvas e conteúdo mantido após a exclusão. Registros de demonstração fictícios.">
</picture>
</a>

<p align="center"><sub>Explore a interface real com registros fictícios. Clique no espaço de trabalho para experimentar.</sub></p>

## O que o TgWitness faz

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">Cada edição e exclusão preservada</a></b><br><sub>Cada versão de uma mensagem é salva, e o texto permanece após um aviso de exclusão.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">Provas que qualquer pessoa pode conferir</a></b><br><sub>Registros assinados e encadeados por hashes. O destinatário verifica o arquivo offline com um único comando.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">Uma origem demonstrável</a></b><br><sub>Mensagens recebidas pela sessão MTProto autenticada da conta e assinadas na chegada; GitHub Actions e Intel TDX acrescentam atestado.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">Medido em escala</a></b><br><sub>48 arquivos verificados com 3.598.381 registros; oito contas obtiveram 768.007 registros de histórico a 687,5 registros/s.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">Feito para investigações</a></b><br><sub>Listas de observação sobre texto, códigos QR e OCR, verificação de carteiras, fichas de alvos, Quadro do Caso e um pacote para o tribunal.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">Sob seu controle</a></b><br><sub>Auto-hospedado e sem telemetria. As sessões ficam em um cofre criptografado; o painel escuta em localhost.</sub></td>
</tr>
</table>

<p align="center"><sub>Desenvolvido e testado por cerca de seis meses: primeiro o coletor, o diário assinado e o verificador; depois, o painel e os módulos complementares. Este repositório foi criado em 29 de outubro de 2026 para publicação, portanto, sua idade não corresponde à idade do projeto.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## Instalação

Python incluído. Use os mesmos comandos para atualizar.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell ou CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Servidor Ubuntu: execute como root. Desktop: execute com seu usuário normal. `-ExecutionPolicy Bypass` vale apenas para este processo do PowerShell.</sub>

Os builds assinados vêm do [fluxo de trabalho Installer](../../.github/workflows/installer.yml) público, e o instalador confere o SHA-256 e a assinatura RSA de cada pacote antes de instalar.

[Verifique o script primeiro](../INSTALLATION.md#verify-before-running) · [Primeira configuração](../SETTINGS.md) · [Versões](https://github.com/phishdestroy/TgWitness/releases) · [Docker](DEPLOYMENT.md)

<details>
<summary><strong>Como o instalador e seus dados são protegidos</strong></summary>

`get.destroy.tools` é o site de download do projeto. O
[fluxo de trabalho Installer](../../.github/workflows/installer.yml) público o gera a partir de
[`deploy/installer/`](../../deploy/installer/README.md) para a revisão exata de `main`,
publica-o depois que os testes de instalação no Linux e no Windows passam e assina os
scripts do instalador e os pacotes do aplicativo com a chave de publicação de versões em
[`release-signing.pub`](../../deploy/installer/release-signing.pub). O instalador confere
o SHA-256 e a assinatura RSA do pacote e do arquivo de bloqueio de dependências antes de instalar.
Para conferir o próprio script antes, baixe-o junto com a assinatura e execute os
[comandos de verificação prévia](../INSTALLATION.md#verify-before-running). Um build que falha
mantém o download anterior; os painéis instalados são atualizados quando você executa o instalador de novo.
As [versões](https://github.com/phishdestroy/TgWitness/releases) do GitHub, o código-fonte e o
[Docker](DEPLOYMENT.md) são as outras formas de instalar.

**Suas sessões e dados.** O TgWitness roda no seu computador ou servidor, e o painel
escuta em localhost por padrão. Sessões do Telegram, credenciais de proxy e hashes de tokens
de acesso ficam no cofre criptografado de cada espaço de trabalho, com uma
[chave mestra externa](../SECURITY-MODEL.md#external-master-key) opcional. O aplicativo
não tem telemetria. Ele se conecta ao Telegram e aos serviços que suas configurações usam:
listas públicas de MTProxy, seus proxies, armazenamento S3, um bot testemunha, autoridades
de carimbo do tempo, provedores de IA e webhooks. O [Mapa do sistema](../SYSTEM-MAP.md) lista
as conexões que o processo do aplicativo faz.
Observe com uma [conta dedicada do Telegram](https://phishdestroy.github.io/TgWitness/pt/docs/dedicated-account/).

O selo de versão descreve esta árvore de código-fonte. Os builds instaláveis aparecem em
[Versões](https://github.com/phishdestroy/TgWitness/releases); um recurso mesclado em
`main` chega a esses downloads na próxima versão.

[Instalação e acesso ao painel](../INSTALLATION.md) ·
[Assinaturas e SHA-256](https://get.destroy.tools/#verification) ·
[Atualização](../INSTALLATION.md#update-an-existing-installation) ·
[Recursos atuais e qualificação](../STATUS.md) ·
[Escolha um método de coleta](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## Um registro que outra pessoa pode conferir

Confira sem conta e sem instalar nada. O exemplo publicado traz o próprio verificador:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # o verificador vem dentro do arquivo
python verify.py tgwitness-demo.zip          # Python 3.11+, só precisa de `cryptography`
```

Ele exibe os registros assinados, o hash do cabeçalho e a impressão digital do signatário e termina com `0`.
O exemplo é fictício; o mesmo verificador funciona com qualquer exportação real.

Uma exportação contém as mensagens, os arquivos e o verificador. Envie ao destinatário a impressão
digital da sua chave por outro canal, e ele mesmo poderá conferir:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

O verificador confere as assinaturas, a cadeia do diário, a lista de arquivos e os anexos.
Para valer como prova, ele precisa da impressão digital da sua chave e de um carimbo do tempo de terceiros que cubra o último
registro, como um carimbo do tempo RFC 3161 conferido com o certificado raiz da autoridade.

**De onde vêm as mensagens.** O TgWitness as recebe do Telegram pela
sessão MTProto criptografada da conta, como fazem os aplicativos oficiais, e grava cada uma no
diário, já assinada, assim que chega. A [captura com GitHub Actions](../SEALED-ACTIONS.md) e o
[Phala Intel TDX](../HIGH-ASSURANCE.md) também atestam o coletor que as recebeu.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="Mensagens novas, edições salvas e observações de exclusão formam um diário encadeado e assinado. Verifique-o com uma chave confiável obtida de forma independente.">
</picture>

[Verificação do arquivo](../wiki/Exports-and-Verification.md) · [Formato das provas](../EVIDENCE.md) · [Testemunha independente](../WITNESS.md) · [Carimbos do tempo externos](../TIMESTAMP.md) · [Verificações e escala testada](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## De uma conversa a um caso

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="Três fluxos de trabalho animados: exportar um chat para HTML e JSON, encontrar um link compartilhado nos chats registrados e manter as versões capturadas após um aviso de exclusão.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>Exportação de chat&nbsp;↗</b></a><br><sub>Um chat em HTML e JSON assinados</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>Investigação&nbsp;↗</b></a><br><sub>Siga uma pista pelos chats registrados</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>Versões salvas&nbsp;↗</b></a><br><sub>Edições e avisos de exclusão, preservados</sub></td>
</tr>
</table>

Duas formas de usar: [exportar sua conta](../ACCOUNT-EXPORT.md) uma vez ou
[acompanhar uma investigação](../INVESTIGATION.md) e continuar salvando as alterações.
Escolha alguns chats, uma pasta do Telegram ou a conta inteira. Cada conta tem seu
próprio espaço de trabalho, sessão e chave de assinatura.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Saiba mais

<details>
<summary><strong>Exportações medidas · 6 de novembro de 2026</strong> · 56.329 mensagens, os dois arquivos verificados</summary>

**56.329 mensagens exportadas em duas execuções do zero.** Os dois arquivos assinados passaram na verificação com chaves de coletor fixadas.

[![Velocidade medida de coleta e de exportação completa](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/pt/docs/validation/)

| Execução | Mensagens | Tempo de coleta | Velocidade de coleta | Exportação completa | Velocidade de ponta a ponta |
| --- | ---: | ---: | ---: | ---: | ---: |
| Servidor A | 27.030 | 189,043 s | **142,983 mensagens/s** | 211,647 s | 127,713 mensagens/s |
| Servidor B | 29.299 | 182,513 s | **160,531 mensagens/s** | 206,650 s | 141,781 mensagens/s |

Texto e metadados via WARP, duas contas por servidor, sem anexos nem registros reaproveitados.
Medido na revisão [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e).
Cada execução publicada informa a revisão de origem, a carga de trabalho, os tempos e o resultado da verificação:
[carga de trabalho, tempos e verificação](../EXPORT-BENCHMARK-2026-11-06.md). As alterações em `main`
passam pelos [fluxos de trabalho de CI](../../.github/workflows/README.md) públicos, incluindo os testes do instalador no Linux e no Windows
e o build do verificador independente.

[**Explore a demo →**](https://phishdestroy.github.io/TgWitness/demo/?lang=pt) ·
[**Medições, datas e método →**](https://phishdestroy.github.io/TgWitness/pt/docs/validation/) ·
[Baixe uma exportação de exemplo fictícia](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[Auditoria assinada em inglês](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>Comece simples. Veja todas as rotas.</strong> · primeira inicialização e o mapa do sistema</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="A primeira inicialização oferece Só baixar, Acompanhar chats ou Provas para um caso e mostra só as seções correspondentes. O mapa do sistema liga o painel, o coletor, o Telegram, o diário, a testemunha e os serviços externos, com observações de rede. Valores fictícios.">
</picture>

A primeira inicialização faz uma única pergunta: **Só baixar**, **Acompanhar chats** ou
**Provas para um caso**. A resposta define o objetivo e o nível da interface, e o
painel mostra só as seções de que essa tarefa precisa. Conexão, login no Telegram e
escolha dos chats vêm em seguida, em cinco etapas. A verificação da conexão roda sozinha, e
as opções de rota só aparecem quando ela falha. As ferramentas avançadas ficam a um botão de distância.

O **Mapa do sistema** mostra como a instalação chega ao Telegram e aos serviços
externos: acesso ao painel, rota e destino no Telegram de cada conta, caminho do diário e
da testemunha e as observações de rede mais recentes. Uma observação ausente é
identificada como ausente.

[Primeira configuração](../SETTINGS.md) · [Mapa do sistema](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>Feito para o resto da investigação</strong> · fichas de alvos, listas de observação, carteiras, monitoramento de status online, documentos para o tribunal</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Acompanhe nomes e nomes de usuário pelo ID do Telegram. Registre as interações compatíveis com bots, com recibos assinados. Pesquise mensagens arquivadas e conecte clientes MCP somente leitura. Implante um coletor com o SSH mascarado e registros do provedor para revisão. Documente uma conversa passo a passo com referências ao diário. Entregue um pacote do caso BagIt com modelos para o tribunal. Fluxos de trabalho ilustrativos.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>Pessoas e dossiês&nbsp;↗</b></a><br><sub>Nomes e nomes de usuário acompanhados pelo ID do Telegram</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>Investigação de bots&nbsp;↗</b></a><br><sub>Interações com bots, com recibos assinados</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/pt/docs/archive/"><b>Busca no arquivo, IA e MCP&nbsp;↗</b></a><br><sub>Pesquise no arquivo e conecte clientes somente leitura</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>Implantação selada na nuvem&nbsp;↗</b></a><br><sub>Um coletor dentro do Intel TDX</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="Três etapas animadas: uma ficha de alvo cujo instantâneo posterior registra uma mudança de nome, um plano de conversa cujos objetivos se fecham com registros do diário e um código QR de pagamento decodificado em uma carteira com soma de verificação válida que gera uma ocorrência na lista de observação. Valores fictícios.">
</picture>

**Documente a conversa.** Abra uma ata para um chat no painel lateral **Documentação**
e cada etapa se registra sozinha: ações no painel, respostas com o intervalo antes
delas, edições, avisos de exclusão, notas e rascunhos de IA. Cada etapa cita seu registro
no diário e o SHA-256. Ao finalizar o documento, ele é assinado e o hash da declaração é gravado
no diário.

| | |
| --- | --- |
| [Fichas de alvos](../INVESTIGATION-MODE.md#subject-cards) | Instantâneos do perfil de um bot, pessoa, canal ou grupo com os rótulos BOT, VERIFIED, SCAM e FAKE do Telegram; um instantâneo posterior lista o que mudou |
| [Planos de conversa](../INVESTIGATION-MODE.md#conversation-plans) | Objetivos para a rota de pagamento, a infraestrutura ou as pessoas, mensagens preparadas, tempos de resposta, atividade por hora e o estilo de escrita do outro lado |
| [Tradução](../INVESTIGATION-MODE.md#machine-translation) | Exibida abaixo do original com idiomas, modelo e registro no diário |
| [Listas de observação](../INVESTIGATION-MODE.md#watchlists) | Palavras, padrões, carteiras, @nomes de usuário, IDs, domínios, telefones e links, detectados em texto, edições, destinos de links ocultos, botões de bots, códigos QR e OCR |
| [Monitoramento de status online](../INVESTIGATION-MODE.md#online-watch) | Verificações a cada 1–60 minutos, até 100 contas por solicitação, com um padrão por hora e dia da semana |
| [Códigos e carteiras](../INVESTIGATION-MODE.md#codes-in-images) | Códigos QR de pagamento; endereços EVM conferidos pelo EIP-55, TON em formato bruto, somas de verificação do XRP Ledger, links de pagamento com rede, valor e token |
| [Rastros do cliente](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-can-and-cannot-show) | Rastros do codificador em vídeos redondos e mensagens de voz; comparar o horário de upload com o de envio revela provas “ao vivo” pré-gravadas |
| [Disfarce e autorização](../INVESTIGATION-MODE.md#cover-and-authority) | Identidades fictícias, autorizações e um registro de atuação infiltrada que sinaliza mensagens fora dos chats ou do período autorizados |
| [Controle da conta](../INVESTIGATION-MODE.md#account-control) | Edição de perfil e privacidade com registros de antes e depois, verificação de exposição e modo offline logo após cada ação |
| [Documentos para o tribunal](../INVESTIGATION-MODE.md#documents-for-court) | Pacote do caso BagIt com modelo de certificação conforme a Rule 902(13)/(14), índice de provas, anexo de solicitação e legendas WebVTT/SRT para gravações de tela |

Conteúdo marcado como 18+, violência ou dados pessoais fica na cópia para o tribunal, selado com
AES-256-GCM; as chaves são enviadas separadamente.

As [configurações de exportação](../EXPORT_HASHES.md) cobrem a aquisição pela API comum e pelo Takeout,
o histórico de mensagens antes dos anexos, o download de arquivos ou os hashes do servidor e visualizações
JSON/HTML compatíveis com o Telegram Desktop. A [exportação distribuída de chats](../DISTRIBUTED-EXPORT.md#history-acquisition)
oferece um caminho opcional pelo Takeout para histórico público, pontos de verificação assinados a cada 100 mensagens
e recuperação dentro de um intervalo usando a mesma conta; seu
[projeto de desempenho](../FAST-ACQUISITION.md) descreve o comportamento de aquisição testado
e as medições ao vivo planejadas.

</details>

<details>
<summary><strong>Todo o resto</strong> · histórico, contas, proxies, IA, integrações</summary>

| | |
| --- | --- |
| [Carregar mensagens antigas](../HISTORY.md) | Baixe o histórico de chats selecionados; pause e retome quando quiser |
| [Várias contas](../ACCOUNTS.md#multiple-accounts) | Espaços de trabalho separados, cada um com sua própria sessão do Telegram, diário e chave de assinatura |
| [Importação em massa](../ACCOUNTS.md#bulk-import-and-account-groups) | Envie vários arquivos de sessão de uma vez e organize as contas em grupos com configurações compartilhadas |
| [Conjunto de MTProxy](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping, países, filtros e suas próprias listas |
| [Sessões existentes](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key ou uma linha `key:DC`; autorização independente opcional por QR a partir de um doador importado |
| [Segurança da conta](../ACCOUNTS.md#create-an-independent-authorization) | Alertas de novas sessões, encerramento de outras sessões, um modo de sessão única que também define uma senha de verificação em duas etapas e uma [sonda testemunha](../ACCOUNTS.md#witness-probe) que percebe quando as atualizações ao vivo deixam de chegar a esta sessão |
| [Exportação de chat retomável](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | Uma exportação interrompida mantém uma cópia parcial assinada: retome, recomece ou baixe o que foi salvo |
| [Proxies](../CONNECTION-SECURITY.md#ip-modes) | SOCKS5, HTTP CONNECT ou MTProxy por espaço de trabalho. **Ocultar IP** nunca recorre à conexão direta |
| [Busca e IA](../ANALYSIS.md) | Busca local e IA opcional com fontes que você pode conferir |
| [Busca de texto completo](../SEARCH.md) | Formas de palavras, frases exatas, domínios, @nomes de usuário e chinês sem espaços, com os melhores resultados primeiro (**versão prévia**) |
| [MCP](../MCP.md) | Acesso somente leitura para clientes MCP, limitado aos chats que você escolher |
| [Linha de comando](../CLI.md) | `search`, `context`, `messages`, `stats` e `export` em JSON Lines com `--json` para scripts e agentes, localmente ou com um token de escopo restrito (**versão prévia**) |
| [OCR e transcrição](../MEDIA-ANALYSIS.md) | Roda localmente; os originais não são alterados |
| [Captura independente](../OPTIONAL-CAPTURE.md) | Gravadores opcionais de navegador/AyuGram em **Mais ferramentas → Extras** (prévia, desativados por padrão) |
| [Trusted Live](../TRUSTED-LIVE.md) | Sessão oficial do Desktop/Web, vídeo protegido e análise de continuidade da exportação nativa (prévia; qualificação ao vivo pendente) |
| [Web oficial selada](../OFFICIAL-WITNESS.md) | Navegador oficial novo no GitHub Actions, controles restritos, vídeo assinado e código-fonte/configurações esperados de forma independente |
| [Webhooks](../WEBHOOKS.md) | Eventos de saída assinados com novas tentativas; exemplo para n8n incluído |
| [Acesso compartilhado](../ACCESS.md) | Dê a alguém acesso só aos chats selecionados, com prazo de validade e limites de IP |
| [Números de mensagens ausentes](../EVIDENCE.md#missing-message-numbers-gap_summary) | Números atribuídos pelo Telegram que nunca foram observados, por canal e para a conta inteira, na cobertura, nos relatórios e no MCP (**versão prévia**) |
| [Instantâneos do estado do chat](../COLLECTION.md) | Instantâneos assinados periódicos do título, da descrição, das mensagens fixadas, dos administradores e dos presentes, com o que mudou (**versão prévia**) |
| [Mapa do sistema](../SYSTEM-MAP.md) | Mapa ao vivo do acesso ao painel, das rotas das contas, dos destinos no Telegram e dos serviços externos, com as 200 mais recentes de até 2.000 observações de rede |

</details>

<details>
<summary><strong>Escolha o que sustenta o registro</strong> · local, nuvem auditada, GitHub Actions ou Intel TDX</summary>

Rode localmente, adicione uma implantação auditada na nuvem ou colete dentro de uma **VM confidencial
do Phala Cloud com Intel TDX**. Todas as opções mantêm o diário assinado; as verificações
extras tratam do ambiente em que ele foi coletado.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="Três opções de implantação: verificação local do diário; uma VM auditada com registros do provedor e de acesso; Phala Intel TDX com quote verificado, sistema operacional e aplicativo medidos e uma chave de coletor vinculada.">
</picture>

O verificador TDX confere o quote com a raiz fixada e os dados de revogação da Intel,
vincula-o a uma declaração assinada do coletor e a um desafio novo e compara o
sistema operacional e o aplicativo medidos com entradas esperadas de forma independente. O relatório lista
cada resultado separadamente, para que o ambiente medido, a identidade do coletor, os registros
de captura e a cobertura possam ser revisados em conjunto.

**Captura com procedência do GitHub** (prévia). Colete um chat em um runner hospedado pelo GitHub
com uma versão fixada do TgWitness e uma sessão nova do Telegram e depois baixe o arquivo
criptografado com o atestado do GitHub. O verificador confere o fluxo de trabalho aprovado e a
versão do coletor, o resumo criptográfico do arquivo, o diário e os anexos. Também disponível
em **Exportações** no painel.
[Abrir a página de captura](https://phishdestroy.github.io/TgWitness/pt/docs/capture/) · [Instruções](../SEALED-ACTIONS.md)

Para observação ao vivo, histórico ou uma exportação pontual, escolha um
[método de coleta](../COLLECTION-MODES.md). Chats privados na nuvem ficam disponíveis
quando a conta conectada tem acesso a eles. O aplicativo publicado também inclui a
[integração com chats secretos](../PSEUDO-SECRET.md): instale a dependência opcional do protocolo
e ative-a por conta para registrar os chats criados ou aceitos nela.
Consulte o [escopo da coleta](../COLLECTION.md) para ver os caminhos de aquisição disponíveis.

[Phala / Intel TDX e implantações auditadas](../HIGH-ASSURANCE.md) ·
[Qualificação ao vivo no Phala](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[Limites de confiança](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>Confira a captura e o registro salvo</strong> · o que o destinatário verifica e a Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="Capture a conversa. Verifique o registro. Salve mensagens, edições e arquivos, confira assinaturas e pontos de verificação e revise o processo de captura.">
</picture>

O TgWitness registra o conteúdo entregue à conta do Telegram conectada, com
identificadores de chat, mensagem e remetente, versões capturadas e metadados de coleta.
O arquivo reúne esses registros, os anexos preservados e os dados de verificação
para revisão.

| Verificação | O que o destinatário verifica |
| --- | --- |
| Diário assinado e manifesto | As assinaturas dos registros, a cadeia de hashes e os arquivos entregues em relação à chave de assinatura esperada. |
| Ponto de verificação guardado à parte | O diário em relação a um comprimento e um hash do cabeçalho registrados anteriormente. |
| Testemunha independente | O diário em relação aos pontos de verificação guardados por uma testemunha separada. |
| Captura com GitHub Actions | O arquivo em relação ao seu atestado, ao fluxo de trabalho hospedado aprovado e à versão do coletor. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
mostra uma conversa do Telegram ao lado de arquivos de exportação do Desktop alterados de propósito.
Compare as versões, examine as alterações e siga as etapas de coleta e
verificação de um arquivo assinado do TgWitness.

[Etapas de verificação](../wiki/Exports-and-Verification.md) ·
[Captura no GitHub](../SEALED-ACTIONS.md) ·
[Modelo técnico de confiança](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>Mantenha a investigação em andamento</strong> · notificações, armazenamento e recuperação</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="Fluxos de trabalho animados: o Apprise envia os alertas configurados; as cópias externas são criptografadas antes do envio para um armazenamento compatível com S3.">
</picture>

[Notificações](../OPERATIONS.md#notifications) · [Cópia externa criptografada](../wiki/Off-site-Copy.md) · [Backup e recuperação](../wiki/Backup-and-Recovery.md) · [Solução de problemas](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/pt/docs/start/"><b>Guia de configuração&nbsp;↗</b></a><br><sub>Da instalação ao primeiro chat</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/pt/docs/dedicated-account/"><b>Prepare sua conta&nbsp;↗</b></a><br><sub>Uma conta dedicada do Telegram</sub></td>
<td width="33%" align="center"><a href="DEPLOYMENT.md"><b>Docker e servidores&nbsp;↗</b></a><br><sub>HTTPS, reinicializações e atualizações</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>Explore o repositório</strong> · onde ficam o código, a documentação e as ferramentas</summary>

| Diretório | Comece por aqui |
| --- | --- |
| [docs/](../README.md) | Configuração, fluxos de investigação e referência técnica |
| [tgwitness/](../../tgwitness/README.md) | Aplicativo principal, coletor, diário e painel web |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | Gravadores independentes e o código de verificação deles |
| [addons/](../../addons/README.md) | Instalação, configuração e testes da captura opcional |
| [deploy/](../../deploy/README.md) | Instaladores, contêineres e serviços em segundo plano |
| [examples/](../../examples/README.md) | Configurações de exportação de conta e de captura selada |
| [integrations/](../../integrations/README.md) | Webhooks assinados e um receptor para n8n |
| [.agents/](../../.agents/README.md) | Instruções de tarefas para ler o arquivo pela CLI |
| [scripts/](../../scripts/README.md) | Inicializadores e utilitários de CI |
| [tools/](../../tools/README.md) | Builds, verificações e empacotamento |
| [website/](../../website/README.md) | Site público, guias traduzidos e demo interativa |
| [.github/](../../.github/AUTOMATION.md) | Fluxos de trabalho, diretrizes de contribuição e suporte |

[Guia completo do projeto](../PROJECT-GUIDE.md) ·
[Como contribuir](../../.github/CONTRIBUTING.md) · [Obter ajuda](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ Aviso ético e continuidade histórica</strong></summary>

A posição dos autores e o aviso sobre o operador, neste idioma:

[Aviso sobre incompatibilidade de licença e arquitetura](TAYLOR-WESSING-EXCLUSION.md) · [Aviso sobre o operador](OPERATOR-INCOMPATIBILITY.md) · [Licença MIT](../../LICENSE) · [NOTICE original](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>Leia a apresentação do projeto no seu idioma</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [Español](../es/README.md) · **Português (Brasil)** · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>Documentação técnica</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Manual de investigação</b></a> ·
  <a href="https://github.com/phishdestroy"><b>Feito pela PhishDestroy</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>Contribua</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>Obter ajuda</b></a> ·
  <a href="../../.github/SECURITY.md"><b>Relatar uma vulnerabilidade</b></a>
</p>

[Índice do projeto legível por máquina](../../llms.txt) · [Manual completo em texto](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [Regras do repositório para agentes](../../AGENTS.md)
