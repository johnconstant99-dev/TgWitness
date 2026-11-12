[TgWitness](../../README.md) / [Documentação](../README.md) / [Pasta](README.md)

![Primeiros passos](../assets/presentation/chapter-start.svg)

[English](../QUICKSTART.md) · [Русский](../ru/QUICKSTART.md) · [Українська](../uk/QUICKSTART.md) · [Español](../es/QUICKSTART.md) · **Português (Brasil)** · [Türkçe](../tr/QUICKSTART.md) · [العربية](../ar/QUICKSTART.md) · [فارسی](../fa/QUICKSTART.md) · [اردو](../ur/QUICKSTART.md) · [हिन्दी](../hi/QUICKSTART.md) · [Bahasa Indonesia](../id/QUICKSTART.md) · [Tiếng Việt](../vi/QUICKSTART.md) · [简体中文](../zh/QUICKSTART.md)

# Início rápido do TgWitness

O TgWitness é um aplicativo independente para observar grupos e canais do Telegram aos quais suas contas têm acesso. Ele roda localmente, com seu próprio diretório de dados.

**Primeira visita?** [Explore a demonstração](#explore-the-interface) antes de conectar uma conta. [Escolha um guia](../README.md) sobre proxies, testemunhas, exportações ou configuração de servidor. A [captura no GitHub Actions](../SEALED-ACTIONS.md) (prévia) executa uma captura no seu próprio fork do GitHub em vez de uma instalação local.

<a name="install-and-start"></a>

## Instalar e iniciar

O instalador guiado inclui seu próprio Python e verifica os hashes dos pacotes e as assinaturas da versão antes de instalar. Executá-lo de novo atualiza uma instalação existente.

**Linux / macOS:**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows (PowerShell ou Prompt de Comando):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

Em um servidor Ubuntu, execute como root para instalar um serviço em segundo plano; em um desktop, execute com seu usuário normal. No Ubuntu, o instalador exibe o endereço do painel e a chave de acesso; no macOS e no Windows, o painel local abre no navegador. Continue em **Conectar o Telegram**, abaixo. [Instalar, verificar e atualizar](../INSTALLATION.md) aborda as opções de acesso ao servidor, a conferência do script antes de executá-lo, as atualizações e a remoção.

### Outros métodos

As versões publicadas no GitHub, o código-fonte e o Docker são alternativas ao instalador. Os downloads portáteis ficam disponíveis depois que um build da versão é publicado:

| Sistema | Sem nada instalado | A partir do código-fonte: Python 3.11+ | Docker: Engine/Desktop com Compose 2.20+ |
| --- | --- | --- | --- |
| Windows | Extraia `TgWitness-<version>-windows-amd64-portable.zip` do GitHub Releases e clique duas vezes em `TgWitness.cmd` | Clique duas vezes em `Start.cmd` | Clique duas vezes em `scripts\Docker.cmd` |
| Linux / macOS | — | `sh start.sh` | `sh scripts/docker-start.sh` |

Para os métodos a partir do código-fonte, [baixe e extraia a branch `main` atual](https://github.com/phishdestroy/TgWitness/archive/refs/heads/main.zip) ou clone o repositório:

```sh
git clone https://github.com/phishdestroy/TgWitness.git
cd TgWitness
```

Se não encontrar um Python adequado, o `Start.cmd` oferece instalar o Python 3.12 para o seu usuário do Windows (via winget ou pelo instalador assinado do python.org). Se o Python estiver ausente, o `start.sh` exibe o comando de instalação exato para sua distribuição Linux ou para o macOS. A primeira execução a partir do código-fonte cria `.venv` e instala as dependências automaticamente.

O Docker compila o aplicativo e o inicia em segundo plano; não é preciso ter Python no host. `scripts\Docker.cmd` e `scripts/docker-start.sh` exibem o endereço do painel e o token quando o contêiner passa na verificação de integridade. Os comandos Docker equivalentes em qualquer host compatível são:

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

Abra **http://127.0.0.1:8787**. Use o token exibido pelo script auxiliar do Docker ou pelo segundo comando Docker; em uma instalação portátil ou a partir do código-fonte, leia **data/live/panel-token.txt**. Continue em **Conectar o Telegram**, abaixo. As instalações nativas e as do Docker usam armazenamento separado; iniciar o Docker não importa um diário nativo existente.

Para um servidor, o guia de [implantação](DEPLOYMENT.md) cobre HTTPS automático, reinicialização, imagens publicadas, atualizações e backups.

<a name="explore-the-interface"></a>

## Explorar a interface

1. Execute **TgWitness-Demo.cmd** no pacote portátil, **scripts\Demo.cmd** em uma pasta de código-fonte no Windows ou `sh start.sh --demo` no Linux/macOS. Uma execução a partir do código-fonte primeiro cria `.venv` e instala as dependências.
2. Abra **http://127.0.0.1:8787**.
3. A demonstração local abre automaticamente o diário de exemplo. Para acesso local direto, não é preciso copiar nenhum token.

As mensagens da demonstração são fictícias. O modo de demonstração não consegue conectar uma conta real do Telegram.

## Conectar o Telegram

> [!WARNING]
> **Use contas dedicadas.** O Telegram pode restringir contas ou bani-las permanentemente por volumes de solicitações que considere excessivos, seja qual for o cliente. Conecte contas preparadas para observação, e não contas pessoais ou valiosas, e crie o ID da API e o hash em uma conta dedicada.

1. Se a demonstração nativa estiver em execução, interrompa-a e execute **Start.cmd** ou `sh start.sh`. Caso contrário, mantenha em execução a instalação real iniciada acima.
2. Entre com o token do painel. Um espaço de trabalho novo abre a [configuração inicial](../SETTINGS.md). Escolha **Só baixar**, **Acompanhar chats** ou **Provas para um caso**.
3. Revise a verificação de conexão. Configure seu próprio proxy, se necessário; as configurações de conexão continuam disponíveis após a configuração inicial.
4. Em **Conectar Telegram**, escolha um número de telefone, um código QR, arquivos de conta
   (TData, `.session`, StringSession, JSON da conta) ou uma chave de autorização completa.
   Conclua a confirmação do Telegram, insira o código e a senha de duas etapas quando
   solicitado.
5. Confira a conta exibida, escolha os chats e revise suas configurações. Conclua na tela final. Em **Só baixar**, **Iniciar exportação** inicia uma exportação única e abre Exportações para mostrar o progresso; isso não ativa a observação contínua.

Depois da configuração, **Conversas → Escolha** altera os chats selecionados. **Configurações** controla a coleta e os arquivos; **Mais ferramentas → Fontes** traz a lista detalhada de fontes no nível Padrão ou Especialista. O [guia do painel](../PANEL.md) descreve as seis seções principais e seus controles contextuais.

**ID da API + Hash** é opcional: o espaço de trabalho usa o par salvo ou importado, ou um par funcional do pool integrado. Para usar seu próprio aplicativo, cole um par `API ID:API Hash` em ID da API. Em **Chave de autenticação**, cole todos os 512 caracteres hexadecimais e selecione o DC ID fornecido com ela. O ID do usuário é opcional e, se informado, é verificado.

As credenciais da API identificam seu aplicativo; por si sós, elas não autorizam uma conta. Grupos privados não precisam de nome de usuário público, mas sua conta precisa ter acesso.

Para contas existentes, consulte [contas e formatos de sessão](../ACCOUNTS.md): o painel aceita Telethon StringSession, Telethon/Pyrogram SQLite, TData ZIP de conta única e JSON de conta compatível. Selecione juntos uma sessão e o JSON que a acompanha e pressione **Conectar conta**. O login por QR também está disponível com as mesmas configurações opcionais de API. TDLib, sessões de bot e inventários de contas em CSV/JSON não são suportados.

Para várias contas, use **Contas → Importar contas** e selecione os arquivos de sessão compatíveis. Os arquivos JSON que os acompanham são pareados pelo nome base; cada conta importada recebe seu próprio espaço de trabalho. Veja [importação em massa e grupos de contas](../ACCOUNTS.md#bulk-import-and-account-groups).

Para adicionar outra conta, pressione **+** ao lado do seletor de contas ou use **Contas → Adicionar conta**. Os espaços de trabalho têm sessões, diários, chaves, fontes e filas separados. Trocar de visualização mantém os outros coletores em execução. A mesma conta do Telegram não pode ser atribuída a dois espaços de trabalho nesta instalação. Não há número fixo de espaços de trabalho; eles compartilham um processo, então a capacidade depende da máquina.

O token do painel da instalação real protege o acesso às suas autorizações do Telegram e ao material salvo; ele é separado das credenciais da API do Telegram. Apenas uma demonstração local iniciada explicitamente e acessada diretamente recebe entrada automática. Uma demonstração remota ou atrás de proxy continua usando `data/demo/panel-token.txt`.

## Revisar e exportar

- **Diário:** pesquise e filtre observações por fonte e tipo de evento.
- Selecione um evento para inspecionar o registro original, a atribuição e as versões salvas.
- Os detalhes de edição mostram o conteúdo disponível antes e depois. Os detalhes de exclusão mostram o último conteúdo capturado, se houver; um autor desconhecido continua desconhecido.
- **Exportações:** ZIP assinado, JSONL, CSV e HTML offline.
- **Exportação completa do chat** (**Conversas → Exportar bate-papo** ou **Exportações → Capturar ou exportar um chat**): baixe todo o histórico visível de um chat como um pacote assinado com `chat.json` (no estilo da exportação do Telegram) e um `chat.html` legível. Chats privados funcionam quando a conta é membro. É um instantâneo atual, não uma reconstrução de mensagens excluídas ou editadas anteriormente. Verifique uma cópia com `python verify.py chat-export.zip --fingerprint TRUSTED_SHA256`.
- **Salvar ponto de verificação:** mantenha o limite assinado do diário fora do coletor.
- **Baixe o comprovante de execução assinado:** preserve o registro do programa e da versão do coletor.
- **Preparar solicitação de carimbo de data/hora:** prepare uma solicitação offline para uma autoridade de carimbo de data/hora; siga o [TIMESTAMP.md](../TIMESTAMP.md) para obter e verificar uma resposta.
- **Verificar o registro:** verifique as assinaturas dos eventos e os elos da cadeia. A exportação ZIP também verifica a mídia.

Os navegadores compatíveis salvam exportações grandes diretamente em um arquivo escolhido. Outros navegadores armazenam em buffer no máximo 128 MiB. Enquanto o servidor estiver em execução, a CLI de streaming permite downloads maiores sem armazenar a resposta inteira em buffer:

```sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
```

Para outro espaço de trabalho, adicione `--profile ID` usando **Exportações → ID do espaço de trabalho**. Para um servidor remoto, adicione `--url https://your-server`. O limite de transferência padrão é 5 GiB; `--max-mib` o altera. O conteúdo de um ZIP assinado tem, por padrão, um limite de verificação separado de 4 GiB descompactado (**Mais ferramentas → Parâmetros** o aumenta; verifique esses arquivos com `verify.py --max-gib N`). Verifique o arquivo com uma cópia confiável do verificador, uma impressão digital da chave guardada de forma independente e, para os requisitos mínimos de prova, o certificado raiz da autoridade de carimbo de data/hora (`--tsa-ca`).

## Verificar a instalação

```sh
python start.py --setup-only
python start.py --check
python start.py --check --json
```

`--check` verifica as dependências locais, o suporte a assinaturas, o armazenamento, a configuração de chaves e o endereço de escuta. Ele não instala nada nem se conecta ao Telegram. Uma porta ocupada pode indicar que outra instância está em execução. Use um `--port` diferente ou interrompa essa instância primeiro.

O iniciador instala em `.venv`. Os comandos auxiliares `python -m tgwitness...` devem usar `.venv\Scripts\python.exe` no Windows ou `.venv/bin/python` no Linux/macOS, a menos que esse ambiente já esteja ativado.

## Sessões, proteção e operação

Um arquivo `.session` do Telethon SQLite fechado e consistente pode ser convertido localmente com `python -m tgwitness.sessions account.session --out account.tgwitness-session` e depois carregado em **Mais ferramentas → Conta → Arquivos**. A importação direta de arquivos e o login por QR também estão disponíveis. Veja [CONNECTION-SECURITY.md](../CONNECTION-SECURITY.md) para formatos de login, SOCKS5, HTTP CONNECT, MTProxy e chaves-mestras externas.

**Pausar a observação** interrompe a coleta. **Bloquear** apenas fecha o acesso pelo navegador. Fechar uma aba mantém o processo do coletor em execução. Interromper o processo interrompe a coleta; um instantâneo do histórico não consegue reconstruir todas as edições ou exclusões perdidas. Veja [como funciona a coleta](../COLLECTION.md) para políticas de eventos, filas de anexos, isolamento de contas e comportamento na reinicialização.

As sessões e os segredos são criptografados. O conteúdo das mensagens, a mídia e as exportações exigem um disco ou volume criptografado. Verifique as assinaturas do diário com uma chave confiável e guarde os pontos de verificação separadamente. Revise os registros de captura, os comprovantes de tempo externos e os atestados de ambiente do modo de coleta selecionado.

Leia [OPERATIONS.md](../OPERATIONS.md) para backup/restauração, [DEPLOYMENT.md](DEPLOYMENT.md) para hospedagem e [deploy/](../../deploy/README.md) para exemplos de serviço. O painel instalado também inclui um guia de configuração offline em `/guide.html`.

A verificação efetivamente realizada e os limites restantes estão registrados em [VERIFICATION.md](../VERIFICATION.md) e [READINESS.md](../internal/READINESS.md).
