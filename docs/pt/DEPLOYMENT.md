[TgWitness](../../README.md) / [Documentação](../README.md) / [Pasta](README.md)

![Implantação e recuperação](../assets/presentation/chapter-operate.svg)

[English](../DEPLOYMENT.md) · [Русский](../ru/DEPLOYMENT.md) · [Українська](../uk/DEPLOYMENT.md) · [Español](../es/DEPLOYMENT.md) · **Português (Brasil)** · [Türkçe](../tr/DEPLOYMENT.md) · [العربية](../ar/DEPLOYMENT.md) · [فارسی](../fa/DEPLOYMENT.md) · [اردو](../ur/DEPLOYMENT.md) · [हिन्दी](../hi/DEPLOYMENT.md) · [Bahasa Indonesia](../id/DEPLOYMENT.md) · [Tiếng Việt](../vi/DEPLOYMENT.md) · [简体中文](../zh/DEPLOYMENT.md)

# Implantação e operação

## Escolher uma instalação

Para o pacote portátil, extraia `TgWitness-<version>-windows-amd64-portable.zip` do GitHub Releases. Para os outros métodos, baixe e extraia o ZIP do código-fonte ou clone o repositório e, em seguida, execute o seguinte a partir do diretório do projeto:

| Instalação | Iniciar | Roda em segundo plano? |
| --- | --- | --- |
| Pacote portátil para Windows | `TgWitness.cmd` | Não; mantenha a janela aberta. |
| Windows nativo | `Start.cmd` | Não; para uso em segundo plano, use a tarefa opcional de logon. |
| Linux/macOS nativo | `sh start.sh` | Não; para uso em segundo plano, use systemd/launchd. |
| Docker em qualquer host compatível | `docker compose up -d --build --wait` | Sim, enquanto o daemon do Docker estiver em execução. |
| Script auxiliar do Docker no Windows | `scripts\Docker.cmd` | Sim; o script aguarda o servidor web ficar íntegro. |
| Script auxiliar do Docker no Linux/macOS | `sh scripts/docker-start.sh` | Sim; o script aguarda o servidor web ficar íntegro. |

Para um servidor em nuvem que um terceiro precise poder verificar — criado pela API do provedor, sem SSH, acessível apenas por um Cloudflare Tunnel —, consulte [implantação de alta garantia](../HIGH-ASSURANCE.md).

A inicialização nativa cria um `.venv` privado e instala as dependências fixadas. O Docker as instala dentro da imagem, sem exigir Python no host. A configuração inicial precisa de acesso à Internet. Quando nenhum Python 3.11+ é encontrado, o `Start.cmd` pergunta antes de instalar o Python 3.12 para o usuário atual do Windows (via winget ou, caso contrário, pelo instalador do python.org após verificar a assinatura da Python Software Foundation); ele nunca solicita privilégios de administrador. O Docker e os serviços do sistema operacional continuam sendo pré-requisitos.

As instalações nativas e portáteis usam `data/live` dentro da própria pasta. O Docker usa o volume nomeado `tgwitness-data` em `/data`. São instalações separadas até que você migre deliberadamente o diretório de dados completo. Não espere que um contêiner Docker novo descubra automaticamente as contas nativas.

## Requisitos de instalação

A instalação nativa precisa do Python 3.11 ou posterior com `venv` e `ensurepip`, acesso à Internet para a primeira instalação de dependências e um diretório de projeto gravável para `.venv`. O painel incluído não precisa de Node.js nem de build de front-end. Execute o iniciador a partir da sua conta normal do sistema operacional; o TgWitness não exige privilégios de administrador/root.

- **Windows:** o `Start.cmd` verifica `py -3`, depois `python` e, em seguida, as pastas de instalação padrão por usuário e de Program Files, e exige a versão 3.11 ou posterior. Se nenhuma funcionar, ele oferece a instalação automática por usuário descrita acima. `py -3 start.py` também funciona. O pacote portátil dispensa totalmente o Python.
- **Linux:** o `start.sh` tenta `python3.13`, `python3.12`, `python3.11`, `python3` e `python` e, quando nenhum atende aos requisitos, exibe o comando de instalação para apt, dnf, pacman, zypper, apk ou Homebrew. Instalações no Debian/Ubuntu podem exigir o pacote `python3-venv` correspondente ao interpretador selecionado. Um Python padrão mais antigo da distribuição precisa ser substituído ou complementado pelo Python 3.11+.
- **macOS:** instale uma distribuição atual do Python 3.11+; não presuma que um interpretador fornecido pelo sistema operacional atende ao requisito. Use `python3 start.py` a partir do diretório do projeto.
- **Docker:** use o Docker Engine/Desktop com Compose v2.20 ou mais recente. No Windows, o Docker Desktop precisa usar contêineres Linux. O contêiner instala suas próprias dependências Python; o host não precisa de uma instalação separada do Python.

## Computador local

Use `Start.cmd` no Windows ou `sh start.sh` no Linux/macOS. `scripts\Setup.cmd` ou `sh start.sh --setup-only` prepara o ambiente. O iniciador instala as dependências no primeiro uso; as execuções seguintes reutilizam o ambiente. O acesso à Internet é necessário para a configuração e a coleta do Telegram, mas consultar registros existentes e criar exportações funciona offline.

Execute `python start.py --check` após a configuração para inspecionar as dependências locais, o Ed25519, o armazenamento, a configuração de chaves e o endereço de escuta sem iniciar um coletor. Use `--json` para saída estruturada. Passe os `--data-dir`, `--host` e `--port` pretendidos. A verificação não instala pacotes, não cria um diário nem se conecta ao Telegram; ela não é uma qualificação de integridade ou de cobertura. A inicialização verifica separadamente os diários existentes. `python start.py --help` também não instala nada.

Depois de usar o start.py, execute os comandos auxiliares com `.venv\Scripts\python.exe` no Windows ou `.venv/bin/python` no Linux/macOS, ou ative esse ambiente antes. Os exemplos `python -m ...` abaixo pressupõem que o ambiente está ativo.

~~~sh
python -m tgwitness --data-dir /path/to/private/data --host 127.0.0.1 --port 8787
~~~

Variáveis de ambiente: TGWITNESS_DATA, TGWITNESS_HOST, TGWITNESS_PORT, TGWITNESS_TOKEN. TGWITNESS_VAULT_KEY_FILE seleciona o modo de chave externa para uma nova instalação; veja [Chave mestra externa](../SECURITY-MODEL.md#external-master-key). Se fornecido, TGWITNESS_TOKEN deve ter pelo menos 24 caracteres; use um valor criptograficamente aleatório. Sem ele, o aplicativo gera um token aleatório de 256 bits em panel-token.txt. A substituição pela variável de ambiente não reescreve esse arquivo. Reinicie para trocar as credenciais.

Exatamente um processo pode ser dono de um diretório de dados. Um bloqueio de arquivo multiplataforma do sistema operacional impede gravações simultâneas acidentais. Use um único worker do Uvicorn. O painel pode gerenciar qualquer número de espaços de trabalho, com diretórios adicionais de espaços de trabalho em profiles/<id>/. Para instâncias de serviço separadas, use diretórios e portas separados. Os arquivos WAL do SQLite devem ficar em armazenamento persistente local, não em um sistema de arquivos de rede. Não compartilhe um volume entre réplicas.

## Pacote portátil para Windows

Cada versão no GitHub Releases traz `TgWitness-<version>-windows-amd64-portable.zip` e o respectivo `.sha256`. Ele contém o runtime embutível oficial do Python 3.12 do python.org (soma de verificação fixada em `tools/build_portable.py`), o TgWitness com suas dependências fixadas e três iniciadores:

| Arquivo | Finalidade |
| --- | --- |
| `TgWitness.cmd` | Inicia o painel; opções extras são repassadas, por exemplo `TgWitness.cmd --port 8790` |
| `TgWitness-Demo.cmd` | Inicia a demonstração sintética em `data\demo` |
| `TgWitness-Check.cmd` | Executa a verificação de prontidão sem iniciar |

O dicionário de morfologia russa fixado e os perfis de cor de PDF vêm incluídos para uso offline. O empacotamento permite apenas os caminhos de arquivo conhecidos deles dentro dos diretórios `data` das dependências; arquivos inesperados nesses diretórios fazem o build falhar.

Extraia o arquivo inteiro para uma pasta gravável, como `Documents\TgWitness`; não o execute de dentro do ZIP nem a partir de Program Files. O runtime usa um caminho de módulos isolado, de modo que outras instalações do Python e `PYTHONPATH` não o afetam. Os dados ficam na pasta `data` do pacote. Para atualizar, interrompa o TgWitness, extraia a nova versão em uma nova pasta e copie a pasta `data` para ela.

Compile você mesmo no Windows de 64 bits com Python 3.12:

~~~sh
python tools/build_portable.py
~~~

## Contêiner

```sh
docker compose up -d --build --wait
```

Isso cria um volume persistente nomeado para /data. A porta web é mapeada para 127.0.0.1:8787. O processo roda como UID 10001 com as capabilities do Linux removidas, sistema de arquivos raiz somente leitura e /data e /tmp graváveis. `--wait` verifica a integridade do servidor web antes de retornar; a autorização do Telegram e a entrega aparecem no painel. Os scripts auxiliares fornecidos usam um tempo limite de prontidão de 180 segundos após o build. Os downloads iniciais de dependências podem levar mais tempo que isso.

Os dois arquivos Compose base usam o nome de projeto `tgwitness`, então extrair uma nova versão em outro diretório não seleciona silenciosamente um novo volume de dados. Mantenha apenas uma implantação ativa para esse projeto. Para instalações independentes, use um `docker compose -p NAME ...` exclusivo e uma porta de host diferente, e mantenha ambos nas atualizações. Para uma implantação mais antiga que usa outro nome de projeto, continue usando o nome original com `-p`; `docker compose ls` lista os projetos existentes.

Copie `deploy/env.example` para `.env` e altere `TGWITNESS_PORT` para usar outra porta de loopback. Por exemplo, `TGWITNESS_PORT=8788` expõe o painel em `http://127.0.0.1:8788`; o contêiner continua escutando na 8787. O `.env` é ignorado pelo Git.

Obtenha o token inicial:

~~~sh
docker compose exec tgwitness cat /data/panel-token.txt
~~~

Comandos úteis:

```sh
docker compose ps
docker compose logs --tail 100 -f
docker compose stop
docker compose up -d --wait
```

`restart: unless-stopped` reinicia o coletor após uma falha ou um reinício do daemon do Docker. Em um servidor Linux, habilite o Docker na inicialização com o gerenciador de serviços da sua distribuição, geralmente `sudo systemctl enable --now docker`. No Windows/macOS, ative a opção do Docker Desktop de iniciar ao entrar na sessão. Sair da sessão do desktop, a suspensão ou um daemon do Docker parado podem interromper a coleta. Um contêiner parado explicitamente permanece parado até que você o inicie de novo.

O volume /tmp é limitado a 512 MiB na configuração de exemplo. A montagem das exportações usa, em vez dele, o `temporary-exports/` de cada espaço de trabalho no /data persistente. Reserve espaço ali para exportações simultâneas, crescimento do diário/WAL, mídia e backups. O iniciador usa deploy/constraints.txt para fixar versões qualificadas das dependências de runtime. O Docker e os servidores de alta garantia instalam a partir de deploy/requirements.lock e deploy/build.lock com pip --require-hashes: cada arquivo de pacote precisa corresponder a um SHA-256 registrado no commit, de modo que um arquivo substituído no PyPI ou em um espelho é recusado. A imagem base do Python e os pacotes do sistema operacional ainda exigem qualificação independente da versão.

Não use docker compose down -v, a menos que pretenda destruir o diário e as chaves. A integridade do contêiner indica a disponibilidade do servidor web, não o sucesso da captura do Telegram. Verifique no painel o estado do coletor, o sinal de vida, os erros e os eventos de cobertura.

### Perfil de testemunha independente

O serviço opcional `witness` executa uma [testemunha independente](../WITNESS.md) em seu próprio contêiner, com chave e diário próprios no volume `witness-data` e apenas um token de testemunha somente leitura para o coletor. Crie o token no painel em **Mais ferramentas → Extras → Testemunha independente**, adicione-o ao `.env` com um token de bot e um canal e, em seguida, inicie o perfil:

```sh
docker compose --profile witness up -d          # deploy/compose/compose.image.yaml: same flag
docker compose logs witness                     # witness key fingerprint
```

O serviço acessa o coletor dentro da rede do Compose em `http://tgwitness:8787` (`TGWITNESS_WITNESS_COLLECTOR` substitui esse endereço, por exemplo por `/profiles/<workspace ID>` para outro espaço de trabalho). Para uma testemunha em um servidor separado, operado por outra pessoa, use lá o `deploy/compose/compose.witness.yaml` com `TGWITNESS_WITNESS_COLLECTOR` definido como o endereço HTTPS do coletor; esse arquivo contém apenas a testemunha.

## Instalar uma imagem publicada

Copie `deploy/env.example` para `.env`. Defina `TGWITNESS_IMAGE` com a versão publicada, usando o caminho do repositório **em minúsculas**, por exemplo:

```dotenv
TGWITNESS_IMAGE=ghcr.io/your-owner/your-repository:0.9.2
TGWITNESS_PORT=8787
```

Execute este arquivo sozinho, em vez de `compose.yaml`:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
docker compose --project-directory . -f deploy/compose/compose.image.yaml exec tgwitness cat /data/panel-token.txt
```

Não é preciso build do código-fonte, Python nem compilador no host. O fluxo de trabalho de lançamento tem como alvo contêineres Linux AMD64 e ARM64, incluindo a VM Linux do Docker Desktop. Use uma tag de versão ou `ghcr.io/owner/repository@sha256:...` do resumo do fluxo de trabalho. Não há tag móvel `latest` nem atualização automática do aplicativo configurada. As variantes por imagem e por código-fonte usam o mesmo volume de dados quando o nome do projeto coincide.

<a name="automatic-https-on-a-server"></a>

## HTTPS automático em um servidor

Use um servidor com Docker, um domínio que você controla e armazenamento local persistente. Aponte os registros A/AAAA do domínio para o servidor; publique AAAA somente se o servidor for acessível por IPv6. Libere a entrada TCP 80 e 443 e a saída DNS/HTTPS para a emissão do certificado. Nenhum outro serviço pode estar ocupando essas portas.

Copie `deploy/env.example` para `.env` e defina um nome de host, sem esquema nem caminho:

```dotenv
TGWITNESS_DOMAIN=watch.your-domain.org
```

Inicie o build a partir do código-fonte com o overlay HTTPS:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml exec tgwitness cat /data/panel-token.txt
```

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml -f deploy/compose/compose.https.yaml up -d --wait
```

Para uma imagem publicada, use em vez disso `deploy/compose/compose.image.yaml` como primeiro arquivo. Mantenha os dois argumentos `-f` nos comandos posteriores de status, logs, atualização e parada.

O Caddy obtém e renova um certificado, redireciona HTTP para HTTPS e encaminha as solicitações ao coletor pela rede privada do Compose. O estado do certificado tem seu próprio volume persistente. A porta direta do coletor no host continua restrita ao loopback. A configuração do Caddy fornecida não ativa o log de acesso.

Abra `https://watch.your-domain.org` e insira o token do painel. A prontidão do Compose cobre os contêineres; a emissão do certificado e o acesso externo dependem do DNS e do firewall. Se o HTTPS não estiver pronto, verifique o DNS, as regras do firewall e:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml logs --tail 100 caddy
```

A imagem do Caddy fornecida acompanha a tag `2-alpine`. Um pull atualiza essa imagem; fixe um digest testado na sua implantação se precisar de versões de infraestrutura fixas.

## Atualizações e backups

Preserve o nome do projeto Compose e o volume de dados entre as atualizações. Primeiro, interrompa o coletor e faça um backup completo. Para a implantação padrão baseada no código-fonte:

```sh
docker compose stop
docker compose cp tgwitness:/data ../tgwitness-backup-before-update
```

Use um destino de backup novo a cada vez, fora do repositório, e proteja-o como material de acesso às contas. O caminho de exemplo é ilustrativo; use o seu local privado de backup. Copie o diretório inteiro, incluindo arquivos ocultos, todos os espaços de trabalho, chaves, diários e mídia. Se houver uma chave-mestra externa do cofre configurada, faça backup dela separadamente. Um ZIP de evidências não é um backup restaurável do aplicativo. Com HTTPS, preserve também os volumes do Caddy se precisar manter o estado de certificado/conta dele.

Para uma implantação a partir do código-fonte, obtenha os arquivos da nova versão e execute:

```sh
docker compose up -d --build --wait
```

Para uma implantação por imagem, altere `TGWITNESS_IMAGE` para a versão desejada e execute:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
```

Use também o(s) arquivo(s) Compose da sua instalação nos comandos de parada/cópia anteriores. Mantenha o `.env`, a configuração personalizada e o mesmo nome de projeto. `down` mantém os volumes nomeados; **`down -v` os exclui**. Não copie `.venv` entre sistemas operacionais ou versões do Python. Para atualizações nativas, interrompa o TgWitness, faça backup do diretório de dados completo, substitua os arquivos do código-fonte e execute `python start.py --setup-only` antes de iniciar.

Verifique o acesso ao painel, a identidade da conta, o estado da observação e a cobertura após uma atualização. Após a reinicialização, o TgWitness retoma a partir da posição de atualizações do Telegram salva e solicita as atualizações do Telegram perdidas durante a atualização do aplicativo. Uma reversão pode exigir o backup anterior à atualização se uma versão futura alterar os formatos de armazenamento.

## Servidor remoto

Mantenha o serviço vinculado ao loopback e use um túnel SSH, ou encerre o HTTPS em um proxy reverso. O arquivo Compose base é apenas local; o overlay opcional `deploy/compose/compose.https.yaml` fornece o Caddy para um domínio configurado. Mantenha o token bearer fora de URLs e dos logs do proxy. Um proxy reverso deve limitar o tamanho das solicitações e a taxa de conexões. Não exponha HTTP sem criptografia à Internet.

Exemplos para systemd, uma tarefa de logon do Windows, um agente de usuário do macOS e o Caddy estão em [deploy/](../../deploy/README.md). Revise e adapte os caminhos antes da instalação. São modelos fornecidos, não qualificações de plataforma executadas localmente. O iniciador normal não registra nenhum serviço ou tarefa em segundo plano.

No Windows, uma execução sem janela via `pythonw.exe` grava os diagnósticos de inicialização/servidor em `logs/server.log`, no diretório de dados (5 MiB por arquivo, dois backups rotacionados). As execuções pelo console mantêm o log no console. O log de acesso HTTP fica desativado nos dois modos. Proteja os logs junto com o diretório de dados e revise-os antes de compartilhá-los.

## Reinício e lacunas

O último estado de observação solicitado é persistido. Se a observação estava ativa, a inicialização tenta se reconectar e retomar as fontes selecionadas. A pausa manual cancela essa intenção. Uma reinicialização com falha é registrada e exibida no painel.

O TgWitness armazena a posição de atualizações do Telegram da conta e de cada canal (pts, qts, seq e date) no cofre do espaço de trabalho e a restaura na inicialização seguinte. Em seguida, o cliente solicita as atualizações perdidas enquanto o processo estava parado, e a reverificação periódica recupera mensagens perdidas e registra as salvas que o Telegram não retorna mais. Os diálogos são recarregados na inicialização. Cada inicialização registra o cabeçalho anterior do diário, o limite do período offline e a posição de atualizações a partir da qual retomou. O monitor verifica a conectividade a cada 10 segundos e adiciona um sinal de vida a cada minuto (**Mais ferramentas → Parâmetros → Registro de atividade a cada**). Desconexões e períodos de silêncio são registrados como lacunas de cobertura, com o motivo. Instantâneos do histórico são armazenados como observações separadas do histórico atual, ao lado dos registros ao vivo.

A fila de mídia é armazenada no banco de dados SQLite de cada espaço de trabalho. Uma mensagem e sua tarefa são confirmadas atomicamente. Tarefas em execução interrompidas são recuperadas para nova tentativa na inicialização. Cada download tem um tempo limite base de 120 segundos mais o tempo correspondente ao seu tamanho a 256 KiB/s, e um limite de 1–2000 MiB por tipo de anexo; tempo limite, velocidade e novas tentativas ficam em **Mais ferramentas → Parâmetros**. O coletor ignora arquivos de tamanho desconhecido. A pausa preserva o trabalho na fila. A nova tentativa usa o descritor de arquivo original observado, nunca a versão mais recente de uma mensagem editada depois. Falhas temporárias têm tentativas limitadas; as pausas FloodWait de mídia sobrevivem à reinicialização. A recuperação de mídia é separada da recuperação de atualizações do Telegram e não pode recriar arquivos desaparecidos.

## Backup, restauração e capacidade

Interrompa o processo antes de copiar o **diretório de dados inteiro**, incluindo vault.key, signing.enc, credentials.enc, os arquivos de banco de dados SQLite/WAL, a mídia, o token, os pontos de verificação e todos os subdiretórios de profiles/. Restaure a cópia completa com o serviço de destino parado. Chaves do cofre ausentes ou divergência da chave de assinatura fazem a inicialização falhar; não gere chaves novas para forçar o acesso.

Mantenha os backups com segredos criptografados e com acesso controlado. Os ZIPs de evidências são artefatos portáteis de revisão, não backups do aplicativo nem de sessões do Telegram. Não há exclusão automática por retenção. Planeje espaço em disco para todas as mensagens, metadados brutos, mídia, exportações temporárias e backups.

A verificação na inicialização e a exportação processam os registros em fluxo, em vez de carregar o diário inteiro. Uma exportação fixa um instantâneo de leitura enquanto novas gravações no WAL podem continuar; exportações longas podem reter páginas do WAL, então a capacidade de disco continua importando. Os ZIPs são limitados a 4 GiB descompactados para corresponder ao padrão do verificador independente; **Mais ferramentas → Parâmetros → Maior arquivo ZIP assinado** aumenta o limite, e esses arquivos são verificados com `verify.py --max-gib N`. Os outros formatos não têm limite de número de eventos. Os navegadores compatíveis transmitem os blocos da resposta para um arquivo escolhido pelo usuário. Outros navegadores armazenam em buffer no máximo 128 MiB e direcionam transferências maiores para a CLI autenticada:

~~~sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
~~~

Use `--profile ID` de **Exportações → ID do espaço de trabalho** para outro espaço de trabalho, `--format zip|jsonl|csv|html`, `--url https://your-server` para um servidor remoto ou `--max-mib` para alterar o limite de transferência de 5 GiB. HTTP sem criptografia só é permitido para loopback. Os tokens trafegam em cabeçalhos, redirecionamentos são recusados, arquivos existentes não são sobrescritos e downloads incompletos não são publicados como arquivos concluídos. Se TGWITNESS_TOKEN substituir o token gerado, use um arquivo protegido separadamente contendo esse valor ativo: o panel-token.txt não é reescrito pela substituição. O SHA-256 do comando é apenas uma soma de verificação da transferência; verifique o ZIP assinado de forma independente.

O painel exibe mídias na fila/com falha, a mídia pendente mais antiga, o espaço livre em disco, as pausas de solicitações do Telegram e as fontes cujo acesso não foi confirmado. Esses diagnósticos não constituem um monitoramento completo de entrega de ponta a ponta. Os espaços de trabalho compartilham um processo; uma conta muito ativa ainda pode afetar as outras. Continuam pendentes processos de trabalho separados, retenção/rotação, recuperação durável de atualizações e qualificação completa da implantação. O acesso ao painel com escopo limitado está documentado em [acesso e permissões](../ACCESS.md); os pontos de verificação independentes são abordados no [guia da testemunha](../WITNESS.md).

Procedimentos detalhados: [conexão/segurança](../CONNECTION-SECURITY.md) e [modos de operação](../OPERATIONS.md).
