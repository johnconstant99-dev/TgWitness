[English](../DEPLOYMENT.md) · [Русский](../ru/DEPLOYMENT.md) · [Українська](../uk/DEPLOYMENT.md) · [Español](../es/DEPLOYMENT.md) · **Português (Brasil)** · [Türkçe](../tr/DEPLOYMENT.md) · [العربية](../ar/DEPLOYMENT.md) · [فارسی](../fa/DEPLOYMENT.md) · [اردو](../ur/DEPLOYMENT.md) · [हिन्दी](../hi/DEPLOYMENT.md) · [Bahasa Indonesia](../id/DEPLOYMENT.md) · [Tiếng Việt](../vi/DEPLOYMENT.md) · [简体中文](../zh/DEPLOYMENT.md)

# Implantação e operações

## Escolha uma opção de instalação

Para o pacote portátil, extraia `TgWitness-<version>-windows-amd64-portable.zip` das versões do GitHub. Para os demais métodos, baixe e extraia o arquivo ZIP com o código-fonte ou clone o repositório e, em seguida, execute o seguinte a partir do diretório do projeto:

| Instalação | Início | Funciona em segundo plano? |
| --- | --- | --- |
| Pacote portátil para Windows | `TgWitness.cmd` | Não; mantenha a janela aberta. |
| Versão nativa para Windows | `Start.cmd` | Não; utilize a tarefa opcional de logon para execução em segundo plano. |
| Versão nativa para Linux/macOS | `sh start.sh` | Não; utilize o systemd/launchd para execução em segundo plano. |
| Docker em qualquer host compatível | `docker compose up -d --build --wait` | Sim, enquanto o daemon do Docker estiver em execução. |
| Auxiliar do Docker no Windows | `scripts\Docker.cmd` | Sim; o helper aguarda a verificação do estado do servidor web. |
| Utilitário do Docker no Linux/macOS | `sh scripts/docker-start.sh` | Sim; o helper aguarda a verificação do estado do servidor web. |

A inicialização nativa cria uma imagem privada `.venv` e instala as dependências fixadas. O Docker as compila dentro da imagem, sem a necessidade do Python do host. A configuração inicial requer acesso à Internet. Quando não for encontrado o Python 3.11 ou superior, o `Start.cmd` solicita permissão antes de instalar o Python 3.12 para o usuário atual do Windows (via winget; caso contrário, o instalador do python.org, após verificar a assinatura da Python Software Foundation); ele nunca solicita privilégios de administrador. O Docker e os serviços do sistema operacional continuam sendo pré-requisitos.

As instalações nativas e portáteis utilizam `data/live` dentro de sua pasta. O Docker utiliza o volume nomeado `tgwitness-data` em `/data`. Trata-se de instalações separadas até que o senhor migre deliberadamente o diretório de dados completo. Não espere que um novo contêiner do Docker identifique contas nativas automaticamente.

## Requisitos de instalação

A instalação nativa requer Python 3.11 ou versão posterior com `venv` e `ensurepip`, acesso à Internet para a instalação da primeira dependência e um diretório de projeto com permissão de gravação para `.venv`. O painel incluído no pacote não requer Node.js nem compilação de front-end. Execute o iniciador a partir de sua conta normal do sistema operacional; o TgWitness não exige privilégios de administrador/root.

- **Windows:** `Start.cmd` verifica `py -3`, depois `python`, em seguida as pastas padrão de instalação por usuário e em “Arquivos de Programas”, e requer a versão 3.11 ou posterior. Caso nenhuma opção funcione, é oferecida a instalação automática por usuário descrita acima. `py -3 start.py` também funciona. O pacote portátil não requer Python.
- **Linux:** `start.sh` verifica `python3.13`, `python3.12`, `python3.11`, `python3` e `python` e exibe o comando de instalação para apt, dnf, pacman, zypper, apk ou Homebrew quando nenhuma opção for adequada. As instalações no Debian/Ubuntu podem exigir o pacote `python3-venv` compatível com o interpretador selecionado. O Python padrão mais antigo de uma distribuição deve ser substituído ou complementado pelo Python 3.11+.
- **macOS:** instale uma distribuição atual do Python 3.11 ou superior; não presuma que o interpretador fornecido pelo sistema operacional atenda aos requisitos. Utilize `python3 start.py` a partir do diretório do projeto.
- **Docker:** utilize o Docker Engine/Desktop com o Compose v2.20 ou mais recente. O Docker Desktop deve utilizar contêineres Linux no Windows. O contêiner instala suas próprias dependências do Python; o host não necessita de uma instalação separada do Python.

Utilize armazenamento local persistente para o diretório de dados. Planeje a capacidade com base em mensagens, mídia, crescimento do WAL, exportações e backups; não há uma especificação mínima universal de disco/RAM, baseada em evidências, para todas as cargas de trabalho. Arquiteturas de CPU e versões do Python sem pacotes de dependências compatíveis podem exigir ferramentas de compilação adicionais e sua própria qualificação. “Portátil” não significa suporte universal a sistemas operacionais ou hardware.

O Windows 11/Python 3.12 foi verificado localmente. As definições para Linux/macOS/contêineres e a integração contínua (CI) são fornecidas, mas não foram executadas neste servidor de desenvolvimento. Consulte [o arquivo VERIFICATION.md](../VERIFICATION.md) para obter o escopo exato.

## Computador local

Utilize `Start.cmd` no Windows ou `sh start.sh` no Linux/macOS. `scripts\Setup.cmd` ou `sh start.sh --setup-only` preparam o ambiente. O iniciador instala as dependências na primeira utilização; as execuções posteriores reutilizam o ambiente. É necessário acesso à Internet para a configuração e a coleta de dados do Telegram, mas a consulta de registros existentes e a criação de exportações funcionam offline.

Execute `python start.py --check` após a configuração para verificar as dependências locais, o Ed25519, o armazenamento, a configuração de chaves e o endereço de escuta sem iniciar um coletor. Utilize `--json` para obter uma saída estruturada. Passe os parâmetros pretendidos `--data-dir`, `--host` e `--port`. A verificação não instala pacotes, não cria um diário nem se conecta ao Telegram; não se trata de uma qualificação de integridade ou cobertura. A inicialização verifica separadamente os diários existentes. `python start.py --help` também evita a instalação.

Opções:

Após executar o start.py, execute os comandos auxiliares com `.venv\Scripts\python.exe` no Windows ou `.venv/bin/python` no Linux/macOS, ou ative primeiro esse ambiente. Os exemplos `python -m ...` abaixo pressupõem que o ambiente esteja ativo.

~~~sh
python -m tgwitness --data-dir /path/to/private/data --host 127.0.0.1 --port 8787
~~~

Variáveis de ambiente: TGWITNESS_DATA, TGWITNESS_HOST, TGWITNESS_PORT, TGWITNESS_TOKEN. TGWITNESS_VAULT_KEY_FILE seleciona o modo de chave externa para uma nova instalação; consulte abaixo. TGWITNESS_TOKEN, se fornecido, deve conter pelo menos 24 caracteres; utilize um valor aleatório criptograficamente seguro. Sem ele, o aplicativo gera um token aleatório de 256 bits no arquivo panel-token.txt. A substituição da variável de ambiente não reescreve esse arquivo. Reinicie o sistema para alternar as credenciais.

Exatamente um processo pode ser o proprietário de um diretório de dados. Um bloqueio de arquivos do sistema operacional, compatível com várias plataformas, impede gravações simultâneas acidentais. Utilize um worker do Uvicorn. O painel pode gerenciar qualquer número de espaços de trabalho, com diretórios adicionais de espaços de trabalho em profiles/<id>/. Para instâncias de serviço separadas, utilize diretórios e portas distintos. Os arquivos WAL do SQLite devem ser armazenados em um armazenamento persistente local, e não em um sistema de arquivos de rede. Não compartilhe um único volume entre réplicas.

## Pacote portátil para Windows

Cada versão do GitHub contém `TgWitness-<version>-windows-amd64-portable.zip` e seu `.sha256`. Ela inclui o runtime oficial do Python 3.12, incorporável, proveniente do site python.org (soma de verificação fixada em `tools/build_portable.py`), o TgWitness e suas dependências fixadas, além de três executáveis:

| Arquivo | Objetivo |
| --- | --- |
| `TgWitness.cmd` | Inicie o painel; opções adicionais são repassadas, por exemplo, `TgWitness.cmd --port 8790` |
| `TgWitness-Demo.cmd` | Inicie a demonstração sintética em `data\demo` |
| `TgWitness-Check.cmd` | Execute a verificação de prontidão sem iniciar o sistema |

Extraia todo o arquivo compactado para uma pasta com permissão de gravação, como `Documents\TgWitness`; não o execute de dentro do ZIP nem da pasta “Arquivos de Programas”. O ambiente de execução utiliza um caminho de módulo isolado, de modo que outras instalações do Python e `PYTHONPATH` não o afetam. Os dados permanecem na pasta `data` do pacote. Para atualizar, interrompa o TgWitness, extraia a nova versão para uma nova pasta e copie a pasta `data` para lá.

Compile-o você mesmo no Windows de 64 bits com Python 3.12:

~~~sh
python tools/build_portable.py
~~~

O construtor verifica a soma de verificação de tempo de execução, instala as dependências restritas no pacote, executa a verificação de prontidão com o interpretador incorporado e grava o arquivo ZIP e a soma de verificação em `dist/`.

## Contêiner

```sh
docker compose up -d --build --wait
```

Isso cria um volume persistente nomeado para /data. A porta da web é mapeada para 127.0.0.1:8787. O processo é executado com o UID 10001, com capacidades restritas, um sistema de arquivos raiz somente leitura e os diretórios /data e /tmp com permissão de gravação. `--wait` verifica a integridade do servidor web antes de retornar; ele não estabelece autorização nem entrega no Telegram. Os auxiliares fornecidos utilizam um tempo limite de prontidão de 180 segundos após a compilação. Os downloads iniciais de dependências podem demorar mais do que isso.

Ambos os arquivos Compose básicos utilizam o nome do projeto `tgwitness`; portanto, a extração de uma nova versão para outro diretório não seleciona automaticamente um novo volume de dados. Mantenha apenas uma implantação ativa para esse projeto. Para instalações independentes, utilize um `docker compose -p NAME ...` exclusivo e uma porta de host diferente, e mantenha ambos nas atualizações. Para uma implantação mais antiga que utilize um nome de projeto diferente, continue usando seu nome original com `-p`; `docker compose ls` lista os projetos existentes.

Copie `deploy/env.example` para `.env` e altere `TGWITNESS_PORT` para utilizar uma porta de loopback diferente. Por exemplo, `TGWITNESS_PORT=8788` expõe o painel em `http://127.0.0.1:8788`; o contêiner continua escutando na porta 8787. `.env` é ignorado pelo Git.

Recupere o token inicial:

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

`restart: unless-stopped` reinicia o coletor após uma falha ou reinicialização do daemon do Docker. Em um servidor Linux, habilite o Docker na inicialização usando o gerenciador de serviços da sua distribuição, geralmente o `sudo systemctl enable --now docker`. No Windows/macOS, habilite a configuração “iniciar ao fazer login” do Docker Desktop. O logout do desktop, o modo de suspensão ou um daemon do Docker parado podem interromper a coleta. Um contêiner explicitamente parado permanece parado até que você o inicie novamente.

O volume /tmp está limitado a 512 MiB na configuração de exemplo. A construção da exportação utiliza, em vez disso, o `temporary-exports/` de cada espaço de trabalho no diretório persistente /data. Reserve espaço nesse local para exportações simultâneas, crescimento do diário/WAL, arquivos de mídia e backups. O iniciador e o Docker utilizam o arquivo deploy/constraints.txt para fixar versões qualificadas de dependências de tempo de execução. Esta não é uma cadeia de suprimentos com bloqueio por hash: a imagem base do Python e os artefatos de pacotes ainda exigem qualificação de versão independente.

Não utilize o comando `docker compose down -v`, a menos que pretenda destruir o diário e as chaves. O relatório de integridade do contêiner informa a disponibilidade do servidor web, e não o sucesso da captura do Telegram. Verifique o estado do coletor do painel, o sinal de vida, os erros e os eventos de cobertura.

### Perfil de testemunha independente

O serviço opcional `witness` executa uma [testemunha independente](../WITNESS.md) em seu próprio contêiner, com sua própria chave e diário no volume `witness-data` e apenas um token de testemunha somente leitura para o coletor. Crie o token na página **Testemunha** do painel, adicione-o com um token de bot e um canal ao `.env` e, em seguida, inicie o perfil:

```sh
docker compose --profile witness up -d          # deploy/compose/compose.image.yaml: same flag
docker compose logs witness                     # witness key fingerprint
```

O serviço acessa o coletor dentro da rede Compose em `http://tgwitness:8787` (`TGWITNESS_WITNESS_COLLECTOR` o substitui; por exemplo, `/profiles/<workspace ID>` para outro espaço de trabalho). Para uma testemunha em um servidor separado, administrado por outra pessoa, utilize `deploy/compose/compose.witness.yaml` nesse local, com `TGWITNESS_WITNESS_COLLECTOR` definido como o endereço HTTPS do coletor; esse arquivo contém apenas a testemunha.

## Instale uma imagem publicada

Isso fica disponível após a conclusão bem-sucedida [do fluxo de trabalho de lançamento](#lançamentos-automatizados-no-github) e da configuração pública do pacote no GHCR. O nome do proprietário do repositório não está codificado de forma rígida nesta árvore de código-fonte. Utilize a imagem exibida no resumo do fluxo de trabalho desse lançamento.

Copie `deploy/env.example` para `.env`. Defina `TGWITNESS_IMAGE` como a versão publicada, utilizando o caminho do repositório **em letras minúsculas**, por exemplo:

```dotenv
TGWITNESS_IMAGE=ghcr.io/your-owner/your-repository:0.7.1
TGWITNESS_PORT=8787
```

Execute este arquivo por conta própria, em vez de `compose.yaml`:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
docker compose --project-directory . -f deploy/compose/compose.image.yaml exec tgwitness cat /data/panel-token.txt
```

Não é necessária nenhuma compilação de código-fonte, Python ou compilador no host. O fluxo de trabalho de lançamento é voltado para contêineres Linux AMD64 e ARM64, incluindo a máquina virtual Linux do Docker Desktop. Utilize uma tag de versão ou `ghcr.io/owner/repository@sha256:...` a partir do resumo do fluxo de trabalho. Não há configuração de tag `latest` móvel nem de atualização automática de aplicativos. As variantes de imagem e de código-fonte utilizam o mesmo volume de dados quando o nome do projeto coincide.

## HTTPS automático em um servidor

Utilize um servidor com o Docker, um domínio sob seu controle e armazenamento local persistente. Direcione os registros A/AAAA do domínio para o servidor; publique o registro AAAA somente se o IPv6 tiver acesso a ele. Permita o tráfego de entrada nas portas TCP 80 e 443 e o tráfego de saída de DNS/HTTPS para emissão de certificados. Essas portas não devem já estar em uso por outros serviços.

Copie `deploy/env.example` para `.env` e defina um nome de host, sem esquema nem caminho:

```dotenv
TGWITNESS_DOMAIN=watch.your-domain.org
```

Inicie a compilação do código-fonte com a sobreposição HTTPS:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml exec tgwitness cat /data/panel-token.txt
```

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml -f deploy/compose/compose.https.yaml up -d --wait
```

Para uma imagem publicada, utilize `deploy/compose/compose.image.yaml` como o primeiro arquivo. Mantenha ambos os argumentos `-f` para comandos posteriores de status, logs, atualização e parada.

O Caddy obtém e renova um certificado, redireciona HTTP para HTTPS e encaminha as solicitações para o coletor na rede privada da Compose. O estado do certificado possui seu próprio volume persistente. A porta direta do host do coletor permanece restrita ao loopback. A configuração do Caddy fornecida não habilita o registro de acesso.

Abra `https://watch.your-domain.org` e insira o token do painel. A verificação de prontidão não confirma a emissão do certificado nem a acessibilidade externa. Caso o HTTPS não esteja pronto, verifique o DNS, as regras do firewall e:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml logs --tail 100 caddy
```

A imagem do Caddy fornecida segue a tag `2-alpine`. A ação de “pull” atualiza essa imagem; fixe um resumo testado em sua implantação caso necessite de versões fixas da infraestrutura.

## Atualizações e backups

Preserve o nome do projeto Compose e o volume de dados ao longo das atualizações. Primeiro, interrompa o coletor e faça um backup completo. Para a implantação padrão baseada no código-fonte:

```sh
docker compose stop
docker compose cp tgwitness:/data ../tgwitness-backup-before-update
```

Utilize um novo destino de backup a cada vez, fora do repositório, e proteja-o como material de acesso à conta. O caminho de exemplo é meramente ilustrativo; utilize seu local de backup privado. Copie o diretório inteiro, incluindo arquivos ocultos, todas as áreas de trabalho, chaves, diários e arquivos de mídia. Faça backup da chave mestra do cofre externo separadamente, caso esteja configurada. Um arquivo ZIP de evidências não é um backup de aplicativo restaurável. Para HTTPS, preserve também os volumes do Caddy caso precise manter o estado do certificado/conta.

Para uma implantação a partir do código-fonte, obtenha os arquivos da nova versão e execute:

```sh
docker compose up -d --build --wait
```

Para uma implantação por imagem, altere `TGWITNESS_IMAGE` para a versão desejada e, em seguida, execute:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
```

Utilize também os arquivos Compose da sua instalação para os comandos stop/copy anteriores. Mantenha `.env`, a configuração personalizada e o mesmo nome do projeto. `down` mantém os volumes nomeados; **`down -v`** **os exclui**. Não copie `.venv` entre sistemas operacionais ou versões do Python. Para atualizações nativas, interrompa o TgWitness, faça backup de todo o diretório de dados, substitua os arquivos de origem e execute `python start.py --setup-only` antes de iniciar.

Verifique o acesso ao painel, a identidade da conta, o status da observação e a cobertura após uma atualização. Reiniciar o sistema não recupera as atualizações do Telegram perdidas. Uma reversão pode exigir o backup pré-atualização caso uma versão futura altere os formatos de armazenamento.

## Lançamentos automatizados no GitHub

O [fluxo de trabalho de lançamento](../../.github/workflows/release.yml) estará pronto para uso após este projeto ser enviado para um repositório do GitHub com o Actions habilitado. Ele é executado quando um lançamento no GitHub é **publicado**, incluindo um pré-lançamento. Rascunhos e envios de tags, por si só, não publicam pacotes.

1. Defina a versão do pacote e o registro de alterações e, em seguida, publique uma versão marcada com `v`, além da versão exata `pyproject.toml`, como `v0.7.1`.
2. O fluxo de trabalho valida a tag e executa as verificações compartilhadas para Python no Windows/Linux/macOS, navegador geral/importação de conta/QR, pacote-fonte e Docker. Também é realizada uma instalação nativa nova em todos os três sistemas operacionais utilizando o Python 3.12.
3. Após a aprovação dessas verificações, ele realiza testes preliminares de uma imagem ARM64 no QEMU, publica imagens AMD64/ARM64 em `ghcr.io/<lowercase-owner>/<lowercase-repository>:<version>` e anexa o ZIP com o código-fonte, a soma de verificação e o pacote Python wheel à versão. Uma tarefa separada no Windows compila e anexa o ZIP portátil e sua soma de verificação.
4. Após a primeira publicação, abra as configurações do pacote GHCR e defina a visibilidade como **Pública**, caso se pretenda realizar baixas anônimas de imagens. Um repositório de código-fonte público, por si só, não garante um pacote de contêiner público. As políticas da organização devem permitir a publicação do pacote. O fluxo de trabalho utiliza `GITHUB_TOKEN`; nenhuma senha de registro ou credenciais de VPS devem constar no repositório.

O sucesso do fluxo de trabalho remoto ainda não foi comprovado por esta preparação local. A emulação ARM64 é um teste preliminar, não uma qualificação em hardware nativo ou no Telegram em ambiente de produção. Isso automatiza a criação do pacote de lançamento; iniciar um servidor ainda requer o comando `Compose` e seus pré-requisitos de domínio/host. Os servidores existentes não são atualizados nem reiniciados automaticamente quando uma versão é publicada.

## Servidor remoto

Mantenha o serviço vinculado ao loopback e utilize um túnel SSH, ou termine a conexão HTTPS em um proxy reverso. O arquivo Compose básico é apenas local; a sobreposição opcional `deploy/compose/compose.https.yaml` fornece o Caddy para um domínio configurado. Evite incluir o token de portador em URLs e nos registros do proxy. Um proxy reverso deve limitar o tamanho das solicitações e as taxas de conexão. Não exponha HTTP simples à Internet.

Exemplos para o systemd, uma tarefa de logon no Windows, um agente de usuário no macOS e o Caddy estão disponíveis na pasta [deploy/.](../../deploy/README.md) Verifique e adapte seus caminhos antes da instalação. Trata-se de modelos fornecidos, e não de configurações específicas para plataformas executadas localmente. Nenhum serviço ou tarefa em segundo plano é registrado pelo iniciador padrão.

No Windows, uma execução sem janela `pythonw.exe` armazena os diagnósticos de inicialização/servidor em `logs/server.log`, no diretório de dados (5 MiB por arquivo, dois backups alternados). As execuções no console mantêm o registro do console. O registro de acesso HTTP está desativado em ambos os modos. Proteja os registros junto com o diretório de dados e analise-os antes de compartilhá-los.

## Reinício e lacunas

O último estado de observação solicitado é mantido. Se a observação estava ativa, o programa tenta, ao iniciar, se reconectar e retomar as fontes selecionadas. A pausa manual cancela essa intenção. Uma tentativa de reinício malsucedida é registrada e exibida no painel.

O StringSession mantém a autorização, mas não o estado duradouro de atualizações/entidades do Telethon. As caixas de diálogo são recarregadas na inicialização. O Telegram/Telethon pode recuperar algumas interrupções de transporte durante a execução, mas o TgWitness não garante a reprodução duradoura após reinicializações do processo. A cada inicialização, é registrado o cabeçalho do diário anterior e o limite de conexão offline. O monitor verifica a conectividade a cada 10 segundos e adiciona um sinal de vida a cada minuto (**Parâmetros → Registrar atividade a cada**). Pequenas interrupções podem passar despercebidas; um canal de transporte conectado não garante a entrega completa das atualizações. Os instantâneos são observações explícitas do histórico atual, nunca uma correção de lacunas.

A fila de mídia é armazenada no banco de dados SQLite de cada espaço de trabalho. Uma mensagem e sua tarefa são confirmadas de forma atômica. Tarefas em execução interrompidas são recuperadas para nova tentativa na inicialização. Cada download possui um tempo limite básico de 120 segundos, acrescido do tempo necessário para baixar o arquivo à taxa de 256 KiB/s, dependendo do tamanho, e um limite de 1 a 2.000 MiB por tipo de anexo; o tempo limite, a velocidade e as tentativas de repetição são configurados em **“Parâmetros**”. O coletor ignora arquivos cujo tamanho é desconhecido. A pausa mantém as tarefas na fila. A repetição utiliza o descritor de arquivo original observado, nunca a versão mais recente de uma mensagem editada posteriormente. Falhas temporárias têm um número limitado de tentativas; as pausas do FloodWait de mídia sobrevivem à reinicialização. A recuperação de mídia é separada da recuperação de atualizações do Telegram e não pode recriar arquivos que tenham desaparecido.

## Backup, restauração e capacidade

Interrompa o processo antes de copiar **todo** o **diretório de dados**, incluindo vault.key, signing.enc, credentials.enc, arquivos do banco de dados SQLite/WAL, mídia, token, pontos de verificação e todos os subdiretórios de perfis. Restaure a cópia completa enquanto o serviço de destino estiver parado. A falta de chaves do cofre ou a incompatibilidade de chaves de assinatura causam falha na inicialização; não gere novas chaves para forçar o acesso.

Mantenha os backups secretos criptografados e com acesso controlado. Os arquivos ZIP de evidências são artefatos portáteis para análise, e não backups de aplicativos ou de sessões do Telegram. Não há exclusão automática por retenção. Planeje espaço em disco para todas as mensagens, metadados brutos, arquivos de mídia, exportações temporárias e backups.

Verificação inicial e exportação de registros de fluxo, em vez de carregar o diário inteiro. Uma exportação fixa um instantâneo de leitura enquanto novas gravações no WAL podem continuar; exportações de longa duração podem reter páginas do WAL, portanto a capacidade do disco ainda é importante. Os arquivos ZIP têm limite máximo de 4 GiB descompactados, para corresponder ao padrão do verificador independente; **Parâmetros → “Maior ZIP assinado”** aumenta o limite, e tais arquivos são verificados com `verify.py --max-gib N`. Outros formatos não têm limite de contagem de eventos. Os navegadores compatíveis transmitem blocos de resposta para um arquivo selecionado pelo usuário. Outros navegadores armazenam em buffer no máximo 128 MiB e direcionam transferências maiores para a CLI autenticada:

~~~sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
~~~

Utilize `--profile ID`, em **Exportações → ID** **do Espaço de Trabalho**, para outro espaço de trabalho; `--format zip|jsonl|csv|html`, `--url https://your-server` para um servidor remoto; ou `--max-mib` para alterar o limite de transferência de 5 GiB. O HTTP simples é permitido apenas para loopback. Os tokens são transmitidos nos cabeçalhos, redirecionamentos são recusados, arquivos existentes não são sobrescritos e downloads incompletos não são publicados como arquivos concluídos. Caso TGWITNESS_TOKEN substitua o token gerado, utilize um arquivo protegido separadamente contendo esse valor ativo: o arquivo panel-token.txt não é reescrito pela substituição. O SHA-256 do comando é apenas uma soma de verificação da transferência; verifique independentemente o ZIP assinado.

Os arquivos de exportação do servidor permanecem dentro do diretório privado `temporary-exports/` de cada espaço de trabalho. Respostas bem-sucedidas limpam seus arquivos. Exportações interrompidas são removidas na próxima inicialização do espaço de trabalho, com o bloqueio exclusivo da instância mantido. Este diretório faz parte do modelo de ameaças/capacidade de armazenamento; utilize um volume de dados criptografado. Transferências de vários gigabytes em escala de produção ainda exigem qualificação no seu sistema de destino.

O painel exibe mídias em fila/com falha, as mídias pendentes mais antigas, espaço livre em disco, pausas nas solicitações do Telegram e fontes cujo acesso não foi confirmado. Esses diagnósticos não constituem um monitor completo de entrega de ponta a ponta. Os espaços de trabalho compartilham um processo; uma conta com atividade intensa ainda pode afetar os demais. Ainda restam a separação de processos de trabalho, retenção/rotação, recuperação durável de atualizações, ancoragem de pontos de verificação remotos, funções e qualificação completa da implantação.

## Opções de conexão e proteção

As rotas de conexão são específicas para cada espaço de trabalho e devem ser configuradas antes da autorização. SOCKS5/HTTP CONNECT utilizam a dependência fixada python-socks. O MTProxy utiliza o transporte intermediário aleatório experimental do Telethon; segredos TLS ee falsos não são suportados. Não há configuração de fallback direto automático. Esta não é uma rota de rede válida para todo o sistema.

Para novas instalações, a variável TGWITNESS_VAULT_KEY_FILE aponta para um arquivo de chave-mestra aleatória protegido separadamente. Monte-o como somente leitura fora do diretório /data em um contêiner. Preserve os metadados públicos de salt do arquivo vault.external.json para cada espaço de trabalho e a chave-mestra separadamente. Os cofres locais existentes exigem uma migração planejada; definir essa variável não os converte automaticamente. O armazenamento e as exportações de mensagens/mídia não são criptografados pelo aplicativo. Utilize volumes criptografados e armazenamento temporário privado suficiente, quando necessário.

Procedimentos detalhados: [conexão/segurança](../CONNECTION-SECURITY.md) e [modos de operação](../OPERATIONS.md).
