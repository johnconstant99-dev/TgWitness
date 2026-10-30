[English](../QUICKSTART.md) · [Русский](../ru/QUICKSTART.md) · [Українська](../uk/QUICKSTART.md) · [Español](../es/QUICKSTART.md) · **Português (Brasil)** · [Türkçe](../tr/QUICKSTART.md) · [العربية](../ar/QUICKSTART.md) · [فارسی](../fa/QUICKSTART.md) · [اردو](../ur/QUICKSTART.md) · [हिन्दी](../hi/QUICKSTART.md) · [Bahasa Indonesia](../id/QUICKSTART.md) · [Tiếng Việt](../vi/QUICKSTART.md) · [简体中文](../zh/QUICKSTART.md)

# Introdução rápida ao TgWitness

O TgWitness é um aplicativo independente para monitorar grupos e canais do Telegram aos quais suas contas têm acesso. Ele é executado localmente com seu próprio diretório de dados.

**É sua primeira visita?** [Explore a demonstração](#explore-a-interface) antes de conectar uma conta. [Escolha um guia](../README.md) sobre proxies, witnesses, exportações ou configuração do servidor.

## Instalar e iniciar

Escolha um método. Os downloads portáteis ficam disponíveis após a publicação de uma versão de lançamento:

| Hospedagem | Nada instalado | A partir da versão: Python 3.11+ | Docker: Engine/Desktop com Compose 2.20 ou superior |
| --- | --- | --- | --- |
| Windows | Extraia `TgWitness-<version>-windows-amd64-portable.zip` das versões do GitHub e clique duas vezes em `TgWitness.cmd` | Clique duas vezes em `Start.cmd` | Clique duas vezes em `scripts\Docker.cmd` |
| Linux / macOS | — | `sh start.sh` | `sh scripts/docker-start.sh` |

Para acessar os métodos de código-fonte, baixe e extraia o arquivo ZIP de código-fonte a partir das versões do GitHub ou clone o repositório. `Start.cmd` oferece a instalação do Python 3.12 para usuários do Windows caso não seja encontrado um Python adequado (winget ou o instalador assinado do python.org). `start.sh` exibe o comando de instalação exato para sua distribuição Linux ou macOS caso o Python esteja ausente. A primeira execução do código-fonte cria `.venv` e instala as dependências automaticamente.

O Docker compila o aplicativo e o inicia em segundo plano; não é necessário ter o Python instalado no host. `scripts\Docker.cmd` e `scripts/docker-start.sh` exibem o endereço do painel e o token quando o contêiner está funcionando corretamente. Os comandos equivalentes do Docker em todos os hosts compatíveis são:

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

Abra **http://127.0.0.1:8787**. Utilize o token gerado pelo auxiliar do Docker ou pelo segundo comando do Docker, ou consulte **o** **arquivo** **data/live/panel-token.txt** para uma instalação portátil ou a partir do código-fonte. Continue na seção **“Conectar o Telegram”** abaixo. As instalações nativas e via Docker utilizam armazenamento separado; iniciar o Docker não importa um diário nativo já existente.

No caso de um servidor, [a implantação](DEPLOYMENT.md) abrange HTTPS automático, reinicialização, imagens publicadas, atualizações e backups.

## Explore a interface

1. Execute **o** **arquivo** **`TgWitness-Demo.cmd`** no pacote portátil, o **`scripts\Demo.cmd`** na pasta de origem do Windows ou o ``sh start.sh --demo`` no Linux/macOS. Ao iniciar a execução a partir da fonte, o sistema cria primeiro o ``.venv`` e instala as dependências.
2. Abra **http://127.0.0.1:8787**.
3. A demonstração local abre automaticamente o diário de amostra. Não é necessário copiar nenhum token para acesso local direto.

As mensagens de demonstração são fictícias. O modo de demonstração não permite conectar uma conta real do Telegram.

## Conecte-se ao Telegram

> [!WARNING]
> **Não utilize nada que o senhor não possa se dar ao luxo de perder.** Recomendamos enfaticamente que não conecte contas pessoais ou valiosas e que não crie um ID de API/hash em uma conta que o senhor considere importante. O Telegram bane contas de forma imprevisível e, muitas vezes, permanentemente, independentemente do cliente utilizado. O bom andamento de um teste depende do Telegram, não do TgWitness, e não oferece nenhuma garantia para o futuro.

1. Caso a demonstração nativa esteja em execução, interrompa-a e execute **o Start.cmd** ou `sh start.sh`. Caso contrário, mantenha em execução a instalação ao vivo iniciada acima.
2. Utilize o token do painel correspondente ao seu método de instalação para abrir o painel.
3. Caso necessite de um proxy, salve-o em **Conta → Configurações → Configurações de conexão → Alterar rota de conexão**.
4. Na seção **“Conta**”, insira seu número de telefone e pressione **“Continuar”**, escolha **“Código QR” → “Mostrar código QR**” ou selecione arquivos e pressione **“Conectar conta**”. **O “ID da API + Hash”** é opcional: o espaço de trabalho utiliza o par salvo ou importado, ou um par válido do conjunto integrado. Para utilizar seu próprio aplicativo, cole um par `API ID:API Hash` no campo “ID da API”. Para obter uma chave de autorização completa, selecione **“Chave de autenticação”**, cole todos os 512 caracteres hexadecimais e selecione o “ID DC” fornecido. O “ID do usuário” é opcional e será marcado caso seja inserido.
5. Conclua o método de login selecionado: telefone/código/2FA, confirmação a partir de um aplicativo do Telegram com login ativo para QR ou importação de uma sessão autorizada compatível.
6. Verifique o ID da conta exibido. Open **Sources**: seus chats são carregados automaticamente; adicione seus grupos.
7. Em **“Escolha quais alterações preservar”**, selecione as categorias de eventos ou a predefinição **“Mensagens, edições e exclusões**” e, em seguida, salve as configurações de monitoramento.
8. Selecione as configurações de anexos separadamente e, em seguida, clique em **“Iniciar observação**”.

As credenciais da API identificam seu aplicativo; elas não autorizam uma conta por si só. Grupos privados não exigem nome de usuário público, mas sua conta deve ter acesso.

Para contas existentes, consulte [os formatos de contas e sessões](../ACCOUNTS.md): o painel aceita Telethon StringSession, Telethon/Pyrogram SQLite, TData ZIP de conta única e JSON de conta compatível. Selecione uma sessão e seu JSON correspondente juntos e pressione **“Conectar conta**”. O login por QR também está disponível com as mesmas configurações opcionais da API. TDLib, bots e listas de contas em massa não são suportados.

Para adicionar outra conta, pressione **o sinal de mais (+)** ao lado do seletor de contas ou acesse **Conta → Configurações → Configurações de conexão → Espaços de trabalho**, ou utilize **a opção Contas**. Os espaços de trabalho possuem sessões, diários, chaves, fontes e filas independentes. A troca de visualizações mantém os demais coletores em execução. A mesma conta do Telegram não pode ser atribuída a dois espaços de trabalho nesta instalação. Não há um número fixo de espaços de trabalho; eles compartilham um único processo, portanto, a capacidade depende do equipamento.

O token do painel ativo protege o acesso às suas autorizações do Telegram e ao material salvo; ele é independente das credenciais da API do Telegram. Apenas uma demonstração local iniciada explicitamente e acessada diretamente recebe acesso automático. Uma demonstração remota ou via proxy continua utilizando `data/demo/panel-token.txt`.

## Revisão e exportação

- **Diário:** pesquise e filtre observações por fonte e tipo de evento.
- Selecione um evento para examinar seu registro original, atribuição e versões salvas.
- Os detalhes de edição mostram o conteúdo disponível antes e depois. Os detalhes de exclusão mostram o último conteúdo capturado, se houver; um agente desconhecido permanece desconhecido.
- **Formatos de exportação:** ZIP assinado, JSONL, CSV e HTML offline.
- **Exportação completa do chat** (Fontes → Exportação completa do chat): baixe todo o histórico visível de um chat como um pacote assinado com `chat.json` (estilo de exportação do Telegram) e um `chat.html` legível. Os chats privados funcionam quando a conta é membro. Trata-se de um instantâneo atual, não de uma reconstrução de mensagens excluídas ou editadas anteriormente. Verifique uma cópia com `python verify.py chat-export.zip --fingerprint TRUSTED_SHA256`.
- **Salvar ponto de verificação:** mantenha o limite do diário assinado fora do coletor.
- **Baixe o comprovante de execução assinado:** preserve o registro do programa e da versão do coletor.
- **Prepare uma solicitação de carimbo de data/hora:** prepare uma solicitação offline para uma autoridade de carimbo de data/hora; siga [o arquivo TIMESTAMP.md](../TIMESTAMP.md) para obter e verificar uma resposta.
- **Verifique o diário:** verifique as assinaturas dos eventos e os links da cadeia. A exportação em ZIP também verifica os arquivos de mídia.

Os navegadores compatíveis salvam exportações de grande porte diretamente em um arquivo de sua escolha. Outros navegadores armazenam em buffer, no máximo, 128 MiB. Enquanto o servidor estiver em execução, a CLI de streaming suporta downloads maiores sem armazenar toda a resposta em buffer:

```sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
```

Para outro espaço de trabalho, adicione `--profile ID` usando **Exportações → ID do Espaço de Trabalho**. Para um servidor remoto, adicione `--url https://your-server`. O limite padrão de transferência é de 5 GiB; `--max-mib` altera esse valor. O conteúdo ZIP assinado possui, por padrão, um limite de verificação separado de 4 GiB quando descompactado (**a opção “Parâmetros”** aumenta esse limite; verifique esses arquivos com `verify.py --max-gib N`). Verifique o arquivo utilizando uma cópia confiável do verificador e uma impressão digital da chave ou ponto de verificação mantida de forma independente.

## Verifique a instalação

```sh
python start.py --setup-only
python start.py --check
python start.py --check --json
```

`--check` verifica as dependências locais, o suporte à assinatura, o armazenamento, a configuração de chaves e o endereço de escuta. Ele não instala nada nem se conecta ao Telegram. Uma porta ocupada pode significar que outra instância está em execução. Utilize um `--port` diferente ou encerre-a primeiro.

O iniciador é instalado em `.venv`. Os comandos auxiliares `python -m tgwitness...` devem utilizar `.venv\Scripts\python.exe` no Windows ou `.venv/bin/python` no Linux/macOS, a menos que esse ambiente já esteja ativado.

## Sessões, proteção e operação

Um Telethon SQLite fechado e consistente `.session` pode ser convertido localmente com `python -m tgwitness.sessions account.session --out account.tgwitness-session` e, em seguida, carregado no Account. A importação direta de arquivos e o login por QR também estão disponíveis. Consulte [CONNECTION-SECURITY.md](../CONNECTION-SECURITY.md) para obter informações sobre formatos de login, SOCKS5, HTTP CONNECT, MTProxy e chaves-mestra externas.

**A pausa na observação** interrompe a coleta. **O bloqueio** apenas interrompe o acesso pelo navegador. Fechar uma aba mantém o processo de coleta em execução. Interromper o processo interrompe a coleta; um instantâneo do histórico não consegue reconstruir todas as edições ou exclusões perdidas. Veja [como funciona a coleta](../COLLECTION.md) para políticas de eventos, filas de anexos, isolamento de contas e comportamento de reinício.

As sessões e os segredos são criptografados. O conteúdo das mensagens, as mídias e as exportações exigem um disco ou volume criptografado. As assinaturas garantem a integridade em relação a uma chave confiável; elas não comprovam a origem do Telegram nem impedem a falsificação por parte de um operador que controle o coletor e sua chave.

Consulte [o arquivo OPERATIONS.md](../OPERATIONS.md) para obter informações sobre backup/restauração, [o arquivo DEPLOYMENT.md](DEPLOYMENT.md) para hospedagem e [a pasta deploy/](../../deploy/README.md) para exemplos de serviço. O painel instalado também inclui um guia de configuração offline em `/guide.html`.

A verificação efetiva e as limitações remanescentes estão registradas nos arquivos [VERIFICATION.md](../VERIFICATION.md) e [READINESS.md](../internal/READINESS.md).
