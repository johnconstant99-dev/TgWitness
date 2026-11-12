[TgWitness](../../README.md) / [Documentação](README.md) · [Aviso ao operador](OPERATOR-INCOMPATIBILITY.md)

![O processo GDPR de 106 dias](../assets/presentation/chapter-gdpr-file.svg)

# Valve, Taylor Wessing e 106 dias de espera sob o GDPR: análise do arquivo e das suas 70.717 palavras

[Registro de origem](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Aviso ao operador](OPERATOR-INCOMPATIBILITY.md) · [English](../TAYLOR-WESSING-GDPR-FILE.md)

Ficamos com perguntas que nunca serão respondidas, porque não somos parte na disputa. Nenhuma pessoa comum aguenta esperar cem dias de cada vez e enfrentar advogados de elite, bancados por corporações por meio de "bolsas de freelancers" como esta. Nunca saberemos como se chamava de fato o serviço que a Valve encomendou. De fora, parece um tratamento de dados sob o GDPR não inteiramente lícito, e uma divulgação de dados em que os denunciantes não foram tarjados, mas vazados, enquanto faltam pelo menos 5.000–10.000 páginas dos próprios dados: o que foi exportado não foi o registro do usuário, mas um registro recortado feito para terceirizados. Não adianta contestar. Uma enorme camada de informação está objetivamente ausente, assim como não há nada que confirme o que qualquer um dos dois advogados disse.

Quanto a Valve paga por um serviço feito de enrolação, tarjas aplicadas à mão e a assinatura de um Doutor sob uma denúncia homofóbica e um PDF quebrado? Este não é o nosso caso, mas o problema aqui claramente não é a lei; é o status e a impunidade. O título de "Doutor" automaticamente faz de uma pessoa quem decide o que conta como prova irrefutável, e de outra quem supostamente entende de números e de PDFs (embora, na realidade, não entenda).

---

## 1. As datas, a palavra do Doutor e um relatório sem nenhum pagamento

O cabeçalho do documento diz `Date of Report: 09-29-2025`, e os arquivos em si foram entregues em 1º ou 2 de outubro. Mas não acreditamos nessas datas. Acreditamos na declaração direta do **Dr. Patrick Vincent Zurheide**:

> „Bei der Zusammenstellung der personenbezogenen Daten Ihres Mandanten musste leider die volle Monatsfrist
> ausgeschöpft werden, da sich bei erneuter Prüfung der Daten gezeigt hat, dass auch nach dem 3. Mai 2025 neue
> Zahlungen durch einen Dritten über das Nutzerkonto Ihres Mandanten erfolgt sind und insofern manuell die Daten
> bereinigt werden mussten.“
>
> *(A compilação dos dados pessoais do seu cliente infelizmente consumiu todo o prazo de um mês, porque uma nova verificação mostrou que também depois de 3 de maio de 2025 novos pagamentos haviam sido feitos por um terceiro através da conta, razão pela qual os dados tiveram de ser limpos manualmente.)*

É justamente essa frase que nos faz deixar de acreditar nos números, nas palavras do doutor no primeiro parágrafo e na sua assinatura. É claro que um doutor não mentiria; ele tem algo a perder, não tem? Acontece que, depois que o arquivo foi exportado e as formas vetoriais foram removidas, nem um único pagamento apareceu no relatório. Não contestamos o trabalho do Dr. Patrick nem o seu atraso. Simplesmente acreditamos e aceitamos "a verdade do Doutor", e registramos o que se vê no próprio arquivo.

---

## 2. 36 segundos e o rótulo vulnerável "Anlage 1 / Taylor Wessing"

Não somos especialistas em nada, e é por isso, aparentemente, que o nosso aviso de vulnerabilidade foi ignorado tanto pela própria plataforma de freelancers quanto pelo doutor. A lógica é bem clara: eles são a lei, que vulnerabilidades poderiam ter?

Mas deixemos de lado as palavras do Doutor e olhemos para a técnica. Montamos um ambiente Windows equivalente, pegamos o arquivo limpo e tentamos posicionar as formas. Posicionar à mão centenas de formas pretas em **36 segundos**, exatamente a duração da sessão registrada, é na nossa visão impossível; ao que tudo indica, as caixas pretas já estavam no documento. Tendemos a achar que nesses 36 segundos foi adicionado exatamente um objeto, no canto superior direito da página 1: o rótulo `"Anlage 1 / Taylor Wessing"`. E é o software que o posicionou que é vulnerável:

* **Objeto, pelos seus marcadores:** de `(929, 294)` a `(1139, 372)`, ou seja, `210 × 78 px`, centrado em aproximadamente `(1034, 333)`.
* **Moldura visível:** de `(936, 300)` a `(1133, 367)`, cerca de `197 × 67 px`, proporções de aproximadamente `3 : 1`; a borda superior da folha está em `y ≈ 275`.
* **Escala:** medida pela régua esquerda do documento, `1 cm ≈ 82 px` (a régua está quase certamente em centímetros; em polegadas, a folha seria mais larga que `15″`).

O estilo e a aparência do selo correspondem ao arquivo devolvido. Mas sem acesso ao ambiente de criação original, ou sem conhecer o formato inicial (se houve uma conversão), o experimento não pode ser limpo, então não podemos afirmar isso com 100% de certeza.

---

## 3. Página 444: o horário oculto e a aritmética das denúncias

As denúncias começam na página 444, incluindo aquela denúncia homofóbica. Um ponto importante:

* Nas denúncias que escolheram mostrar (as convenientes para os advogados), o campo **`Time of Report`** foi deliberadamente ocultado, além de todo o resto. Não há horário exato, e esta é a única coisa em todo o arquivo que foi ocultada de forma tecnicamente correta.
* No artigo principal, comparamos matematicamente as denúncias mostradas com as demais, por conteúdo, estilo de escrita e apelidos. Quase em toda parte a fórmula padrão de geração de nomes do Reddit é grosseiramente reutilizada, e há um pico acentuado exatamente na faixa que era necessária. Não estamos dizendo que as denúncias foram falsificadas, mas estamos dizendo que as contas provavelmente não são reais, e que a maioria delas se parece matematicamente com uma botnet.

---

## 4. Uma pergunta ao Dr. Patrick Zurheide sobre as entradas `2025-02-03 16:29:23` e `2025-04-02 15:55:19`

Doutor Patrick, o senhor escreveu que leu a piada homofóbica e decidiu fazer uma piada sua. Tudo bem, muito engraçado. As outras denúncias, como disse o seu colega, não importam no mérito (*„Unabhängig von den Einzelheiten der Beschwerden zeigt schon die bloße Anzahl…“*). Tudo bem, vamos pulá-las. Esperamos que o **Doutor Tobias** explique aos seus alunos em uma aula por que um quarto aleatório das 1.938 denúncias (485 delas), cheias de desejos de morte e declarações nazistas, não importa, e para quem exatamente não importa. Se ele fizer isso, admitiremos imediatamente que estávamos errados, pediremos desculpas e apagaremos as menções.

Vamos chamar as coisas pelo nome: os senhores entregaram conscientemente os dados dos haters, os russos, o alemão, todos eles, à própria pessoa que eles odiavam, e isso entre dois países em guerra entre si. Descobriu-se que os senhores lhe serviram crianças russas: ele está encantado, e Tobias apontou-as diretamente como o problema. Mas, na realidade, este é o vazamento dos senhores; só que as crianças não são suas.

Nossa pergunta, no entanto, diz respeito a outro usuário, que não poderia ter passado despercebido:

* **`2025-02-03 16:29:23`**: um link e uma pessoa do mesmo país, com coisas muito graves escritas ali que saltam aos olhos imediatamente;
* **`2025-04-02 15:55:19`**: uma referência direta, um nome específico e o que ele escreve.

Verificamos: é exatamente o que parece. Os senhores colocaram abertamente dados estatais e dados pessoais completos nas mãos de uma pessoa que os próprios senhores consideram um criminoso. Isso não deveria ter sido feito, quando mais não fosse por causa do contexto. O que acontece se ele escrever ali? Da parte dos senhores, isso não é apenas baixo; é um desprezo descarado pela vida e pela saúde das pessoas. Enquanto investigávamos, detivemos essa pessoa e deixamos todos em segurança. Esta é, no geral, nossa única queixa real; todo o resto são simplesmente fatos e uma demonstração de como trabalham os advogados de elite. Pedimos ao Doutor Patrick que assuma a devida responsabilidade por isso, a menos, é claro, que o título antes do seu nome lhe dê o direito de agir assim (não somos advogados e não conhecemos a lei).

---

## 5. Ao público, à seguradora, aos reguladores e às empresas dos EUA

* **Ao público e aos clientes da Taylor Wessing:** a julgar pelo descuido, a Taylor Wessing tem uma seguradora generosa que considera tudo isso normal. Verifiquem seus arquivos e informem o regulador. Não há necessidade de contar aos próprios advogados: eles escolheram esconder isso por mais de um ano, desde que a Valve os procurou pela primeira vez.
* **Aos reguladores, sobre a vulnerabilidade de cada arquivo:** examinem a atividade do Dr. Patrick e solicitem cada PDF que passou por ele com o selo `"Anlage 1 / Taylor Wessing"` (ou semelhante) colocado no topo da primeira página. A probabilidade de que este não seja um caso isolado, e de que todo documento dele com esse adesivo seja vulnerável, é criticamente alta.
* **À seguradora:** por favor, auditem o seu cliente e o software que ele usa para trabalhar com PDFs e colocar o rótulo `"Anlage 1 / Taylor Wessing"` no topo da página 1. É muito provavelmente exatamente aí que está o problema, e não é um caso isolado. Não adianta pedir uma auditoria de toda a Taylor Wessing: além do nome, eles parecem não compartilhar nada em termos de ambientes de trabalho ou de regras de revisão de segurança, que deveriam existir naturalmente (aparentemente, uma chave física de assinatura e o título antes de um nome cobrem tudo isso).
* **Às empresas dos EUA, e a quem na Comissão Europeia por acaso ler isto:** experimentem simplesmente cumprir a lei. Contratar doutores renomados de uma renomada "empresa de freelancers" parece perigoso e absolutamente vil para com os seus clientes. Se na Valve os cheques são simplesmente assinados e ninguém verifica o que os advogados fizeram durante 106 dias, então talvez pagar por tempo arrastado em vez de resultados seja exatamente o motivo pelo qual o software está desatualizado e ninguém entende como um PDF funciona. E se não houver outros vazamentos ali, então o Doutor Patrick simplesmente conseguiu desgastar todos com a espera ou com ameaças. Em essência, o que está à venda é um serviço de não conformidade com o GDPR: execução de má qualidade e ameaças ("vocês não vão ganhar um único caso"), combinadas com uma limpeza de alta qualidade dos resultados do Google feita em nome deles próprios. Não redigimos textos jurídicos e não acusamos ninguém. Simplesmente escrevemos o que vimos, e o que eles se esforçam tanto para apagar.

---

## 6. O que a Valve comprou não foi um tratamento conforme o GDPR

Não somos parte na disputa e não defendemos nem a conta nem o banimento. Resta uma pergunta. A Valve contratou advogados de ponta: dois doutores renomados de uma renomada "empresa de freelancers", **Dr. Tobias Schelinski** (`Doc. No. 42282474`, 15 de agosto de 2025) e **Dr. Patrick Vincent Zurheide** (`Doc. No. 42603633`, 1º de outubro de 2025). Pelo que ela pagou? Não por um tratamento conforme o GDPR: o pedido não foi atendido naquela época e não está atendido agora.

### O que entregaram no lugar, nas palavras deles

* **Um prazo "se é que":** *„wenn überhaupt“* — Doutor Tobias.
* **Peça seus dados, perca sua conta:** rescisão *„mit sofortiger Wirkung“*, em resposta a um pedido de acesso — Doutor Tobias.
* **Prova pela quantidade:** *„Unabhängig von den Einzelheiten der Beschwerden…“* O conteúdo não importa, conta-se tudo — Doutor Tobias.
* **Um diagnóstico do requerente:** *„…Ihr Mandant bzw. dessen Komplizen…“* — Doutor Patrick.
* **Um veredito por todos os tribunais:** *„Aus unserer Erfahrung wird jedes Gericht…“* — Doutor Patrick. Nenhum tribunal decidiu; achávamos que era para isso que existiam tribunais.
* **Quatro artigos do Código Penal:** `§§ 263, 263a, 202a, 303a StGB`, por pedir os próprios dados.
* **No lugar dos dados:** cinco páginas da Política de Privacidade pública da Steam, uma cópia do Dashboard que o usuário já vê e uma resposta traduzida do Suporte da Steam. Dois doutores em Direito entregaram o que um atendente do suporte já tinha escrito.
* **Uma promissória por escrito:** *„Gerne beauskunften wir die restlichen … Daten, sobald …“* O resto, algum dia.
* **Terceiros protegidos por meio do vazamento:** os dados do banimento retidos "para proteger terceiros", os dados de terceiros enviados num PDF cujas tarjas pretas saem.
* **Duas versões dos fatos:** um doutor data o usuário de maio de 2025, o outro de 2019. Os dois assinaram. Um doutor não assinaria algo falso, então aceitamos as duas.
* **Ortografia premium:** *„Die Antwortet lautet ja“*, duas vezes, e o próprio e-mail do sócio escrito errado na própria assinatura.

### Não é um erro

> [!IMPORTANT]
> Erros costumam ser escondidos. Aqui ninguém nem tentou. **O que está à venda é o descumprimento do GDPR, e ele é vendido abertamente.** Isso não é um erro; é arrogância.

### Para eles, para o usuário e para todos os outros

* **Para eles:** desindexação pelo `Art. 17`. O Doutor Patrick pediu primeiro; publicamos a Parte 3 no Medium; logo depois, os resultados sobre o Doutor Tobias também foram desindexados.
* **Para o titular dos dados:** dezessete meses, e contando.
* **Sem advogados:** o Suporte da Steam fechou o pedido de outro titular de conta em **3 dias**, com um link para Account Data: *"there's no further information Steam Support can offer, this request will be closed"* (ticket `HT-2YBP-F7JP-D4VB`; capturas de tela do requerente, [Seção 18 do dossiê da Steam](https://phishdestroy.io/steam_dossier/#gdpr-live-case)).
* **Com advogados:** o mesmo ticket fechado em **106 dias**, em papel timbrado. Quem permitiu à Valve simplesmente não processar pedidos do GDPR? O Doutor Tobias?

### Títulos

Nós os chamamos de "Doutor" o tempo todo, e com respeito: o título é um fato histórico. O do Doutor Tobias se apoia em [um estudo de 2005 sobre como as autoridades alemãs supervisionam serviços online estrangeiros](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm); o do Doutor Patrick, em [um estudo de 2020 sobre contratos de desenvolvimento de software em Scrum](https://books.google.pl/books/about/Herausforderungen_bei_einer_Softwareentw.html?id=uh4PzgEACAAJ&redir_esc=y). Cada um é uma pesquisa estreita, sobre um tema estreito, feita uma única vez. Não é expertise em proteção de dados, nem em arquivos PDF, nem no que todo tribunal vai decidir. Sob os títulos, neste processo: nenhuma supervisão, e um PDF feito com `Aspose.PDF for .NET 20.8`, de 2020.

Não lemos nenhuma das duas teses, nem a do Doutor Tobias nem a do Doutor Patrick. Lemos a descrição da editora sobre a do Doutor Tobias. Em 2005 não existia o GDPR, claro. Mas parece que a solução já estava lá.

<details>
<summary><b>A descrição da editora sobre a tese do Doutor Tobias (original em alemão e tradução)</b></summary>

> „Darüber hinaus geht der Autor auf Probleme ein, die sich aus der Durchführung der behördlichen Aufsicht über die Online-Dienste ergeben. Hier sind insbesondere die Ausführungen über die örtliche Zuständigkeit von Behörden hervorzuheben. Dem Autor gelingt es insoweit, anhand einzelner Gesetze Lösungsmöglichkeiten aufzuzeigen wie der Gegensatz einer beschränkten örtlichen Zuständigkeit im Verhältnis zu der weltweiten Präsenz von Online-Diensten zu lösen ist.“
>
> *(Além disso, o autor trata dos problemas decorrentes do exercício da supervisão administrativa sobre os serviços online. Merecem destaque especial suas considerações sobre a competência territorial das autoridades. Com base em leis específicas, o autor consegue mostrar soluções possíveis para a contradição entre uma competência territorial limitada e a presença mundial dos serviços online.)*

Fonte: [Verlag Dr. Kovač](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm).

</details>

A julgar por este processo, o autor de fato encontrou uma solução, também para o GDPR: um advogado decide quem tem direito aos próprios dados e quem não tem. Que leis foram necessárias para estreitar um regulamento europeu no interesse de uma única empresa americana, não sabemos. Uma solução possível teria sido processar o pedido do GDPR de forma legal. Mas o autor já é doutor.

### Três maneiras de errar um pedido de acesso

Até onde nós, que não somos advogados, conseguimos ler o Regulamento, são três, e as três foram usadas:

* **Não entregar os dados:** ilegal.
* **Entregá-los incompletos:** ilegal.
* **"Limpar manualmente" e vazar dados de terceiros:** duplamente ilegal (`Art. 5(1)(f)`, `Art. 32`).

> [!TIP]
> **A quarta maneira:** simplesmente atender o pedido. É a única que dois doutores em Direito não usaram. Isso não é azar; é uma escolha.

### Quem responde?

Até onde vemos, ninguém: nem financeira nem pessoalmente. Não dá para deixar uma avaliação. Não dá para escrever uma opinião. A empresa é "descentralizada", então não há outra empresa a quem se dirigir. E no momento em que você nomeia as pessoas que assinaram as cartas em nome da empresa, os representantes da empresa viram de repente pessoas físicas, com um direito ao esquecimento escrito para pessoas físicas, aplicado na hora. No entanto, tudo o que foi desindexado tratava do trabalho profissional deles. Um relato sobre uma violação, ou sobre competência profissional, cabe mesmo no direito ao esquecimento? Como as pessoas vão distinguir um bom advogado de um ruim: pelo perfil no próprio site da Taylor Wessing? E dá para confiar nisso, quando o escritório edita a própria história na Wikipédia?

Simplesmente não entendemos por que o fato histórico de um doutorado sobre um tema estreito dá a alguém o direito de desligar os direitos do GDPR. Talvez estejamos entendendo errado. Talvez o Doutor Tobias ensine aos seus alunos algo não muito certo. Ou talvez esteja certo, e a Alemanha tenha desistido do GDPR em silêncio. Ou isso cabe ao Doutor Tobias decidir?

E por que, só para publicar a nossa auditoria, a nossa opinião e a nossa experiência (sobre competência e sobre o risco de vazamento no software vulnerável do Doutor Patrick), precisamos embutir o texto no nosso próprio software para que ele sobreviva? É exatamente por isso que tudo isso nos parece corporatocracia. E se quem pede não recebe nada, para que serve o GDPR? Faturamento para advogados que não sabem usar um PDF?

### Nossa conclusão

Não somos parte nesta disputa e, sinceramente, estamos cansados dela. Nesse tempo, vimos de tudo: a história da Wikipédia apagada duas vezes, as crianças nas denúncias, um pedido do GDPR que nunca foi processado, o direito ao esquecimento usado em causa própria, um fundador que ajudou a redigir a versão nazista do §175 e uma estrutura "descentralizada" em que a responsabilidade não pertence a ninguém. Pela nossa pequena experiência, a conclusão é triste: títulos são títulos. Responsabilidade do lado dos advogados: zero. O que resta é arrogância e um GDPR que não foi cumprido. Só perguntamos o que a Valve comprou, já que claramente não foi um tratamento conforme o GDPR.

---

Já que os advogados acham que são a lei, e que a vida das pessoas, a vida das crianças, não importa, a escolha é deles. Este não é o nosso conflito. Mas podemos dizer com segurança que a impunidade do escritório é historicamente confirmada, desde o seu fundador Goltz, um dos oito que redigiram as alterações ao §175, e desde o seu único caso famoso, às vezes lido como uma defesa de pessoas LGBT: o caso do general von Fritsch.

<details>
<summary><b>História: Goltz, o §175 e o caso Fritsch</b></summary>

Vamos pular a história; nós a estudamos diretamente em uma fonte confiável e nos autos originais. Mas foi assim que o caso terminou: havia um réu, e nós temos três mortos. Achim von Frisch, esmagado pelas engrenagens da repressão. Otto Schmidt, fuzilado em 1943. E o próprio general Fritsch: não importa que tenha sido absolvido, o preço foi alto. Em 1939, buscando a morte, ele se ofereceu como voluntário para o front na Polônia e foi morto (ou se deixou matar).

É claro que nunca contamos este caso como uma defesa de pessoas LGBT pelo fundador do escritório. Mas o desfecho é muito mais interessante do que uma vitória.

**Justiça assimétrica:** Goltz de fato salvou um oficial de alta patente, cuja culpa havia sido inteiramente fabricada pela Gestapo. Mas esse álibi foi pago com o sangue de outros. O mesmo Goltz, como membro da Comissão de Direito Penal a partir de 1933, projetou e introduziu pessoalmente a versão nazista do Parágrafo 175 (1935).

**Estatística contra relações públicas:** ele defendeu um general heterossexual da elite da Wehrmacht depois de ter primeiro posto em marcha uma esteira jurídica que mandou cerca de 50.000 homossexuais reais para a prisão e cerca de 15.000 para campos de concentração, com uma taxa de mortalidade de 60%. Salvar um general não anula a arquitetura do genocídio.

**Desnazificação, contornada com sucesso:** o caso Fritsch tornou-se a "porta dos fundos" perfeita através das comissões de desnazificação do pós-guerra. O arquiteto das leis repressivas usou a defesa de um general como prova da sua "independência", escapou de Nuremberg, manteve o seu status e a sua licença e, em 1957, fundou o escritório que hoje negocia o seu progressismo sob a placa Taylor Wessing.

</details>

Então sim, no fim das contas: temos certeza de que não faz diferença se é esta Taylor Wessing alemã ou qualquer outra; isto não tem nada a ver com a lei. O que dizemos aqui é uma declaração, não a afirmação de um fato, mas uma suposição, porque na realidade eles vão procurar qualquer palavra para se agarrar. É por isso que isto vai para os arquivos: as tentativas de censura e ocultação, e os vínculos diretos com a herança deles. Do Doutor Patrick: a primeiríssima denúncia, com a palavra homofóbica grosseira deixada à vista. Talvez por acidente, é claro, mas está lá, e é a primeira.

Do Doutor Tobias esperamos, naturalmente, uma aula sobre a prova irrefutável na forma de uma contagem de denúncias, e uma explicação de qual parte daquele quarto não importa para ele pessoalmente. Para a história, e para entender onde estão os limites, isso importa.

O fato de a Steam atuar como controladora dos dados, em vez de moderar, simplesmente aponta para o óbvio: o Doutor Patrick os vazou. Bem, foi assim que aconteceu. Aparentemente ele não sabia que o software do adesivo estava quebrado, sendo estes doutores de ponta, e a Steam não pagou por isso: se processava ou não o pedido do GDPR, e depois encobrir o vazamento que ele tinha visto.

Pedimos sensatez no trato com a verdade e queremos lembrar a todos da confiança zero: em relação a todos, inclusive nós. Tudo é um ambiente hostil, e no contexto desta análise literalmente: banimentos em 9 de maio, nazistas, doutores, pessoas LGBT, crianças. Foi divertido.

Mas as nossas opções em relação à Taylor Wessing provavelmente estão esgotadas, já que a estratégia deles é conseguir a remoção de links. Somos obrigados a preservar o nosso texto e os nossos dados, por isso os incorporamos ao nosso software, que já tem três cartas de agradecimento confirmadas de órgãos governamentais, inclusive na Alemanha e na Bélgica, e que nem sequer foi lançado ainda.

Queremos avisar quem gosta de dobrar a lei: não há necessidade de derrubar o repositório. Em todo esse tempo não entramos em nenhum conflito com vocês. Mas se decidirem quebrar o nosso trabalho para esconder a verdade, então sem um repositório ativo os reguladores e outros não poderão comparar a assinatura de uma versão (embora eu esteja contando isso para quem?), e então entraremos em conflito direto. Com isso, esperamos nos despedir da megaespecialização e dos advogados de elite. Não foi divertido, e não estou contente. Tudo de bom.

> [!CAUTION]
> **Derrubar este repositório não vai apagar nada.** Investigadores e pesquisadores usam o TgWitness, e é com este repositório que as cópias deles são verificadas. Temos backups. Mas uma derrubada nos transformaria de auditores de um caso em parte de um conflito. Chega de apagar a verdade.

[Registro de origem](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Aviso ao operador](OPERATOR-INCOMPATIBILITY.md) · [Licença MIT](../../LICENSE)

[Projeto](../../README.md) · [Documentação](README.md) · [Wiki](../wiki/Home.md)
