[TgWitness](../../README.md) / [Documentación](README.md) · [Aviso del operador](OPERATOR-INCOMPATIBILITY.md)

![El expediente RGPD de 106 días](../assets/presentation/chapter-gdpr-file.svg)

# Valve, Taylor Wessing y 106 días de espera bajo el RGPD: análisis del expediente y sus 70.717 palabras

[Registro original](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Aviso del operador](OPERATOR-INCOMPATIBILITY.md) · [English](../TAYLOR-WESSING-GDPR-FILE.md)

Nos quedan preguntas que nunca tendrán respuesta, porque no somos parte en la disputa. Ninguna persona corriente aguanta esperar cien días cada vez y enfrentarse a abogados de élite, financiados por corporaciones a través de «bolsas de freelance» como esta. Nunca sabremos cómo se llamaba realmente el servicio que encargó Valve. Desde fuera parece un tratamiento conforme al RGPD no del todo lícito, y una comunicación de datos en la que a los denunciantes no se les tachó, sino que se les filtró, mientras faltan al menos 5.000–10.000 páginas de los propios datos: lo que se exportó no fue el registro del usuario, sino un registro recortado hecho para subcontratistas. No tiene sentido impugnarlo. Falta objetivamente una enorme capa de información, igual que no hay nada que confirme lo que dijo cualquiera de los dos abogados.

¿Cuánto paga Valve por un servicio hecho de dilaciones, tachaduras aplicadas a mano y la firma de un Doctor bajo una denuncia homófoba y un PDF roto? No es nuestro caso, pero aquí el problema claramente no es la ley, sino el estatus y la impunidad. El título de «Doctor» convierte automáticamente a una persona en quien decide qué cuenta como prueba irrefutable, y a otra en quien supuestamente entiende de números y de PDF (aunque en realidad no).

---

## 1. Las fechas, la palabra del Doctor y un informe sin pagos

El encabezado del documento dice `Date of Report: 09-29-2025`, y los archivos se entregaron el 1 o el 2 de octubre. Pero no creemos estas fechas. Creemos la declaración directa del **Dr. Patrick Vincent Zurheide**:

> „Bei der Zusammenstellung der personenbezogenen Daten Ihres Mandanten musste leider die volle Monatsfrist
> ausgeschöpft werden, da sich bei erneuter Prüfung der Daten gezeigt hat, dass auch nach dem 3. Mai 2025 neue
> Zahlungen durch einen Dritten über das Nutzerkonto Ihres Mandanten erfolgt sind und insofern manuell die Daten
> bereinigt werden mussten.“
>
> *(La recopilación de los datos personales de su cliente agotó por desgracia todo el plazo de un mes, porque una nueva revisión mostró que también después del 3 de mayo de 2025 un tercero había realizado nuevos pagos a través de la cuenta, por lo que los datos tuvieron que depurarse manualmente.)*

Es precisamente esta frase la que hace que dejemos de creer en las cifras, en las palabras del doctor en el primer párrafo y en su firma. Por supuesto, un doctor no mentiría; tiene algo en juego, ¿no? Lo que pasa es que, una vez exportado el archivo y eliminadas las formas vectoriales, no apareció ni un solo pago en el informe. No discutimos el trabajo del Dr. Patrick ni su retraso. Simplemente creemos y aceptamos «la verdad del Doctor», y dejamos constancia de lo que se ve en el propio archivo.

---

## 2. 36 segundos y la etiqueta vulnerable «Anlage 1 / Taylor Wessing»

No somos expertos en nada, y por eso, al parecer, tanto la propia plataforma de freelance como el doctor ignoraron nuestro aviso de vulnerabilidad. La lógica está clara: ellos son la ley, ¿qué vulnerabilidades podrían tener?

Pero dejemos a un lado las palabras del Doctor y miremos la técnica. Montamos un entorno Windows equivalente, tomamos el archivo depurado e intentamos colocar las formas. Colocar a mano cientos de formas negras en **36 segundos**, exactamente lo que duró la sesión registrada, es en nuestra opinión imposible; a todas luces, los recuadros negros ya estaban en el documento. Nos inclinamos a pensar que en esos 36 segundos se añadió exactamente un objeto, arriba a la derecha de la página 1: la etiqueta `"Anlage 1 / Taylor Wessing"`. Y lo vulnerable es precisamente el software que la colocó:

* **Objeto, según sus marcadores:** de `(929, 294)` a `(1139, 372)`, es decir, `210 × 78 px`, centrado aproximadamente en `(1034, 333)`.
* **Marco visible:** de `(936, 300)` a `(1133, 367)`, unos `197 × 67 px`, proporciones de aproximadamente `3 : 1`; el borde superior de la hoja está en `y ≈ 275`.
* **Escala:** medida con la regla izquierda del documento, `1 cm ≈ 82 px` (la regla está casi con seguridad en centímetros; en pulgadas la hoja sería más ancha de `15″`).

El estilo y el aspecto del distintivo coinciden con el archivo devuelto. Pero sin acceso al entorno de creación original, o sin conocer el formato inicial (si hubo una conversión), el experimento no puede ser limpio, así que no podemos afirmarlo con un 100 % de certeza.

---

## 3. Página 444: la hora oculta y la aritmética de las denuncias

Las denuncias empiezan en la página 444, incluida aquella denuncia homófoba. Un punto importante:

* En las denuncias que decidieron mostrar (las convenientes para los abogados), el campo **`Time of Report`** se ha ocultado deliberadamente además de todo lo demás. No hay hora exacta, y es lo único de todo el archivo que se ha ocultado de forma técnicamente correcta.
* En el artículo principal comparamos matemáticamente las denuncias mostradas con el resto, por contenido, estilo de escritura y nombres de usuario. Casi en todas partes se reutiliza toscamente la fórmula estándar de generación de nombres de Reddit, y hay un pico brusco justo en el rango que hacía falta. No decimos que las denuncias se falsificaran, pero sí que las cuentas probablemente no son reales y que la mayoría se parecen matemáticamente a una botnet.

---

## 4. Una pregunta para el Dr. Patrick Zurheide sobre las entradas `2025-02-03 16:29:23` y `2025-04-02 15:55:19`

Doctor Patrick, usted escribió que leyó el chiste homófobo y decidió hacer uno propio. Bien, muy gracioso. Las demás denuncias, como dijo su colega, no importan en lo sustancial (*„Unabhängig von den Einzelheiten der Beschwerden zeigt schon die bloße Anzahl…“*). Bien, las saltamos. Esperamos que el **Doctor Tobias** explique a sus estudiantes en una clase por qué una cuarta parte aleatoria de las 1.938 denuncias (485), llenas de deseos de muerte y declaraciones nazis, no importa, y a quién exactamente no le importa. Si lo hace, reconoceremos de inmediato nuestro error, pediremos disculpas y borraremos las menciones.

Llamemos a las cosas por su nombre: ustedes entregaron a sabiendas los datos de los haters, los rusos, el alemán, todos ellos, a la misma persona a la que odiaban, y esto entre dos países en guerra. Resultó que le sirvieron a niños rusos: él está encantado, y Tobias los señaló directamente como el problema. Pero en realidad esta es su filtración; solo que los niños no son suyos.

Nuestra pregunta, sin embargo, se refiere a otro usuario, uno que no podía pasar desapercibido:

* **`2025-02-03 16:29:23`**: un enlace y una persona del mismo país, con cosas muy graves escritas allí que saltan a la vista de inmediato;
* **`2025-04-02 15:55:19`**: una referencia directa, un nombre concreto y lo que él escribe.

Lo comprobamos: es exactamente lo que parece. Ustedes pusieron abiertamente datos estatales y datos personales completos en manos de una persona a la que ustedes mismos consideran un delincuente. Esto no debía hacerse, aunque solo fuera por el contexto. ¿Qué pasa si él escribe allí? Por su parte, esto no es solo bajo; es un desprecio directo por la vida y la salud de las personas. Mientras investigábamos, detuvimos a esta persona y pusimos a salvo a todos. Esta es, en conjunto, nuestra única queja real; todo lo demás son simplemente hechos y una demostración de cómo trabajan los abogados de élite. Pedimos al Doctor Patrick que asuma la responsabilidad correspondiente, salvo, claro está, que el título delante de su nombre le dé derecho a actuar así (no somos abogados y no conocemos la ley).

---

## 5. Al público, a la aseguradora, a los reguladores y a las empresas de EE. UU.

* **Al público y a los clientes de Taylor Wessing:** a juzgar por el descuido, Taylor Wessing tiene una aseguradora generosa que considera todo esto normal. Revisen sus archivos e informen al regulador. No hace falta decírselo a los propios abogados: han elegido ocultarlo durante más de un año, desde que Valve acudió a ellos por primera vez.
* **A los reguladores, sobre la vulnerabilidad de cada archivo:** revisen la actividad del Dr. Patrick y soliciten cada PDF que haya pasado por sus manos con el distintivo `"Anlage 1 / Taylor Wessing"` (u otro similar) colocado en la parte superior de la primera página. La probabilidad de que no sea un caso aislado, y de que todo documento suyo con esta pegatina sea vulnerable, es críticamente alta.
* **A la compañía de seguros:** por favor, auditen a su cliente y el software que usa para trabajar con PDF y colocar la etiqueta `"Anlage 1 / Taylor Wessing"` en la parte superior de la página 1. Lo más probable es que el problema esté exactamente ahí, y no es un caso aislado. No tiene sentido pedir una auditoría de todo Taylor Wessing: aparte del nombre, no parecen compartir nada en cuanto a entornos de trabajo o reglas de revisión de seguridad, que deberían existir por defecto (al parecer, una llave física de firma y el título delante de un nombre lo cubren todo).
* **A las empresas de EE. UU., y a quien en la Comisión Europea lea esto por casualidad:** prueben simplemente a cumplir la ley. Contratar a doctores de renombre de una «empresa de freelance» de renombre parece peligroso y absolutamente vil hacia sus clientes. Si en Valve los cheques simplemente se firman y nadie comprueba qué hicieron los abogados durante 106 días, quizá pagar por tiempo alargado en lugar de por resultados sea exactamente la razón de que el software esté anticuado y nadie entienda cómo funciona un PDF. Y si allí no hay otras filtraciones, entonces el Doctor Patrick simplemente logró agotar a todos con la espera o las amenazas. En esencia, lo que se vende es un servicio de incumplimiento del RGPD: una ejecución de mala calidad y amenazas («no ganará ni un solo caso»), combinadas con una limpieza de alta calidad de los resultados de Google hecha en su propio nombre. No redactamos textos jurídicos ni acusamos a nadie. Simplemente escribimos lo que vimos y lo que con tanto empeño intentan borrar.

---

## 6. Lo que Valve compró no fue un tratamiento conforme al RGPD

No somos parte en la disputa y no defendemos ni la cuenta ni el baneo. Queda una pregunta. Valve contrató a abogados de primera: dos doctores de renombre de una «empresa de freelance» de renombre, **Dr. Tobias Schelinski** (`Doc. No. 42282474`, 15 de agosto de 2025) y **Dr. Patrick Vincent Zurheide** (`Doc. No. 42603633`, 1 de octubre de 2025). ¿Qué pagó? No un tratamiento conforme al RGPD: la solicitud no se cumplió entonces y no se ha cumplido ahora.

### Lo que entregaron en su lugar, en sus propias palabras

* **Un plazo «si acaso»:** *„wenn überhaupt“* — el Doctor Tobias.
* **Pide tus datos, pierde tu cuenta:** rescisión *„mit sofortiger Wirkung“*, en respuesta a una solicitud de acceso — el Doctor Tobias.
* **Prueba por cantidad:** *„Unabhängig von den Einzelheiten der Beschwerden…“* El contenido da igual, se cuenta todo — el Doctor Tobias.
* **Un diagnóstico del solicitante:** *„…Ihr Mandant bzw. dessen Komplizen…“* — el Doctor Patrick.
* **Un veredicto por todos los tribunales:** *„Aus unserer Erfahrung wird jedes Gericht…“* — el Doctor Patrick. Ningún tribunal ha resuelto; creíamos que para eso estaban los tribunales.
* **Cuatro artículos del Código Penal:** `§§ 263, 263a, 202a, 303a StGB`, por pedir los propios datos.
* **En lugar de los datos:** cinco páginas de la Política de privacidad pública de Steam, una copia del Dashboard que el usuario ya ve y una respuesta traducida del Soporte de Steam. Dos doctores en Derecho entregaron lo que un agente de soporte ya había escrito.
* **Un pagaré por escrito:** *„Gerne beauskunften wir die restlichen … Daten, sobald …“* El resto, algún día.
* **Terceros protegidos filtrándolos:** los datos del baneo, retenidos «para proteger a terceros»; los datos de terceros, enviados en un PDF cuyos recuadros negros se quitan.
* **Dos versiones de los hechos:** un doctor fecha al usuario en mayo de 2025, el otro en 2019. Los dos firmaron. Un doctor no firmaría algo falso, así que aceptamos ambas.
* **Ortografía premium:** *„Die Antwortet lautet ja“*, dos veces, y el propio e-mail del socio mal escrito en su propia firma.

### No es un error

> [!IMPORTANT]
> Los errores suelen esconderse. Aquí nadie lo intentó siquiera. **Lo que se vende es el incumplimiento del RGPD, y se vende abiertamente.** Eso no es un error; es arrogancia.

### Para ellos, para el usuario y para todos los demás

* **Para ellos:** desindexación por el `Art. 17`. Primero lo solicitó el Doctor Patrick; publicamos la Parte 3 en Medium; justo después, también se desindexaron los resultados sobre el Doctor Tobias.
* **Para el interesado:** diecisiete meses, y sigue la cuenta.
* **Sin abogados:** el Soporte de Steam cerró la solicitud de otro titular de cuenta en **3 días**, con un enlace a Account Data: *"there's no further information Steam Support can offer, this request will be closed"* (ticket `HT-2YBP-F7JP-D4VB`; capturas del solicitante, [sección 18 del dossier de Steam](https://phishdestroy.io/steam_dossier/#gdpr-live-case)).
* **Con abogados:** el mismo ticket cerrado en **106 días**, con membrete. ¿Quién permitió a Valve no tramitar en absoluto las solicitudes RGPD? ¿El Doctor Tobias?

### Títulos

Los llamamos «Doctor» en todo el texto, y lo decimos con respeto: el título es un hecho histórico. El del Doctor Tobias se apoya en [un estudio de 2005 sobre cómo las autoridades alemanas supervisan los servicios en línea extranjeros](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm); el del Doctor Patrick, en [un estudio de 2020 sobre contratos de desarrollo de software en Scrum](https://books.google.pl/books/about/Herausforderungen_bei_einer_Softwareentw.html?id=uh4PzgEACAAJ&redir_esc=y). Cada uno es una investigación estrecha, sobre un tema estrecho, hecha una sola vez. No es pericia en protección de datos, ni en archivos PDF, ni en lo que decidirá todo tribunal. Bajo los títulos, en este expediente: ninguna supervisión, y un PDF hecho con `Aspose.PDF for .NET 20.8`, de 2020.

No hemos leído ninguna de las dos tesis, ni la del Doctor Tobias ni la del Doctor Patrick. Hemos leído la descripción editorial de la del Doctor Tobias. En 2005 no existía el RGPD, por supuesto. Pero suena como si la solución ya estuviera ahí.

<details>
<summary><b>La descripción editorial de la tesis del Doctor Tobias (original en alemán y traducción)</b></summary>

> „Darüber hinaus geht der Autor auf Probleme ein, die sich aus der Durchführung der behördlichen Aufsicht über die Online-Dienste ergeben. Hier sind insbesondere die Ausführungen über die örtliche Zuständigkeit von Behörden hervorzuheben. Dem Autor gelingt es insoweit, anhand einzelner Gesetze Lösungsmöglichkeiten aufzuzeigen wie der Gegensatz einer beschränkten örtlichen Zuständigkeit im Verhältnis zu der weltweiten Präsenz von Online-Diensten zu lösen ist.“
>
> *(Además, el autor aborda los problemas derivados del ejercicio de la supervisión administrativa sobre los servicios en línea. Merecen especial mención sus consideraciones sobre la competencia territorial de las autoridades. A partir de leyes concretas, el autor logra mostrar posibles soluciones a la contradicción entre una competencia territorial limitada y la presencia mundial de los servicios en línea.)*

Fuente: [Verlag Dr. Kovač](https://www.verlagdrkovac.de/978-3-8300-1791-2.htm).

</details>

A juzgar por este expediente, el autor sí encontró una solución, también para el RGPD: un abogado decide quién tiene derecho a sus propios datos y quién no. Qué leyes hubo que usar para estrechar un reglamento europeo en interés de una sola empresa estadounidense, no lo sabemos. Una solución posible habría sido tramitar la solicitud RGPD conforme a la ley. Pero el autor ya es doctor.

### Tres maneras de hacer mal una solicitud de acceso

Hasta donde nosotros, que no somos abogados, sabemos leer el Reglamento, hay tres, y se tomaron las tres:

* **No entregar los datos:** ilegal.
* **Entregarlos incompletos:** ilegal.
* **«Limpiarlos a mano» y filtrar datos de terceros:** doblemente ilegal (`Art. 5(1)(f)`, `Art. 32`).

> [!TIP]
> **La cuarta manera:** simplemente cumplir la solicitud. Es la única que dos doctores en Derecho no tomaron. Eso no es mala suerte; es una elección.

### ¿Quién responde?

Hasta donde vemos, nadie: ni económica ni personalmente. No se les puede dejar una reseña. No se puede escribir una opinión. La empresa es «descentralizada», así que no hay otra empresa a la que dirigirse. Y en cuanto se nombra a las personas que firmaron las cartas en nombre de la empresa, sus representantes se convierten de repente en particulares, con un derecho al olvido escrito para particulares, aplicado al instante. Sin embargo, todo lo desindexado trataba de su trabajo profesional. ¿De verdad un informe sobre una infracción, o sobre competencia profesional, cae bajo el derecho al olvido? ¿Cómo se supone que la gente distinga a un buen abogado de uno malo: por el perfil en la propia web de Taylor Wessing? ¿Y se puede confiar en eso, cuando el bufete edita su propia historia en Wikipedia?

Simplemente no entendemos por qué el hecho histórico de un doctorado sobre un tema estrecho da a alguien el derecho a desactivar los derechos del RGPD. Quizá lo entendemos mal. Quizá el Doctor Tobias enseña a sus estudiantes algo no del todo correcto. O quizá es correcto, y Alemania ha renunciado discretamente al RGPD. ¿O eso lo decide el Doctor Tobias?

¿Y por qué, solo para publicar nuestra auditoría, nuestra opinión y nuestra experiencia (sobre competencia y sobre el riesgo de filtración del software vulnerable del Doctor Patrick), tenemos que integrar el texto en nuestro propio software para que sobreviva? Precisamente por eso todo esto nos parece corporatocracia. Y si quien pregunta no recibe nada, ¿para qué sirve el RGPD? ¿Para facturar a abogados que no saben usar un PDF?

### Nuestra conclusión

No somos parte en esta disputa y, francamente, estamos cansados de ella. En este tiempo lo hemos visto todo: la historia de Wikipedia borrada dos veces, los niños en las denuncias, una solicitud RGPD que nunca se tramitó, el derecho al olvido usado para sí mismos, un fundador que ayudó a redactar la versión nazi del §175 y una estructura «descentralizada» en la que la responsabilidad no es de nadie. Desde nuestra pequeña experiencia, la conclusión es triste: los títulos son títulos. Responsabilidad por parte de los abogados: cero. Lo que queda es arrogancia y un RGPD que no se cumplió. Solo preguntamos qué compró Valve, porque está claro que no fue un tratamiento conforme al RGPD.

---

Ya que los abogados creen que ellos son la ley, y que la vida de las personas, la vida de los niños, no importa, es su elección. No es nuestro conflicto. Pero podemos decir con seguridad que la impunidad del bufete está históricamente confirmada, desde su fundador Goltz, uno de los ocho que redactaron las reformas del §175, y desde su único caso famoso, que a veces se interpreta como una defensa de las personas LGBT: el caso del general von Fritsch.

<details>
<summary><b>Historia: Goltz, el §175 y el caso Fritsch</b></summary>

Nos saltaremos la historia; la estudiamos directamente en una fuente fiable y en el expediente original. Pero así terminó el caso: había un acusado, y nosotros tenemos tres muertos. Achim von Frisch, triturado por los engranajes de la represión. Otto Schmidt, fusilado en 1943. Y el propio general Fritsch: da igual que fuera absuelto, el precio fue alto. En 1939, buscando la muerte, se ofreció voluntario para el frente en Polonia y murió (o se dejó matar).

Por supuesto, nunca contamos este caso como una defensa de las personas LGBT por parte del fundador del bufete. Pero el desenlace es mucho más interesante que una victoria.

**Justicia asimétrica:** Goltz salvó, en efecto, a un alto oficial cuya culpa había sido fabricada por completo por la Gestapo. Pero esa coartada se pagó con sangre ajena. El mismo Goltz, como miembro de la Comisión de Derecho Penal desde 1933, diseñó e introdujo personalmente la versión nazi del Párrafo 175 (1935).

**Estadística frente a relaciones públicas:** defendió a un general heterosexual de la élite de la Wehrmacht después de haber puesto en marcha una cadena jurídica que envió a unos 50.000 homosexuales reales a prisión y a unos 15.000 a campos de concentración, con una tasa de mortalidad del 60 %. Salvar a un general no anula la arquitectura del genocidio.

**Desnazificación, eludida con éxito:** el caso Fritsch se convirtió en la «puerta trasera» perfecta a través de los tribunales de desnazificación de posguerra. El arquitecto de las leyes represivas usó la defensa de un general como prueba de su «independencia», escapó de Núremberg, conservó su estatus y su licencia, y en 1957 fundó el despacho que hoy comercia con su progresismo bajo el rótulo de Taylor Wessing.

</details>

Así que sí, en resumen: estamos seguros de que da igual que sea este Taylor Wessing alemán o cualquier otro; esto no tiene nada que ver con la ley. Lo que decimos aquí es una declaración, no una afirmación de hechos sino una suposición, porque en realidad buscarán cualquier palabra a la que aferrarse. Por eso esto va a los archivos: los intentos de censura y ocultación, y los vínculos directos con su herencia. Del Doctor Patrick: la primerísima denuncia, con la burda palabra homófoba sin tachar. Quizá por accidente, claro, pero está ahí, y es la primera.

Del Doctor Tobias esperamos, naturalmente, una clase sobre la prueba irrefutable en forma de recuento de denuncias, y una explicación de qué parte de esa cuarta parte no le importa a él personalmente. Para la historia, y para entender dónde están los límites, esto importa.

Que Steam actúe como responsable del tratamiento en lugar de moderar apunta simplemente a lo obvio: el Doctor Patrick los filtró. Bueno, así fue. Al parecer no sabía que el software de la pegatina estaba roto, siendo como son doctores de primera, y Steam no pagó por ello: si tramitar o no la solicitud del RGPD, y luego encubrir la filtración que había visto.

Pedimos cordura en el trato con la verdad y queremos recordar a todos la confianza cero: hacia todos, incluidos nosotros. Todo es un entorno hostil, y en el contexto de este análisis literalmente: bloqueos el 9 de mayo, nazis, doctores, personas LGBT, niños. Fue divertido.

Pero nuestras opciones respecto a Taylor Wessing probablemente están agotadas, ya que su estrategia es conseguir que se eliminen los enlaces. Nos vemos obligados a preservar nuestro texto y nuestros datos, así que los integramos en nuestro software, que ya tiene tres cartas de agradecimiento confirmadas de organismos públicos, entre ellos en Alemania y Bélgica, y que ni siquiera se ha publicado todavía.

Queremos advertir a quienes gustan de doblar la ley: no hace falta tumbar el repositorio. En todo este tiempo no hemos entrado en ningún conflicto con ustedes. Pero si deciden romper nuestro trabajo para ocultar la verdad, entonces sin un repositorio activo los reguladores y otros no podrán comparar la firma de una versión (aunque a quién se lo cuento), y entonces entraremos en conflicto directo. Con esto esperamos despedirnos de la megaexperiencia y de los abogados de élite. No fue divertido, y no me alegro. Que les vaya bien.

> [!CAUTION]
> **Retirar este repositorio no borrará nada.** Investigadores y analistas usan TgWitness, y sus copias se verifican contra este repositorio. Tenemos copias de seguridad. Pero una retirada nos convertiría de auditores de un caso en parte de un conflicto. Basta de borrar la verdad.

[Registro original](https://phishdestroy.io/steam_dossier/taylor_wessing) · [Aviso del operador](OPERATOR-INCOMPATIBILITY.md) · [licencia MIT](../../LICENSE)

[Proyecto](../../README.md) · [Documentación](README.md) · [Wiki](../wiki/Home.md)
