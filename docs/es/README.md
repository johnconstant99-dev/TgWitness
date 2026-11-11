<p align="right"><sub><a href="../../README.md">English</a> · <a href="#languages">Otros idiomas</a></sub></p>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-hero-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-hero-mobile.svg">
  <img src="../assets/presentation/casework-hero.svg" width="1440" alt="TgWitness — Siga el rastro. Conserve las pruebas. Un diario firmado y encadenado por hashes, un punto de control conservado por separado y un archivo de pruebas verificable.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/demo/?lang=es"><b>Explore la demo&nbsp;↗</b></a><br><sub>La interfaz real con registros ficticios</sub></td>
<td width="33%" align="center"><a href="#quick-start"><b>Descargue e inicie&nbsp;↓</b></a><br><sub>Un solo comando para Linux, macOS y Windows</sub></td>
<td width="33%" align="center"><a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Lea el manual&nbsp;↗</b></a><br><sub>Guías de investigación, paso a paso</sub></td>
</tr>
</table>

<p align="center"><strong>Espacio de trabajo autoalojado para investigaciones en Telegram.</strong><br>Guarde chats, conserve ediciones y eliminaciones, vea quién está conectado con quién<br>y entregue exportaciones firmadas que cualquiera puede comprobar.</p>

<p align="center"><strong>CONFIANZA CERO.</strong> TgWitness no toma partido: las mismas comprobaciones se aplican al operador, a PhishDestroy y a cualquier otro.<br>Solo cuenta lo que confirma un tercero o las matemáticas. <a href="../QUESTIONS-AND-CHECKS.md">Preguntas y comprobaciones</a></p>

<p align="center">
  <a href="../CHANGELOG.md"><img src="../assets/presentation/identity-meta-version.svg" width="146" height="30" alt="v0.9.2 · versión preliminar"></a>
  <a href="../../LICENSE"><img src="../assets/presentation/identity-meta-license.svg" width="60" height="30" alt="MIT"></a><br>
  <sub><a href="../VERIFICATION.md">Entornos probados</a> · 25 idiomas de interfaz · 26 idiomas de guías</sub>
</p>

<a name="screenshots"></a>

<a href="https://phishdestroy.github.io/TgWitness/demo/?lang=es">
<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-mobile-dark-still.webp">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-workspace-dark-still.webp">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-workspace-mobile-dark.webp">
  <img src="../assets/presentation/readme-workspace-dark.webp" width="1440" alt="La demo de TgWitness en movimiento: mensajes capturados, versiones guardadas y contenido conservado tras la eliminación. Registros de demostración ficticios.">
</picture>
</a>

<p align="center"><sub>Explore la interfaz real con registros ficticios. Haga clic en el espacio de trabajo para probarla.</sub></p>

## Qué hace TgWitness

<table>
<tr>
<td width="33%" valign="top"><b><a href="../COLLECTION.md">Cada edición y eliminación, conservada</a></b><br><sub>Se guarda cada versión de un mensaje, y su texto permanece tras un aviso de eliminación.</sub></td>
<td width="33%" valign="top"><b><a href="../wiki/Exports-and-Verification.md">Pruebas que cualquiera puede comprobar</a></b><br><sub>Registros firmados y encadenados por hashes. El destinatario verifica el archivo sin conexión con un solo comando.</sub></td>
<td width="33%" valign="top"><b><a href="../EVIDENCE.md#where-the-messages-come-from">Un origen demostrable</a></b><br><sub>Los mensajes llegan por la sesión MTProto autenticada de la cuenta y se firman al recibirse; GitHub Actions e Intel TDX añaden certificación.</sub></td>
</tr>
<tr>
<td width="33%" valign="top"><b><a href="../EXPORT-BENCHMARK-2026-11-06.md">Medido a escala</a></b><br><sub>48 archivos verificados con 3.598.381 registros; ocho cuentas obtuvieron 768.007 registros del historial a 687,5 registros/s.</sub></td>
<td width="33%" valign="top"><b><a href="../INVESTIGATION-MODE.md">Pensado para investigaciones</a></b><br><sub>Listas de vigilancia sobre texto, códigos QR y OCR, comprobación de carteras, fichas de sujeto, Tablero del caso y un paquete judicial.</sub></td>
<td width="33%" valign="top"><b><a href="../SECURITY-MODEL.md">Bajo su control</a></b><br><sub>Autoalojado y sin telemetría. Las sesiones se guardan en una bóveda cifrada; el panel escucha en localhost.</sub></td>
</tr>
</table>

<p align="center"><sub>Se ha desarrollado y probado durante unos seis meses: primero el recopilador, el registro firmado y el verificador; después, el panel y los módulos complementarios. Este repositorio se creó el 29 de octubre de 2026 con fines de publicación, por lo que su antigüedad no coincide con la del proyecto.</sub></p>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="quick-start"></a>
<a name="run-it-on-your-machine"></a>

## Instalación

Python incluido. Use los mismos comandos para actualizar.

**Linux / macOS**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows · PowerShell o CMD**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

<sub>Servidor Ubuntu: ejecútelo como root. Escritorio: ejecútelo con su usuario habitual. `-ExecutionPolicy Bypass` solo se aplica a este proceso de PowerShell.</sub>

Las compilaciones firmadas proceden del [flujo de trabajo Installer](../../.github/workflows/installer.yml) público, y el instalador comprueba el SHA-256 y la firma RSA de cada paquete antes de instalarlo.

[Verifique primero el script](../INSTALLATION.md#verify-before-running) · [Primera configuración](../SETTINGS.md) · [Versiones](https://github.com/phishdestroy/TgWitness/releases) · [Docker](DEPLOYMENT.md)

<details>
<summary><strong>Cómo se protegen el instalador y sus datos</strong></summary>

`get.destroy.tools` es el sitio de descargas del proyecto. El
[flujo de trabajo Installer](../../.github/workflows/installer.yml) público lo genera a partir de
[`deploy/installer/`](../../deploy/installer/README.md) para la revisión exacta de `main`,
lo publica cuando se superan las pruebas de instalación en Linux y Windows, y firma los
scripts del instalador y los paquetes de la aplicación con la clave de publicación de
[`release-signing.pub`](../../deploy/installer/release-signing.pub). Antes de instalar, el instalador comprueba
el SHA-256 y la firma RSA del paquete y del archivo de bloqueo de dependencias.
Para comprobar antes el propio script, descárguelo junto con su firma y ejecute los
[comandos de verificación previa](../INSTALLATION.md#verify-before-running). Si una compilación falla,
se mantiene la descarga anterior; los paneles instalados se actualizan al volver a ejecutar el instalador.
Las otras formas de instalar son las [versiones](https://github.com/phishdestroy/TgWitness/releases) de GitHub, el código fuente y
[Docker](DEPLOYMENT.md).

**Sus sesiones y datos.** TgWitness se ejecuta en su equipo o servidor, y el panel
escucha en localhost de forma predeterminada. Las sesiones de Telegram, las credenciales de proxy y los hashes
de los tokens de acceso se guardan en la bóveda cifrada de cada espacio de trabajo, con una
[clave maestra externa](../SECURITY-MODEL.md#external-master-key) opcional. La aplicación
no tiene telemetría. Se conecta a Telegram y a los servicios que usa su configuración:
listas públicas de MTProxy, sus proxies, almacenamiento S3, un bot testigo, autoridades
de sellado de tiempo, proveedores de IA y webhooks. El [Mapa del sistema](../SYSTEM-MAP.md) enumera
las conexiones que realiza el proceso de la aplicación.
Observe con una [cuenta de Telegram dedicada](https://phishdestroy.github.io/TgWitness/es/docs/dedicated-account/).

La insignia de versión describe este árbol de código fuente. Las compilaciones instalables figuran en
[Versiones](https://github.com/phishdestroy/TgWitness/releases); una función fusionada en
`main` llega a esas descargas con la siguiente versión.

[Instalación y acceso al panel](../INSTALLATION.md) ·
[Firmas y SHA-256](https://get.destroy.tools/#verification) ·
[Actualización](../INSTALLATION.md#update-an-existing-installation) ·
[Capacidades actuales y cualificación](../STATUS.md) ·
[Elegir un método de recopilación](../COLLECTION-MODES.md)

</details>

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

<a name="how-it-works"></a>

## Un registro que otros pueden comprobar

Compruébelo sin cuenta ni instalación. La muestra publicada incluye su propio verificador:

```sh
curl -LO https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip
unzip -o tgwitness-demo.zip verify.py        # el verificador viene dentro del archivo
python verify.py tgwitness-demo.zip          # Python 3.11+, solo necesita `cryptography`
```

Muestra los registros firmados, el hash de cabecera y la huella del firmante, y termina con `0`.
La muestra es ficticia; el mismo verificador funciona con cualquier exportación real.

Una exportación contiene los mensajes, los archivos y el verificador. Envíe al destinatario la huella
de su clave por otro canal y podrá comprobarla por su cuenta:

```sh
python -m tgwitness.verify evidence.zip --fingerprint TRUSTED_SHA256 --tsa-ca TSA-ROOT.pem --require evidence
```

El verificador comprueba las firmas, la cadena del diario, la lista de archivos y los adjuntos.
Para que valga como prueba, necesita la huella de su clave y un sello de tiempo de un tercero que cubra el último
registro, como un sello de tiempo RFC 3161 comprobado con el certificado raíz de la autoridad.

**De dónde proceden los mensajes.** TgWitness los recibe de Telegram a través de la
sesión MTProto cifrada de la cuenta, igual que las aplicaciones oficiales, y añade cada uno al
diario, firmado, en cuanto llega. La [captura con GitHub Actions](../SEALED-ACTIONS.md) y
[Phala Intel TDX](../HIGH-ASSURANCE.md) también certifican el recopilador que los recibió.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-chain-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-chain-mobile.svg">
  <img src="../assets/presentation/casework-chain.svg" width="1200" alt="Los mensajes nuevos, las ediciones guardadas y las observaciones de eliminación forman un diario enlazado y firmado. Verifíquelo con una clave de confianza obtenida de forma independiente.">
</picture>

[Verificación del archivo](../wiki/Exports-and-Verification.md) · [Formato de las pruebas](../EVIDENCE.md) · [Testigo independiente](../WITNESS.md) · [Sellos de tiempo externos](../TIMESTAMP.md) · [Comprobaciones y escala probada](../VERIFICATION.md)

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## De una conversación a un caso

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-features-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-features-mobile.svg">
  <img src="../assets/presentation/readme-features.svg" width="1200" alt="Tres flujos de trabajo animados: exportar un chat a HTML y JSON, encontrar un enlace compartido en los chats registrados y conservar las versiones capturadas tras un aviso de eliminación.">
</picture>

<table>
<tr>
<td width="33%" align="center"><a href="../wiki/Chat-Export.md"><b>Exportación de chat&nbsp;↗</b></a><br><sub>Un chat a HTML y JSON firmados</sub></td>
<td width="33%" align="center"><a href="../INVESTIGATION.md"><b>Investigación&nbsp;↗</b></a><br><sub>Siga una pista por los chats registrados</sub></td>
<td width="33%" align="center"><a href="../COLLECTION.md"><b>Versiones guardadas&nbsp;↗</b></a><br><sub>Ediciones y avisos de eliminación, conservados</sub></td>
</tr>
</table>

Dos formas de usarlo: [exportar su cuenta](../ACCOUNT-EXPORT.md) una vez, o
[seguir una investigación](../INVESTIGATION.md) y guardar los cambios de forma continua.
Elija algunos chats, una carpeta de Telegram o la cuenta entera. Cada cuenta tiene su
propio espacio de trabajo, sesión y clave de firma.

<p align="center"><picture><source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-divider-static.svg"><img src="../assets/presentation/readme-divider.svg" width="1200" height="28" alt=""></picture></p>

## Descubra más

<details>
<summary><strong>Exportaciones medidas · 6 de noviembre de 2026</strong> · 56.329 mensajes, ambos archivos verificados</summary>

**56.329 mensajes exportados en dos ejecuciones desde cero.** Ambos archivos firmados superaron la verificación con claves de recopilador fijadas.

[![Velocidad medida de recopilación y de exportación completa](../../website/validation/performance.svg)](https://phishdestroy.github.io/TgWitness/es/docs/validation/)

| Ejecución | Mensajes | Tiempo de recopilación | Velocidad de recopilación | Exportación completa | Velocidad de extremo a extremo |
| --- | ---: | ---: | ---: | ---: | ---: |
| Servidor A | 27.030 | 189,043 s | **142,983 mensajes/s** | 211,647 s | 127,713 mensajes/s |
| Servidor B | 29.299 | 182,513 s | **160,531 mensajes/s** | 206,650 s | 141,781 mensajes/s |

Texto y metadatos a través de WARP, dos cuentas por servidor, sin adjuntos ni registros reutilizados.
Medido en la revisión [`92e539af`](https://github.com/phishdestroy/TgWitness/commit/92e539af40d8368d198ff5e040f1d876f2c1310e).
Cada ejecución publicada indica su revisión de origen, carga de trabajo, tiempos y resultado de verificación:
[carga de trabajo, tiempos y verificación](../EXPORT-BENCHMARK-2026-11-06.md). Los cambios en `main`
ejecutan los [flujos de trabajo de CI](../../.github/workflows/README.md) públicos, incluidas las pruebas del instalador
en Linux y Windows y la compilación del verificador independiente.

[**Explore la demo →**](https://phishdestroy.github.io/TgWitness/demo/?lang=es) ·
[**Mediciones, fechas y método →**](https://phishdestroy.github.io/TgWitness/es/docs/validation/) ·
[Descargue una exportación de muestra ficticia](https://phishdestroy.github.io/TgWitness/demo/downloads/tgwitness-demo.zip) ·
[Auditoría firmada en inglés](../../website/validation/audit/REPORT.md)

</details>

<a name="start-simple"></a>

<details>
<summary><strong>Empiece de forma sencilla. Vea todas las rutas.</strong> · primer inicio y mapa del sistema</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-start-map-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-start-map-mobile.svg">
  <img src="../assets/presentation/readme-start-map.svg" width="1200" alt="El primer inicio ofrece Solo descargar, Seguir chats o Pruebas para un caso y muestra solo las secciones correspondientes. El mapa del sistema conecta el panel, el recopilador, Telegram, el diario, el testigo y los servicios externos, con observaciones de red. Valores ficticios.">
</picture>

El primer inicio hace una sola pregunta: **Solo descargar**, **Seguir chats** o
**Pruebas para un caso**. La respuesta fija el objetivo y el nivel de la interfaz, de modo que el
panel solo muestra las secciones que necesita esa tarea. Después vienen, en cinco etapas, la conexión, el inicio de sesión en Telegram y
la elección de chats. La comprobación de la conexión se ejecuta sola, y
las opciones de ruta solo se abren si falla. Las herramientas para expertos se activan con un solo interruptor.

El **Mapa del sistema** muestra cómo llega la instalación a Telegram y a los servicios
externos: el acceso al panel, la ruta y el destino de Telegram de cada cuenta, la ruta del diario y
del testigo, y las últimas observaciones de red. Una observación que falta
se marca como ausente.

[Primera configuración](../SETTINGS.md) · [Mapa del sistema](../SYSTEM-MAP.md)

</details>

<details>
<summary><strong>Pensado para el resto de la investigación</strong> · fichas de sujeto, listas de vigilancia, carteras, seguimiento del estado en línea, documentos judiciales</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-capabilities-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-capabilities-mobile.svg">
  <img src="../assets/presentation/readme-capabilities.svg" width="1200" alt="Siga nombres y nombres de usuario por ID de Telegram. Registre las interacciones admitidas con bots, con recibos firmados. Busque mensajes archivados y conecte clientes MCP de solo lectura. Despliegue un recopilador con SSH enmascarado y registros del proveedor para su revisión. Documente una conversación paso a paso con referencias al diario. Entregue un paquete del caso BagIt con plantillas judiciales. Flujos de trabajo ilustrativos.">
</picture>

<table>
<tr>
<td width="50%" align="center"><a href="../INVESTIGATION.md#4-connect-observations-across-chats"><b>Personas y expedientes&nbsp;↗</b></a><br><sub>Nombres y nombres de usuario seguidos por ID de Telegram</sub></td>
<td width="50%" align="center"><a href="../COLLECTION.md#act-from-the-panel"><b>Investigación de bots&nbsp;↗</b></a><br><sub>Interacciones con bots, con recibos firmados</sub></td>
</tr>
<tr>
<td width="50%" align="center"><a href="https://phishdestroy.github.io/TgWitness/es/docs/archive/"><b>Búsqueda en el archivo, IA y MCP&nbsp;↗</b></a><br><sub>Busque en el archivo y conecte clientes de solo lectura</sub></td>
<td width="50%" align="center"><a href="../HIGH-ASSURANCE.md"><b>Despliegue sellado en la nube&nbsp;↗</b></a><br><sub>Un recopilador dentro de Intel TDX</sub></td>
</tr>
</table>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-documentation-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-documentation-mobile.svg">
  <img src="../assets/presentation/readme-documentation.svg" width="1200" alt="Tres pasos animados: una ficha de sujeto cuya instantánea posterior registra un cambio de nombre, un plan de conversación cuyos objetivos se cierran con registros del diario y un código QR de pago decodificado en una cartera con suma de comprobación válida que genera una coincidencia en una lista de vigilancia. Valores ficticios.">
</picture>

**Documente la conversación.** Abra un acta para un chat en el panel lateral **Documentación**
y cada paso se anota solo: acciones del panel, respuestas con el tiempo transcurrido antes
de ellas, ediciones, avisos de eliminación, notas y borradores de IA. Cada paso cita su registro
del diario y su SHA-256. Al cerrar definitivamente el documento, este se firma y el hash de la declaración se escribe en
el diario.

| | |
| --- | --- |
| [Fichas de sujeto](../INVESTIGATION-MODE.md#subject-cards) | Instantáneas del perfil de un bot, persona, canal o grupo con las etiquetas BOT, VERIFIED, SCAM y FAKE de Telegram; una instantánea posterior indica qué ha cambiado |
| [Planes de conversación](../INVESTIGATION-MODE.md#conversation-plans) | Objetivos sobre la ruta de pago, la infraestructura o las personas, mensajes preparados, tiempos de respuesta, actividad por hora y estilo de escritura de la otra parte |
| [Traducción](../INVESTIGATION-MODE.md#machine-translation) | Se muestra bajo el original con los idiomas, el modelo y el registro del diario |
| [Listas de vigilancia](../INVESTIGATION-MODE.md#watchlists) | Palabras, patrones, carteras, @nombres de usuario, ID, dominios, teléfonos y enlaces, detectados en el texto, las ediciones, los destinos de enlaces ocultos, los botones de bots, los códigos QR y el OCR |
| [Seguimiento del estado en línea](../INVESTIGATION-MODE.md#online-watch) | Comprobaciones cada 1–60 minutos, hasta 100 cuentas por solicitud, con un patrón por hora y día de la semana |
| [Códigos y carteras](../INVESTIGATION-MODE.md#codes-in-images) | Códigos QR de pago; direcciones EVM comprobadas según EIP-55, TON en formato bruto, sumas de comprobación de XRP Ledger, enlaces de pago con cadena, importe y token |
| [Rastros del cliente](../INVESTIGATION-MODE.md#what-a-client-and-an-upload-time-show) | Rastros del codificador en videomensajes redondos y mensajes de voz; comparar la hora de subida con la de envío delata pruebas «en directo» pregrabadas |
| [Identidad encubierta y autorización](../INVESTIGATION-MODE.md#cover-and-authority) | Perfiles ficticios, autorizaciones y un registro de actividad encubierta que señala los mensajes fuera de los chats o del periodo autorizados |
| [Control de la cuenta](../INVESTIGATION-MODE.md#account-control) | Edición del perfil y la privacidad con registros de antes y después, una comprobación de exposición y desconexión inmediata tras cada acción |
| [Documentos judiciales](../INVESTIGATION-MODE.md#documents-for-court) | Paquete del caso BagIt con una plantilla de certificación según la Rule 902(13)/(14), índice de pruebas documentales, anexo de solicitud y subtítulos WebVTT/SRT para grabaciones de pantalla |

El contenido marcado como 18+, violencia o datos personales permanece en la copia judicial, sellado con
AES-256-GCM; las claves se envían por separado.

Los [ajustes de exportación](../EXPORT_HASHES.md) abarcan la adquisición por la API normal y por Takeout,
el historial de mensajes antes que los adjuntos, la descarga de archivos o los hashes del servidor, y vistas
JSON/HTML compatibles con Telegram Desktop. La [exportación distribuida de chats](../DISTRIBUTED-EXPORT.md#history-acquisition)
ofrece una vía opcional por Takeout para el historial público, puntos de control firmados cada 100 mensajes
y recuperación dentro de un rango con la misma cuenta; su
[diseño de rendimiento](../FAST-ACQUISITION.md) describe el comportamiento de adquisición probado
y las mediciones en vivo previstas.

</details>

<details>
<summary><strong>Todo lo demás</strong> · historial, cuentas, proxies, IA, integraciones</summary>

| | |
| --- | --- |
| [Cargar mensajes anteriores](../HISTORY.md) | Descargue el historial de los chats seleccionados; pause y reanude cuando quiera |
| [Varias cuentas](../ACCOUNTS.md#multiple-accounts) | Espacios de trabajo separados, cada uno con su propia sesión de Telegram, diario y clave de firma |
| [Importación masiva](../ACCOUNTS.md#bulk-import-and-account-groups) | Añada un lote de archivos de sesión y organice las cuentas en grupos con ajustes compartidos |
| [Conjunto de MTProxy](../wiki/Proxies.md#pool-dashboard-and-custom-sources) | Ping, países, filtros y sus propias listas |
| [Sesiones existentes](../ACCOUNTS.md) | TData, Telethon, Pyrogram, StringSession, auth key o una línea `key:DC`; autorización QR independiente opcional desde un donante importado |
| [Seguridad de la cuenta](../ACCOUNTS.md#create-an-independent-authorization) | Alertas de nuevas sesiones, cierre de otras sesiones, un modo de sesión única que también establece una contraseña de verificación en dos pasos y una [sonda testigo](../ACCOUNTS.md#witness-probe) que detecta cuándo las actualizaciones en vivo dejan de llegar a esta sesión |
| [Exportación de chats reanudable](../EXPORT_HASHES.md#restricted-github-capture-and-single-chat-export) | Una exportación detenida conserva una copia parcial firmada: reanúdela, empiece de nuevo o descargue lo guardado |
| [Proxies](../CONNECTION-SECURITY.md#ip-modes) | SOCKS5, HTTP CONNECT o MTProxy por espacio de trabajo. **Ocultar IP** nunca recurre a la conexión directa |
| [Búsqueda e IA](../ANALYSIS.md) | Búsqueda local e IA opcional con fuentes que puede comprobar |
| [Búsqueda de texto completo](../SEARCH.md) | Formas de palabras, frases exactas, dominios, @nombres de usuario y chino sin espacios, con los mejores resultados primero (**versión preliminar**) |
| [MCP](../MCP.md) | Acceso de solo lectura para clientes MCP, limitado a los chats que elija |
| [Línea de comandos](../CLI.md) | `search`, `context`, `messages`, `stats` y `export` en JSON Lines con `--json` para scripts y agentes, en local o con un token de alcance limitado (**versión preliminar**) |
| [OCR y transcripción](../MEDIA-ANALYSIS.md) | Se ejecuta en local; los originales no se modifican |
| [Captura independiente](../OPTIONAL-CAPTURE.md) | Grabadores opcionales de navegador/AyuGram en **Más herramientas → Extras** (vista previa, desactivados por defecto) |
| [Trusted Live](../TRUSTED-LIVE.md) | Sesión oficial de Desktop/Web, video protegido y análisis de continuidad de la exportación nativa (vista previa; cualificación en vivo pendiente) |
| [Web oficial sellada](../OFFICIAL-WITNESS.md) | Navegador oficial recién iniciado en GitHub Actions, controles restringidos, video firmado y código fuente/configuración esperados de forma independiente |
| [Webhooks](../WEBHOOKS.md) | Eventos salientes firmados con reintentos; incluye un ejemplo para n8n |
| [Acceso compartido](../ACCESS.md) | Comparta solo los chats seleccionados, con caducidad y límites por IP |
| [Números de mensajes que faltan](../EVIDENCE.md#missing-message-numbers-gap_summary) | Números asignados por Telegram que nunca se observaron, por canal y para toda la cuenta, en la cobertura, los informes y MCP (**versión preliminar**) |
| [Instantáneas del estado del chat](../COLLECTION.md) | Instantáneas firmadas periódicas del título, la descripción, los mensajes fijados, los administradores y los regalos, con lo que ha cambiado (**versión preliminar**) |
| [Mapa del sistema](../SYSTEM-MAP.md) | Mapa en vivo del acceso al panel, las rutas de las cuentas, los destinos de Telegram y los servicios externos, con las últimas 200 de hasta 2.000 observaciones de red |

</details>

<details>
<summary><strong>Elija qué respalda el registro</strong> · local, nube auditada, GitHub Actions o Intel TDX</summary>

Ejecútelo en local, añada un despliegue auditado en la nube o recopile dentro de una **VM confidencial
de Phala Cloud con Intel TDX**. Todas las opciones conservan el diario firmado; las comprobaciones
adicionales se refieren al entorno en el que se recopiló.

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/casework-assurance-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/casework-assurance-mobile.svg">
  <img src="../assets/presentation/casework-assurance.svg" width="1200" alt="Tres opciones de despliegue: verificación local del diario; una VM auditada con registros del proveedor y de acceso; Phala Intel TDX con un quote verificado, sistema operativo y aplicación medidos y una clave de recopilador vinculada.">
</picture>

El verificador TDX comprueba el quote con la raíz fijada de Intel y los datos de revocación,
lo vincula a una declaración firmada del recopilador y a un desafío nuevo, y compara el
sistema operativo y la aplicación medidos con entradas esperadas de forma independiente. El informe muestra
cada resultado por separado, para poder revisar juntos el entorno medido, la identidad del recopilador, los registros
de captura y la cobertura.

**Captura con procedencia de GitHub** (vista previa). Recopile un chat en un runner alojado en GitHub
con una versión fijada de TgWitness y una sesión de Telegram nueva, y descargue después el archivo
cifrado con su certificación de GitHub. El verificador comprueba el flujo de trabajo aprobado y la
versión del recopilador, el resumen criptográfico del archivo, el diario y los adjuntos. También está disponible
en **Exportaciones**, dentro del panel.
[Abrir la página de captura](https://phishdestroy.github.io/TgWitness/es/docs/capture/) · [Instrucciones](../SEALED-ACTIONS.md)

Para la observación en vivo, el historial o una exportación puntual, elija un
[método de recopilación](../COLLECTION-MODES.md). Los chats privados en la nube están disponibles
cuando la cuenta conectada tiene acceso a ellos. La aplicación publicada también incluye la
[integración con chats secretos](../PSEUDO-SECRET.md): instale la dependencia opcional del protocolo
y actívela por cuenta para registrar los chats creados o aceptados en ella.
Consulte el [alcance de la recopilación](../COLLECTION.md) para ver las vías de adquisición disponibles.

[Phala / Intel TDX y despliegues auditados](../HIGH-ASSURANCE.md) ·
[Cualificación en vivo en Phala](../VERIFICATION.md#live-phala-cloud-deployment--4-november-2026) ·
[Límites de confianza](../SECURITY-MODEL.md)

</details>

<a name="manifesto"></a>

<details>
<summary><strong>Compruebe la captura y el registro guardado</strong> · qué verifica el destinatario y Export Clinic</summary>

<picture>
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-manifesto-mobile.svg">
  <img src="../assets/presentation/readme-manifesto.svg" width="1200" alt="Capture la conversación. Verifique el registro. Guarde mensajes, ediciones y archivos, compruebe firmas y puntos de control y revise el proceso de captura.">
</picture>

TgWitness registra el contenido entregado a la cuenta de Telegram conectada, con
identificadores de chat, mensaje y remitente, versiones capturadas y metadatos de recopilación.
El archivo reúne esos registros, los adjuntos conservados y los datos de verificación
para su revisión.

| Comprobación | Qué verifica el destinatario |
| --- | --- |
| Diario firmado y manifiesto | Las firmas de los registros, la cadena de hashes y los archivos entregados frente a la clave de firma esperada. |
| Punto de control conservado por separado | El diario frente a una longitud y un hash de cabecera registrados previamente. |
| Testigo independiente | El diario frente a los puntos de control conservados por un testigo separado. |
| Captura con GitHub Actions | El archivo frente a su certificación, el flujo de trabajo alojado aprobado y la versión del recopilador. |

[Export Clinic](https://phishdestroy.github.io/TgWitness/docs/export-clinic/)
muestra una conversación de Telegram junto a archivos de exportación de Desktop alterados a propósito.
Compare las versiones, examine los cambios y siga los pasos de recopilación y
verificación de un archivo firmado de TgWitness.

[Pasos de verificación](../wiki/Exports-and-Verification.md) ·
[Captura con GitHub](../SEALED-ACTIONS.md) ·
[Modelo técnico de confianza](../SECURITY-MODEL.md)

</details>

<a name="operations"></a>

<details>
<summary><strong>Mantenga la investigación en marcha</strong> · notificaciones, almacenamiento y recuperación</summary>

<picture>
  <source media="(max-width: 640px) and (prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-mobile-static.svg">
  <source media="(prefers-reduced-motion: reduce)" srcset="../assets/presentation/readme-services-static.svg">
  <source media="(max-width: 640px)" srcset="../assets/presentation/readme-services-mobile.svg">
  <img src="../assets/presentation/readme-services.svg" width="1200" alt="Flujos de trabajo animados: Apprise envía las alertas configuradas; las copias externas se cifran antes de subirse a un almacenamiento compatible con S3.">
</picture>

[Notificaciones](../OPERATIONS.md#notifications) · [Copia externa cifrada](../wiki/Off-site-Copy.md) · [Copia de seguridad y recuperación](../wiki/Backup-and-Recovery.md) · [Solución de problemas](../OPERATIONS.md)

<table>
<tr>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/es/docs/start/"><b>Guía de configuración&nbsp;↗</b></a><br><sub>De la instalación al primer chat</sub></td>
<td width="33%" align="center"><a href="https://phishdestroy.github.io/TgWitness/es/docs/dedicated-account/"><b>Prepare su cuenta&nbsp;↗</b></a><br><sub>Una cuenta de Telegram dedicada</sub></td>
<td width="33%" align="center"><a href="DEPLOYMENT.md"><b>Docker y servidores&nbsp;↗</b></a><br><sub>HTTPS, reinicios y actualizaciones</sub></td>
</tr>
</table>

</details>

<a name="repository-map"></a>

<details>
<summary><strong>Explore el repositorio</strong> · dónde están el código, la documentación y las herramientas</summary>

| Directorio | Empiece aquí |
| --- | --- |
| [docs/](../README.md) | Configuración, flujos de trabajo de investigación y referencia técnica |
| [tgwitness/](../../tgwitness/README.md) | Aplicación principal, recopilador, diario y panel web |
| [tgwitness_capture/](../../tgwitness_capture/README.md) | Grabadores independientes y su código de verificación |
| [addons/](../../addons/README.md) | Instalación, configuración y pruebas de la captura opcional |
| [deploy/](../../deploy/README.md) | Instaladores, contenedores y servicios en segundo plano |
| [examples/](../../examples/README.md) | Configuraciones para exportar cuentas y para la captura sellada |
| [integrations/](../../integrations/README.md) | Webhooks firmados y un receptor para n8n |
| [.agents/](../../.agents/README.md) | Instrucciones de tareas para leer el archivo mediante la CLI |
| [scripts/](../../scripts/README.md) | Lanzadores y utilidades de CI |
| [tools/](../../tools/README.md) | Compilaciones, comprobaciones y empaquetado |
| [website/](../../website/README.md) | Sitio público, guías traducidas y demo interactiva |
| [.github/](../../.github/AUTOMATION.md) | Flujos de trabajo, pautas de contribución y soporte |

[Guía completa del proyecto](../PROJECT-GUIDE.md) ·
[Contribuir](../../.github/CONTRIBUTING.md) · [Obtener ayuda](../../.github/SUPPORT.md)

</details>

<details>
<summary><strong>⚖️ Aviso ético y continuidad histórica</strong></summary>

La postura de los autores y el aviso sobre el operador, en este idioma:

[Aviso sobre el operador](OPERATOR-INCOMPATIBILITY.md) · [Licencia MIT](../../LICENSE) · [NOTICE original](../../NOTICE)

</details>

<a name="languages"></a>

<details>
<summary><strong>Lea la presentación del proyecto en su idioma</strong></summary>

[English](../../README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · **Español** · [Português (Brasil)](../pt/README.md) · [Türkçe](../tr/README.md) · [العربية](../ar/README.md) · [فارسی](../fa/README.md) · [اردو](../ur/README.md) · [हिन्दी](../hi/README.md) · [Bahasa Indonesia](../id/README.md) · [Tiếng Việt](../vi/README.md) · [简体中文](../zh/README.md) · [繁體中文](../zh-Hant/README.md) · [Français](../fr/README.md) · [Deutsch](../de/README.md) · [Italiano](../it/README.md) · [Polski](../pl/README.md) · [O‘zbekcha](../uz/README.md) · [한국어](../ko/README.md) · [日本語](../ja/README.md) · [Bahasa Melayu](../ms/README.md) · [ไทย](../th/README.md) · [עברית](../he/README.md) · [বাংলা](../bn/README.md) · [አማርኛ](../am/README.md)

</details>

<p align="center">
  <a href="../README.md"><b>Documentación técnica</b></a> ·
  <a href="https://github.com/phishdestroy/TgWitness/wiki"><b>Manual de investigación</b></a> ·
  <a href="https://github.com/phishdestroy"><b>Creado por PhishDestroy</b></a> ·
  <a href="../../.github/CONTRIBUTING.md"><b>Contribuir</b></a> ·
  <a href="../../.github/SUPPORT.md"><b>Obtener ayuda</b></a> ·
  <a href="../../.github/SECURITY.md"><b>Informar de una vulnerabilidad</b></a>
</p>

[Índice del proyecto legible por máquinas](../../llms.txt) · [Manual completo en texto](https://phishdestroy.github.io/TgWitness/llms-full.txt) · [Reglas del repositorio para agentes](../../AGENTS.md)
