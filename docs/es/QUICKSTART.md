[English](../QUICKSTART.md) · [Русский](../ru/QUICKSTART.md) · [Українська](../uk/QUICKSTART.md) · **Español** · [Português (Brasil)](../pt/QUICKSTART.md) · [Türkçe](../tr/QUICKSTART.md) · [العربية](../ar/QUICKSTART.md) · [فارسی](../fa/QUICKSTART.md) · [اردو](../ur/QUICKSTART.md) · [हिन्दी](../hi/QUICKSTART.md) · [Bahasa Indonesia](../id/QUICKSTART.md) · [Tiếng Việt](../vi/QUICKSTART.md) · [简体中文](../zh/QUICKSTART.md)

# Guía de inicio rápido de TgWitness

TgWitness es una aplicación independiente destinada a la observación de grupos y canales de Telegram a los que sus cuentas puedan acceder. Se ejecuta de forma local con su propio directorio de datos.

**¿Es su primera visita?** [Explore la demostración](#explore-la-interfaz) antes de vincular una cuenta. [Elija una guía](../README.md) sobre proxies, testigos, exportaciones o configuración del servidor.

## Instalación y puesta en marcha

Elija un método. Las descargas portátiles estarán disponibles una vez que se haya publicado una versión estable:

| Servidor | No hay nada instalado | A partir de la versión: Python 3.11+ | Docker: Engine/Desktop con Compose 2.20 o superior |
| --- | --- | --- | --- |
| Windows | Extraiga `TgWitness-<version>-windows-amd64-portable.zip` de las versiones de GitHub y haga doble clic en `TgWitness.cmd` | Haga doble clic en `Start.cmd` | Haga doble clic en `scripts\Docker.cmd` |
| Linux / macOS | — | `sh start.sh` | `sh scripts/docker-start.sh` |

Para acceder al código fuente, descargue y extraiga el archivo ZIP de GitHub Releases o clone el repositorio. `Start.cmd` le ofrece instalar Python 3.12 en su sistema Windows si no se encuentra una versión adecuada de Python (winget o el instalador firmado de python.org). `start.sh` muestra el comando de instalación exacto para su distribución de Linux o macOS si no dispone de Python. La primera ejecución del código fuente crea `.venv` e instala las dependencias automáticamente.

Docker compila la aplicación y la inicia en segundo plano; no es necesario disponer de Python en el host. `scripts\Docker.cmd` y `scripts/docker-start.sh` muestran la dirección del panel y el token cuando el contenedor funciona correctamente. Los comandos de Docker equivalentes en todos los hosts compatibles son:

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

Abra **http://127.0.0.1:8787**. Utilice el token generado por la herramienta auxiliar de Docker o por el segundo comando de Docker, o consulte **el** **archivo** **data/live/panel-token.txt** si se trata de una instalación portátil o desde el código fuente. Continúe en **«Conectar Telegram»** más abajo. Las instalaciones nativas y las de Docker utilizan un almacenamiento independiente; al iniciar Docker no se importa ningún diario nativo existente.

En el caso de un servidor, [la implementación](DEPLOYMENT.md) incluye HTTPS automático, reinicio, imágenes publicadas, actualizaciones y copias de seguridad.

## Explore la interfaz

1. Ejecute **«TgWitness-Demo.cmd»** en el paquete portátil, **«scripts\Demo.cmd»** en una carpeta de origen de Windows o `sh start.sh --demo` en Linux/macOS. Al ejecutarlo desde la fuente, primero se crea `.venv` y se instalan las dependencias.
2. Abrir **http://127.0.0.1:8787**.
3. La demostración local abre automáticamente el diario de muestra. No es necesario copiar ningún token para acceder directamente de forma local.

Los mensajes de demostración son ficticios. El modo de demostración no permite conectarse a una cuenta real de Telegram.

## Conectarse a Telegram

> [!WARNING]
> **No utilice nada que no pueda permitirse perder.** Le recomendamos encarecidamente que no vincule cuentas personales o valiosas, ni que cree un ID de API o un hash en una cuenta que considere importante. Telegram bloquea cuentas de forma impredecible y, a menudo, de manera permanente, independientemente del cliente utilizado. El buen funcionamiento de una prueba depende de Telegram, no de TgWitness, y no garantiza nada para el futuro.

1. Si la demostración nativa está en ejecución, deténgala y ejecute **Start.cmd** o `sh start.sh`. De lo contrario, mantenga en ejecución la instalación en vivo iniciada anteriormente.
2. Utilice el token del panel correspondiente a su método de instalación para abrir el panel.
3. Si necesita un proxy, guárdelo en **Cuenta → Ajustes → Ajustes de conexión → Cambiar ruta de conexión**.
4. En **«Cuenta**», introduzca su número de teléfono y pulse **«Continuar»**, seleccione **«Código QR» → «Mostrar código QR**», o seleccione archivos y pulse **«Conectar cuenta**». **El «ID de API + Hash»** es opcional: el espacio de trabajo utiliza el par guardado o importado, o bien un par válido del conjunto integrado. Para utilizar su propia aplicación, pegue un par `API ID:API Hash` en «ID de API». Para obtener una clave de autorización completa, seleccione **«Clave de autenticación»**, pegue los 512 caracteres hexadecimales y seleccione el «ID de DC» facilitado. El «ID de usuario» es opcional y se marca si se introduce.
5. Complete el método de inicio de sesión que haya seleccionado: teléfono/código/autenticación de dos factores (2FA), confirmación desde una aplicación de Telegram en la que haya iniciado sesión para el código QR, o una importación de sesión autorizada compatible.
6. Compruebe el ID de cuenta que se muestra. Open **Sources**: sus chats se cargan automáticamente; añada sus grupos.
7. En **«Elija qué cambios desea conservar**», seleccione las categorías de eventos o la configuración preestablecida **«Mensajes, ediciones y eliminaciones**» y, a continuación, guarde la configuración de supervisión.
8. Seleccione la configuración de los archivos adjuntos por separado y, a continuación, pulse **«Iniciar observación**».

Las credenciales de la API identifican su aplicación; por sí solas, no autorizan una cuenta. Los grupos privados no necesitan un nombre de usuario público, pero su cuenta debe tener acceso.

Para las cuentas existentes, consulte [los formatos de cuentas y sesiones](../ACCOUNTS.md): el panel admite Telethon StringSession, Telethon/Pyrogram SQLite, TData ZIP de una sola cuenta y JSON de cuentas compatibles. Seleccione una sesión y su archivo JSON correspondiente, y pulse **«Conectar cuenta**». También está disponible el inicio de sesión mediante código QR con la misma configuración opcional de la API. No se admiten TDLib, bots ni listas de cuentas masivas.

Para añadir otra cuenta, pulse **el signo «+»** situado junto al selector de cuentas, abra **Cuenta → Ajustes → Ajustes de conexión → Espacios de trabajo**, o utilice **la opción Cuentas**. Los espacios de trabajo cuentan con sesiones, diarios, claves, fuentes y colas independientes. Al cambiar de vista, los demás recopiladores siguen en funcionamiento. En esta instalación, no es posible asignar la misma cuenta de Telegram a dos espacios de trabajo. No hay un número fijo de espacios de trabajo; estos comparten un único proceso, por lo que la capacidad depende del equipo.

El token del panel en tiempo real protege el acceso a sus autorizaciones de Telegram y al material guardado; es independiente de las credenciales de la API de Telegram. Solo una demostración local iniciada explícitamente y a la que se acceda directamente obtiene acceso automático. Una demostración remota o a través de un proxy sigue utilizando `data/demo/panel-token.txt`.

## Revisión y exportación

- **Diario:** busque y filtre las observaciones por fuente y tipo de evento.
- Seleccione un evento para consultar su registro original, su atribución y las versiones guardadas.
- Los detalles de edición muestran el contenido disponible antes y después. Los detalles de eliminación muestran el último contenido capturado, si lo hubiera; un agente desconocido sigue sin identificarse.
- **Formatos de exportación:** ZIP firmado, JSONL, CSV y HTML sin conexión.
- **Exportación completa del chat** (Fuentes → Exportación completa del chat): descargue todo el historial visible de un chat como un paquete firmado con `chat.json` (estilo de exportación de Telegram) y un archivo legible `chat.html`. Los chats privados funcionan cuando la cuenta es miembro. Se trata de una instantánea actual, no de una reconstrucción de mensajes eliminados o editados previamente. Verifique una copia con `python verify.py chat-export.zip --fingerprint TRUSTED_SHA256`.
- **Guardar punto de control:** mantenga el límite del diario firmado fuera del colector.
- **Descargue el recibo de ejecución firmado:** conserve el registro del programa y la versión del recopilador.
- **Preparación de una solicitud de marca de tiempo:** prepare una solicitud fuera de línea dirigida a una autoridad de marcas de tiempo; siga las instrucciones de [TIMESTAMP.md](../TIMESTAMP.md) para obtener y verificar una respuesta.
- **Verificación del diario:** compruebe las firmas de los eventos y los enlaces de la cadena. La exportación en formato ZIP también comprueba los archivos multimedia.

Los navegadores compatibles guardan las exportaciones de gran tamaño directamente en el archivo elegido. Otros navegadores almacenan en el búfer un máximo de 128 MiB. Mientras el servidor está en funcionamiento, la CLI de streaming admite descargas de mayor tamaño sin necesidad de almacenar en el búfer la respuesta completa:

```sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
```

Para otro espacio de trabajo, añada `--profile ID` utilizando **«Exportaciones» → «ID del espacio de trabajo**». Para un servidor remoto, añada `--url https://your-server`. El límite de transferencia predeterminado es de 5 GiB; `--max-mib` permite modificarlo. El contenido ZIP firmado tiene, por defecto, un límite de verificación sin comprimir independiente de 4 GiB (**la opción «Parámetros»** lo aumenta; verifique dichos archivos con `verify.py --max-gib N`). Verifique el archivo utilizando una copia fiable del verificador y una huella digital o punto de control de la clave conservada de forma independiente.

## Compruebe la instalación

```sh
python start.py --setup-only
python start.py --check
python start.py --check --json
```

`--check` comprueba las dependencias locales, la compatibilidad con la firma, el almacenamiento, la configuración de claves y la dirección de escucha. No instala nada ni se conecta a Telegram. Si el puerto está ocupado, es posible que haya otra instancia en ejecución. Utilice un `--port` diferente o deténgala primero.

El lanzador se instala en `.venv`. Los comandos auxiliares `python -m tgwitness...` deben utilizar `.venv\Scripts\python.exe` en Windows o `.venv/bin/python` en Linux/macOS, a menos que dicho entorno ya esté activado.

## Sesiones, protección y funcionamiento

Se puede convertir localmente una base de datos SQLite de Telethon cerrada y coherente `.session` mediante `python -m tgwitness.sessions account.session --out account.tgwitness-session` y, a continuación, cargarla en Account. También están disponibles la importación directa de archivos y el inicio de sesión mediante código QR. Consulte [CONNECTION-SECURITY.md](../CONNECTION-SECURITY.md) para conocer los formatos de inicio de sesión, SOCKS5, HTTP CONNECT, MTProxy y las claves maestras externas.

**Al pausar la observación**, se detiene la recopilación. **Al bloquearla,** solo se cierra el acceso al navegador. Al cerrar una pestaña, el proceso de recopilación sigue en ejecución. Al detener el proceso, se interrumpe la recopilación; una instantánea del historial no puede reconstruir todas las modificaciones o eliminaciones que se hayan perdido. Consulte [cómo funciona la recopilación](../COLLECTION.md) en lo que respecta a las políticas de eventos, las colas de archivos adjuntos, el aislamiento de cuentas y el comportamiento de reinicio.

Las sesiones y los secretos están cifrados. El contenido de los mensajes, los archivos multimedia y las exportaciones requieren un disco o volumen cifrado. Las firmas garantizan la integridad en relación con una clave de confianza; no garantizan el origen de Telegram ni impiden la falsificación por parte de un operador que controle el colector y su clave.

Consulte [el archivo OPERATIONS.md](../OPERATIONS.md) para obtener información sobre copias de seguridad y restauración, [el archivo DEPLOYMENT.md](DEPLOYMENT.md) para el alojamiento, y [la carpeta deploy/](../../deploy/README.md) para ver ejemplos de servicio. El panel instalado también incluye una guía de configuración sin conexión en `/guide.html`.

La verificación efectiva y las limitaciones restantes se recogen en [los archivos VERIFICATION.md](../VERIFICATION.md) y [READINESS.md](../internal/READINESS.md).
