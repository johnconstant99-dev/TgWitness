[TgWitness](../../README.md) / [Documentación](../README.md) / [Carpeta](README.md)

![Primeros pasos](../assets/presentation/chapter-start.svg)

[English](../QUICKSTART.md) · [Русский](../ru/QUICKSTART.md) · [Українська](../uk/QUICKSTART.md) · **Español** · [Português (Brasil)](../pt/QUICKSTART.md) · [Türkçe](../tr/QUICKSTART.md) · [العربية](../ar/QUICKSTART.md) · [فارسی](../fa/QUICKSTART.md) · [اردو](../ur/QUICKSTART.md) · [हिन्दी](../hi/QUICKSTART.md) · [Bahasa Indonesia](../id/QUICKSTART.md) · [Tiếng Việt](../vi/QUICKSTART.md) · [简体中文](../zh/QUICKSTART.md)

# Inicio rápido de TgWitness

TgWitness es una aplicación independiente para observar grupos y canales de Telegram a los que tienen acceso sus cuentas. Se ejecuta localmente con su propio directorio de datos.

**¿Primera visita?** [Explore la demo](#explore-the-interface) antes de conectar una cuenta. [Elija una guía](../README.md) sobre proxies, testigos, exportaciones o configuración de servidores. La [captura con GitHub Actions](../SEALED-ACTIONS.md) (versión preliminar) ejecuta una captura en su propio fork de GitHub en lugar de una instalación local.

<a name="install-and-start"></a>

## Instalación e inicio

El instalador guiado incluye su propio Python y comprueba los hashes de los paquetes y las firmas de la versión antes de instalar. Si lo vuelve a ejecutar, actualiza una instalación existente.

**Linux / macOS:**

```sh
curl -fsSL https://get.destroy.tools/install.sh | bash
```

**Windows (PowerShell o Símbolo del sistema):**

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.destroy.tools/install.ps1 | iex"
```

En un servidor Ubuntu, ejecútelo como root para instalar un servicio en segundo plano; en un equipo de escritorio, ejecútelo con su usuario habitual. En Ubuntu, el instalador muestra la dirección del panel y la clave de acceso; en macOS y Windows, el panel local se abre en el navegador. Continúe en **Conectar Telegram**, más abajo. [Instalación, verificación y actualización](../INSTALLATION.md) explica las opciones de acceso al servidor, cómo revisar el script antes de ejecutarlo, las actualizaciones y la desinstalación.

### Otros métodos

Las versiones publicadas en GitHub, el código fuente y Docker son alternativas al instalador. Las descargas portátiles estarán disponibles cuando se publique una compilación de la versión:

| Sistema | Sin nada instalado | Desde el código fuente: Python 3.11+ | Docker: Engine/Desktop con Compose 2.20+ |
| --- | --- | --- | --- |
| Windows | Extraiga `TgWitness-<version>-windows-amd64-portable.zip` de GitHub Releases y haga doble clic en `TgWitness.cmd` | Haga doble clic en `Start.cmd` | Haga doble clic en `scripts\Docker.cmd` |
| Linux / macOS | — | `sh start.sh` | `sh scripts/docker-start.sh` |

Para los métodos desde el código fuente, [descargue y extraiga la rama `main` actual](https://github.com/phishdestroy/TgWitness/archive/refs/heads/main.zip) o clone el repositorio:

```sh
git clone https://github.com/phishdestroy/TgWitness.git
cd TgWitness
```

Si no encuentra un Python adecuado, `Start.cmd` ofrece instalar Python 3.12 para su usuario de Windows (con winget o con el instalador firmado de python.org). Si falta Python, `start.sh` muestra el comando de instalación exacto para su distribución de Linux o para macOS. El primer inicio desde el código fuente crea `.venv` e instala las dependencias automáticamente.

Docker construye la aplicación y la inicia en segundo plano; no hace falta Python en el equipo anfitrión. `scripts\Docker.cmd` y `scripts/docker-start.sh` muestran la dirección del panel y el token cuando el contenedor supera la comprobación de estado. Los comandos de Docker equivalentes en cualquier sistema compatible son:

```sh
docker compose up -d --build --wait
docker compose exec tgwitness cat /data/panel-token.txt
```

Abra **http://127.0.0.1:8787**. Use el token que muestra el script auxiliar de Docker o el segundo comando de Docker; en una instalación portátil o desde el código fuente, lea **data/live/panel-token.txt**. Continúe en **Conectar Telegram**, más abajo. Las instalaciones nativas y las de Docker usan almacenamientos separados; iniciar Docker no importa un diario nativo existente.

Para un servidor, la guía de [despliegue](DEPLOYMENT.md) cubre HTTPS automático, reinicio, imágenes publicadas, actualizaciones y copias de seguridad.

<a name="explore-the-interface"></a>

## Exploración de la interfaz

1. Ejecute **TgWitness-Demo.cmd** en el paquete portátil, **scripts\Demo.cmd** en una carpeta de código fuente de Windows o `sh start.sh --demo` en Linux/macOS. Un inicio desde el código fuente crea primero `.venv` e instala las dependencias.
2. Abra **http://127.0.0.1:8787**.
3. La demo local abre automáticamente el diario de ejemplo. Con acceso local directo no hace falta copiar ningún token.

Los mensajes de la demo son ficticios. El modo demo no puede conectar una cuenta real de Telegram.

## Conectar Telegram

> [!WARNING]
> **Use cuentas dedicadas.** Telegram puede restringir cuentas o bloquearlas de forma permanente por volúmenes de solicitudes que considere excesivos, sea cual sea el cliente. Conecte cuentas preparadas para la observación, no personales ni valiosas, y cree el ID de la API y el hash en una cuenta dedicada.

1. Si la demo nativa está en ejecución, deténgala y ejecute **Start.cmd** o `sh start.sh`. De lo contrario, mantenga en ejecución la instalación real iniciada antes.
2. Inicie sesión con el token del panel. Un espacio de trabajo nuevo abre la [configuración inicial](../SETTINGS.md). Elija **Solo descargar**, **Seguir chats** o **Pruebas para un caso**.
3. Revise la comprobación de conexión. Configure su propio proxy si es necesario; la configuración de conexión sigue disponible después de la configuración inicial.
4. En **Conectar Telegram**, escanee el código QR o introduzca su número de teléfono. La importación de archivos y la clave de autenticación completa están en **Otros métodos de inicio de sesión**. Complete la confirmación de Telegram, el código y la contraseña de verificación en dos pasos cuando se le soliciten.
5. Compruebe la cuenta mostrada, elija los chats y revise la configuración. Termine desde la pantalla final. Con **Solo descargar**, **Iniciar exportación** inicia una exportación única y abre Exportaciones para mostrar su progreso; no activa la observación continua.

Tras la configuración, **Chats → Seleccione** cambia los chats seleccionados. **Configuración** controla la recopilación y los archivos; **Más herramientas → Fuentes** ofrece la lista detallada de fuentes en el nivel Estándar o Experto. La [guía del panel](../PANEL.md) describe las seis secciones principales y sus controles contextuales.

**ID de la API + Hash** es opcional: el espacio de trabajo usa su par guardado o importado, o un par operativo del conjunto integrado. Para usar su propia aplicación, pegue un par `API ID:API Hash` en ID de la API. Para **Clave de autenticación**, pegue los 512 caracteres hexadecimales y seleccione el DC ID que se le proporcionó. El ID de usuario es opcional y, si se introduce, se comprueba.

Las credenciales de la API identifican su aplicación; por sí solas no autorizan una cuenta. Los grupos privados no necesitan un nombre de usuario público, pero su cuenta debe tener acceso.

Para cuentas existentes, consulte [cuentas y formatos de sesión](../ACCOUNTS.md): el panel acepta Telethon StringSession, Telethon/Pyrogram SQLite, TData ZIP de una sola cuenta y JSON de cuenta compatibles. Seleccione juntos una sesión y su JSON complementario y pulse **Conectar cuenta**. El inicio de sesión con QR también está disponible con los mismos ajustes opcionales de la API. No se admiten TDLib, las sesiones de bots ni los inventarios de cuentas en CSV/JSON.

Para varias cuentas, use **Cuentas → Importar cuentas** y seleccione sus archivos de sesión compatibles. Los JSON complementarios se emparejan por nombre base; cada cuenta importada obtiene su propio espacio de trabajo. Consulte [importación masiva y grupos de cuentas](../ACCOUNTS.md#bulk-import-and-account-groups).

Para añadir otra cuenta, pulse **+** junto al selector de cuentas o use **Cuentas → Añadir cuenta**. Los espacios de trabajo tienen sesiones, diarios, claves, fuentes y colas separados. Cambiar de vista deja en marcha los demás recopiladores. La misma cuenta de Telegram no puede asignarse a dos espacios de trabajo en esta instalación. No hay un número fijo de espacios de trabajo; comparten un mismo proceso, así que la capacidad depende del equipo.

El token del panel de la instalación real protege el acceso a sus autorizaciones de Telegram y al material guardado; es independiente de las credenciales de la API de Telegram. Solo una demo local iniciada explícitamente y a la que se accede directamente obtiene entrada automática. Una demo remota o detrás de un proxy sigue usando `data/demo/panel-token.txt`.

## Revisión y exportación

- **Registro:** busque y filtre las observaciones por fuente y tipo de evento.
- Seleccione un evento para inspeccionar su entrada original, la atribución y las versiones guardadas.
- Los detalles de una edición muestran el contenido disponible antes y después. Los detalles de una eliminación muestran el último contenido capturado, si lo hay; un autor desconocido sigue siendo desconocido.
- **Exportaciones:** ZIP firmado, JSONL, CSV y HTML sin conexión.
- **Exportación completa de chats** (**Chats → Exportar chat** o **Exportaciones → Capturar o exportar un chat**): descargue todo el historial visible de un chat como paquete firmado con `chat.json` (al estilo de la exportación de Telegram) y un `chat.html` legible. Los chats privados funcionan si la cuenta es miembro. Es una instantánea actual, no una reconstrucción de mensajes eliminados o editados anteriormente. Verifique una copia con `python verify.py chat-export.zip --fingerprint TRUSTED_SHA256`.
- **Guardar punto de control:** conserve el límite firmado del diario fuera del recopilador.
- **Descargar el recibo de ejecución firmado:** conserve la constancia del programa y la versión del recopilador.
- **Preparar solicitud de marca de tiempo:** prepare una solicitud sin conexión para una autoridad de sellado de tiempo; siga [TIMESTAMP.md](../TIMESTAMP.md) para obtener y verificar una respuesta.
- **Verificar el registro:** compruebe las firmas de los eventos y los enlaces de la cadena. La exportación ZIP también comprueba los archivos multimedia.

Los navegadores compatibles guardan las exportaciones grandes directamente en el archivo que elija. Otros navegadores almacenan en búfer como máximo 128 MiB. Mientras el servidor está en ejecución, la CLI de streaming permite descargas más grandes sin almacenar en búfer toda la respuesta:

```sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
```

Para otro espacio de trabajo, añada `--profile ID` con el valor de **Exportaciones → ID del espacio de trabajo**. Para un servidor remoto, añada `--url https://your-server`. El límite de transferencia predeterminado es de 5 GiB; `--max-mib` lo cambia. El contenido de un ZIP firmado tiene por defecto un límite de verificación aparte de 4 GiB sin comprimir (**Más herramientas → Parámetros** lo aumenta; verifique esos archivos con `verify.py --max-gib N`). Verifique el archivo con una copia de confianza del verificador, una huella de la clave conservada de forma independiente y, para el mínimo probatorio, el certificado raíz de la autoridad de sellado de tiempo (`--tsa-ca`).

## Comprobación de la instalación

```sh
python start.py --setup-only
python start.py --check
python start.py --check --json
```

`--check` comprueba las dependencias locales, la compatibilidad con firmas, el almacenamiento, la configuración de claves y la dirección de escucha. No instala nada ni se conecta a Telegram. Si el puerto está ocupado, puede que haya otra instancia en ejecución. Use otro `--port` o deténgala primero.

El lanzador instala en `.venv`. Los comandos auxiliares `python -m tgwitness...` deben usar `.venv\Scripts\python.exe` en Windows o `.venv/bin/python` en Linux/macOS, salvo que ese entorno ya esté activado.

## Sesiones, protección y funcionamiento

Un archivo `.session` de Telethon SQLite cerrado y coherente puede convertirse localmente con `python -m tgwitness.sessions account.session --out account.tgwitness-session` y cargarse después en **Más herramientas → Cuenta → Archivos**. También están disponibles la importación directa de archivos y el inicio de sesión con QR. Consulte [CONNECTION-SECURITY.md](../CONNECTION-SECURITY.md) para los formatos de inicio de sesión, SOCKS5, HTTP CONNECT, MTProxy y las claves maestras externas.

**Pausar la observación** detiene la recopilación. **Bloquear** solo cierra el acceso desde el navegador. Cerrar una pestaña deja en ejecución el proceso del recopilador. Detener el proceso interrumpe la recopilación; una instantánea del historial no puede reconstruir todas las ediciones o eliminaciones perdidas. Consulte [cómo funciona la recopilación](../COLLECTION.md) para las políticas de eventos, las colas de archivos adjuntos, el aislamiento de cuentas y el comportamiento al reiniciar.

Las sesiones y los secretos están cifrados. El contenido de los mensajes, los archivos multimedia y las exportaciones requieren un disco o volumen cifrado. Verifique las firmas del diario con una clave de confianza y conserve los puntos de control por separado. Revise los registros de captura, los comprobantes de tiempo externos y las atestaciones del entorno del modo de recopilación seleccionado.

Consulte [OPERATIONS.md](../OPERATIONS.md) para copias de seguridad y restauración, [DEPLOYMENT.md](DEPLOYMENT.md) para el alojamiento y [deploy/](../../deploy/README.md) para ejemplos de servicios. El panel instalado también incluye una guía de configuración sin conexión en `/guide.html`.

La verificación realizada y los límites que persisten se documentan en [VERIFICATION.md](../VERIFICATION.md) y [READINESS.md](../internal/READINESS.md).
