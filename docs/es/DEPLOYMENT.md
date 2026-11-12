[TgWitness](../../README.md) / [Documentación](../README.md) / [Carpeta](README.md)

![Despliegue y recuperación](../assets/presentation/chapter-operate.svg)

[English](../DEPLOYMENT.md) · [Русский](../ru/DEPLOYMENT.md) · [Українська](../uk/DEPLOYMENT.md) · **Español** · [Português (Brasil)](../pt/DEPLOYMENT.md) · [Türkçe](../tr/DEPLOYMENT.md) · [العربية](../ar/DEPLOYMENT.md) · [فارسی](../fa/DEPLOYMENT.md) · [اردو](../ur/DEPLOYMENT.md) · [हिन्दी](../hi/DEPLOYMENT.md) · [Bahasa Indonesia](../id/DEPLOYMENT.md) · [Tiếng Việt](../vi/DEPLOYMENT.md) · [简体中文](../zh/DEPLOYMENT.md)

# Despliegue y operación

## Elección de la instalación

Para el paquete portátil, extraiga `TgWitness-<version>-windows-amd64-portable.zip` de GitHub Releases. Para los demás métodos, descargue y extraiga el ZIP del código fuente o clone el repositorio y, después, ejecute lo siguiente desde el directorio del proyecto:

| Instalación | Inicio | ¿Se ejecuta en segundo plano? |
| --- | --- | --- |
| Paquete portátil para Windows | `TgWitness.cmd` | No; mantenga la ventana abierta. |
| Windows nativo | `Start.cmd` | No; para el uso en segundo plano, use la tarea opcional de inicio de sesión. |
| Linux/macOS nativo | `sh start.sh` | No; para el uso en segundo plano, use systemd/launchd. |
| Docker en cualquier sistema compatible | `docker compose up -d --build --wait` | Sí, mientras el daemon de Docker esté en ejecución. |
| Script auxiliar de Docker en Windows | `scripts\Docker.cmd` | Sí; el script espera a que el servidor web esté en buen estado. |
| Script auxiliar de Docker en Linux/macOS | `sh scripts/docker-start.sh` | Sí; el script espera a que el servidor web esté en buen estado. |

Para un servidor en la nube que un tercero deba poder comprobar —creado mediante la API del proveedor, sin SSH y accesible solo a través de un Cloudflare Tunnel—, consulte [despliegue de alta garantía](../HIGH-ASSURANCE.md).

El inicio nativo crea un `.venv` privado e instala las dependencias fijadas. Docker las instala al construir la imagen, sin requerir Python en el equipo anfitrión. La primera configuración necesita acceso a Internet. Si no se encuentra Python 3.11+, `Start.cmd` pregunta antes de instalar Python 3.12 para el usuario actual de Windows (con winget o, si no, con el instalador de python.org tras comprobar su firma de la Python Software Foundation); nunca solicita privilegios de administrador. Docker y los servicios del sistema operativo siguen siendo requisitos previos.

Las instalaciones nativas y portátiles usan `data/live` dentro de su carpeta. Docker usa el volumen con nombre `tgwitness-data` en `/data`. Son instalaciones separadas hasta que migre deliberadamente el directorio de datos completo. No espere que un contenedor Docker nuevo descubra automáticamente las cuentas nativas.

## Requisitos de instalación

La instalación nativa necesita Python 3.11 o posterior con `venv` y `ensurepip`, acceso a Internet para la primera instalación de dependencias y un directorio de proyecto con permiso de escritura para `.venv`. El panel incluido no necesita Node.js ni compilación del frontend. Ejecute el lanzador desde su cuenta habitual del sistema operativo; TgWitness no requiere privilegios de administrador ni de root.

- **Windows:** `Start.cmd` comprueba `py -3`, después `python` y luego las carpetas de instalación predeterminadas por usuario y de Program Files, y requiere la versión 3.11 o posterior. Si ninguna funciona, ofrece la instalación automática por usuario descrita arriba. `py -3 start.py` también funciona. El paquete portátil no necesita Python en absoluto.
- **Linux:** `start.sh` prueba `python3.13`, `python3.12`, `python3.11`, `python3` y `python` y, si ninguno cumple los requisitos, muestra el comando de instalación para apt, dnf, pacman, zypper, apk o Homebrew. Las instalaciones en Debian/Ubuntu pueden requerir el paquete `python3-venv` correspondiente al intérprete seleccionado. Si el Python predeterminado de la distribución es más antiguo, debe sustituirse o complementarse con Python 3.11+.
- **macOS:** instale una distribución actual de Python 3.11+; no dé por hecho que el intérprete que incluye el sistema operativo cumple el requisito. Use `python3 start.py` desde el directorio del proyecto.
- **Docker:** use Docker Engine/Desktop con Compose v2.20 o posterior. En Windows, Docker Desktop debe usar contenedores Linux. El contenedor instala sus propias dependencias de Python; el equipo anfitrión no necesita una instalación de Python aparte.

## Equipo local

Use `Start.cmd` en Windows o `sh start.sh` en Linux/macOS. `scripts\Setup.cmd` o `sh start.sh --setup-only` prepara el entorno. El lanzador instala las dependencias en el primer uso; los inicios posteriores reutilizan el entorno. Se necesita acceso a Internet para la configuración y la recopilación de Telegram, pero consultar los registros existentes y crear exportaciones funciona sin conexión.

Ejecute `python start.py --check` tras la configuración para inspeccionar las dependencias locales, Ed25519, el almacenamiento, la configuración de claves y la dirección de escucha sin iniciar un recopilador. Use `--json` para obtener una salida estructurada. Indique los `--data-dir`, `--host` y `--port` que piensa usar. La comprobación no instala paquetes, no crea un diario ni se conecta a Telegram; no es una cualificación de integridad ni de cobertura. El inicio verifica por separado los diarios existentes. `python start.py --help` tampoco instala nada.

Tras usar start.py, ejecute los comandos auxiliares con `.venv\Scripts\python.exe` en Windows o `.venv/bin/python` en Linux/macOS, o active antes ese entorno. Los ejemplos `python -m ...` siguientes suponen que el entorno está activo.

~~~sh
python -m tgwitness --data-dir /path/to/private/data --host 127.0.0.1 --port 8787
~~~

Variables de entorno: TGWITNESS_DATA, TGWITNESS_HOST, TGWITNESS_PORT, TGWITNESS_TOKEN. TGWITNESS_VAULT_KEY_FILE selecciona el modo de clave externa para una instalación nueva; véase [Clave maestra externa](../SECURITY-MODEL.md#external-master-key). Si se proporciona TGWITNESS_TOKEN, debe tener al menos 24 caracteres; use un valor aleatorio criptográficamente seguro. Sin él, la aplicación genera un token aleatorio de 256 bits en panel-token.txt. El valor de la variable de entorno no reescribe ese archivo. Reinicie para rotar las credenciales.

Un directorio de datos solo puede pertenecer a un proceso. Un bloqueo de archivos multiplataforma del sistema operativo impide escrituras simultáneas accidentales. Use un solo worker de Uvicorn. El panel puede gestionar cualquier número de espacios de trabajo, con directorios adicionales para cada espacio de trabajo en profiles/<id>/. Para instancias de servicio separadas, use directorios y puertos distintos. Los archivos WAL de SQLite deben estar en almacenamiento persistente local, no en un sistema de archivos de red. No comparta un volumen entre réplicas.

## Paquete portátil para Windows

Cada versión publicada en GitHub incluye `TgWitness-<version>-windows-amd64-portable.zip` y su `.sha256`. Contiene el entorno de ejecución integrable oficial de Python 3.12 de python.org (suma de comprobación fijada en `tools/build_portable.py`), TgWitness con sus dependencias fijadas y tres lanzadores:

| Archivo | Finalidad |
| --- | --- |
| `TgWitness.cmd` | Inicia el panel; las opciones adicionales se transmiten, p. ej., `TgWitness.cmd --port 8790` |
| `TgWitness-Demo.cmd` | Inicia la demo sintética en `data\demo` |
| `TgWitness-Check.cmd` | Ejecuta la comprobación de preparación sin iniciar |

El diccionario de morfología rusa fijado y los perfiles de color PDF se incluyen para el uso sin conexión. El empaquetado solo permite sus rutas de archivo conocidas dentro de los directorios `data` de las dependencias; cualquier archivo inesperado en esos directorios hace fallar la compilación.

Extraiga el archivo completo en una carpeta con permiso de escritura, como `Documents\TgWitness`; no lo ejecute desde dentro del ZIP ni desde Program Files. El entorno de ejecución usa una ruta de módulos aislada, por lo que otras instalaciones de Python y `PYTHONPATH` no lo afectan. Los datos permanecen en la carpeta `data` del paquete. Para actualizar, detenga TgWitness, extraiga la nueva versión en una carpeta nueva y copie allí la carpeta `data`.

Compílelo usted mismo en Windows de 64 bits con Python 3.12:

~~~sh
python tools/build_portable.py
~~~

## Contenedor

```sh
docker compose up -d --build --wait
```

Esto crea un volumen persistente con nombre para /data. El puerto web se asigna a 127.0.0.1:8787. El proceso se ejecuta como UID 10001 con las capabilities de Linux eliminadas, un sistema de archivos raíz de solo lectura y /data y /tmp con permiso de escritura. `--wait` comprueba el estado del servidor web antes de terminar; la autorización de Telegram y la entrega se muestran en el panel. Los scripts auxiliares incluidos usan un tiempo de espera de preparación de 180 segundos tras la compilación. Las descargas iniciales de dependencias pueden tardar más.

Ambos archivos Compose base usan el nombre de proyecto `tgwitness`, de modo que extraer una versión nueva en otro directorio no selecciona en silencio un volumen de datos nuevo. Mantenga activo un solo despliegue para ese proyecto. Para instalaciones independientes, use un `docker compose -p NAME ...` único y un puerto de host distinto, y conserve ambos en las actualizaciones. Para un despliegue antiguo con otro nombre de proyecto, siga usando su nombre original con `-p`; `docker compose ls` muestra los proyectos existentes.

Copie `deploy/env.example` en `.env` y cambie `TGWITNESS_PORT` para usar otro puerto de loopback. Por ejemplo, `TGWITNESS_PORT=8788` expone el panel en `http://127.0.0.1:8788`; el contenedor sigue escuchando en 8787. Git ignora `.env`.

Obtenga el token inicial:

~~~sh
docker compose exec tgwitness cat /data/panel-token.txt
~~~

Comandos útiles:

```sh
docker compose ps
docker compose logs --tail 100 -f
docker compose stop
docker compose up -d --wait
```

`restart: unless-stopped` reinicia el recopilador tras un fallo o un reinicio del daemon de Docker. En un servidor Linux, habilite el arranque de Docker con el gestor de servicios de su distribución, normalmente `sudo systemctl enable --now docker`. En Windows/macOS, active el ajuste de Docker Desktop para iniciarse al iniciar sesión. Cerrar la sesión del escritorio, la suspensión o un daemon de Docker detenido pueden interrumpir la recopilación. Un contenedor detenido explícitamente permanece detenido hasta que vuelva a iniciarlo.

En la configuración de ejemplo, el volumen /tmp está limitado a 512 MiB. La creación de exportaciones usa en su lugar el directorio `temporary-exports/` de cada espacio de trabajo en el /data persistente. Reserve allí espacio para exportaciones simultáneas, el crecimiento del diario/WAL, archivos multimedia y copias de seguridad. El lanzador usa deploy/constraints.txt para fijar versiones cualificadas de las dependencias de ejecución. Docker y los servidores de alta garantía instalan desde deploy/requirements.lock y deploy/build.lock con pip --require-hashes: cada archivo de paquete debe coincidir con un SHA-256 registrado en el commit, de modo que se rechaza un archivo sustituido en PyPI o en un espejo. La imagen base de Python y los paquetes del sistema operativo siguen requiriendo una cualificación independiente de la versión.

No use docker compose down -v a menos que quiera destruir el diario y las claves. El estado de salud del contenedor indica la disponibilidad del servidor web, no que la captura de Telegram funcione. Revise en el panel el estado del recopilador, la señal de actividad, los errores y los eventos de cobertura.

### Perfil de testigo independiente

El servicio opcional `witness` ejecuta un [testigo independiente](../WITNESS.md) en su propio contenedor, con su propia clave y su propio diario en el volumen `witness-data`, y para el recopilador solo dispone de un token de testigo de solo lectura. Cree el token en el panel en **Más herramientas → Extras → Testigo independiente**, añádalo a `.env` junto con un token de bot y un canal y, después, inicie el perfil:

```sh
docker compose --profile witness up -d          # deploy/compose/compose.image.yaml: same flag
docker compose logs witness                     # witness key fingerprint
```

El servicio accede al recopilador dentro de la red de Compose en `http://tgwitness:8787` (`TGWITNESS_WITNESS_COLLECTOR` lo sustituye, por ejemplo por `/profiles/<workspace ID>` para otro espacio de trabajo). Para un testigo en un servidor aparte gestionado por otra persona, use allí `deploy/compose/compose.witness.yaml` con `TGWITNESS_WITNESS_COLLECTOR` configurado con la dirección HTTPS del recopilador; ese archivo solo contiene el testigo.

## Instalación de una imagen publicada

Copie `deploy/env.example` en `.env`. Establezca `TGWITNESS_IMAGE` en la versión publicada usando la ruta del repositorio **en minúsculas**, por ejemplo:

```dotenv
TGWITNESS_IMAGE=ghcr.io/your-owner/your-repository:0.9.3
TGWITNESS_PORT=8787
```

Ejecute este archivo por sí solo, en lugar de `compose.yaml`:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
docker compose --project-directory . -f deploy/compose/compose.image.yaml exec tgwitness cat /data/panel-token.txt
```

En el equipo anfitrión no se necesita compilar el código fuente, ni Python, ni un compilador. El flujo de trabajo de publicación está orientado a contenedores Linux AMD64 y ARM64, incluida la máquina virtual Linux de Docker Desktop. Use una etiqueta de versión o `ghcr.io/owner/repository@sha256:...` del resumen del flujo de trabajo. No se configura ninguna etiqueta móvil `latest` ni actualizaciones desatendidas de la aplicación. Las variantes de imagen y de código fuente usan el mismo volumen de datos cuando coincide el nombre del proyecto.

<a name="automatic-https-on-a-server"></a>

## HTTPS automático en un servidor

Use un servidor con Docker, un dominio que controle y almacenamiento local persistente. Apunte los registros A/AAAA del dominio al servidor; publique AAAA solo si el servidor es accesible por IPv6. Permita TCP 80 y 443 entrantes y DNS/HTTPS salientes para la emisión del certificado. Ningún otro servicio debe ocupar ya esos puertos.

Copie `deploy/env.example` en `.env` y establezca un nombre de host, sin esquema ni ruta:

```dotenv
TGWITNESS_DOMAIN=watch.your-domain.org
```

Inicie la compilación desde el código fuente con la superposición HTTPS:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml up -d --build --wait
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml exec tgwitness cat /data/panel-token.txt
```

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml -f deploy/compose/compose.https.yaml up -d --wait
```

Para una imagen publicada, use en su lugar `deploy/compose/compose.image.yaml` como primer archivo. Mantenga ambos argumentos `-f` en los comandos posteriores de estado, logs, actualización y detención.

Caddy obtiene y renueva un certificado, redirige HTTP a HTTPS y reenvía las solicitudes al recopilador por la red privada de Compose. El estado del certificado tiene su propio volumen persistente. El puerto directo del recopilador en el host sigue limitado a loopback. La configuración de Caddy incluida no activa el registro de accesos.

Abra `https://watch.your-domain.org` e introduzca el token del panel. La preparación de Compose abarca los contenedores; la emisión del certificado y la accesibilidad desde fuera dependen del DNS y del cortafuegos. Si HTTPS no está listo, revise el DNS, las reglas del cortafuegos y:

```sh
docker compose -f compose.yaml -f deploy/compose/compose.https.yaml logs --tail 100 caddy
```

La imagen de Caddy incluida sigue su etiqueta `2-alpine`. Hacer pull actualiza esa imagen; fije un digest probado en su despliegue si necesita versiones de infraestructura fijas.

## Actualizaciones y copias de seguridad

Conserve el nombre del proyecto Compose y el volumen de datos entre actualizaciones. Primero detenga el recopilador y haga una copia de seguridad completa. Para el despliegue predeterminado basado en el código fuente:

```sh
docker compose stop
docker compose cp tgwitness:/data ../tgwitness-backup-before-update
```

Use cada vez un destino de copia de seguridad nuevo, fuera del repositorio, y protéjalo como material que da acceso a las cuentas. La ruta de ejemplo es ilustrativa; use su ubicación privada de copias de seguridad. Copie el directorio completo, incluidos los archivos ocultos, todos los espacios de trabajo, las claves, los diarios y los archivos multimedia. Si hay configurada una clave maestra externa de la bóveda, haga una copia de seguridad de ella por separado. Un ZIP de pruebas no es una copia de seguridad restaurable de la aplicación. Con HTTPS, conserve también los volúmenes de Caddy si necesita mantener su estado de certificado y cuenta.

Para un despliegue desde el código fuente, obtenga los archivos de la nueva versión y ejecute:

```sh
docker compose up -d --build --wait
```

Para un despliegue con imagen, cambie `TGWITNESS_IMAGE` a la versión deseada y ejecute:

```sh
docker compose --project-directory . -f deploy/compose/compose.image.yaml pull
docker compose --project-directory . -f deploy/compose/compose.image.yaml up -d --wait
```

Use también los archivos Compose de su instalación para los comandos anteriores de detención y copia. Conserve `.env`, la configuración personalizada y el mismo nombre de proyecto. `down` conserva los volúmenes con nombre; **`down -v` los elimina**. No copie `.venv` entre sistemas operativos ni entre versiones de Python. Para actualizaciones nativas, detenga TgWitness, haga una copia de seguridad de su directorio de datos completo, sustituya los archivos del código fuente y ejecute `python start.py --setup-only` antes de iniciarlo.

Tras una actualización, compruebe el acceso al panel, la identidad de la cuenta, el estado de la observación y la cobertura. Tras el reinicio, TgWitness reanuda desde la posición de actualizaciones de Telegram guardada y solicita las actualizaciones de Telegram perdidas mientras se actualizaba la aplicación. Una reversión puede requerir la copia de seguridad previa a la actualización si una versión futura cambia los formatos de almacenamiento.

## Servidor remoto

Mantenga el servicio vinculado a loopback y use un túnel SSH, o termine HTTPS en un proxy inverso. El archivo Compose base es solo local; la superposición opcional `deploy/compose/compose.https.yaml` aporta Caddy para un dominio configurado. Mantenga el token bearer fuera de las URL y de los logs del proxy. Un proxy inverso debe limitar el tamaño de las solicitudes y la frecuencia de conexiones. No exponga HTTP sin cifrar a Internet.

En [deploy/](../../deploy/README.md) se incluyen ejemplos para systemd, una tarea de inicio de sesión de Windows, un agente de usuario de macOS y Caddy. Revise y adapte sus rutas antes de instalarlos. Son plantillas incluidas, no cualificaciones de plataforma ejecutadas localmente. El lanzador normal no registra ningún servicio ni tarea en segundo plano.

En Windows, un inicio sin ventana con `pythonw.exe` guarda los diagnósticos de arranque y del servidor en `logs/server.log`, dentro del directorio de datos (5 MiB por archivo, dos copias rotadas). Los inicios desde la consola mantienen el registro en la consola. El registro de acceso HTTP está desactivado en ambos modos. Proteja los logs junto con el directorio de datos y revíselos antes de compartirlos.

## Reinicio y lagunas

Se conserva el último estado de observación solicitado. Si la observación estaba activa, al iniciar se intenta volver a conectar y reanudar las fuentes seleccionadas. La pausa manual anula esa intención. Un reinicio fallido se registra y se muestra en el panel.

TgWitness guarda la posición de actualizaciones de Telegram de la cuenta y de cada canal (pts, qts, seq y date) en la bóveda del espacio de trabajo y la restaura en el siguiente inicio. Después, el cliente solicita las actualizaciones perdidas mientras el proceso estaba detenido, y la revisión periódica recupera los mensajes perdidos y registra los guardados que Telegram ya no devuelve. Los diálogos se recargan al iniciar. Cada inicio registra el encabezado anterior del diario, el límite del periodo sin conexión y la posición de actualizaciones desde la que se reanudó. El monitor comprueba la conectividad cada 10 segundos y añade una señal de actividad cada minuto (**Más herramientas → Parámetros → Registro de actividad cada**). Las desconexiones y los periodos de silencio se registran como lagunas de cobertura con su motivo. Las instantáneas del historial se guardan como observaciones separadas del historial actual junto a los registros en directo.

La cola de archivos multimedia se guarda en la base de datos SQLite de cada espacio de trabajo. Un mensaje y su tarea se confirman de forma atómica. Las tareas en ejecución interrumpidas se recuperan al iniciar para reintentarlas. Cada descarga tiene un tiempo de espera base de 120 segundos más el tiempo correspondiente a su tamaño a 256 KiB/s, y un límite de 1–2000 MiB por tipo de archivo adjunto; el tiempo de espera, la velocidad y los reintentos están en **Más herramientas → Parámetros**. El recopilador omite los archivos de tamaño desconocido. La pausa conserva el trabajo en cola. El reintento usa el descriptor de archivo original observado, nunca la última versión de un mensaje editado después. Los fallos temporales tienen reintentos limitados; las pausas FloodWait de multimedia sobreviven al reinicio. La recuperación de multimedia es independiente de la recuperación de actualizaciones de Telegram y no puede recrear archivos desaparecidos.

## Copia de seguridad, restauración y capacidad

Detenga el proceso antes de copiar **todo el directorio de datos**, incluidos vault.key, signing.enc, credentials.enc, los archivos de base de datos SQLite/WAL, los archivos multimedia, el token, los puntos de control y todos los subdirectorios de profiles/. Restaure la copia completa con el servicio de destino detenido. Si faltan claves de la bóveda o la clave de firma no coincide, el inicio falla; no regenere claves para forzar el acceso.

Mantenga cifradas y con acceso controlado las copias de seguridad que contienen secretos. Los ZIP de pruebas son artefactos portátiles de revisión, no copias de seguridad de la aplicación ni de sesiones de Telegram. No hay eliminación automática por retención. Planifique espacio en disco para todos los mensajes, metadatos sin procesar, archivos multimedia, exportaciones temporales y copias de seguridad.

La verificación al iniciar y la exportación procesan los registros en flujo, sin cargar todo el diario. Una exportación fija una instantánea de lectura mientras pueden continuar nuevas escrituras en el WAL; las exportaciones largas pueden retener páginas del WAL, así que la capacidad del disco sigue importando. Los ZIP están limitados a 4 GiB sin comprimir para coincidir con el valor predeterminado del verificador independiente; **Más herramientas → Parámetros → El archivo ZIP firmado más grande** aumenta el límite, y esos archivos se verifican con `verify.py --max-gib N`. Los demás formatos no tienen límite de número de eventos. Los navegadores compatibles transmiten los fragmentos de la respuesta a un archivo elegido por el usuario. Otros navegadores almacenan en búfer como máximo 128 MiB y remiten las transferencias más grandes a la CLI autenticada:

~~~sh
python -m tgwitness.download --token-file data/live/panel-token.txt --out evidence.zip
~~~

Use `--profile ID` de **Exportaciones → ID del espacio de trabajo** para otro espacio de trabajo, `--format zip|jsonl|csv|html`, `--url https://your-server` para un servidor remoto o `--max-mib` para cambiar el límite de transferencia de 5 GiB. El HTTP sin cifrar solo se permite para loopback. Los tokens viajan en cabeceras, las redirecciones se rechazan, los archivos existentes no se sobrescriben y las descargas incompletas no se publican como archivos terminados. Si TGWITNESS_TOKEN sustituye el token generado, use un archivo protegido por separado que contenga ese valor activo: la sustitución no reescribe panel-token.txt. El SHA-256 del comando es solo una suma de comprobación de la transferencia; verifique el ZIP firmado de forma independiente.

El panel muestra los archivos multimedia en cola o fallidos, el archivo multimedia pendiente más antiguo, el espacio libre en disco, las pausas de solicitudes de Telegram y las fuentes cuyo acceso no está confirmado. Estos diagnósticos no son una supervisión completa de la entrega de extremo a extremo. Los espacios de trabajo comparten un proceso; una cuenta muy activa aún puede afectar a las demás. Quedan pendientes los procesos de trabajo separados, la retención/rotación, la recuperación duradera de actualizaciones y la cualificación completa del despliegue. El acceso al panel con alcance limitado se documenta en [acceso y permisos](../ACCESS.md); los puntos de control independientes se tratan en la [guía del testigo](../WITNESS.md).

Procedimientos detallados: [conexión/seguridad](../CONNECTION-SECURITY.md) y [modos de funcionamiento](../OPERATIONS.md).
