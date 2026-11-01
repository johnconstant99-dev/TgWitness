# Local OCR and transcription

[Workflow guide](https://phishdestroy.github.io/TgWitness/docs/archive/) · [Wiki](wiki/Archive-and-Integrations.md)

Open a `media.saved` journal record, choose **Recognize attachment**, then select
OCR or transcription under **Ask the archive**. Processing is manual and local.
There is no cloud media mode or automatic upload. Original attachment bytes and
`media_sha256` remain unchanged; recognized text is explicitly marked as machine
recognition and stored separately with the source hash, engine/model version,
language, parameters and completion time. Transcripts retain returned timestamps.

Search these results using **Search recognized text** and the OCR/transcript
filter. This is a separate derived-data search; it does not silently turn machine
recognition into original Telegram text or add it to signed events.

## Set up the optional worker

Version 1 requires a Linux host with a local Docker daemon. Windows installations
can run TgWitness inside a Linux VM/WSL environment with its own local daemon.
The panel never decodes an untrusted attachment itself.

```sh
docker build -f deploy/media-worker/Dockerfile -t tgwitness-media:local .
export TGWITNESS_MEDIA_IMAGE=tgwitness-media:local
```

Set these variables in the TgWitness service environment and restart it. The
daemon socket defaults to `/var/run/docker.sock`; rootless deployments can set
`TGWITNESS_DOCKER_SOCKET`. The worker explicitly uses that Unix socket rather
than a remote Docker context. Do not expose a Docker API to panel users or mount
its socket inside the recognition container.

For transcription, separately install a CTranslate2-compatible Whisper model,
then set `TGWITNESS_WHISPER_MODEL_DIR` to its directory. The worker loads it with
`local_files_only=True`; the selected model and input are mounted read-only.
See the engine's [model-loading documentation](https://github.com/SYSTRAN/faster-whisper).
The supplied OCR image includes English and Russian trained data. Build another
language into your image when needed; language codes follow
[Tesseract's CLI](https://tesseract-ocr.github.io/tessdoc/Command-Line-Usage.html).

No model is fetched while processing. Build/download setup may use the network;
each actual recognition container has networking disabled. Install the image
before enabling it; runtime uses `--pull=never`.

## Bounds and recovery

The container runs as an unprivileged user with a read-only root, dropped
capabilities, `no-new-privileges`, one CPU, 2 GiB memory, a PID limit and a bounded
temporary filesystem. Only a verified copy of the selected file and an optional
model directory are mounted. The collector's database, vault and session are
not mounted. The [Docker runtime flags](https://docs.docker.com/reference/cli/docker/container/run/)
enforce these limits; this remains a container boundary, not a hardware enclave.

Files are limited to 50 MiB, images to 20 million pixels, audio to 30 minutes with
a known duration, and processing to five minutes. One worker runs at a time,
with at most 20 queued/running jobs and 100 retained jobs per workspace.
Cancel stops the container; retry creates a new job linked to the prior attempt.
Interrupted jobs are marked after restart. Processing can fail when a model
cannot fit the configured limits; it does not silently run without isolation.
