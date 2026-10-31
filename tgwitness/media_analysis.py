"""Manual derived OCR/transcription jobs; untrusted decoding runs only in a restricted container."""
import asyncio
import hashlib
import os
from pathlib import Path
import re
import secrets
import shutil
import tempfile
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .access import Refused
from .archive import ArchiveQuery
from .store import utcnow

MAX_FILE = 50 * 1024 * 1024


class MediaJob(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace: str = "default"
    chat_id: int
    event_seq: int = Field(ge=1)
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    engine: Literal["ocr", "transcription"]
    language: str = Field(default="", pattern=r"^[a-z]{0,3}$")


class Segment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: float = Field(ge=0, le=1800)
    end: float = Field(ge=0, le=1800)
    text: str = Field(max_length=100000)

    @model_validator(mode="after")
    def ordered(self):
        if self.end < self.start:
            raise ValueError("The media worker returned an invalid result.")
        return self


class Recognition(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    text: str = Field(max_length=100000)
    engine: str = Field(min_length=1, max_length=80)
    engine_version: str = Field(min_length=1, max_length=160)
    model_version: str = Field(min_length=1, max_length=256)
    language: str = Field(max_length=20)
    segments: list[Segment] = Field(max_length=3000)
    parameters: dict[str, str | float | int | bool] = Field(max_length=20)


def available():
    image = os.environ.get("TGWITNESS_MEDIA_IMAGE", "")
    return bool(image and shutil.which("docker") and os.name == "posix")


def docker():
    return ["docker", "--host", "unix://" + os.environ.get("TGWITNESS_DOCKER_SOCKET", "/var/run/docker.sock")]


def authorize(reader, job):
    state = reader.workspace(ArchiveQuery(tool="get_journal_event", workspace=job.workspace, chat_id=job.chat_id), chat=True)
    event = reader.read(ArchiveQuery(tool="get_journal_event", workspace=job.workspace,
                                    chat_id=job.chat_id, event_seq=job.event_seq))
    if event["media_sha256"] != job.digest or not state.store.media_in_chats(job.digest, {job.chat_id}):
        raise Refused("This attachment is unavailable to the selected chat.")
    path = state.store.root / "media" / job.digest
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_FILE:
        raise ValueError("Choose an available attachment of at most 50 MiB.")
    return state, path, event["source"]


def container_command(name, media, job):
    image = os.environ.get("TGWITNESS_MEDIA_IMAGE", "")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,240}", image):
        raise ValueError("Configure a local media worker image on the server.")
    command = docker() + ["run", "--rm", "--pull=never", "--name", name, "--network=none", "--read-only",
               "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64", "--cpus=1",
               "--memory=2g", "--memory-swap=2g", "--user=65534:65534", "--ulimit=nofile=128:128",
               "--tmpfs=/tmp:rw,noexec,nosuid,size=128m", "-e", "OMP_NUM_THREADS=1",
               "-e", "HF_HUB_OFFLINE=1", "-e", "TRANSFORMERS_OFFLINE=1",
               "--mount", "type=bind,src=" + str(media) + ",dst=/input/media,readonly"]
    if job.engine == "transcription":
        model = Path(os.environ.get("TGWITNESS_WHISPER_MODEL_DIR", "")).resolve()
        if not os.environ.get("TGWITNESS_WHISPER_MODEL_DIR") or not (model / "model.bin").is_file() or "," in str(model):
            raise ValueError("Install a local Whisper model and set TGWITNESS_WHISPER_MODEL_DIR.")
        command += ["--mount", "type=bind,src=" + str(model) + ",dst=/model,readonly"]
    return command + [image, job.engine, job.language]


async def bounded(stream, limit):
    chunks, total = [], 0
    while chunk := await stream.read(16384):
        total += len(chunk)
        if total > limit:
            raise ValueError("The media worker output exceeded its limit.")
        chunks.append(chunk)
    return b"".join(chunks)


async def run_container(path, job, ident):
    if not available():
        raise ValueError("Local media processing requires the configured Linux container worker.")
    name = "tgw-media-" + ident
    with tempfile.TemporaryDirectory(prefix="tgw-media-") as temp:
        media = Path(temp) / "media"
        await asyncio.to_thread(shutil.copyfile, path, media)
        media.chmod(0o444)
        with media.open("rb") as stream:
            digest = await asyncio.to_thread(lambda: hashlib.file_digest(stream, "sha256").hexdigest())
        if digest != job.digest:
            raise ValueError("The stored attachment does not match its saved hash.")
        process = await asyncio.create_subprocess_exec(*container_command(name, media, job),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            async with asyncio.timeout(300):
                output, _ = await asyncio.gather(bounded(process.stdout, 1024 * 1024), bounded(process.stderr, 16384))
                if await process.wait() != 0:
                    raise ValueError("Local media processing failed. Check the worker image, file format and model.")
                try:
                    return Recognition.model_validate_json(output).model_dump()
                except ValueError:
                    raise ValueError("The media worker returned an invalid result.") from None
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
            cleanup = await asyncio.create_subprocess_exec(*docker(), "rm", "-f", name,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            try:
                await asyncio.wait_for(cleanup.wait(), 10)
            except TimeoutError:
                cleanup.kill()
                await cleanup.wait()


class MediaQueue:
    def __init__(self):
        self.slots = asyncio.Semaphore(1)
        self.tasks = {}

    def recover(self, state):
        entries = state.store.get_setting("media_analysis_jobs", [])
        changed = False
        for entry in entries:
            if entry["status"] in ("queued", "running") and entry["id"] not in self.tasks:
                entry.update(status="interrupted", error="Processing stopped before completion.")
                changed = True
        if changed:
            state.store.set_setting("media_analysis_jobs", entries)
        return entries

    @staticmethod
    def update(state, ident, **values):
        entries = state.store.get_setting("media_analysis_jobs", [])
        for entry in entries:
            if entry["id"] == ident:
                entry.update(values)
        state.store.set_setting("media_analysis_jobs", entries)

    def start(self, reader, job, owner, retry_of=None):
        state, path, source = authorize(reader, job)
        if not available():
            raise ValueError("Local media processing requires the configured Linux container worker.")
        entries = self.recover(state)
        if len(self.tasks) >= 20 or len(entries) >= 100:
            raise ValueError("The media processing queue or result limit has been reached.")
        ident = secrets.token_hex(16)
        entry = {"id": ident, "owner": owner, "request": job.model_dump(), "source": source,
                 "created_at": utcnow(), "status": "queued", "error": None, "retry_of": retry_of}
        entries.append(entry)
        state.store.set_setting("media_analysis_jobs", entries)

        async def work():
            try:
                async with self.slots:
                    authorize(reader, job)
                    self.update(state, ident, status="running")
                    result = await run_container(path, job, ident)
                    artifact = {"schema": "tgwitness.media-analysis/1", "id": ident, "media_sha256": job.digest,
                                "source": source, "completed_at": utcnow(), "machine_recognition": True,
                                "processing": "local-container", "limits": {"cpu": 1, "memory_mib": 2048,
                                "timeout_seconds": 300}, **{k: result[k] for k in ("text", "engine", "engine_version",
                                "model_version", "language", "segments", "parameters")}}
                    state.vault.save("media-analysis-" + ident, artifact)
                    self.update(state, ident, status="completed", completed_at=artifact["completed_at"])
            except asyncio.CancelledError:
                self.update(state, ident, status="cancelled")
                raise
            except Exception as exc:
                text = str(exc) if isinstance(exc, (ValueError, Refused)) else "Local processing stopped: " + type(exc).__name__
                self.update(state, ident, status="failed", error=text[:300])
            finally:
                self.tasks.pop(ident, None)
        self.tasks[ident] = asyncio.create_task(work())
        return entry

    async def cancel(self, ident, state):
        task = self.tasks.get(ident)
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.update(state, ident, status="cancelled")
        self.tasks.pop(ident, None)

    async def close(self):
        tasks = list(self.tasks.values())
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.tasks.clear()
