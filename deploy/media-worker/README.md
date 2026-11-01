# Media decoder boundary

The optional worker accepts one attachment in a networkless, unprivileged
container. Its root and input mounts are read-only; the caller limits memory,
CPU, processes, output and wall time. Native decoders still process untrusted
bytes, so these container restrictions remain necessary.

Transcription decodes once to mono 16 kHz samples before loading Whisper. The
worker checks both reported duration and actual decoded sample counts. A forged
short duration cannot authorize an arbitrarily long decoded recording. Samples
are checked before each NumPy conversion or PCM buffer append; the final buffers
are at most 57.6 MB of signed 16-bit PCM and 115.2 MB of float32 audio. Native
decoder allocations remain subject to the container's 2 GiB memory limit.

Supported demuxers are AAC, AIFF, AMR, ASF, AVI, FLAC, FLV, Matroska/WebM,
MOV/MP4/M4A/3GP, MP3, MPEG, MPEG-TS, Ogg, WAV and W64. Telegram Ogg/Opus voice
messages, MP3/M4A audio and MP4 round videos are covered by generated fixtures.
Only the first audio stream is decoded. Files with more than eight streams,
more than eight audio channels, sample rates above 192 kHz, frames longer than
ten seconds, or more than thirty minutes of decoded audio are rejected.

HLS, DASH, concat playlists, devices and image-sequence demuxers are excluded.
The decoder receives an already-open input stream and rejects secondary opens;
referenced files and URLs are not part of the selected attachment. Decoder
errors and flagged corrupt packets fail the job instead of silently skipping
frames. Some mutations are valid media, so the regression corpus distinguishes
rejections from successful, bounded decodes.

Run `python tools/check_media_worker.py` on Linux after building the image and
setting `TGWITNESS_MEDIA_IMAGE`. It runs the native decoder regression harness
inside the restricted image, then performs real OCR on a generated image. The
harness needs only the image's pinned PyAV and NumPy packages; no Whisper model,
Telegram account or network service is used. It demonstrates the old duration
precheck accepting forged FLAC metadata and the old demuxer following a local
concat reference before checking that the worker rejects both.

These controls reduce decoding exposure. They do not remove installed Debian
packages, fix every native parser vulnerability, or change the container
scanner's unresolved findings.
