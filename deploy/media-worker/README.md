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

Install `espeak-ng` on the Linux test host, build the image, and set
`TGWITNESS_MEDIA_IMAGE`. Prepare the small English test model outside the source
tree with `python tools/prepare_media_test_model.py --output /path/to/test-model`,
then set `TGWITNESS_WHISPER_MODEL_DIR` to that directory and run
`python tools/check_media_worker.py`. Preparation downloads 78.1 MB from the
fixed Systran `faster-whisper-tiny.en` revision recorded in the helper and verifies
all four file sizes and SHA-256 hashes. The model is MIT licensed; its source and
the original Whisper license are linked in the preparation receipt.

The check runs the native decoder regression harness, real English and Russian
OCR on generated images, and real ASR on speech generated locally by espeak-ng.
Each worker runs without network access, with read-only input and model mounts.
The checks verify recognized text, engine/model identifiers and unchanged input
bytes. Missing models or a missing speech generator fail the check. The decoder
harness also exercises forged FLAC duration and forbidden secondary references.

Container vulnerability scans remain separate release checks. These functional
tests establish that the restricted worker can decode and recognize the
synthetic fixtures with the installed libraries and models.
