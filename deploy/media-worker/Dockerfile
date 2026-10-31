FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-rus \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir 'pillow>=13,<14' 'faster-whisper>=1.2,<2'
COPY deploy/media-worker/worker.py /worker.py
USER 65534:65534
ENTRYPOINT ["python", "/worker.py"]
