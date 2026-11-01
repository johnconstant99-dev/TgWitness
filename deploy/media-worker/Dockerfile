FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-rus \
    && rm -rf /var/lib/apt/lists/*
COPY deploy/media-worker/requirements.lock /requirements.lock
# Install only reviewed wheel artifacts, including every transitive dependency.
RUN pip install --no-cache-dir --only-binary=:all: --require-hashes -r /requirements.lock
COPY deploy/media-worker/worker.py /worker.py
USER 65534:65534
ENTRYPOINT ["python", "/worker.py"]
