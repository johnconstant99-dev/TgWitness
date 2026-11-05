FROM cgr.dev/chainguard/wolfi-base@sha256:fd50bd0cdeb808cf4f45c9c9189e0cc7f7fcc27195d69abd6622c80527e7e021 AS ocr-build
COPY deploy/containers /build/containers
RUN sh /build/containers/install-packages.sh build
COPY deploy/media-worker/build-tesseract.sh deploy/media-worker/fetch-sources.py deploy/media-worker/tesseract.nfpm.yaml deploy/media-worker/sources.lock.json /build/ocr/
RUN sh /build/ocr/build-tesseract.sh

FROM cgr.dev/chainguard/wolfi-base@sha256:fd50bd0cdeb808cf4f45c9c9189e0cc7f7fcc27195d69abd6622c80527e7e021
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONUTF8=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:$PATH" TESSDATA_PREFIX=/usr/share/tesseract-ocr/5/tessdata
COPY deploy/containers /usr/share/tgwitness-build/containers
RUN sh /usr/share/tgwitness-build/containers/install-packages.sh media \
    && python3.12 -m venv /opt/venv
COPY --from=ocr-build /out/tgwitness-tesseract-build.rsa.pub /etc/apk/keys/
COPY --from=ocr-build /out/tesseract.apk /tmp/tesseract.apk
RUN apk add --no-network --repositories-file /dev/null /tmp/tesseract.apk && rm /tmp/tesseract.apk \
    && tesseract --version && tesseract --list-langs
COPY deploy/media-worker/requirements.lock /requirements.lock
# Install only reviewed wheel artifacts, including every transitive dependency.
RUN pip install --no-cache-dir --only-binary=:all: --require-hashes -r /requirements.lock \
    && python -m pip check && python -m pip uninstall --yes pip
COPY deploy/media-worker/worker.py /worker.py
USER 65534:65534
ENTRYPOINT ["python", "/worker.py"]
