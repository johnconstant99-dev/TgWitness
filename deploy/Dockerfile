FROM python:3.12-slim
LABEL org.opencontainers.image.title="TgWitness" \
      org.opencontainers.image.description="Self-hosted Telegram observation journal with signed exports" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1 TGWITNESS_DATA=/data
WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY deploy/build.lock deploy/requirements.lock ./
COPY tgwitness ./tgwitness
# Every package must match a SHA-256 in the locks; builds use the hashed setuptools only.
RUN pip install --no-cache-dir --require-hashes -r build.lock \
    && pip install --no-cache-dir --require-hashes --no-build-isolation -r requirements.lock \
    && pip install --no-cache-dir --no-deps --no-build-isolation . && useradd --uid 10001 --create-home collector \
    && mkdir /data /witness && chown collector:collector /data /witness
USER collector
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/', timeout=4)" || exit 1
CMD ["python", "-m", "tgwitness", "--host", "0.0.0.0"]
