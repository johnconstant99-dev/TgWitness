FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home recorder && mkdir /data && chown recorder:recorder /data
WORKDIR /app
COPY deploy/build.lock /tmp/build.lock
COPY addons/capture/requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /tmp/build.lock \
    && pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock
COPY addons/capture/pyproject.toml ./addons/capture/pyproject.toml
COPY tgwitness_capture ./tgwitness_capture
RUN pip install --no-cache-dir --no-deps --no-build-isolation ./addons/capture
USER recorder
CMD ["python", "-m", "tgwitness_capture", "serve", "--data", "/data", "--config", "/config.json", "--host", "0.0.0.0"]
