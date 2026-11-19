FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    CLOUDSHIELD_HOST=0.0.0.0 \
    CLOUDSHIELD_PORT=8765 \
    CLOUDSHIELD_CONTAINER_MODE=1 \
    CLOUDSHIELD_DB=/data/evidence.sqlite3

WORKDIR /app
COPY requirements-cloud.lock ./requirements-cloud.lock
RUN python -m pip install --no-cache-dir pip==26.3 \
    && python -m pip install --no-cache-dir -r requirements-cloud.lock
COPY . .
RUN python -m pip install --no-cache-dir --no-build-isolation --no-deps -e . \
    && mkdir -p /data \
    && useradd --system --uid 10001 --create-home cloudshield \
    && chown -R cloudshield:cloudshield /data
USER 10001:10001
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=3).read()" || exit 1
CMD ["python", "-m", "cloudshield.api"]
