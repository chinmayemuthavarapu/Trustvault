FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    TV_ENV=production TV_DATA_DIR=/data

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static
COPY scripts ./scripts
COPY wsgi.py docker-entrypoint.sh ./

# Run as an unprivileged user; only /data is writable.
RUN useradd --system --uid 10001 tv && mkdir -p /data && chown tv /data && chmod 700 /data \
    && chmod +x docker-entrypoint.sh
USER tv

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
ENTRYPOINT ["./docker-entrypoint.sh"]
