FROM python:3.13.5-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    DGS_DATA_DIR=/data \
    HOME=/home/dgs

WORKDIR /app

RUN groupadd --gid 10001 dgs \
    && useradd \
        --uid 10001 \
        --gid dgs \
        --create-home \
        --home-dir /home/dgs \
        --shell /usr/sbin/nologin \
        dgs

COPY requirements.txt .

RUN python -m pip install --upgrade pip \
    && python -m pip install --no-cache-dir \
        -r requirements.txt

COPY --chown=dgs:dgs . .

RUN mkdir -p \
        /data/scan_snapshots \
        /data/client_scan_results \
        /data/backups \
        /data/restored_backups \
    && rm -rf \
        /app/scan_snapshots \
        /app/client_scan_results \
        /app/backups \
        /app/restored_backups \
    && ln -s /data/scan_snapshots /app/scan_snapshots \
    && ln -s /data/client_scan_results /app/client_scan_results \
    && ln -s /data/backups /app/backups \
    && ln -s /data/restored_backups /app/restored_backups \
    && chown -R dgs:dgs /app /data /home/dgs

VOLUME ["/data"]

USER dgs

EXPOSE 8501

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=20s \
    --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3).read()"]

CMD ["streamlit", "run", "app.py"]
