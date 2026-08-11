# syntax=docker/dockerfile:1

FROM python:3.12-alpine

WORKDIR /app

RUN addgroup -S proxy && adduser -S -G proxy proxy

COPY src/minbot_selective_proxy/server.py /app/server.py

ENV PYTHONUNBUFFERED=1 \
    PROXY_DOMAINS_STATE_PATH=/tmp/selective-proxy/domains.json

USER proxy

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT','8080'), timeout=2).read()" || exit 1

CMD ["python", "/app/server.py"]
