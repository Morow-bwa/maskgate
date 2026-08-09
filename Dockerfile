FROM node:22-alpine AS playground-build

WORKDIR /frontend

RUN corepack enable && corepack prepare pnpm@11.16.0 --activate
COPY playground-react/package.json playground-react/pnpm-lock.yaml playground-react/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY playground-react/ ./
RUN pnpm build

FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp

WORKDIR /app

# OpenCV's wheel needs these runtime libraries. No compiler or package manager
# cache is retained in the final image.
RUN apt-get update \
    && apt-get install --no-install-recommends -y libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --upgrade "pip==26.2.1"
RUN python -m pip install --no-cache-dir --requirement requirements.lock

COPY app ./app
COPY --from=playground-build /frontend/dist ./playground-react/dist

RUN groupadd --system --gid 10001 maskgate \
    && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent \
       --shell /usr/sbin/nologin maskgate
USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/live', timeout=3).read()"]

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-access-log", "--limit-concurrency", "100", "--backlog", "128", "--timeout-keep-alive", "5", "--timeout-graceful-shutdown", "20"]
