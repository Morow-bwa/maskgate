FROM node:22-alpine AS playground-build

WORKDIR /frontend

COPY playground-react/package.json playground-react/pnpm-lock.yaml* ./
RUN corepack enable && pnpm install --frozen-lockfile --ignore-scripts && pnpm approve-builds --all && pnpm install --frozen-lockfile
COPY playground-react ./
RUN pnpm build

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY app ./app
COPY --from=playground-build /frontend/dist ./playground-react/dist

RUN pip install .

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
