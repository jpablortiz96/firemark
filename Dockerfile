# syntax=docker/dockerfile:1

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY api ./api
RUN python -m pip wheel --wheel-dir /wheels .

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

RUN groupadd --system firemark \
    && useradd --system --gid firemark --home-dir /app --shell /usr/sbin/nologin firemark

WORKDIR /app
COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels firemark \
    && rm -rf /wheels

USER firemark
EXPOSE 8000

CMD ["/bin/sh", "-c", "exec uvicorn api.firemark.app:create_app --factory --host 0.0.0.0 --port ${PORT} --workers 1 --timeout-graceful-shutdown 30 --no-server-header"]
