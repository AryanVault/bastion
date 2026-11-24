# Bastion, always on, in a hardened container. See docs/DEPLOYMENT.md.
#
# - Base images pinned by digest (Dependabot keeps them current).
# - Dependencies installed exactly as locked in uv.lock (hash-checked); no build tools in the
#   final image.
# - Runs as an unprivileged user with no shell; built to run with a read-only root filesystem,
#   all capabilities dropped and no-new-privileges (see compose.yaml).
# - Secrets live in a sealed file in /data, unlocked by a master key mounted as a secret.

ARG PYTHON_IMAGE=python:3.13.18-slim-trixie@sha256:6d68eb6310a906f26c7638eb6ea7557d4261662df3181af2f80f1f9a7e34c549

FROM ghcr.io/astral-sh/uv:0.13.9@sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf84db79a7d AS uv

FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src
# Dependencies first, so source changes do not invalidate the cached dependency layer.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="Bastion" \
      org.opencontainers.image.description="A secure, always-on personal AI agent" \
      org.opencontainers.image.source="https://github.com/AryanVault/bastion" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN groupadd --system --gid 10001 bastion \
    && useradd --system --uid 10001 --gid bastion --home-dir /data --no-create-home \
       --shell /usr/sbin/nologin bastion \
    && mkdir /data \
    && chown bastion:bastion /data \
    && chmod 0700 /data
COPY --from=build /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BASTION_HOME=/data \
    BASTION_SECRET_STORE=file \
    BASTION_MASTER_KEY_FILE=/run/secrets/bastion_master_key
USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
ENTRYPOINT ["bastion"]
CMD ["daemon"]
