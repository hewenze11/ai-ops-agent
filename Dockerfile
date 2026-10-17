# Clean Linux runtime. Executes inside THIS container, not on the Docker host.
FROM python:3.14-slim AS build
WORKDIR /src
COPY pyproject.toml LICENSE ./
COPY ai_ops_agent ./ai_ops_agent
RUN pip install --no-cache-dir build && python -m build --wheel

FROM build AS test
COPY tests ./tests
RUN pip install --no-cache-dir '.[test]' && pytest -q

FROM python:3.14-slim AS runtime
LABEL org.opencontainers.image.source="https://github.com/hewenze11/ai-ops-agent"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --gid 10001 aiops \
    && useradd --uid 10001 --gid 10001 --create-home --shell /bin/sh aiops \
    && mkdir -p /etc/ai-ops-agent /var/lib/ai-ops-agent \
    && chown 10001:10001 /var/lib/ai-ops-agent \
    && chmod 700 /var/lib/ai-ops-agent
COPY --from=build /src/dist/*.whl /tmp/wheels/
RUN pip install --no-cache-dir /tmp/wheels/*.whl && rm -rf /tmp/wheels
WORKDIR /home/aiops
USER 10001:10001
ENTRYPOINT ["ai-ops-agent"]
CMD ["--config", "/etc/ai-ops-agent/config.json"]
