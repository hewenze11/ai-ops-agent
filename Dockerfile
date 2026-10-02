# This image is for isolated tests, NOT privileged host administration.
FROM python:3.12-slim AS test
WORKDIR /src
COPY pyproject.toml ./
COPY ai_ops_agent ./ai_ops_agent
COPY tests ./tests
RUN pip install --no-cache-dir '.[test]' && pytest -q

FROM python:3.12-slim AS runtime
WORKDIR /app
COPY pyproject.toml ./
COPY ai_ops_agent ./ai_ops_agent
RUN pip install --no-cache-dir .
USER 65534:65534
ENTRYPOINT ["ai-ops-agent"]
