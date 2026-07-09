FROM python:3.12-slim

# Pin specific stable uv tool version for reproducible builds
COPY --from=ghcr.io/astral-sh/uv:0.3.0 /uv /uvx /bin/

# Create a non-privileged system user for executing sandbox tasks
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Copy the workspace files
COPY . .

# Set correct read/write permissions for the non-root execution context
RUN chown -R appuser:appuser /app

USER appuser

# Synchronize the workspace dependencies programmatically
RUN uv sync --no-dev

# Install sandbox app runtime dependencies
RUN uv pip install -r apps/nanda-sandbox/requirements.txt

EXPOSE 8000

# Run uvicorn server in the workspace virtual environment, binding dynamically to the Railway assigned port
CMD ["sh", "-c", ".venv/bin/uvicorn apps.nanda-sandbox.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
