# Multistage Dockerfile for the FastAPI auth example
# Builder: install build deps, create venv, install deps and run tests
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build tools needed for some wheels (bcrypt, etc.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*


# Create and activate virtualenv, install runtime + test deps
RUN python -m venv /o
# Copy application sources
COPY . /apppt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip
# Install only runtime dependencies in the builder. Tests run in CI, not in
# the image build.
RUN pip install --no-cache-dir \
    fastapi[all] uvicorn[standard] pyjwt bcrypt python-multipart redis


# Final: lightweight runtime image which reuses the built venv
FROM python:3.12-slim

WORKDIR /app

# Copy the virtualenv from the builder stage and application files
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app /app

ENV PATH="/opt/venv/bin:$PATH"

# Optional: non-root user can be added here for security
# RUN useradd -m appuser && chown -R appuser /app
# USER appuser

EXPOSE 8000

# Run Uvicorn (adjust host/port as needed)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
