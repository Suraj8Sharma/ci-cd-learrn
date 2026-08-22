# Multistage Dockerfile for the FastAPI auth example
# Builder: install build deps, create venv, install deps
FROM python:3.12-slim AS builder

WORKDIR /app

# 1. Install build tools needed for some wheels (bcrypt, etc.)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# 2. Create and activate virtualenv
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# 3. Upgrade pip and install runtime dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir \
    fastapi[all] uvicorn[standard] pyjwt bcrypt python-multipart redis

# 4. Copy application sources
COPY . /app

# ---------------------------------------------------------
# Final: lightweight runtime image which reuses the built venv
# ---------------------------------------------------------
FROM python:3.12-slim

WORKDIR /app

# 5. Copy the virtualenv from the builder stage and application files
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app /app

# 6. Make sure the final stage also uses the virtual environment
ENV PATH="/opt/venv/bin:$PATH"

EXPOSE 8000

# Run Uvicorn 
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]