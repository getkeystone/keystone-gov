FROM python:3.12-slim

WORKDIR /app

# poppler-utils: pdftotext fallback for image-heavy PDFs that pypdf can't extract
RUN apt-get update && apt-get install -y --no-install-recommends \
    poppler-utils \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1

# Build provenance — injected by scripts/build-api.sh via --build-arg.
# Default "unknown" is intentionally detectable so preflight can warn.
ARG GIT_SHA=unknown
ARG BUILD_TIMESTAMP=unknown
ENV GIT_SHA=$GIT_SHA
ENV BUILD_TIMESTAMP=$BUILD_TIMESTAMP

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
