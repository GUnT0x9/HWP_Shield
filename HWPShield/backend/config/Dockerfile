FROM python:3.11-slim

# Security: Run as non-root user
RUN useradd -m -u 1000 hwpshield && \
    mkdir -p /app /tmp/hwpshield && \
    chown -R hwpshield:hwpshield /app /tmp/hwpshield

WORKDIR /app

# Install dependencies first (for better caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=hwpshield:hwpshield . .

# Switch to non-root user
USER hwpshield

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV TEMP=/tmp/hwpshield
ENV MAX_FILE_SIZE=52428800

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

# Run server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
