# Build stage
FROM python:3.9-slim as builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.9-slim

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Create non-root user and directories
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --gid 1001 --no-create-home appuser && \
    mkdir -p /app /data && \
    chown -R appuser:appgroup /app /data && \
    chmod 755 /app /data

# Add local bin to PATH
ENV PATH=/root/.local/bin:$PATH \
    DATA_DIR=/data

# Copy application files
COPY --chown=appuser:appgroup . /app

# Switch to non-root user
USER appuser

VOLUME ["/data"]
EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", "--access-logfile", "-", "--error-logfile", "-", "app:app"]