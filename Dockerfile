FROM python:3.9-slim

# Install system dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install dependencies as root (but with --user flag for non-root later)
RUN pip install --no-cache-dir --user -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app /root/.local

# Switch to non-root user
USER appuser

# Add user's local bin to PATH
ENV PATH="/root/.local/bin:$PATH"

EXPOSE 8000
CMD ["python", "app.py"]