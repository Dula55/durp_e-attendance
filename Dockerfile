FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# App working directory
WORKDIR /app

# Copy only requirements first (for caching)
COPY requirements.txt .

# Install system dependencies if needed (uncomment if you need them)
# RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

# Install Python packages globally (simpler approach)
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Create a non-root user to run the app
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --gid 1001 appuser

# Change ownership of the app directory to the non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port (most platforms, including PandaStack, expect 8000)
EXPOSE 8000

# Run app with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]