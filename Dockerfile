FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# App working directory
WORKDIR /app

# Copy only requirements first (for caching)
COPY requirements.txt .

# Install Python packages in /app/.local (writable by non-root)
ENV PYTHONUSERBASE=/app/.local
ENV PATH=/app/.local/bin:$PATH

RUN python -m pip install --upgrade pip \
    && pip install --user --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Expose port (most platforms, including PandaStack, expect 8000)
EXPOSE 8000

# Run app with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]