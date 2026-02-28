FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install pip system-wide as root
RUN python -m pip install --upgrade pip

# Copy requirements first (leverage cache)
COPY requirements.txt .

# Install dependencies **system-wide** (root) to avoid user permissions issues
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY . .

# Expose port
EXPOSE 8000

# Use JSON array form for CMD (avoids signal issues)
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]