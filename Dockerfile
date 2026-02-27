FROM python:3.9-slim

# Prevent Python from writing pyc files & enable logs immediately
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies (optional but good practice)
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

# Upgrade pip first
RUN pip install --upgrade pip

# Copy only requirements first (better layer caching)
COPY requirements.txt .

# Install dependencies as root (no permission issue)
RUN pip install --no-cache-dir -r requirements.txt

# Now copy application code
COPY . .

# Expose port (Render / most PaaS use 8000)
EXPOSE 5000

# Use JSON array format (correct signal handling)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]