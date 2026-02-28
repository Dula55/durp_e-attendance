# Use official Python image
FROM python:3.9-slim

# Prevent Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Copy only requirements first (better caching)
COPY requirements.txt .

# Upgrade pip
RUN python -m pip install --upgrade pip

# Install dependencies as root
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY . .

# Create non-root user
RUN useradd -m appuser

# Change ownership of app directory
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Use JSON CMD (no shell form)
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8000"]