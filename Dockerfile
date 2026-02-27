FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install pip cleanly
RUN python -m pip install --upgrade pip

# Copy only requirements first
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose port (Render/most platforms expect 8000)
EXPOSE 8000

# Run app
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]