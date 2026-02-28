# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Copy project files into the container
COPY . /app

# Upgrade pip and install dependencies as root
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Create a non-root user and switch to it
RUN useradd --create-home appuser
USER appuser

# Expose the port your app runs on (adjust if needed)
EXPOSE 8000

# Run the app using gunicorn
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8000"]