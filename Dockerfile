FROM python:3.9-slim

WORKDIR /app
COPY . /app

# Install dependencies as root
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Switch to non-root user
USER 1000

CMD ["gunicorn", "app:app"]