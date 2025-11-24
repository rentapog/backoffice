FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . /app/

# Ensure uploads directory exists
RUN mkdir -p /app/uploads

EXPOSE 8080

ENV FLASK_APP=coey_agent.py
ENV FLASK_RUN_HOST=0.0.0.0

# Use the PORT environment variable set by Fly.io/Cloud Run, default to 8080
ENV PORT=8080
CMD ["sh", "-c", "gunicorn -b 0.0.0.0:${PORT} app:app"]