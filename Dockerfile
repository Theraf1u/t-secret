FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./
COPY vendor ./vendor
RUN pip install --no-cache-dir --no-index --find-links=/app/vendor -r requirements.txt
COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app
CMD ["sh", "-c", "alembic upgrade head && exec python -m app.main"]
