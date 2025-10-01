FROM python:3.11-slim

# system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# install deps first (better cache)
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# now copy the Django project (this brings manage.py + app_blockchain/)
COPY . /app/

# settings / gunicorn target match your tree
ENV DJANGO_SETTINGS_MODULE=app_blockchain.settings

EXPOSE 8000
CMD ["sh","-lc","python manage.py migrate && gunicorn app_blockchain.wsgi:application --bind 0.0.0.0:8000 --workers 3"]
