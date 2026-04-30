FROM python:3.10-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080

ENV FLASK_APP=app.py

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]