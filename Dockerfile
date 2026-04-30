FROM python:3.10-slim

WORKDIR /app

COPY . /app

# ✅ Install Artifact Registry auth support FIRST
RUN pip install --no-cache-dir keyrings.google-artifactregistry-auth

# ✅ Then install your dependencies
RUN pip install --no-cache-dir \
    --extra-index-url https://us-west1-python.pkg.dev/pgc-dma-dev-sandbox/rasp-repo/simple/ \
    -r requirements.txt

EXPOSE 8080

ENV FLASK_APP=app.py

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]