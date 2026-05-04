FROM python:3.13-slim

WORKDIR /app

RUN pip install keyrings.google-artifactregistry-auth

ENV PYTHON_KEYRING_BACKEND=keyrings.gauth.GooglePythonAuth

COPY requirements.txt .

RUN pip install --no-cache-dir \
    --keyring-provider import \
    --extra-index-url https://us-west1-python.pkg.dev/pgc-dma-dev-sandbox/rasp-repo/simple/ \
    -r requirements.txt

# 4. Copy the rest of your application code
COPY . .

# 5. Inform Docker that the container listens on port 8080
EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
