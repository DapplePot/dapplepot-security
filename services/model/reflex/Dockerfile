# syntax=docker/dockerfile:1.7
FROM python:3.12-slim

# Runtime deps: CA certs for HuggingFace downloads at build time.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install CPU-only PyTorch first (no CUDA layers → ~600 MB saved).
# Then the app requirements. Pinning avoids the extra-index resolving CUDA wheels.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu \
        "torch>=2.3" && \
    pip install --no-cache-dir -r requirements.txt

# Bake the model into the image. Pass HF_TOKEN as a build secret so it never
# lives in an image layer:
#
#   docker build --secret id=hf_token,env=HF_TOKEN -t dapplepot-reflex .
#
# The model is license-gated; the token holder must have accepted the Llama
# Community License on Hugging Face at least once for their account.
ARG MODEL_ID=meta-llama/Llama-Prompt-Guard-2-86M
ENV MODEL_ID=${MODEL_ID}
ENV HF_HOME=/models/.hf

RUN --mount=type=secret,id=hf_token \
    HF_TOKEN="$(cat /run/secrets/hf_token 2>/dev/null || echo '')" \
    python -c "\
import os; \
from transformers import pipeline; \
tok = os.environ.get('HF_TOKEN') or None; \
pipeline('text-classification', model=os.environ['MODEL_ID'], token=tok);"

COPY main.py .

ENV PORT=8080
EXPOSE 8080
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]
