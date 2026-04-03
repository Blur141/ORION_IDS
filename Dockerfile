# ============================================================
# Dockerfile — Instructions to build the IDS container image
# ============================================================
# Docker is like a recipe: it creates a self-contained box
# (container) with Python, our code, and all dependencies.
# The app runs the same on ANY computer or server.
# ============================================================

# ── Base image ───────────────────────────────────────────────
# We start from the official Python 3.11 "slim" image.
# "slim" = smaller size (no extra tools we don't need).
FROM python:3.11-slim

# ── Set working directory inside the container ───────────────
# All subsequent commands run from /app.
# Think of this as "cd /app" inside the container.
WORKDIR /app

# ── Install system-level dependencies ────────────────────────
# Scapy needs libpcap (the packet capture library).
# tcpdump is optional but useful for debugging inside Docker.
RUN apt-get update && \
    apt-get install -y libpcap-dev tcpdump && \
    rm -rf /var/lib/apt/lists/*

# ── Copy requirements first (Docker caching trick) ───────────
# If requirements.txt hasn't changed, Docker reuses the cached
# layer — making rebuilds much faster!
COPY requirements.txt .

# ── Install Python packages ───────────────────────────────────
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy all project files into the container ─────────────────
COPY . .

# ── Expose port 8000 ──────────────────────────────────────────
# This tells Docker that port 8000 is used.
# You still need -p 8000:8000 when running to access it.
EXPOSE 8000

# ── Start the FastAPI server ──────────────────────────────────
# uvicorn = the ASGI server that runs FastAPI apps
# --host 0.0.0.0 = accept connections from outside the container
# --port 8000 = listen on port 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
