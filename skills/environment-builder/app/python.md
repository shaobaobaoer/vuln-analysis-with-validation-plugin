# Python Project Setup

Used when no Docker Compose / Dockerfile is present and the project is identified as a Python project.

> **MANDATORY**: All Python dependency management must use `uv`. Direct use of `pip install`, `conda install`, or `python -m venv` is prohibited. All Python execution must be done inside Docker containers.

---

## Step 1: Install uv in Docker

All Python project Dockerfiles must install `uv`:

```dockerfile
# Install uv in Dockerfile
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"
```

---

## Step 2: Create Environment + Install Dependencies (Inside Docker)

All operations are executed inside Docker containers, using `uv` to manage dependencies:

```bash
# Option 1: Project has pyproject.toml (recommended)
docker exec <container> uv sync

# Option 2: Project has requirements.txt
docker exec <container> uv pip install --system -r requirements.txt

# Option 3: Project has environment.yml (ML project fallback only)
# Install conda packages first, then use uv to install pip dependencies
docker exec <container> uv pip install --system -r requirements.txt

# Specify Python version
docker exec <container> uv python install 3.11
docker exec <container> uv venv --python 3.11
```

**NEVER** run `python3` or `pip install` on the host machine.

---

## Step 3: ML Dependencies (ML/AI Projects Only)

```bash
# PyTorch CPU (inside Docker container)
docker exec <container> uv pip install --system torch torchvision torchaudio \
    --index-url https://download.pytorch.org/whl/cpu

# TensorFlow CPU
docker exec <container> uv pip install --system tensorflow-cpu

# PyTorch GPU
docker exec <container> uv pip install --system torch torchvision torchaudio
```

### Script Return Status Codes and Agent Response

| Status Code | Meaning | Agent Action |
|-------|------|-----------|
| `ML_GPU_OK` | GPU version installed successfully | Continue |
| `ML_NO_GPU` | No GPU detected | **Ask user**: Really no GPU? Install CPU version after user confirms |
| `ML_GPU_INSTALL_FAILED` | GPU version installation failed | **Ask user**: Downgrade to CPU version? |
| `ML_GPU_VERIFY_FAILED` | Installed but CUDA unavailable | **Ask user**: Continue anyway? |
| `ML_NO_ML_DEPS` | Project does not need ML | Skip |

---

## Step 4: Database Migration (As Needed, Inside Docker)

```bash
# Execute inside Docker container
docker exec <container> python manage.py migrate            # Django
docker exec <container> flask db upgrade                     # Flask + Alembic
docker exec <container> python manage.py init_db             # Generic
```

---

## Step 5: Start Application (Inside Docker)

```bash
# Application starts inside Docker container, exposed to host via port mapping
# Started via Dockerfile CMD or docker-compose command

# Django
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

# Flask
CMD ["flask", "run", "--host", "0.0.0.0", "--port", "5000"]

# FastAPI
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Gradio
CMD ["python", "app.py"]
```

ML script projects do not need to start a service; report READY once the environment is verified.

---

## Dockerfile Template (Python + uv)

```dockerfile
FROM python:3.12-slim
WORKDIR /app

# Install system dependencies + uv
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc g++ python3-dev libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/* && \
    curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Install Python dependencies (using uv, NEVER pip)
COPY requirements.txt .
RUN uv pip install --system -r requirements.txt

COPY . .
EXPOSE <port>
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:<port>/health || exit 1
CMD ["python", "app.py"]
```

---

## Cleanup

```bash
# Stop and remove Docker containers
docker-compose down -v

# Remove build artifacts
docker rmi <image_name> 2>/dev/null
```

---

## uv Installation Failure Handling

```bash
# Missing build dependencies
docker exec <container> apt-get update && apt-get install -y gcc g++ python3-dev libffi-dev libssl-dev

# uv network timeout — use mirror
docker exec <container> uv pip install --system -r requirements.txt \
    --index-url https://pypi.tuna.tsinghua.edu.cn/simple

# uv itself failed to install — use pip bootstrap
docker exec <container> pip install uv
```
