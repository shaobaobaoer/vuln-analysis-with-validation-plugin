# Python 项目搭建

没有 Docker Compose / Dockerfile 时，识别为 Python 项目后使用。

> **MANDATORY**: 所有 Python 依赖管理必须使用 `uv`。禁止直接使用 `pip install`、`conda install`、`python -m venv`。所有 Python 执行必须在 Docker 容器内进行。

---

## 第一步：在 Docker 中安装 uv

所有 Python 项目的 Dockerfile 必须安装 `uv`：

```dockerfile
# 在 Dockerfile 中安装 uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"
```

---

## 第二步：创建环境 + 安装依赖（Docker 内）

所有操作在 Docker 容器内执行，使用 `uv` 管理依赖：

```bash
# 方式一：项目有 pyproject.toml（推荐）
docker exec <container> uv sync

# 方式二：项目有 requirements.txt
docker exec <container> uv pip install --system -r requirements.txt

# 方式三：项目有 environment.yml（仅 ML 项目 fallback）
# 先安装 conda 包，再用 uv 安装 pip 依赖
docker exec <container> uv pip install --system -r requirements.txt

# 指定 Python 版本
docker exec <container> uv python install 3.11
docker exec <container> uv venv --python 3.11
```

**NEVER** 在宿主机上运行 `python3` 或 `pip install`。

---

## 第三步：ML 依赖（仅 ML/AI 项目）

```bash
# PyTorch CPU（在 Docker 容器内）
docker exec <container> uv pip install --system torch torchvision torchaudio \
    --index-url https://download.pytorch.org/whl/cpu

# TensorFlow CPU
docker exec <container> uv pip install --system tensorflow-cpu

# PyTorch GPU
docker exec <container> uv pip install --system torch torchvision torchaudio
```

### 脚本返回的状态码及 agent 应对

| 状态码 | 含义 | agent 行动 |
|-------|------|-----------|
| `ML_GPU_OK` | GPU 版安装成功 | 继续 |
| `ML_NO_GPU` | 没检测到 GPU | **问用户**：确实没 GPU？用户确认后安装 CPU 版 |
| `ML_GPU_INSTALL_FAILED` | GPU 版安装失败 | **问用户**：是否降级 CPU 版？ |
| `ML_GPU_VERIFY_FAILED` | 装了但 CUDA 不可用 | **问用户**：是否继续？ |
| `ML_NO_ML_DEPS` | 项目不需要 ML | 跳过 |

---

## 第四步：数据库迁移（按需，Docker 内执行）

```bash
# 在 Docker 容器内执行
docker exec <container> python manage.py migrate            # Django
docker exec <container> flask db upgrade                     # Flask + Alembic
docker exec <container> python manage.py init_db             # 通用
```

---

## 第五步：启动应用（Docker 内）

```bash
# 应用在 Docker 容器内启动，通过端口映射暴露到宿主机
# Dockerfile CMD 或 docker-compose command 启动

# Django
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

# Flask
CMD ["flask", "run", "--host", "0.0.0.0", "--port", "5000"]

# FastAPI
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Gradio
CMD ["python", "app.py"]
```

ML 脚本项目无需启动服务，验证环境可用即可报告 READY。

---

## Dockerfile 模板（Python + uv）

```dockerfile
FROM python:3.12-slim
WORKDIR /app

# 安装系统依赖 + uv
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc g++ python3-dev libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/* && \
    curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# 安装 Python 依赖（使用 uv，NEVER pip）
COPY requirements.txt .
RUN uv pip install --system -r requirements.txt

COPY . .
EXPOSE <port>
HEALTHCHECK --interval=5s --timeout=3s --retries=5 \
    CMD curl -f http://localhost:<port>/health || exit 1
CMD ["python", "app.py"]
```

---

## 清理

```bash
# 停止并删除 Docker 容器
docker-compose down -v

# 删除构建产物
docker rmi <image_name> 2>/dev/null
```

---

## uv 安装失败处理

```bash
# 缺编译依赖
docker exec <container> apt-get update && apt-get install -y gcc g++ python3-dev libffi-dev libssl-dev

# uv 网络超时 — 使用镜像源
docker exec <container> uv pip install --system -r requirements.txt \
    --index-url https://pypi.tuna.tsinghua.edu.cn/simple

# uv 本身安装失败 — 使用 pip bootstrap
docker exec <container> pip install uv
```
