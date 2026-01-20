# ==============================================================================
# Stage 1: 构建 Go Agent 二进制文件
# ==============================================================================
FROM golang:1.21-alpine AS go-builder

WORKDIR /build
ENV GOPROXY=https://goproxy.cn,direct

RUN --mount=type=bind,source=backend/agents/go-agent,target=/src \
    --mount=type=cache,target=/go/pkg/mod \
    cp /src/go.mod /src/go.sum ./ && go mod download && cp -r /src/* ./ && \
    mkdir -p /dist && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /dist/configflow-agent-linux-amd64 . && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o /dist/configflow-agent-linux-arm64 . && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o /dist/configflow-agent-linux-armv7 .

# ==============================================================================
# Stage 2: 构建前端
# ==============================================================================
FROM node:18-alpine AS frontend-builder

WORKDIR /app/frontend

RUN --mount=type=bind,source=frontend,target=/src \
    --mount=type=cache,target=/root/.npm \
    cp /src/package*.json ./ && npm ci && cp -r /src/* ./ && npm run build

# ==============================================================================
# Stage 3: 最终镜像
# ==============================================================================
FROM python:3.11-slim

WORKDIR /app

# 复制依赖文件、Go Agent、前端构建产物
COPY backend/requirements.txt ./
COPY --from=go-builder /dist/ /opt/configflow/static/agents/
COPY --from=frontend-builder /app/frontend/dist /usr/share/nginx/html

# 安装依赖、配置 nginx/supervisor（合并为单个 RUN 减少层数）
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    --mount=type=cache,target=/root/.cache/pip \
    apt-get update && \
    apt-get install -y --no-install-recommends nginx supervisor && \
    rm -rf /var/lib/apt/lists/* && \
    pip install --no-cache-dir -r requirements.txt && \
    groupadd -r nginx && useradd -r -g nginx -s /sbin/nologin -d /nonexistent nginx && \
    mkdir -p /data /var/log/supervisor /var/cache/nginx /var/log/nginx /opt/configflow/static/agents && \
    chown -R nginx:nginx /var/cache/nginx /var/log/nginx /usr/share/nginx/html && \
    echo '[supervisord]\n\
nodaemon=true\n\
logfile=/var/log/supervisor/supervisord.log\n\
pidfile=/var/run/supervisord.pid\n\
\n\
[program:nginx]\n\
command=/usr/sbin/nginx -g "daemon off;"\n\
autostart=true\n\
autorestart=true\n\
stdout_logfile=/dev/stdout\n\
stdout_logfile_maxbytes=0\n\
stderr_logfile=/dev/stderr\n\
stderr_logfile_maxbytes=0\n\
\n\
[program:flask]\n\
command=python app.py\n\
directory=/app\n\
autostart=true\n\
autorestart=true\n\
stdout_logfile=/dev/stdout\n\
stdout_logfile_maxbytes=0\n\
stderr_logfile=/dev/stderr\n\
stderr_logfile_maxbytes=0\n\
environment=FLASK_APP=app.py,PYTHONUNBUFFERED=1,DATA_DIR=/data\n\
' > /etc/supervisor/conf.d/supervisord.conf

# 复制后端代码和 nginx 配置
COPY backend ./backend
COPY main.py app.py ./
COPY docker/nginx.conf /etc/nginx/nginx.conf

ENV FLASK_APP=app.py PYTHONUNBUFFERED=1 DATA_DIR=/data TZ=Asia/Shanghai

EXPOSE 80

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
