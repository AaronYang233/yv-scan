## Trivy Scanner Service

完整的容器化 Trivy 扫描服务，包含 Web 界面。

### 功能特性

- ✅ 支持多种扫描类型（镜像、文件系统、Git 仓库、配置文件）
- ✅ 异步任务处理
- ✅ 可配置严重等级过滤
- ✅ 扫描结果下载
- ✅ 现代化 Web 界面
- ✅ Docker 完全容器化

### 快速开始

```bash
# 1. 克隆项目
git clone <repo>
cd trivy-scanner-service

# 2. 部署服务
chmod +x deploy.sh
./deploy.sh

# 3. 访问界面
open http://localhost
```

### API 文档

```bash
# 健康检查
GET /api/health

# 创建扫描任务
POST /api/scan
{
  "type": "image",
  "target": "nginx:latest",
  "options": {
    "severity": ["CRITICAL", "HIGH"],
    "ignore_unfixed": true
  }
}

# 查询扫描状态
GET /api/scan/{task_id}

# 下载报告
GET /api/scan/{task_id}/report

# 列出所有扫描
GET /api/scans
```

### 扫描示例

```bash
# 扫描 Docker 镜像
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"type":"image","target":"alpine:latest"}'

# 扫描文件系统
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"type":"fs","target":"/path/to/code"}'
```

### 架构说明

- **Backend**: Flask + Trivy (Python)
- **Frontend**: Vue 3 + Vite
- **部署**: Docker + Docker Compose
- **反向代理**: Nginx

这个方案提供了完整的 Trivy 扫描服务，包括现代化的 Web 界面和 RESTful API！