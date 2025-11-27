# deploy.sh
#!/bin/bash

echo "🚀 Deploying Trivy Scanner Service..."

# 创建必要的目录
mkdir -p frontend/src backend

# 构建并启动服务
docker-compose down
docker-compose build --no-cache
docker-compose up -d

echo "✅ Service deployed successfully!"
echo "Frontend: http://localhost"
echo "Backend API: http://localhost:8000"
echo ""
echo "Health check: curl http://localhost:8000/api/health"