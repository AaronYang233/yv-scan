#!/bin/bash
# test-api.sh

echo "🧪 测试 Trivy 扫描 API..."
echo ""

API_URL="http://localhost:8000"

echo "1️⃣ 健康检查..."
curl -s "$API_URL/api/health" | python3 -m json.tool
echo ""

echo "2️⃣ 创建镜像扫描任务..."
TASK1=$(curl -s -X POST "$API_URL/api/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "image",
    "target": "alpine:latest"
  }' | python3 -c "import sys, json; print(json.load(sys.stdin)['task_id'])")

echo "任务 ID: $TASK1"
echo ""

echo "3️⃣ 创建仓库扫描任务..."
TASK2=$(curl -s -X POST "$API_URL/api/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "repo",
    "target": "https://github.com/aquasecurity/trivy"
  }' | python3 -c "import sys, json; print(json.load(sys.stdin)['task_id'])" 2>/dev/null)

if [ -n "$TASK2" ]; then
  echo "任务 ID: $TASK2"
else
  echo "仓库扫描任务创建失败（可能需要网络访问）"
fi
echo ""

echo "4️⃣ 查看所有任务..."
curl -s "$API_URL/api/scans" | python3 -m json.tool
echo ""

echo "5️⃣ 等待扫描完成（10秒后查询）..."
sleep 10

echo "6️⃣ 查询任务状态..."
curl -s "$API_URL/api/scan/$TASK1" | python3 -m json.tool
echo ""

echo "✅ 测试完成！"
echo "💡 访问 http://localhost 查看 Web 界面"
EOF

chmod +x test-api.sh