#!/bin/bash

# PostgreSQL 蜜罐系统启动脚本

set -e

echo "🍯 Starting PostgreSQL Honeypot System..."
echo ""

# 检查 Docker 是否安装
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# 创建日志目录
mkdir -p logs

# 停止现有服务
echo "Stopping existing services..."
docker-compose down -v 2>/dev/null || true

# 启动服务
echo "Starting services..."
docker-compose up -d --build

# 等待服务启动
echo "Waiting for services to start..."
sleep 10

# 检查服务状态
echo ""
echo "📊 Service Status:"
docker-compose ps

# 检查健康状态
echo ""
echo "🏥 Health Check:"
if docker-compose exec -T postgres pg_isready -U postgres -d postgres >/dev/null 2>&1; then
    echo "✅ PostgreSQL: Healthy"
else
    echo "❌ PostgreSQL: Unhealthy"
fi

if curl -s http://localhost:8080/health >/dev/null 2>&1; then
    echo "✅ Monitor Service: Healthy"
else
    echo "❌ Monitor Service: Unhealthy"
fi

echo ""
echo "🚀 System Ready!"
echo ""
echo "📱 Access Points:"
echo "   🌐 Web Dashboard: http://localhost:8080"
echo "   🔌 Database:     localhost:5432 (user: postgres, password: honeypot123)"
echo "   📡 API Endpoint: http://localhost:8080/alert"
echo "   💓 Health Check: http://localhost:8080/health"
echo ""
echo "🧪 Test Commands:"
echo "   # Connect to database"
echo "   docker-compose exec postgres psql -U postgres -d postgres"
echo ""
echo "   # Trigger honeypot alert"
echo '   docker-compose exec postgres psql -U postgres -d postgres -c "SELECT * FROM honeypot_customer_view LIMIT 1;"'
echo ""
echo "   # View logs"
echo "   docker-compose logs -f monitor"
echo ""
echo "   # Stop system"
echo "   docker-compose down"
echo ""
echo "📖 For more information, visit: http://localhost:8080"