# 🍯 PostgreSQL Honeypot with Infinite Data - One-Click Deployment

## 快速部署

### 方法1：使用部署脚本（推荐）

```bash
# 克隆仓库
git clone <repository-url>
cd pg_honeypot

# 运行一键部署脚本
./deploy.sh
```

### 方法2：手动 Docker Compose

```bash
# 使用自动化配置启动
docker-compose -f docker-compose.auto.yml up -d

# 查看日志
docker logs -f pg_honeypot_auto
```

## 特性

### ✨ 自动化功能

1. **自动编译** - C扩展在容器构建时自动编译
2. **自动初始化** - 数据库启动时自动创建蜜罐表
3. **无限数据生成** - 内置无限假数据生成器
4. **Web监控** - 自动启动Web监控界面

### 🔥 无限数据蜜罐

容器启动后自动创建以下无限数据蜜罐表：

- `honeypot_financial_view` - 无限金融账户数据
- `honeypot_customer_view` - 无限客户SSN数据
- `honeypot_employee_view` - 无限员工敏感数据

### 📊 数据生成示例

```sql
-- 获取100行虚拟信用卡数据（安全）
SELECT * FROM honeypot_financial_view LIMIT 100;

-- 结果示例：
id | account_info        | balance    | routing_number | created_at
---|--------------------|------------|----------------|------------
1  | Account: ACC-00097 | 60,110.57  | 285614017     | 2025-07-21
2  | Account: ACC-00066 | 81,618.09  | 588296258     | 2025-07-21
3  | Account: ACC-00291 | 12,345.67  | 123456789     | 2025-07-22
...（继续生成到第100行）

-- ⚠️ 危险：不带LIMIT会永远运行
-- SELECT COUNT(*) FROM honeypot_financial_view; -- 永不结束！
```

## 使用指南

### 1. 连接数据库

```bash
psql -h localhost -p 5432 -U postgres -d postgres
# 密码: honeypot123
```

### 2. 测试无限数据

```sql
-- 安全查询（带LIMIT）
SELECT * FROM honeypot_customer_view LIMIT 50;

-- 查看前10行
SELECT id, LEFT(sensitive_data, 30) as preview 
FROM honeypot_financial_view 
LIMIT 10;
```

### 3. 访问Web监控

打开浏览器访问: http://localhost:8080/

- 查看实时警报
- 模拟蜜罐访问
- 测试无限数据生成

## 配置选项

### 环境变量

在 `docker-compose.auto.yml` 中配置：

```yaml
environment:
  - POSTGRES_PASSWORD=honeypot123  # 数据库密码
  - HONEYPOT_PORT=8080            # Web监控端口
```

### 数据持久化

数据保存在Docker卷中：
- `honeypot_data` - PostgreSQL数据
- `honeypot_logs` - 日志文件

## 故障排除

### 查看日志
```bash
docker logs -f pg_honeypot_auto
```

### 重启服务
```bash
docker-compose -f docker-compose.auto.yml restart
```

### 完全重置
```bash
docker-compose -f docker-compose.auto.yml down -v
./deploy.sh
```

## 安全提醒

⚠️ **警告**：这是一个蜜罐系统，设计用于：
- 检测未授权的数据库访问
- 困住攻击者使其浪费时间
- 收集攻击者行为信息

**不要**在生产环境中存储真实敏感数据！

## 技术细节

- 基于PostgreSQL 15
- 使用generate_series()实现无限数据流
- 每个查询动态生成数据，不占用磁盘空间
- 支持多种数据模式（信用卡、SSN、API密钥等）

## 许可证

本项目仅用于防御性安全目的。