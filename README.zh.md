[English](./README.md) | 中文

# PostgreSQL 蜜罐数据表插件

一个 PostgreSQL 安全扩展，创建蜜罐表来检测未授权的数据库访问。当有人读取这些表时，会触发通知发送到指定的 API 端点。这是一个用于数据库管理员的防御性网络安全工具。

## 🚀 快速开始（推荐使用 Docker）

### 1. 一键启动
```bash
git clone <repository>
cd pg_honeypot
docker-compose -f docker-compose-simple.yml up -d
```

### 2. 测试蜜罐
```bash
# 连接数据库（密码：honeypot123）
psql -h localhost -U postgres -d postgres

# 查询蜜罐表触发警报
SELECT * FROM honeypot_customer_view LIMIT 1;
```

### 3. 查看警报
- **Web 控制台**: http://localhost:8090
- **API 接口**: http://localhost:8080

## 📋 功能特性

- 🍯 **蜜罐表**: 自动创建包含虚假敏感数据的表
- ⚠️ **实时警报**: 访问时立即发送 HTTP 通知
- 📊 **Web 控制台**: 查看警报历史和统计的中文界面
- 🐳 **容器化部署**: 一键启动，包含所有依赖
- 🔧 **开发友好**: 完整的构建系统和开发工具

## 🏗️ 系统架构

该系统包含以下组件：

### 核心服务
1. **PostgreSQL 数据库**: 主数据库，包含蜜罐功能（端口 5432）
2. **Python 警报监听器**: HTTP 服务器，接收蜜罐警报（端口 8080）
3. **警报转发器**: 从数据库读取警报并转发到 HTTP API
4. **Web 控制台**: 查看警报的简单界面（端口 8090）

### 数据流
```
蜜罐表访问 → PostgreSQL 日志 → 数据库警报表 → 转发器 → HTTP API → Web 控制台
```

## 📦 部署方式

### 选项 1: Docker Compose（推荐）

**启动服务**
```bash
docker-compose -f docker-compose-simple.yml up -d
```

**查看服务状态**
```bash
docker-compose -f docker-compose-simple.yml ps
```

**查看日志**
```bash
docker-compose -f docker-compose-simple.yml logs -f
```

**停止服务**
```bash
docker-compose -f docker-compose-simple.yml down
```

### 选项 2: 手动部署

**1. 安装依赖**
```bash
# 安装 PostgreSQL 开发包
sudo apt-get install postgresql-server-dev-all

# 安装 Python 依赖
pip install -r requirements.txt
```

**2. 编译扩展**
```bash
make
sudo make install
```

**3. 初始化数据库**
```sql
CREATE EXTENSION pg_honeypot;
```

**4. 启动 Python 服务**
```bash
# 启动警报监听器
python3 honeypot_listener.py &

# 启动转发器
python3 honeypot_forwarder.py &

# 启动 Web 控制台
cd dashboard && python3 dashboard.py &
```

## 🎯 使用指南

### 基本使用

**1. 连接数据库**
```bash
psql -h localhost -U postgres -d postgres
# 密码: honeypot123
```

**2. 查看可用的蜜罐表**
```sql
-- 查看所有蜜罐视图
\dv honeypot*

-- 蜜罐表包括：
-- honeypot_customer_view    (客户数据)
-- honeypot_financial_view   (财务记录) 
-- honeypot_employee_view    (员工信息)
```

**3. 触发蜜罐警报**
```sql
-- 查询任意蜜罐表都会触发警报
SELECT * FROM honeypot_customer_view LIMIT 3;
SELECT account_number, balance FROM honeypot_financial_view;
SELECT employee_id, salary FROM honeypot_employee_view;
```

**4. 查看警报记录**
```sql
-- 查看数据库中的警报记录
SELECT * FROM honeypot_alerts ORDER BY created_at DESC LIMIT 5;
```

### 高级配置

**创建自定义蜜罐表**
```sql
-- 创建新的蜜罐表
CREATE TABLE secret_projects (
    id SERIAL PRIMARY KEY,
    project_code VARCHAR(20) DEFAULT 'PROJ-' || LPAD(floor(random() * 10000)::TEXT, 4, '0'),
    classified_info TEXT DEFAULT 'Top Secret Project Data',
    budget DECIMAL(15,2) DEFAULT round((random() * 1000000)::numeric, 2)
);

-- 插入虚假数据
INSERT INTO secret_projects DEFAULT VALUES;

-- 创建蜜罐视图
CREATE VIEW honeypot_secrets_view AS 
SELECT *, log_honeypot_access_function('secret_projects') as _alert 
FROM secret_projects;

-- 授权给测试用户
GRANT SELECT ON honeypot_secrets_view TO honeypot_test;
```

**监控和警报**
```bash
# 实时查看 PostgreSQL 日志中的警报
docker-compose -f docker-compose-simple.yml logs -f postgres | grep "HONEYPOT ALERT"

# 查看 HTTP 监听器日志
docker-compose -f docker-compose-simple.yml logs -f honeypot_listener

# 查看警报转发器日志
docker-compose -f docker-compose-simple.yml logs -f honeypot_forwarder
```

## 🔧 开发和调试

### 开发环境设置
```bash
# 克隆项目
git clone <repository>
cd pg_honeypot

# 开发模式启动
make dev-setup

# 构建 Docker 镜像
make docker
```

### 调试命令
```bash
# 检查数据库连接
python3 honeypot_forwarder.py --check-db

# 测试 HTTP API
curl -X POST http://localhost:8080/alert \
  -H "Content-Type: application/json" \
  -d '{"alert":"测试警报","table":"test_table","user":"test_user"}'

# 查看警报 API 响应
curl http://localhost:8090/api/alerts | python3 -m json.tool
```

### 故障排除

**常见问题及解决方案**

1. **容器启动失败**
   ```bash
   # 检查端口占用
   netstat -tlnp | grep -E "(5432|8080|8090)"
   
   # 清理旧容器
   docker-compose -f docker-compose-simple.yml down -v
   ```

2. **数据库连接失败**
   ```bash
   # 检查数据库状态
   docker-compose -f docker-compose-simple.yml logs postgres
   
   # 测试连接
   docker exec pg_honeypot_simple pg_isready -U postgres
   ```

3. **警报不显示**
   ```bash
   # 检查警报转发器状态
   docker-compose -f docker-compose-simple.yml logs honeypot_forwarder
   
   # 手动触发警报测试
   docker exec pg_honeypot_simple psql -U postgres -d postgres -c "SELECT * FROM honeypot_customer_view LIMIT 1;"
   ```

## 🔒 安全注意事项

该扩展设计用于检测对数据库的未授权访问。请确保：

1. **隔离蜜罐表**: 将蜜罐表保存在单独的模式中
2. **合适的权限**: 使用适当的权限使表看起来合法
3. **监控 API 端点**: 监控 API 端点的警报
4. **保持代码安全**: 保持扩展代码安全并及时更新
5. **生产环境**: 在生产环境中更改默认密码并使用安全的 API 端点
6. **日志管理**: 定期清理和备份警报日志

## 📚 文件结构

```
pg_honeypot/
├── pg_honeypot.c              # PostgreSQL C 扩展源码
├── pg_honeypot.control        # 扩展控制文件
├── pg_honeypot--1.0.sql       # SQL 定义文件
├── honeypot_listener.py       # Python HTTP 警报监听器
├── honeypot_forwarder.py      # 数据库到 HTTP 的警报转发器
├── dashboard/
│   └── dashboard.py           # Web 控制台界面
├── docker-compose-simple.yml  # Docker Compose 配置
├── init-simple.sql            # 数据库初始化脚本
├── requirements.txt           # Python 依赖
├── Makefile                   # 构建系统
└── README.md                  # 英文文档
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。

## 📄 许可证

本项目仅用于教育和防御性安全目的。

---

**重要提醒**: 这是一个合法的防御性安全工具，旨在帮助数据库管理员检测未授权访问。请仅将其用于防御目的。
