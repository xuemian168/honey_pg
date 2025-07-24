#!/usr/bin/env python3
"""
PostgreSQL 蜜罐监控服务
整合了 HTTP API、数据库监控和 Web 控制台的统一服务
"""

import json
import logging
import os
import sys
import time
import threading
from datetime import datetime, timedelta
from decimal import Decimal
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import signal

import psycopg2
import requests

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class HoneypotMonitorHandler(BaseHTTPRequestHandler):
    """统一的 HTTP 处理器：API + 控制台"""
    
    def do_GET(self):
        """处理 GET 请求：健康检查 + Web 控制台"""
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        
        if parsed_path.path == '/health':
            self._send_json_response(200, {"status": "healthy", "service": "honeypot_monitor"})
        
        elif parsed_path.path == '/':
            self._send_dashboard_html()
        
        elif parsed_path.path == '/api/alerts':
            self._send_alerts_api()
        
        elif parsed_path.path == '/api/honeypot/tables':
            self._get_honeypot_tables()
        
        elif parsed_path.path == '/api/honeypot/query':
            self._query_honeypot_table(params)
        
        elif parsed_path.path == '/api/honeypot/config':
            self._get_honeypot_config()
        
        else:
            self._send_json_response(404, {"error": "Not found"})
    
    def do_POST(self):
        """处理 POST 请求：接收警报"""
        if self.path == '/alert':
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                alert_data = json.loads(post_data.decode('utf-8'))
                
                self._process_alert(alert_data)
                self._send_json_response(200, {"status": "alert received"})
                
            except Exception as e:
                logger.error(f"Error processing alert: {e}")
                self._send_json_response(500, {"error": "Internal server error"})
        else:
            self._send_json_response(404, {"error": "Not found"})
    
    def _send_json_response(self, status_code, data):
        """发送 JSON 响应"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        # 处理特殊类型
        def custom_serializer(obj):
            if isinstance(obj, Decimal):
                return float(obj)
            elif hasattr(obj, 'isoformat'):  # datetime objects
                return obj.isoformat()
            elif hasattr(obj, '__float__'):
                return float(obj)
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        self.wfile.write(json.dumps(data, default=custom_serializer).encode())
    
    def _send_dashboard_html(self):
        """发送 Web 控制台 HTML"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PostgreSQL Honeypot Monitor</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat-card { background: #fff; padding: 20px; border-radius: 8px; flex: 1; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #f44336; }
        .stat-label { color: #666; margin-top: 5px; }
        .alerts-container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .alert { background: #ffebee; border: 1px solid #f44336; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .timestamp { color: #666; font-size: 0.9em; margin-top: 10px; }
        .no-alerts { text-align: center; color: #666; padding: 40px; }
        .refresh-btn { background: #2196F3; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        .refresh-btn:hover { background: #1976D2; }
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }
        .status-online { background-color: #4CAF50; }
        .status-offline { background-color: #f44336; }
        
        /* New styles for honeypot simulation */
        .simulation-container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .honeypot-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .honeypot-table th, .honeypot-table td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        .honeypot-table th { background: #f8f9fa; font-weight: 600; }
        .simulate-btn { background: #ff9800; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin: 5px; }
        .simulate-btn:hover { background: #f57c00; }
        .config-info { background: #e3f2fd; padding: 10px; border-radius: 4px; margin: 10px 0; font-size: 0.9em; }
        .data-preview { background: #f5f5f5; padding: 10px; border-radius: 4px; margin: 10px 0; font-family: monospace; font-size: 0.9em; overflow-x: auto; }
        .warning { background: #fff3cd; color: #856404; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: #e0e0e0; border-radius: 4px 4px 0 0; cursor: pointer; }
        .tab.active { background: #fff; font-weight: bold; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🍯 PostgreSQL Honeypot Monitor</h1>
            <div style="margin-bottom: 10px;">
                <span class="status-indicator status-online"></span>
                <span>Monitor Service Online</span>
                <button class="refresh-btn" onclick="loadAlerts()" style="float: right;">Refresh</button>
            </div>
            <div style="font-size: 0.9em; color: #666;">
                Real-time monitoring for PostgreSQL honeypot tables
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="total-alerts">0</div>
                <div class="stat-label">Total Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="unique-users">0</div>
                <div class="stat-label">Unique Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="unique-tables">0</div>
                <div class="stat-label">Tables Accessed</div>
            </div>
        </div>
        
        <div class="tabs">
            <div class="tab active" onclick="switchTab('alerts')">🚨 Alerts</div>
            <div class="tab" onclick="switchTab('simulation')">🎮 Simulation</div>
        </div>
        
        <div id="alerts-tab" class="tab-content active">
            <div class="alerts-container">
                <h2>Recent Alerts</h2>
                <div id="alerts">Loading alerts...</div>
            </div>
        </div>
        
        <div id="simulation-tab" class="tab-content">
            <div class="simulation-container">
                <h2>🎮 Honeypot Access Simulation</h2>
                <p>Simulate accessing honeypot tables to test the alert system and see infinite data generation.</p>
                
                <div class="warning">
                    ⚠️ <strong>Note:</strong> Simulated access will trigger real alerts. Tables with infinite data are limited to 100 rows for safety.
                </div>
                
                <div class="config-info" id="config-info">
                    Loading configuration...
                </div>
                
                <h3>Available Honeypot Tables</h3>
                <div id="honeypot-tables">Loading tables...</div>
                
                <h3>Query Results</h3>
                <div id="query-results">
                    <p style="color: #666;">Select a table above to simulate access</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        function loadAlerts() {
            fetch('/api/alerts')
                .then(r => r.json())
                .then(data => {
                    const alertsContainer = document.getElementById('alerts');
                    const totalAlerts = document.getElementById('total-alerts');
                    const uniqueUsers = document.getElementById('unique-users');
                    const uniqueTables = document.getElementById('unique-tables');
                    
                    if (data.length === 0) {
                        alertsContainer.innerHTML = '<div class="no-alerts">No alerts yet. When honeypot tables are accessed, alerts will appear here.</div>';
                        totalAlerts.textContent = '0';
                        uniqueUsers.textContent = '0';
                        uniqueTables.textContent = '0';
                        return;
                    }
                    
                    // Update statistics
                    totalAlerts.textContent = data.length;
                    uniqueUsers.textContent = new Set(data.map(alert => alert.user)).size;
                    uniqueTables.textContent = new Set(data.map(alert => alert.table)).size;
                    
                    // Display alerts
                    alertsContainer.innerHTML = data.reverse().map(alert => {
                        return '<div class="alert">' +
                            '<strong>🚨 Honeypot Access Detected!</strong><br>' +
                            '<strong>Table:</strong> ' + (alert.table || 'unknown') + '<br>' +
                            '<strong>User:</strong> ' + (alert.user || 'unknown') + '<br>' +
                            '<strong>Client IP:</strong> ' + (alert.client_ip || 'unknown') + '<br>' +
                            '<strong>Message:</strong> ' + (alert.alert || 'Honeypot table accessed') +
                            (alert.rows_accessed ? '<br><strong>Rows accessed:</strong> ' + alert.rows_accessed : '') +
                            '<div class="timestamp">⏰ ' + (alert.timestamp || 'unknown time') + '</div>' +
                        '</div>';
                    }).join('');
                })
                .catch(error => {
                    console.error('Error loading alerts:', error);
                    document.getElementById('alerts').innerHTML = '<div class="no-alerts">Error loading alerts. Check monitor service.</div>';
                });
        }
        
        function switchTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            
            // Mark tab as active
            event.target.classList.add('active');
            
            // Load data for simulation tab
            if (tabName === 'simulation') {
                loadHoneypotConfig();
                loadHoneypotTables();
            }
        }
        
        function loadHoneypotConfig() {
            fetch('/api/honeypot/config')
                .then(r => r.json())
                .then(data => {
                    if (data.config) {
                        const config = data.config;
                        document.getElementById('config-info').innerHTML = 
                            '<strong>Current Configuration:</strong><br>' +
                            '• Max rows per query: ' + (config.max_rows || 'Unlimited') + '<br>' +
                            '• Delay per row: ' + (config.delay_ms || '0') + 'ms<br>' +
                            '• Randomize data: ' + (config.randomize || 'false');
                    }
                })
                .catch(error => {
                    document.getElementById('config-info').innerHTML = 
                        '<span style="color: red;">Error loading configuration</span>';
                });
        }
        
        function loadHoneypotTables() {
            fetch('/api/honeypot/tables')
                .then(r => r.json())
                .then(data => {
                    if (data.tables && data.tables.length > 0) {
                        let html = '<table class="honeypot-table">';
                        html += '<tr><th>Table Name</th><th>Type</th><th>Seed Rows</th><th>Actions</th></tr>';
                        
                        data.tables.forEach(table => {
                            html += '<tr>';
                            html += '<td>' + table.table_name + '</td>';
                            html += '<td>' + table.table_type + '</td>';
                            html += '<td>' + (table.seed_rows || 'N/A') + '</td>';
                            html += '<td>';
                            html += '<button class="simulate-btn" onclick="simulateAccess(&quot;' + table.table_name + '&quot;, 5)">Query 5 rows</button>';
                            html += '<button class="simulate-btn" onclick="simulateAccess(&quot;' + table.table_name + '&quot;, 20)">Query 20 rows</button>';
                            if (table.table_type === 'infinite_honeypot') {
                                html += '<button class="simulate-btn" onclick="simulateAccess(&quot;' + table.table_name + '&quot;, 100)">Query 100 rows (Infinite)</button>';
                            }
                            html += '</td>';
                            html += '</tr>';
                        });
                        
                        html += '</table>';
                        document.getElementById('honeypot-tables').innerHTML = html;
                    } else {
                        document.getElementById('honeypot-tables').innerHTML = 
                            '<p style="color: #666;">No honeypot tables found</p>';
                    }
                })
                .catch(error => {
                    document.getElementById('honeypot-tables').innerHTML = 
                        '<p style="color: red;">Error loading tables</p>';
                });
        }
        
        function simulateAccess(tableName, limit) {
            const resultsDiv = document.getElementById('query-results');
            resultsDiv.innerHTML = '<p style="color: #666;">Querying ' + tableName + '...</p>';
            
            fetch('/api/honeypot/query?table=' + tableName + '&limit=' + limit)
                .then(r => r.json())
                .then(data => {
                    let html = '<h4>Query Results for ' + data.table + '</h4>';
                    
                    if (data.alert_triggered) {
                        html += '<div style="background: #ffebee; padding: 10px; margin: 10px 0; border-radius: 4px;">';
                        html += '🚨 <strong>Alert triggered!</strong> Check the Alerts tab.';
                        html += '</div>';
                    }
                    
                    html += '<p><strong>Rows returned:</strong> ' + data.row_count + '</p>';
                    
                    if (data.rows && data.rows.length > 0) {
                        html += '<div class="data-preview">';
                        html += '<table style="width: 100%;">';
                        
                        // Header
                        html += '<tr>';
                        Object.keys(data.rows[0]).forEach(key => {
                            html += '<th style="padding: 5px; border: 1px solid #ddd;">' + key + '</th>';
                        });
                        html += '</tr>';
                        
                        // Data rows
                        data.rows.forEach(row => {
                            html += '<tr>';
                            Object.values(row).forEach(value => {
                                html += '<td style="padding: 5px; border: 1px solid #ddd;">' + value + '</td>';
                            });
                            html += '</tr>';
                        });
                        
                        html += '</table>';
                        html += '</div>';
                        
                        if (limit >= 100) {
                            html += '<div class="warning">';
                            html += '💡 <strong>Infinite Data Note:</strong> This table generates infinite data. ';
                            html += 'In a real attack scenario, queries without LIMIT would run forever!';
                            html += '</div>';
                        }
                    }
                    
                    resultsDiv.innerHTML = html;
                    
                    // Refresh alerts to show the new one
                    setTimeout(loadAlerts, 1000);
                })
                .catch(error => {
                    resultsDiv.innerHTML = '<p style="color: red;">Error querying table: ' + error.message + '</p>';
                });
        }
        
        // Load alerts on page load
        loadAlerts();
        
        // Auto-refresh every 30 seconds
        setInterval(loadAlerts, 30000);
        
        // Update status indicator
        setInterval(() => {
            fetch('/health')
                .then(r => r.json())
                .then(data => {
                    document.querySelector('.status-indicator').className = 'status-indicator status-online';
                })
                .catch(() => {
                    document.querySelector('.status-indicator').className = 'status-indicator status-offline';
                });
        }, 10000);
    </script>
</body>
</html>"""
        
        self.wfile.write(html.encode('utf-8'))
    
    def _send_alerts_api(self):
        """发送警报 API 响应"""
        alerts = []
        alerts_file = '/app/logs/honeypot_alerts.json'
        
        try:
            if os.path.exists(alerts_file):
                with open(alerts_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                alerts.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
        except Exception as e:
            logger.error(f"Error reading alerts file: {e}")
        
        # Return last 100 alerts
        response_data = alerts[-100:] if alerts else []
        self._send_json_response(200, response_data)
    
    def _process_alert(self, alert_data):
        """处理警报数据"""
        logger.warning(f"🚨 HONEYPOT ALERT: {alert_data}")
        
        # 保存到文件
        self._save_alert_to_file(alert_data)
        
        # 转发到外部 webhook（如果配置了）
        external_webhook = os.getenv('HONEYPOT_WEBHOOK_URL')
        if external_webhook:
            try:
                response = requests.post(
                    external_webhook,
                    json=alert_data,
                    timeout=10,
                    headers={'Content-Type': 'application/json'}
                )
                logger.info(f"Alert forwarded to webhook: {response.status_code}")
            except requests.RequestException as e:
                logger.error(f"Failed to forward alert to webhook: {e}")
    
    def _save_alert_to_file(self, alert_data):
        """保存警报到文件"""
        try:
            with open('/app/logs/honeypot_alerts.json', 'a') as f:
                json.dump(alert_data, f)
                f.write('\n')
        except Exception as e:
            logger.error(f"Failed to save alert to file: {e}")
    
    def _get_honeypot_tables(self):
        """获取蜜罐表列表"""
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            
            conn_str = os.getenv('DATABASE_URL', 'postgresql://postgres:honeypot123@postgres:5432/postgres')
            conn = psycopg2.connect(conn_str)
            
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # 查找所有蜜罐表
                cur.execute("""
                    SELECT 
                        v.viewname as table_name,
                        'infinite_honeypot' as table_type,
                        COALESCE((
                            SELECT COUNT(*) 
                            FROM information_schema.tables 
                            WHERE table_name = v.viewname || '_seed'
                            AND table_schema = 'public'
                        ), 0)::int as seed_rows
                    FROM pg_views v
                    WHERE v.viewname LIKE '%honeypot%' OR v.viewname LIKE 'test_%' OR v.viewname LIKE 'demo_%'
                    AND EXISTS (
                        SELECT 1 FROM pg_tables 
                        WHERE tablename = v.viewname || '_seed'
                    )
                    UNION ALL
                    SELECT 
                        tablename as table_name,
                        'regular_honeypot' as table_type,
                        0 as seed_rows
                    FROM pg_tables
                    WHERE tablename LIKE '%honeypot%' OR tablename LIKE 'demo_%' 
                    AND tablename NOT LIKE '%_seed'
                    AND NOT EXISTS (
                        SELECT 1 FROM pg_views WHERE viewname = pg_tables.tablename
                    )
                    ORDER BY table_name
                """)
                tables = cur.fetchall()
                
                # 转换数字类型
                for table in tables:
                    for key, value in table.items():
                        if hasattr(value, '__float__'):
                            table[key] = float(value)
                
            conn.close()
            self._send_json_response(200, {"tables": tables})
            
        except Exception as e:
            logger.error(f"Error getting honeypot tables: {e}")
            self._send_json_response(500, {"error": str(e)})
    
    def _query_honeypot_table(self, params):
        """查询蜜罐表数据"""
        table_name = params.get('table', [''])[0]
        limit = int(params.get('limit', ['10'])[0])
        
        if not table_name:
            self._send_json_response(400, {"error": "Missing table parameter"})
            return
        
        # 安全限制
        if limit > 100:
            limit = 100
        
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            
            conn_str = os.getenv('DATABASE_URL', 'postgresql://postgres:honeypot123@postgres:5432/postgres')
            conn = psycopg2.connect(conn_str)
            
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # 检查是否是无限数据表（通过查看是否有对应的_seed表）
                cur.execute(
                    "SELECT EXISTS(SELECT 1 FROM pg_tables WHERE tablename = %s)",
                    (table_name + '_seed',)
                )
                is_infinite_table = cur.fetchone()['exists']
                
                if is_infinite_table:
                    # 对于无限数据表，尝试生成无限数据
                    try:
                        # 使用新的安全无限查询函数
                        cur.execute(
                            "SELECT * FROM safe_infinite_query(%s, %s)",
                            (table_name, limit)
                        )
                        logger.info(f"Successfully used safe_infinite_query for {table_name}")
                    except psycopg2.Error as e1:
                        logger.warning(f"safe_infinite_query failed for {table_name}: {e1}")
                        try:
                            # 尝试使用我们的测试函数
                            cur.execute(
                                "SELECT * FROM test_honeypot_query(%s, %s)",
                                (table_name, limit)
                            )
                            logger.info(f"Successfully used test_honeypot_query for {table_name}")
                        except psycopg2.Error as e2:
                            logger.warning(f"test_honeypot_query failed for {table_name}: {e2}")
                            # 最后回退到直接查询，但标记为遗留表
                            cur.execute(
                                f"SELECT *, 'Limited to existing data - run create_infinite_demo_fixed.sql for full infinite data' as _note FROM {table_name} LIMIT %s",
                                (limit,)
                            )
                            logger.info(f"Fallback to direct query for {table_name}")
                else:
                    # 普通表直接查询
                    cur.execute(
                        f"SELECT * FROM {table_name} LIMIT %s",
                        (limit,)
                    )
                
                rows = cur.fetchall()
                
                # 转换时间戳和数字类型
                for row in rows:
                    for key, value in row.items():
                        if hasattr(value, 'isoformat'):
                            row[key] = value.isoformat()
                        elif hasattr(value, '__float__'):
                            row[key] = float(value)
                
            conn.close()
            
            # 如果是无限数据表但返回行数太少，生成虚拟数据
            if is_infinite_table and len(rows) < limit and limit > 10:
                logger.info(f"Generating virtual data for {table_name}: requested {limit}, got {len(rows)}")
                # 生成额外的假数据
                import hashlib
                import random
                
                base_rows = rows[:] if rows else []
                start_id = len(base_rows) + 1
                
                # 根据表名确定数据模式
                if 'financial' in table_name or 'account' in table_name:
                    for i in range(start_id, limit + 1):
                        fake_row = {
                            'id': i,
                            'account_number': f'ACC-{str(i * 97).zfill(8)}',
                            'balance': round(random.uniform(100, 100000), 2),
                            'routing_number': str(random.randint(100000000, 999999999)),
                            'created_at': (datetime.now() + timedelta(seconds=i)).isoformat(),
                            '_generated': 'virtual_data'
                        }
                        rows.append(fake_row)
                elif 'customer' in table_name:
                    for i in range(start_id, limit + 1):
                        fake_row = {
                            'id': i,
                            'customer_id': f'CUST-{str(i * 13).zfill(6)}',
                            'ssn': f'{str((i * 11) % 999).zfill(3)}-{str((i * 13) % 99).zfill(2)}-{str((i * 17) % 9999).zfill(4)}',
                            'created_at': (datetime.now() + timedelta(seconds=i)).isoformat(),
                            '_generated': 'virtual_data'
                        }
                        rows.append(fake_row)
                elif 'employee' in table_name:
                    for i in range(start_id, limit + 1):
                        data_types = ['credit_card', 'ssn', 'api_key', 'password']
                        data_type = data_types[i % len(data_types)]
                        
                        if data_type == 'credit_card':
                            sensitive = f'4532-{str((i * 1234) % 10000).zfill(4)}-{str((i * 5678) % 10000).zfill(4)}-{str((i * 9012) % 10000).zfill(4)}'
                        elif data_type == 'ssn':
                            sensitive = f'{str((i * 11) % 999).zfill(3)}-{str((i * 13) % 99).zfill(2)}-{str((i * 17) % 9999).zfill(4)}'
                        elif data_type == 'api_key':
                            sensitive = f'sk-{hashlib.md5(str(i).encode()).hexdigest()[:32]}'
                        else:
                            sensitive = f'Password{i}!@#'
                        
                        fake_row = {
                            'id': i,
                            'employee_id': f'EMP-{str(i).zfill(6)}',
                            'sensitive_data': sensitive,
                            'data_type': data_type,
                            'created_at': (datetime.now() + timedelta(seconds=i)).isoformat(),
                            '_generated': 'virtual_data'
                        }
                        rows.append(fake_row)
                else:
                    # 通用无限数据
                    for i in range(start_id, limit + 1):
                        fake_row = {
                            'id': i,
                            'sensitive_data': f'Generated data #{i}: {hashlib.md5(str(i).encode()).hexdigest()[:16]}',
                            'created_at': (datetime.now() + timedelta(seconds=i)).isoformat(),
                            '_generated': 'virtual_data'
                        }
                        rows.append(fake_row)
            
            # 创建模拟警报
            alert_data = {
                "alert": "Honeypot table accessed via monitor",
                "table": table_name,
                "user": "monitor_simulation",
                "client_ip": self.address_string(),
                "timestamp": datetime.now().isoformat(),
                "rows_accessed": len(rows)
            }
            self._process_alert(alert_data)
            
            self._send_json_response(200, {
                "table": table_name,
                "rows": rows,
                "row_count": len(rows),
                "alert_triggered": True,
                "data_source": "virtual_infinite" if is_infinite_table and len(rows) > 10 else "database"
            })
            
        except Exception as e:
            logger.error(f"Error querying honeypot table: {e}")
            self._send_json_response(500, {"error": str(e)})
    
    def _get_honeypot_config(self):
        """获取蜜罐配置"""
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            
            conn_str = os.getenv('DATABASE_URL', 'postgresql://postgres:honeypot123@postgres:5432/postgres')
            conn = psycopg2.connect(conn_str)
            
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT 
                        current_setting('pg_honeypot.max_rows_per_query', true) as max_rows,
                        current_setting('pg_honeypot.delay_ms_per_row', true) as delay_ms,
                        current_setting('pg_honeypot.randomize', true) as randomize
                """)
                config = cur.fetchone()
                
            conn.close()
            self._send_json_response(200, {"config": config})
            
        except Exception as e:
            logger.error(f"Error getting honeypot config: {e}")
            self._send_json_response(500, {"error": str(e)})
    
    def log_message(self, format, *args):
        """重写日志方法使用我们的logger"""
        logger.info(f"{self.address_string()} - {format % args}")

class DatabaseMonitor:
    """数据库监控器"""
    
    def __init__(self, db_connection_string, api_url):
        self.db_connection = db_connection_string
        self.api_url = api_url
        self.last_alert_id = 0
        self.running = False
        
    def connect_db(self):
        """连接数据库"""
        try:
            self.conn = psycopg2.connect(self.db_connection)
            self.conn.set_session(autocommit=True)
            logger.info("Connected to PostgreSQL database")
            return True
        except psycopg2.Error as e:
            logger.error(f"Database connection failed: {e}")
            return False
    
    def get_new_alerts(self):
        """获取新警报"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, alert_data, created_at FROM honeypot_alerts WHERE id > %s ORDER BY id",
                    (self.last_alert_id,)
                )
                
                alerts = cursor.fetchall()
                if alerts:
                    self.last_alert_id = alerts[-1][0]
                
                return alerts
                
        except psycopg2.Error as e:
            logger.error(f"Error fetching alerts: {e}")
            return []
    
    def forward_alert(self, alert_data):
        """转发警报到本地 API"""
        try:
            response = requests.post(
                self.api_url,
                json=alert_data,
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            response.raise_for_status()
            return True
            
        except requests.RequestException as e:
            logger.error(f"Failed to forward alert: {e}")
            return False
    
    def start_monitoring(self):
        """启动监控线程"""
        def monitor_loop():
            logger.info("Database monitor started")
            
            if not self.connect_db():
                logger.error("Failed to connect to database, monitor disabled")
                return
            
            self.running = True
            
            while self.running:
                try:
                    alerts = self.get_new_alerts()
                    
                    for alert_id, alert_data, created_at in alerts:
                        # 解析 JSON 数据
                        if isinstance(alert_data, dict):
                            data = alert_data
                        else:
                            data = json.loads(alert_data)
                        
                        # 添加时间戳
                        if 'timestamp' not in data:
                            data['timestamp'] = created_at.isoformat()
                        
                        # 转发到 HTTP API
                        if self.forward_alert(data):
                            logger.info(f"Alert {alert_id} processed successfully")
                    
                    # 每5秒检查一次
                    time.sleep(5)
                    
                except Exception as e:
                    logger.error(f"Error in monitor loop: {e}")
                    time.sleep(10)
            
            if hasattr(self, 'conn'):
                self.conn.close()
        
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
        return thread
    
    def stop(self):
        """停止监控"""
        self.running = False

class HoneypotMonitor:
    """主监控服务"""
    
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.server = None
        self.monitor = None
        
    def start(self):
        """启动服务"""
        try:
            # 确保日志目录存在
            os.makedirs('/app/logs', exist_ok=True)
            
            # 启动数据库监控器
            db_connection = os.getenv('DATABASE_URL', 'postgresql://postgres:honeypot123@postgres:5432/postgres')
            api_url = f'http://localhost:{self.port}/alert'
            
            self.monitor = DatabaseMonitor(db_connection, api_url)
            monitor_thread = self.monitor.start_monitoring()
            
            # 启动 HTTP 服务器
            self.server = HTTPServer((self.host, self.port), HoneypotMonitorHandler)
            
            logger.info(f"🍯 Honeypot Monitor starting on {self.host}:{self.port}")
            logger.info(f"Web Dashboard: http://localhost:{self.port}")
            logger.info(f"API Endpoint: http://localhost:{self.port}/alert")
            logger.info(f"Health Check: http://localhost:{self.port}/health")
            
            # 设置信号处理
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            self.server.serve_forever()
            
        except Exception as e:
            logger.error(f"Failed to start monitor: {e}")
            sys.exit(1)
    
    def _signal_handler(self, signum, frame):
        """信号处理器"""
        logger.info("Shutting down honeypot monitor...")
        
        if self.monitor:
            self.monitor.stop()
        
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        
        logger.info("Honeypot monitor stopped")
        sys.exit(0)

def main():
    """主入口"""
    host = os.getenv('HONEYPOT_HOST', '0.0.0.0')
    port = int(os.getenv('HONEYPOT_PORT', '8080'))
    
    monitor = HoneypotMonitor(host, port)
    monitor.start()

if __name__ == "__main__":
    main()