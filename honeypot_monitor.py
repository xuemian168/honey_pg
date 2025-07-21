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
from datetime import datetime
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
        
        if parsed_path.path == '/health':
            self._send_json_response(200, {"status": "healthy", "service": "honeypot_monitor"})
        
        elif parsed_path.path == '/':
            self._send_dashboard_html()
        
        elif parsed_path.path == '/api/alerts':
            self._send_alerts_api()
        
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
        self.wfile.write(json.dumps(data).encode())
    
    def _send_dashboard_html(self):
        """发送 Web 控制台 HTML"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        
        html = '''<!DOCTYPE html>
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
        .alerts-container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .alert { background: #ffebee; border: 1px solid #f44336; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .timestamp { color: #666; font-size: 0.9em; margin-top: 10px; }
        .no-alerts { text-align: center; color: #666; padding: 40px; }
        .refresh-btn { background: #2196F3; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        .refresh-btn:hover { background: #1976D2; }
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }
        .status-online { background-color: #4CAF50; }
        .status-offline { background-color: #f44336; }
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
        
        <div class="alerts-container">
            <h2>Recent Alerts</h2>
            <div id="alerts">Loading alerts...</div>
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
                    alertsContainer.innerHTML = data.reverse().map(alert => 
                        '<div class="alert">' +
                            '<strong>🚨 Honeypot Access Detected!</strong><br>' +
                            '<strong>Table:</strong> ' + (alert.table || 'unknown') + '<br>' +
                            '<strong>User:</strong> ' + (alert.user || 'unknown') + '<br>' +
                            '<strong>Client IP:</strong> ' + (alert.client_ip || 'unknown') + '<br>' +
                            '<strong>Message:</strong> ' + (alert.alert || 'Honeypot table accessed') +
                            '<div class="timestamp">⏰ ' + (alert.timestamp || 'unknown time') + '</div>' +
                        '</div>'
                    ).join('');
                })
                .catch(error => {
                    console.error('Error loading alerts:', error);
                    document.getElementById('alerts').innerHTML = '<div class="no-alerts">Error loading alerts. Check monitor service.</div>';
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
</html>'''
        
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