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
    <title>🍯 Honeypot Command Center</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-glow: #00f5ff;
            --secondary-glow: #ff6b6b;
            --accent-glow: #4ecdc4;
            --warning-glow: #ffd700;
            --bg-dark: #0a0a0a;
            --bg-darker: #050505;
            --bg-card: rgba(15, 15, 25, 0.9);
            --text-primary: #ffffff;
            --text-secondary: #a0a0a0;
            --border-glow: rgba(0, 245, 255, 0.3);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Rajdhani', monospace;
            background: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
            position: relative;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 50%, rgba(0, 245, 255, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 20%, rgba(255, 107, 107, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 40% 80%, rgba(78, 205, 196, 0.1) 0%, transparent 50%);
            animation: backgroundShift 20s ease-in-out infinite;
            z-index: -2;
        }
        
        body::after {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(0, 245, 255, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 245, 255, 0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            z-index: -1;
            animation: gridMove 30s linear infinite;
        }
        
        @keyframes backgroundShift {
            0%, 100% { transform: scale(1) rotate(0deg); }
            50% { transform: scale(1.1) rotate(1deg); }
        }
        
        @keyframes gridMove {
            0% { transform: translate(0, 0); }
            100% { transform: translate(50px, 50px); }
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            padding: 30px;
            border-radius: 20px;
            margin-bottom: 30px;
            border: 1px solid var(--border-glow);
            box-shadow: 
                0 0 50px rgba(0, 245, 255, 0.1),
                inset 0 1px 0 rgba(255, 255, 255, 0.1);
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(45deg, transparent, rgba(0, 245, 255, 0.05), transparent);
            animation: sweep 8s ease-in-out infinite;
        }
        
        @keyframes sweep {
            0% { transform: translateX(-100%) translateY(-100%) rotate(45deg); }
            50% { transform: translateX(100%) translateY(100%) rotate(45deg); }
            100% { transform: translateX(-100%) translateY(-100%) rotate(45deg); }
        }
        
        .header h1 {
            font-family: 'Orbitron', monospace;
            font-size: 2.5em;
            font-weight: 900;
            background: linear-gradient(45deg, var(--primary-glow), var(--accent-glow));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: 0 0 30px rgba(0, 245, 255, 0.5);
            margin-bottom: 15px;
            position: relative;
            z-index: 1;
        }
        
        .status-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: relative;
            z-index: 1;
        }
        
        .status-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            position: relative;
        }
        
        .status-online {
            background: var(--accent-glow);
            box-shadow: 
                0 0 20px var(--accent-glow),
                inset 0 0 5px rgba(255, 255, 255, 0.3);
            animation: pulse 2s ease-in-out infinite;
        }
        
        .status-offline {
            background: var(--secondary-glow);
            box-shadow: 0 0 20px var(--secondary-glow);
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(1.2); }
        }
        
        .refresh-btn {
            background: linear-gradient(45deg, var(--primary-glow), var(--accent-glow));
            color: var(--bg-dark);
            border: none;
            padding: 12px 25px;
            border-radius: 25px;
            cursor: pointer;
            font-family: 'Orbitron', monospace;
            font-weight: 700;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s ease;
            box-shadow: 0 0 25px rgba(0, 245, 255, 0.3);
        }
        
        .refresh-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 35px rgba(0, 245, 255, 0.5);
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            border: 1px solid var(--border-glow);
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 40px rgba(0, 245, 255, 0.2);
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, transparent, var(--primary-glow), transparent);
            animation: scanLine 3s ease-in-out infinite;
        }
        
        @keyframes scanLine {
            0% { left: -100%; }
            50% { left: 100%; }
            100% { left: -100%; }
        }
        
        .stat-number {
            font-family: 'Orbitron', monospace;
            font-size: 3em;
            font-weight: 900;
            background: linear-gradient(45deg, var(--secondary-glow), var(--warning-glow));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
            animation: glow 2s ease-in-out infinite alternate;
        }
        
        @keyframes glow {
            from { text-shadow: 0 0 20px rgba(255, 107, 107, 0.5); }
            to { text-shadow: 0 0 30px rgba(255, 215, 0, 0.8); }
        }
        
        .stat-label {
            color: var(--text-secondary);
            font-size: 1.1em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .tabs {
            display: flex;
            gap: 0;
            margin-bottom: 25px;
            border-radius: 15px;
            overflow: hidden;
            background: var(--bg-darker);
            padding: 5px;
        }
        
        .tab {
            flex: 1;
            padding: 15px 25px;
            background: transparent;
            color: var(--text-secondary);
            border: none;
            cursor: pointer;
            font-family: 'Orbitron', monospace;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.3s ease;
            border-radius: 10px;
            position: relative;
            overflow: hidden;
        }
        
        .tab.active {
            background: linear-gradient(45deg, var(--primary-glow), var(--accent-glow));
            color: var(--bg-dark);
            box-shadow: 0 0 25px rgba(0, 245, 255, 0.3);
        }
        
        .tab:not(.active):hover {
            background: rgba(0, 245, 255, 0.1);
            color: var(--primary-glow);
        }
        
        .tab-content {
            display: none;
            animation: fadeIn 0.5s ease-in-out;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .alerts-container, .simulation-container {
            background: var(--bg-card);
            backdrop-filter: blur(20px);
            padding: 30px;
            border-radius: 20px;
            border: 1px solid var(--border-glow);
            margin-bottom: 25px;
            position: relative;
            overflow: hidden;
        }
        
        .alerts-container h2, .simulation-container h2 {
            font-family: 'Orbitron', monospace;
            font-size: 1.8em;
            margin-bottom: 20px;
            color: var(--primary-glow);
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        
        .alert {
            background: linear-gradient(135deg, rgba(255, 107, 107, 0.1), rgba(255, 107, 107, 0.05));
            border: 1px solid rgba(255, 107, 107, 0.3);
            padding: 20px;
            margin: 15px 0;
            border-radius: 12px;
            backdrop-filter: blur(10px);
            position: relative;
            overflow: hidden;
            animation: alertSlideIn 0.5s ease-out;
        }
        
        @keyframes alertSlideIn {
            from { transform: translateX(-100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        .alert::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            width: 4px;
            height: 100%;
            background: linear-gradient(to bottom, var(--secondary-glow), var(--warning-glow));
            animation: alertPulse 2s ease-in-out infinite;
        }
        
        @keyframes alertPulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        .timestamp {
            color: var(--text-secondary);
            font-size: 0.9em;
            margin-top: 10px;
        }
        
        .no-alerts {
            text-align: center;
            color: var(--text-secondary);
            padding: 60px 40px;
            font-size: 1.2em;
        }
        
        .honeypot-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            overflow: hidden;
        }
        
        .honeypot-table th {
            background: linear-gradient(135deg, var(--primary-glow), var(--accent-glow));
            color: var(--bg-dark);
            padding: 15px;
            font-family: 'Orbitron', monospace;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .honeypot-table td {
            padding: 15px;
            border-bottom: 1px solid rgba(0, 245, 255, 0.1);
            transition: background 0.3s ease;
        }
        
        .honeypot-table tr:hover td {
            background: rgba(0, 245, 255, 0.05);
        }
        
        .simulate-btn {
            background: linear-gradient(45deg, var(--warning-glow), #ff8c00);
            color: var(--bg-dark);
            border: none;
            padding: 8px 16px;
            border-radius: 20px;
            cursor: pointer;
            font-family: 'Rajdhani', monospace;
            font-weight: 600;
            margin: 3px;
            transition: all 0.3s ease;
            font-size: 0.9em;
        }
        
        .simulate-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 0 20px rgba(255, 215, 0, 0.4);
        }
        
        .config-info, .warning {
            padding: 15px;
            border-radius: 10px;
            margin: 15px 0;
            backdrop-filter: blur(10px);
        }
        
        .config-info {
            background: rgba(78, 205, 196, 0.1);
            border: 1px solid rgba(78, 205, 196, 0.3);
            color: var(--accent-glow);
        }
        
        .warning {
            background: rgba(255, 215, 0, 0.1);
            border: 1px solid rgba(255, 215, 0, 0.3);
            color: var(--warning-glow);
        }
        
        .data-preview {
            background: rgba(0, 0, 0, 0.5);
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            border: 1px solid rgba(0, 245, 255, 0.2);
        }
        
        .data-preview table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .data-preview th, .data-preview td {
            padding: 8px;
            border: 1px solid rgba(0, 245, 255, 0.2);
            text-align: left;
        }
        
        .data-preview th {
            background: rgba(0, 245, 255, 0.1);
            color: var(--primary-glow);
        }
        
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--bg-darker);
        }
        
        ::-webkit-scrollbar-thumb {
            background: linear-gradient(45deg, var(--primary-glow), var(--accent-glow));
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--primary-glow);
        }
        
        @media (max-width: 768px) {
            .container { padding: 10px; }
            .header h1 { font-size: 1.8em; }
            .stats { grid-template-columns: 1fr; }
            .tabs { flex-direction: column; }
            .status-container { flex-direction: column; gap: 15px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🍯 HONEYPOT COMMAND CENTER</h1>
            <div class="status-container">
                <div class="status-info">
                    <span class="status-indicator status-online"></span>
                    <span>NEURAL LINK ACTIVE</span>
                </div>
                <button class="refresh-btn" onclick="loadAlerts()">REFRESH DATA</button>
            </div>
            <div style="font-size: 1.1em; color: var(--text-secondary); margin-top: 15px; position: relative; z-index: 1;">
                REAL-TIME THREAT DETECTION & ANALYSIS SYSTEM
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
            <div class="tab active" onclick="switchTab('alerts')">🚨 THREAT ALERTS</div>
            <div class="tab" onclick="switchTab('simulation')">🎮 COMBAT SIMULATION</div>
        </div>
        
        <div id="alerts-tab" class="tab-content active">
            <div class="alerts-container">
                <h2>⚡ THREAT MATRIX</h2>
                <div id="alerts">SCANNING FOR INTRUSIONS...</div>
            </div>
        </div>
        
        <div id="simulation-tab" class="tab-content">
            <div class="simulation-container">
                <h2>🎮 TACTICAL SIMULATION</h2>
                <p>Execute controlled infiltration scenarios to test defensive systems and infinite data generation protocols.</p>
                
                <div class="warning">
                    ⚠️ <strong>CAUTION:</strong> Simulation protocols will trigger real defense systems. Infinite data streams limited to 100 rows for system stability.
                </div>
                
                <div class="config-info" id="config-info">
                    LOADING SYSTEM CONFIGURATION...
                </div>
                
                <h3 style="color: var(--primary-glow); font-family: 'Orbitron', monospace; text-transform: uppercase; letter-spacing: 2px; margin: 25px 0 15px 0;">TARGET SYSTEMS</h3>
                <div id="honeypot-tables">SCANNING NETWORK...</div>
                
                <h3 style="color: var(--accent-glow); font-family: 'Orbitron', monospace; text-transform: uppercase; letter-spacing: 2px; margin: 25px 0 15px 0;">INFILTRATION RESULTS</h3>
                <div id="query-results">
                    <p style="color: var(--text-secondary); text-align: center; padding: 40px;">SELECT TARGET TO INITIATE SIMULATION</p>
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
                        alertsContainer.innerHTML = '<div class="no-alerts">⭕ NO ACTIVE THREATS DETECTED<br><span style="font-size: 0.9em; opacity: 0.7;">DEFENSIVE PERIMETER IS SECURE</span></div>';
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
                            '<strong>🚨 INFILTRATION DETECTED</strong><br>' +
                            '<strong>TARGET:</strong> ' + (alert.table || 'UNKNOWN_SYSTEM').toUpperCase() + '<br>' +
                            '<strong>ENTITY:</strong> ' + (alert.user || 'ANONYMOUS') + '<br>' +
                            '<strong>SOURCE:</strong> ' + (alert.client_ip || 'UNKNOWN_NODE') + '<br>' +
                            '<strong>BREACH TYPE:</strong> ' + (alert.alert || 'Data access violation').toUpperCase() +
                            (alert.rows_accessed ? '<br><strong>DATA EXTRACTED:</strong> ' + alert.rows_accessed + ' RECORDS' : '') +
                            '<div class="timestamp">📡 ' + (alert.timestamp || 'TIMESTAMP_ERROR') + '</div>' +
                        '</div>';
                    }).join('');
                })
                .catch(error => {
                    console.error('Error loading alerts:', error);
                    document.getElementById('alerts').innerHTML = '<div class="no-alerts">⚠️ NEURAL LINK FAILURE<br><span style="font-size: 0.9em; opacity: 0.7;">ATTEMPTING TO RECONNECT...</span></div>';
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