#!/usr/bin/env python3

import json
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime

class DashboardHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html = '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PostgreSQL Honeypot Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .alert { background: #ffebee; border: 1px solid #f44336; padding: 15px; margin: 10px 0; border-radius: 4px; }
        .timestamp { color: #666; font-size: 0.9em; margin-top: 10px; }
        .no-alerts { text-align: center; color: #666; padding: 40px; }
        .refresh-btn { background: #2196F3; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        .refresh-btn:hover { background: #1976D2; }
        .stats { display: flex; gap: 20px; margin-bottom: 20px; }
        .stat-card { background: #fff; padding: 20px; border-radius: 8px; flex: 1; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #f44336; }
        .stat-label { color: #666; margin-top: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🍯 PostgreSQL Honeypot Dashboard</h1>
            <button class="refresh-btn" onclick="loadAlerts()">Refresh Alerts</button>
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
                <div class="stat-label">Unique Tables</div>
            </div>
        </div>
        
        <div style="background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h2>Recent Alerts</h2>
            <div id="alerts">Loading...</div>
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
                            '<strong>🚨 Honeypot Table Accessed!</strong><br>' +
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
                    document.getElementById('alerts').innerHTML = '<div class="no-alerts">Error loading alerts. Make sure the honeypot service is running.</div>';
                });
        }
        
        // Load alerts on page load
        loadAlerts();
        
        // Auto-refresh every 30 seconds
        setInterval(loadAlerts, 30000);
    </script>
</body>
</html>'''
            
            self.wfile.write(html.encode())
            
        elif self.path == '/api/alerts':
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
                print(f"Error reading alerts file: {e}")
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            # Return last 100 alerts
            response_data = alerts[-100:] if alerts else []
            self.wfile.write(json.dumps(response_data).encode())
        
        else:
            # Return 404 for other paths
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    port = 8090
    server = HTTPServer(('0.0.0.0', port), DashboardHandler)
    print(f'🍯 Honeypot Dashboard running on http://localhost:{port}')
    print('Dashboard will auto-refresh every 30 seconds')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down dashboard...')
        server.shutdown()