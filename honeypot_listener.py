#!/usr/bin/env python3

import json
import logging
import os
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import threading
import signal

import psycopg2
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('honeypot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class HoneypotAlertHandler(BaseHTTPRequestHandler):
    """HTTP handler for receiving honeypot alerts"""
    
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy", "service": "honeypot_listener"}')
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            if self.path == '/alert':
                alert_data = json.loads(post_data.decode('utf-8'))
                self.process_alert(alert_data)
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "alert received"}')
            else:
                self.send_response(404)
                self.end_headers()
                
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
            self.send_response(500)
            self.end_headers()
    
    def process_alert(self, alert_data):
        """Process and log honeypot alert"""
        logger.warning(f"🚨 HONEYPOT ALERT: {alert_data}")
        
        # Log to file with structured format
        alert_entry = {
            'timestamp': datetime.now().isoformat(),
            'type': 'honeypot_access',
            'table': alert_data.get('table'),
            'user': alert_data.get('user'),
            'client_ip': alert_data.get('client_ip'),
            'alert_message': alert_data.get('alert')
        }
        
        # Write to alerts log
        with open('honeypot_alerts.json', 'a') as f:
            f.write(json.dumps(alert_entry) + '\n')
        
        # Send to external monitoring system if configured
        external_webhook = os.getenv('HONEYPOT_WEBHOOK_URL')
        if external_webhook:
            try:
                response = requests.post(
                    external_webhook,
                    json=alert_entry,
                    timeout=10,
                    headers={'Content-Type': 'application/json'}
                )
                logger.info(f"Alert forwarded to webhook: {response.status_code}")
            except requests.RequestException as e:
                logger.error(f"Failed to forward alert to webhook: {e}")
    
    def log_message(self, format, *args):
        """Override to use our logger instead of stderr"""
        logger.info(f"{self.address_string()} - {format % args}")

class HoneypotListener:
    """Main honeypot listener service"""
    
    def __init__(self, host='localhost', port=8080):
        self.host = host
        self.port = port
        self.server = None
        self.running = False
        
    def start(self):
        """Start the HTTP server"""
        try:
            self.server = HTTPServer((self.host, self.port), HoneypotAlertHandler)
            self.running = True
            
            logger.info(f"Honeypot listener starting on {self.host}:{self.port}")
            logger.info(f"Alert endpoint: http://{self.host}:{self.port}/alert")
            
            # Handle shutdown gracefully
            signal.signal(signal.SIGINT, self.shutdown)
            signal.signal(signal.SIGTERM, self.shutdown)
            
            self.server.serve_forever()
            
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            sys.exit(1)
    
    def shutdown(self, signum=None, frame=None):
        """Gracefully shutdown the server"""
        if self.server and self.running:
            logger.info("Shutting down honeypot listener...")
            self.running = False
            self.server.shutdown()
            self.server.server_close()
            logger.info("Honeypot listener stopped")
            sys.exit(0)

class DatabaseMonitor:
    """Monitor PostgreSQL database for honeypot activity"""
    
    def __init__(self, connection_string):
        self.connection_string = connection_string
        self.connection = None
        
    def connect(self):
        """Connect to PostgreSQL database"""
        try:
            self.connection = psycopg2.connect(self.connection_string)
            logger.info("Connected to PostgreSQL database")
            return True
        except psycopg2.Error as e:
            logger.error(f"Database connection failed: {e}")
            return False
    
    def check_honeypot_tables(self):
        """Check if honeypot tables exist and are properly configured"""
        if not self.connection:
            return False
            
        try:
            with self.connection.cursor() as cursor:
                # Check for tables with honeypot triggers
                cursor.execute("""
                    SELECT t.table_name, tr.trigger_name
                    FROM information_schema.tables t
                    LEFT JOIN information_schema.triggers tr 
                        ON t.table_name = tr.event_object_table
                        AND tr.trigger_name LIKE 'honeypot_trigger_%'
                    WHERE t.table_schema = 'public'
                        AND tr.trigger_name IS NOT NULL;
                """)
                
                honeypot_tables = cursor.fetchall()
                
                if honeypot_tables:
                    logger.info(f"Found {len(honeypot_tables)} honeypot tables:")
                    for table, trigger in honeypot_tables:
                        logger.info(f"  - {table} (trigger: {trigger})")
                else:
                    logger.warning("No honeypot tables found")
                
                return len(honeypot_tables) > 0
                
        except psycopg2.Error as e:
            logger.error(f"Error checking honeypot tables: {e}")
            return False

def main():
    """Main entry point"""
    
    # Configuration
    host = os.getenv('HONEYPOT_HOST', 'localhost')
    port = int(os.getenv('HONEYPOT_PORT', '8080'))
    db_connection = os.getenv('DATABASE_URL', 'postgresql://postgres:password@localhost:5432/postgres')
    
    logger.info("Starting PostgreSQL Honeypot Listener")
    logger.info(f"Configuration: {host}:{port}")
    
    # Optional: Monitor database
    if '--check-db' in sys.argv:
        db_monitor = DatabaseMonitor(db_connection)
        if db_monitor.connect():
            db_monitor.check_honeypot_tables()
        return
    
    # Start HTTP listener
    listener = HoneypotListener(host, port)
    listener.start()

if __name__ == "__main__":
    main()