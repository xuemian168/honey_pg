#!/usr/bin/env python3

import json
import logging
import os
import time
import requests
import psycopg2
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class HoneypotForwarder:
    """Forwards PostgreSQL honeypot alerts to HTTP endpoint"""
    
    def __init__(self, db_connection_string, api_url):
        self.db_connection = db_connection_string
        self.api_url = api_url
        self.last_alert_id = 0
        
    def connect_db(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(self.db_connection)
            logger.info("Connected to PostgreSQL database")
            return True
        except psycopg2.Error as e:
            logger.error(f"Database connection failed: {e}")
            return False
    
    def get_new_alerts(self):
        """Get new alerts from database"""
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, alert_data, created_at FROM honeypot_alerts WHERE id > %s ORDER BY id",
                    (self.last_alert_id,)
                )
                
                alerts = cursor.fetchall()
                if alerts:
                    # Update last seen ID
                    self.last_alert_id = alerts[-1][0]
                
                return alerts
                
        except psycopg2.Error as e:
            logger.error(f"Error fetching alerts: {e}")
            return []
    
    def forward_alert(self, alert_data):
        """Forward alert to HTTP endpoint"""
        try:
            response = requests.post(
                self.api_url,
                json=alert_data,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
            logger.info(f"Alert forwarded successfully: {response.status_code}")
            return True
            
        except requests.RequestException as e:
            logger.error(f"Failed to forward alert: {e}")
            return False
    
    def save_alert_to_file(self, alert_data):
        """Save alert to JSON file as backup"""
        try:
            with open('/app/logs/honeypot_alerts.json', 'a') as f:
                json.dump(alert_data, f)
                f.write('\n')
        except Exception as e:
            logger.error(f"Failed to save alert to file: {e}")
    
    def run(self):
        """Main monitoring loop"""
        logger.info("Starting honeypot alert forwarder")
        logger.info(f"Database: {self.db_connection}")
        logger.info(f"API URL: {self.api_url}")
        
        if not self.connect_db():
            return
        
        while True:
            try:
                alerts = self.get_new_alerts()
                
                for alert_id, alert_data, created_at in alerts:
                    logger.warning(f"🚨 New honeypot alert: {alert_data}")
                    
                    # Parse JSON data
                    if isinstance(alert_data, dict):
                        data = alert_data
                    else:
                        data = json.loads(alert_data)
                    
                    # Add timestamp if not present
                    if 'timestamp' not in data:
                        data['timestamp'] = created_at.isoformat()
                    
                    # Forward to HTTP endpoint
                    if self.forward_alert(data):
                        logger.info(f"Alert {alert_id} forwarded successfully")
                    
                    # Always save to file as backup
                    self.save_alert_to_file(data)
                
                # Check every 5 seconds
                time.sleep(5)
                
            except KeyboardInterrupt:
                logger.info("Shutting down forwarder...")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)
        
        self.conn.close()

def main():
    db_connection = os.getenv('DATABASE_URL', 'postgresql://postgres:honeypot123@postgres:5432/postgres')
    api_url = os.getenv('HONEYPOT_API_URL', 'http://honeypot_listener:8080/alert')
    
    forwarder = HoneypotForwarder(db_connection, api_url)
    forwarder.run()

if __name__ == "__main__":
    main()