#!/usr/bin/env python3

import sys
import json
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

# Configuration
SMTP_SERVER = '127.0.0.1'
SMTP_PORT = 25
SENDER_EMAIL = 'sender.email@gmail.com'  # Sender's email address
RECEIVER_EMAIL = 'wazuhcriticallog@gmail.com'  # Receiver's email address

# Logging Configuration
LOG_FILE = '/var/ossec/logs/custom-email_integration.log'
logging.basicConfig(filename=LOG_FILE,
                    filemode='a',
                    format='%(asctime)s %(levelname)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG)

def read_alert_file(file_path):
    """Reads the JSON alert file and returns the data."""
    try:
        with open(file_path, 'r', encoding='utf-8') as alert_file:
            return json.load(alert_file)
    except Exception as e:
        logging.error("Error reading alert file: %s", str(e))
        sys.exit(1)

def format_email_content(alert_data):
    """Formats the alert data into an HTML email template."""
    try:
        timestamp = alert_data.get('timestamp', 'N/A')
        location = alert_data.get('location', 'Unknown Location')
        rule_id = alert_data.get('rule', {}).get('id', 'N/A')
        rule_level = alert_data.get('rule', {}).get('level', 'N/A')
        description = alert_data.get('rule', {}).get('description', 'No Description Available')
        agent_id = alert_data.get('agent', {}).get('id', 'N/A')
        agent_name = alert_data.get('agent', {}).get('name', 'Unknown Agent')

        # Extract source IP from the alert
        src_ip = alert_data.get('data', {}).get('srcip', 'Unknown IP')

        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <h2 style="color: #d9534f;">🚨 Wazuh Alert Notification 🚨</h2>
            <p><strong>Timestamp:</strong> {timestamp}</p>
            <p><strong>Location:</strong> {location}</p>
            <p><strong>Rule:</strong> {rule_id} (Level {rule_level})</p>
            <p><strong>Description:</strong> {description}</p>
            <p><strong>Agent:</strong> {agent_name} (ID: {agent_id})</p>
            <p><strong>Source IP:</strong> {src_ip}</p>  <!-- Added Source IP -->
            <hr>
            <p style="color: #555;">📌 This is an automated notification from Wazuh.</p>
        </body>
        </html>
        """
        return html_content
    except Exception as e:
        logging.error("Error formatting email content: %s", str(e))
        sys.exit(1)

def send_email(subject, content):
    """Sends an HTML email notification."""
    try:
        message = MIMEMultipart()
        message['From'] = SENDER_EMAIL
        message['To'] = RECEIVER_EMAIL
        message['Subject'] = subject
        message.attach(MIMEText(content, 'html'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.send_message(message)

        logging.info("Email sent successfully to %s", RECEIVER_EMAIL)
    except Exception as e:
        logging.error("Failed to send email: %s", str(e))
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        logging.error("No alert file specified. Exiting.")
        sys.exit(1)

    alert_file_path = sys.argv[1]
    logging.info("Processing alert file: %s", alert_file_path)

    alert_data = read_alert_file(alert_file_path)
    email_content = format_email_content(alert_data)

    # Extracting description from alert_data
    description = alert_data.get('rule', {}).get('description', 'No Description Available')

    # Setting subject dynamically
    if description == "Invalid User successfully logged in":
        email_subject = "🚨 Invalid User successfully logged in"
    else:
        email_subject = "🚨 Wazuh Alert Notification"

    send_email(email_subject, email_content)

    logging.info("Script execution completed.")
    sys.exit(0)
