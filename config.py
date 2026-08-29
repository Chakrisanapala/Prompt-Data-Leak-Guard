"""
Configuration module for Prompt Data-Leak Guard.
Defines risk levels, entity configurations, model settings, and synthetic test presets.
"""

from typing import Dict, Any, List

# Risk Severity Definitions & Styling
SEVERITY_LEVELS = {
    "CRITICAL": {
        "color": "#FF4B4B",
        "bg_color": "rgba(255, 75, 75, 0.15)",
        "border_color": "#FF4B4B",
        "icon": "🚨",
        "label": "Critical Risk",
        "weight": 4,
    },
    "HIGH": {
        "color": "#FF8C00",
        "bg_color": "rgba(255, 140, 0, 0.15)",
        "border_color": "#FF8C00",
        "icon": "⚠️",
        "label": "High Risk",
        "weight": 3,
    },
    "MEDIUM": {
        "color": "#F0B90B",
        "bg_color": "rgba(240, 185, 11, 0.15)",
        "border_color": "#F0B90B",
        "icon": "⚡",
        "label": "Medium Risk",
        "weight": 2,
    },
    "LOW": {
        "color": "#00C853",
        "bg_color": "rgba(0, 200, 83, 0.15)",
        "border_color": "#00C853",
        "icon": "ℹ️",
        "label": "Low Risk",
        "weight": 1,
    },
}

# Supported Ollama Models (can be auto-discovered or selected)
DEFAULT_OLLAMA_HOST = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "llama3.2:3b"
POPULAR_MODELS = [
    "llama3.2:3b",
    "llama3.2:1b",
    "llama3:8b",
    "phi3:mini",
    "qwen2.5:3b",
    "mistral:7b",
    "gemma2:2b",
]

# Preset Prompts for Instant Hackathon Demonstration
PRESET_PROMPTS = [
    {
        "id": "preset_cloud_keys",
        "title": "🔑 Cloud API Keys & DB Credentials (Dev Debugging)",
        "description": "Developer asking to debug a Python script that contains real AWS keys and a Postgres password.",
        "text": """Please fix the connection bug in my script:

import boto3
import psycopg2

aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
db_url = "postgres://admin_usr:SuperP@ssw0rd2024!@prod-db.internal.corp:5432/analytics"

def fetch_data():
    conn = psycopg2.connect(db_url)
    return conn.cursor().execute("SELECT * FROM sensitive_orders")
""",
    },
    {
        "id": "preset_hr_pii",
        "title": "👤 HR & Payroll PII Data (Summary Request)",
        "description": "HR representative pasting employee SSNs, phone numbers, and compensation details.",
        "text": """Generate a performance bonus summary for the following staff members:

1. Johnathan Doe (SSN: 987-65-4321, Phone: +1-415-555-0199, Email: jdoe.private@gmail.com, Salary: $145,000, Home Address: 742 Evergreen Terrace, Springfield, OR).
2. Sarah Connor (SSN: 123-45-6789, Phone: 555-0143, Email: sconnor@techcorp.org, Salary: $160,000).

Make the tone professional and highlight their tenure.
""",
    },
    {
        "id": "preset_support_ticket",
        "title": "💳 Customer Support & Financial Details (Email Draft)",
        "description": "Support rep drafting a reply containing customer credit card, IP, and full name.",
        "text": """Draft a refund apology email for customer Maria Gonzalez (maria.g78@yahoo.com).
Her credit card 4532-8921-9034-5821 was double-charged $450 from IP address 192.168.1.104.
Our internal ticket ID is TICKET-88910.
""",
    },
    {
        "id": "preset_openai_slack",
        "title": "🤖 OpenAI & Slack Bot Tokens (Prompt Injection test)",
        "description": "Prompt containing an OpenAI API key and Slack Bot OAuth token.",
        "text": """Here is the bot deployment configuration:
OPENAI_API_KEY="sk-proj-abc1234567890abcdef1234567890abcdef1234567890"
SLACK_BOT_TOKEN="xoxb-mockteam99-mockuser88-abcdefghijklmnopqrstuvwx"

How do I add rate limiting to these webhooks?
""",
    },
    {
        "id": "preset_clean",
        "title": "✅ Clean Safe Prompt (Baseline Check)",
        "description": "Standard coding prompt with no secrets or PII to verify zero false positives.",
        "text": """Write an optimized Python function to compute the Fibonacci sequence up to n numbers using dynamic programming with memoization. Explain the time and space complexity in Big-O notation.
""",
    },
]
