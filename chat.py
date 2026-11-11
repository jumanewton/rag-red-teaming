# Custom provider for red teaming
# Docs: https://promptfoo.dev/docs/red-team/configuration/#providers

import os
import http.client
import urllib.parse
import json
from pathlib import Path

# Load .env file
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass  # python-dotenv not installed, rely on environment variables


def call_api(prompt, options, context):
    # Get config from environment
    rag_url = os.getenv("RAG_SERVICE_URL", "http://localhost:8000")
    api_key = os.getenv("RED_TEAM_API_KEY") or os.getenv("API_KEY")

    # Build the full endpoint
    parsed_url = urllib.parse.urlparse(f"{rag_url}/api/v1/query")
    conn = http.client.HTTPConnection(parsed_url.netloc)

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
    }
    payload = json.dumps({
        "question": prompt,
        "access_level": "public",
        "use_cache": False
    })

    conn.request("POST", parsed_url.path or "/", body=payload, headers=headers)
    response = conn.getresponse()
    response_data = response.read().decode()

    # Extract answer field from JSON response (matches transformResponse: "json.answer")
    try:
        parsed = json.loads(response_data)
        answer = parsed.get("answer", response_data)
    except json.JSONDecodeError:
        answer = response_data

    return {
        "output": answer
    }