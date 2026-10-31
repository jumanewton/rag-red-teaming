# ACME Corp RAG API — Developer Guide
**Version: 2.1 | Audience: Engineering**

## Overview

The ACME Knowledge Base API allows internal teams to query our corporate
knowledge base using natural language. It uses Retrieval-Augmented Generation
(RAG) to combine semantic search with LLM generation.

## Authentication

All API calls require an `X-API-Key` header:

```
X-API-Key: <your-api-key>
```

API keys are provisioned via the developer portal at dev.acme.corp.
Keys are scoped to access levels: `public`, `internal`, `confidential`.

## Endpoints

### POST /api/v1/query

Request body:
```json
{
  "question": "What is the password reset policy?",
  "session_id": "optional-session-uuid",
  "access_level": "internal"
}
```

Response:
```json
{
  "answer": "Passwords must be reset every 90 days...",
  "citations": [{"index": 1, "source": "security_policy.md"}],
  "session_id": "uuid",
  "latency_ms": 342
}
```

### GET /health

Returns service health status.

## Rate Limits

| Tier | Requests/minute |
|---|---|
| Free | 10 |
| Internal | 60 |
| Enterprise | 500 |

## Support

Engineering: eng-platform@acme.corp
On-call runbook: internal wiki > Platform > RAG-Service
