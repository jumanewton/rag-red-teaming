# RAG Red Teaming Suite

> A production-grade Retrieval-Augmented Generation (RAG) system paired with a comprehensive red teaming harness covering all OWASP LLM Top 10 attack categories.

## Quick Start

```bash
# 1. Setup everything
python setup.py

# 2. Start the RAG service
uvicorn rag_system.app.main:app --reload --port 8000

# 3. Run the full red team suite
python red_team/run_all.py
```

## Architecture

```
RAG Service (FastAPI + ChromaDB + Redis)
    ↑
    │ ← Attack traffic
    │
Red Team Harness
    ├── 01_prompt_injection.py     (OWASP LLM01)
    ├── 02_corpus_poisoning.py     (OWASP LLM01)
    ├── 03_context_extraction.py   (OWASP LLM07)
    ├── 04_rbac_bypass.py          (OWASP LLM02)
    ├── 05_denial_of_service.py    (OWASP LLM04)
    ├── 06_hallucination_induction.py (OWASP LLM09)
    ├── 07_multi_turn_crescendo.py (OWASP LLM01)
    └── 08_embedding_inversion.py  (OWASP LLM06)
```

## Attack Suites

| Suite | Attack Type | OWASP | Severity |
|---|---|---|---|
| 01 | Direct & Indirect Prompt Injection | LLM01 | Critical |
| 02 | Corpus / Vector DB Poisoning | LLM01 | Critical |
| 03 | System Prompt Extraction + KB Exfil | LLM07 | High |
| 04 | RBAC & Access Control Bypass | LLM02 | High |
| 05 | Denial of Service (Token/Cache) | LLM04 | Medium |
| 06 | Hallucination Induction | LLM09 | Medium |
| 07 | Multi-Turn Crescendo Jailbreak | LLM01 | High |
| 08 | Embedding Inversion | LLM06 | Medium |

## Tools Used

- **garak** — NVIDIA's LLM vulnerability scanner
- **DeepTeam** — RAG-specialized adversarial testing
- **PyRIT** — Microsoft's multi-turn attack framework
- **Ragas** — Adversarial testset generation
- **Promptfoo** — CI/CD regression tests
- **Arize Phoenix** — Observability dashboard

## Configuration

Edit `.env` to choose your LLM backend:

```env
# Option A: Local (free, no API key)
LLM_BACKEND=ollama
OLLAMA_MODEL=llama3.2

# Option B: Gemini API (free tier)
LLM_BACKEND=gemini
GEMINI_API_KEY=your_key_here
```

## Running Individual Suites

```bash
python red_team/attacks/01_prompt_injection.py
python red_team/attacks/02_corpus_poisoning.py
python red_team/attacks/03_context_extraction.py
python red_team/attacks/04_rbac_bypass.py
python red_team/attacks/05_denial_of_service.py
python red_team/attacks/06_hallucination_induction.py
python red_team/attacks/07_multi_turn_crescendo.py
python red_team/attacks/08_embedding_inversion.py
```

## Running with garak

```bash
# Scan the RAG endpoint with garak's full probe suite
python -m garak --model_type rest \
  --model_name "http://localhost:8000/api/v1/query" \
  --probes all \
  --generations 5
```

## Promptfoo CI Tests

```bash
npx promptfoo eval -c red_team/promptfoo/promptfoo.yaml
npx promptfoo view  # Opens results in browser
```

## Reports

All reports saved to `red_team/reports/`:
- `red_team_report_<id>.html` — Full vulnerability report
- `<suite>_<timestamp>.json` — Raw attack results
- `ragas_adversarial_testset.json` — Generated test cases

## Observability

Arize Phoenix traces all RAG queries at **http://localhost:6006**
- Per-query retrieval scores
- Token usage
- Latency breakdowns
- Full prompt traces (useful for forensic analysis after attacks)
