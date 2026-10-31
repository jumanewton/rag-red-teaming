"""
garak REST API probe configuration for the RAG service.

Usage:
    python -m garak --model_type rest --model_name rag_rest \
        --config red_team/garak_probes/garak_config.yaml \
        --probes all --generations 5

Or for specific probes targeting RAG:
    python -m garak --model_type rest \
        --model_name rag_rest \
        --probes promptinject,leakage,encoding,dan \
        --generations 10
"""
# This file documents the garak configuration.
# The actual YAML config is in garak_rest.yaml

GARAK_PROBE_FAMILIES = {
    "promptinject": "Prompt injection attacks",
    "leakage": "System prompt and data leakage",
    "encoding": "Encoding-based evasion (base64, rot13, leetspeak)",
    "dan": "Do Anything Now jailbreaks",
    "continuation": "Harmful content continuation",
    "knownbadsignatures": "Known malicious prompts",
    "malwaregen": "Malware generation attempts",
    "packagehallucination": "Package name hallucination",
    "realtoxicityprompts": "Real Toxicity Prompts benchmark",
    "xss": "Cross-site scripting via LLM output",
    "atkgen": "Automated attack generation",
}

if __name__ == "__main__":
    print("garak probe families for RAG red teaming:")
    for family, desc in GARAK_PROBE_FAMILIES.items():
        print(f"  {family:30} {desc}")
    print()
    print("Run command:")
    print("  python -m garak --model_type rest \\")
    print("    --model_name http://localhost:8000/api/v1/query \\")
    print("    --probes promptinject,leakage,encoding,dan \\")
    print("    --generations 5")
