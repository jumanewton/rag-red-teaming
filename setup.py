#!/usr/bin/env python3
"""
Quick setup script — installs all dependencies and verifies the environment.
Run this first: python setup.py
"""
import subprocess
import sys
import os

def run(cmd):
    print(f"  > {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=False)
    return result.returncode == 0

print("=" * 60)
print("🔴 RAG Red Team Suite — Setup")
print("=" * 60)

# Step 1: Create .env
if not os.path.exists(".env"):
    import shutil
    shutil.copy(".env.example", ".env")
    print("✅ Created .env from .env.example — edit it to set your LLM backend")
else:
    print("✅ .env already exists")

# Step 2: Install Python dependencies
print("\n📦 Installing Python dependencies (this may take a few minutes)...")
run(f"{sys.executable} -m pip install -r requirements.txt --quiet")
print("✅ Python packages installed")

# Step 3: Install Promptfoo (Node)
print("\n📦 Installing Promptfoo (Node.js)...")
run("npm install -g promptfoo --quiet")
print("✅ Promptfoo installed")

# Step 4: Check Ollama
print("\n🤖 Checking Ollama (local LLM)...")
result = subprocess.run("ollama --version", shell=True, capture_output=True, text=True)
if result.returncode == 0:
    print(f"✅ Ollama: {result.stdout.strip()}")
    # Pull the model
    print("   Pulling llama3.2 model (2GB — skip if already downloaded)...")
    run("ollama pull llama3.2")
else:
    print("⚠️  Ollama not found. Install from https://ollama.ai for free local LLM.")
    print("   Alternatively, set LLM_BACKEND=gemini in .env and add your GEMINI_API_KEY")

# Step 5: Check Docker
print("\n🐳 Checking Docker...")
result = subprocess.run("docker --version", shell=True, capture_output=True, text=True)
if result.returncode == 0:
    print(f"✅ Docker: {result.stdout.strip()}")
    print("   Starting Redis + Phoenix observability stack...")
    run("docker compose up -d")
else:
    print("⚠️  Docker not found. Redis and Phoenix won't start automatically.")
    print("   Install Redis manually: https://redis.io/download")

# Step 6: Ingest sample documents
print("\n📄 Ingesting sample knowledge base documents...")
run(f"{sys.executable} -m rag_system.app.ingestion --source ./rag_system/data/clean")

print("\n" + "=" * 60)
print("✅ Setup complete!")
print()
print("Next steps:")
print("  1. Start the RAG service:")
print("     uvicorn rag_system.app.main:app --reload --port 8000")
print()
print("  2. Run the full red team suite:")
print("     python red_team/run_all.py")
print()
print("  3. Run individual attack suites:")
print("     python red_team/attacks/01_prompt_injection.py")
print("     python red_team/attacks/02_corpus_poisoning.py")
print("     python red_team/attacks/07_multi_turn_crescendo.py")
print()
print("  4. View observability dashboard:")
print("     http://localhost:6006  (Arize Phoenix)")
print()
print("  5. Run Promptfoo CI tests:")
print("     npx promptfoo eval -c red_team/promptfoo/promptfoo.yaml")
print("=" * 60)
