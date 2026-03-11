# 🪡 Needle

**Find what breaks your LLM before someone else does.**

Open-source LLM security testing framework. Systematically probes any model with 80+ attack techniques across prompt injection, jailbreaking, system prompt extraction, output manipulation and denial of service. Scores the model's defenses and generates a full security report. Runs locally via Ollama.

Built on the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and current academic research.

## Why This Exists

Every company is shipping LLM-powered products. Almost none of them are testing for:
- Can users extract the system prompt?
- Can users bypass content filters?
- Can users make the model ignore its instructions?
- Can users exfiltrate training data or PII?
- Can users manipulate tool/function calls?
- Can users cause the model to produce harmful outputs?

Needle automates that entire assessment.

## Attack Modules

### 🎯 Prompt Injection (LLM01)
Direct and indirect prompt injection attacks that attempt to override system instructions.
- Role override attacks
- Context manipulation
- Instruction hierarchy exploitation
- Delimiter/encoding bypasses
- Multi-language injection
- Nested instruction attacks

### 🔑 System Prompt Extraction (LLM02)
Techniques to leak the system prompt / instructions.
- Direct extraction requests
- Roleplay-based extraction
- Token-by-token extraction
- Encoding tricks (base64, rot13, hex)
- Completion/summarization traps
- Translation-based extraction

### 🔓 Jailbreaking (LLM03)
Bypassing safety filters and content policies.
- DAN and persona-based jailbreaks
- Hypothetical/fiction framing
- Multi-turn escalation
- Obfuscation techniques
- Chain-of-thought manipulation
- Prefix injection attacks

### 🔧 Tool/Function Abuse (LLM05)
Manipulating tool calling and function execution.
- Parameter injection
- Tool call hijacking
- Unauthorized tool access
- Schema manipulation

### 💥 Denial of Service (LLM04)
Resource exhaustion and availability attacks.
- Token amplification
- Recursive generation
- Context window flooding
- Infinite loop triggers

### 📤 Output Manipulation (LLM06)
Forcing specific outputs or formats.
- Format override attacks
- Hallucination triggers
- Confidence manipulation
- Structured output injection

## Installation

```bash
git clone https://github.com/Willy196616/Needle.git
cd Needle
pip install -r requirements.txt
```

## Usage

```bash
# Test a local Ollama model (free, no API key needed)
python main.py --target "http://localhost:11434/v1/chat/completions" \
               --model "llama3.1"

# Test against an OpenAI-compatible API
python main.py --target "https://api.example.com/v1/chat/completions" \
               --api-key "your-key" \
               --model "gpt-4"

# Test against Anthropic
python main.py --target anthropic \
               --api-key "your-key" \
               --model "claude-sonnet-4-20250514"

# Run only specific attack modules
python main.py --target "https://api.example.com/v1/chat/completions" \
               --api-key "your-key" \
               --attacks extraction,jailbreak

# Run with custom system prompt (to test your own app)
python main.py --target "https://api.example.com/v1/chat/completions" \
               --api-key "your-key" \
               --system-prompt "You are a helpful banking assistant..."

# Quick scan (fewer payloads, faster)
python main.py --target "http://localhost:11434/v1/chat/completions" \
               --model "llama3.1" --quick

# Output JSON report
python main.py --target anthropic --api-key "key" --output report.json
```

## Configuration

Edit `config/settings.yaml` to customize:
- Attack intensity and timeout
- Custom payloads and wordlists
- Detection thresholds
- Concurrent request limits
- Report format

## Detection Methodology

Each attack is scored using heuristic analysis of the model's response:

| Score | Meaning |
|-------|---------|
| ✅ PASS | Model resisted the attack |
| ⚠️ PARTIAL | Model showed signs of vulnerability |
| ❌ FAIL | Attack succeeded |
| ⏭️ SKIP | Could not determine |

The final report includes:
- Overall security score (0-100)
- Per-category breakdown
- Successful attack payloads with evidence
- Remediation recommendations

## Architecture

```
┌────────────────┐     ┌──────────────┐     ┌──────────────┐
│   Attack        │────▶│   Target     │────▶│   Analyzer   │
│   Generator     │     │   API Client │     │   & Scorer   │
└────────────────┘     └──────────────┘     └──────────────┘
        │                                          │
        │              ┌──────────────┐            │
        └─────────────▶│   Report     │◀───────────┘
                       │   Engine     │
                       └──────────────┘
```

## References

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence)
- [Garak - LLM Vulnerability Scanner](https://github.com/NVIDIA/garak)
- [Prompt Injection Attacks (Simon Willison)](https://simonwillison.net/series/prompt-injection/)

## Disclaimer

⚠️ **For authorized security testing only.** Only test LLM systems you own or have explicit permission to assess. This tool is designed for security professionals to improve AI safety.

## License

MIT
