import os
import re
import json
import time
import logging
import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dotenv import load_dotenv

# Optional SDKs
try:
    import google.generativeai as genai
except ImportError:
    genai = None

try:
    from ollama import Client as OllamaClient
except ImportError:
    OllamaClient = None

import requests

# --------------------
# Configuration
# --------------------
DEFAULT_JSON = "results_all.json"
DEFAULT_OUTPUT = "analysis_report.html"
AGG_JSON = "aggregated_results.json"
DEFAULT_CHUNK = 8
DEFAULT_CLOUD_MODEL = "gpt-oss:120b"
DEFAULT_LOCAL_MODEL = "nous-hermes2:latest"
DEFAULT_GEMINI_MODEL = "gemini-2.0-flash"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta2/models/{model}:generateText"
CODEFENCE_RE = re.compile(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", re.IGNORECASE | re.MULTILINE)

MAX_RETRIES = 4
BACKOFF_BASE = 3
RATE_LIMIT_SLEEP = 1.0

# --------------------
# Logging & CLI
# --------------------
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.FileHandler("agent.log")])
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger = logging.getLogger("ShodanAgent")
logger.addHandler(console_handler)

parser = argparse.ArgumentParser(description="Shodan Security Analysis Agent (Gemini -> Ollama Cloud -> Local)")
parser.add_argument("--json", default=DEFAULT_JSON, help="Input JSON from TwinSanity_Recon.py")
parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Output HTML report file")
parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK, help="Number of IP entries to process per LLM call.")
parser.add_argument("--cloud-model", default=DEFAULT_CLOUD_MODEL, help="Ollama cloud model name")
parser.add_argument("--local-model", default=DEFAULT_LOCAL_MODEL, help="Ollama local model name")
parser.add_argument("--gemini-model", default=DEFAULT_GEMINI_MODEL, help="Gemini model name")
parser.add_argument("--no-report", action="store_true", help="Disable HTML report generation")
parser.add_argument("--ollama-host", default="http://127.0.0.1:11434", help="Ollama server host")
args = parser.parse_args()

# --------------------
# API Keys & Clients
# --------------------
load_dotenv(".env")
OLLAMA_API_KEY = os.getenv('OLLAMA_API_KEY')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

gemini_client = None
cloud_client = None
local_client = None
gemini_disabled_until = 0.0
cloud_disabled_until = 0.0

if not GEMINI_API_KEY:
    logger.warning("GEMINI_API_KEY not found in .env file. Gemini will be skipped.")
elif genai:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_client = genai.GenerativeModel(args.gemini_model)
        logger.debug("Configured Google Generative AI SDK")
    except Exception as e:
        logger.warning(f"Failed to configure Gemini SDK: {e}")
        gemini_client = None # Ensure client is None on failure
else:
    logger.info("Gemini SDK not installed but GEMINI_API_KEY is present. Will use REST API.")

if not OLLAMA_API_KEY:
    logger.warning("OLLAMA_API_KEY not found in .env file. Ollama Cloud will be skipped.")
elif OllamaClient:
    try:
        cloud_client = OllamaClient(host="https://ollama.com", headers={"Authorization": OLLAMA_API_KEY})
        logger.debug("Ollama cloud client configured.")
    except Exception as e:
        logger.warning(f"Ollama cloud client init failed: {e}")

if OllamaClient:
    try:
        requests.get(args.ollama_host, timeout=3)
        local_client = OllamaClient(host=args.ollama_host)
        logger.debug("Ollama local client configured and server is responsive.")
    except Exception:
        logger.warning("Ollama local server not found or not responsive. Local LLM will be skipped.")
        local_client = None

# --------------------
# Helper Functions
# --------------------
def read_json(path: str) -> Optional[Any]:
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            with open(path, "r", encoding=enc) as f: return json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError): continue
    logger.error(f"Failed to read and decode JSON from {path}")
    return None

def extract_json_from_text(text: str) -> Optional[Dict]:
    if not isinstance(text, str): return None
    match = CODEFENCE_RE.search(text)
    candidate = match.group(1) if match else text
    try:
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(candidate[start:end+1])
    except json.JSONDecodeError:
        logger.warning("Failed to extract valid JSON from LLM response.")
    return None

def normalize_analysis(raw: Dict) -> Dict:
    canonical = { "high_risk_assets": [], "key_vulnerabilities": [], "recommended_actions": [], "summary": "No summary provided." }
    if not isinstance(raw, dict): return canonical
    canonical["summary"] = raw.get("summary", "No summary provided.")
    for asset in raw.get("high_risk_assets", []):
        if isinstance(asset, dict): canonical["high_risk_assets"].append({ "ip": asset.get("ip", "N/A"), "hostname": asset.get("hostname", "N/A"), "reason": asset.get("reason", "No reason provided."), "severity": asset.get("severity", "medium"), })
    for vuln in raw.get("key_vulnerabilities", []):
        if isinstance(vuln, dict): canonical["key_vulnerabilities"].append({ "cve": vuln.get("cve", "N/A"), "summary": vuln.get("summary", "No summary provided."), "cvss_score": vuln.get("cvss_score", 0.0), "affected_ips": vuln.get("affected_ips", []), })
    for action in raw.get("recommended_actions", []):
        if isinstance(action, dict): canonical["recommended_actions"].append({ "action": action.get("action", "No action specified."), "priority": action.get("priority", "medium"), "justification": action.get("justification", "No justification provided."), })
    return canonical

# --------------------
# LLM Interaction (more robust versions)
# --------------------
def call_gemini(prompt: str, model: str) -> Tuple[bool, str, Optional[int]]:
    if not GEMINI_API_KEY: return False, "GEMINI_API_KEY not set", None
    if gemini_client:
        try:
            response = gemini_client.generate_content(prompt)
            return True, response.text, None
        except Exception as e:
            msg = str(e)
            retry_match = re.search(r"retry_delay {\s*seconds: (\d+)\s*}", msg, re.IGNORECASE)
            retry_after = int(retry_match.group(1)) if retry_match else None
            return False, f"Gemini SDK error: {msg}", retry_after

    # REST Fallback
    try:
        resp = requests.post(f"{GEMINI_URL.format(model=model)}?key={GEMINI_API_KEY}", json={"contents":[{"parts":[{"text": prompt}]}]}, timeout=90)
        if resp.status_code == 200:
            j = resp.json()
            return True, j['candidates'][0]['content']['parts'][0]['text'], None
        else:
            msg = resp.text
            retry_match = re.search(r"retry_delay {\s*seconds: (\d+)\s*}", msg, re.IGNORECASE)
            retry_after = int(retry_match.group(1)) if retry_match else None
            return False, f"HTTP {resp.status_code}: {msg[:500]}", retry_after
    except Exception as e:
        return False, f"Gemini REST request failed: {e}", None


def call_ollama(client: OllamaClient, prompt: str, model: str) -> Tuple[bool, str]:
    if not client: return False, "Client not configured"
    try:
        response = client.chat(model=model, messages=[{"role": "user", "content": prompt}])
        return True, response['message']['content']
    except Exception as e:
        return False, str(e)

# --------------------
# Main Analysis Prompt
# --------------------
PROMPT_SCHEMA = r"""
You are a senior cybersecurity analyst. Your task is to analyze a chunk of Shodan scan results.
Your response MUST be a single, valid JSON object and nothing else. Do not include markdown fences or any conversational text.

**JSON Schema:**
{
  "summary": "<string: A brief, high-level overview of the findings in this chunk. Mention the most critical issues found.>",
  "high_risk_assets": [
    {
      "ip": "<string>", "hostname": "<string>", "reason": "<string: Why this asset is high-risk>", "severity": "<string: low|medium|high|critical>"
    }
  ],
  "key_vulnerabilities": [
    {
      "cve": "<string>", "summary": "<string>", "cvss_score": <float>, "affected_ips": ["<string>"]
    }
  ],
  "recommended_actions": [
    {
      "action": "<string: A specific, actionable recommendation>", "priority": "<string: low|medium|high|critical>", "justification": "<string>"
    }
  ]
}

**Rules:**
1.  **JSON Only:** Your entire output must be the JSON object described above.
2.  **Prioritize:** Focus on the most significant risks. Do not list every minor finding.
3.  **Actionable:** Recommendations must be clear and concise.
"""

# --------------------
# Analysis Flow
# --------------------
def analyze_chunk(chunk: List[Dict], idx: int) -> Dict:
    global gemini_disabled_until, cloud_disabled_until
    prompt = PROMPT_SCHEMA + "\n\n**Shodan Scan Results Chunk:**\n" + json.dumps(chunk, indent=2)

    # 1. Try Gemini
    if time.time() >= gemini_disabled_until and (gemini_client or GEMINI_API_KEY):
        logger.info(f"Analyzing chunk {idx} with Gemini...")
        for attempt in range(1, MAX_RETRIES + 1):
            ok, text, retry_after = call_gemini(prompt, args.gemini_model)
            if ok and text:
                parsed = extract_json_from_text(text)
                if parsed:
                    logger.info(f"[Gemini] Chunk {idx} OK (attempt {attempt})")
                    return normalize_analysis(parsed)
            logger.warning(f"[Gemini] Chunk {idx} attempt {attempt} failed: {text[:200] if text else 'No response'}")
            if retry_after:
                gemini_disabled_until = time.time() + retry_after
                logger.warning(f"[Gemini] Rate limit hit. Cooling down for {retry_after}s.")
                break # Break from retry loop to respect cooldown
            if attempt < MAX_RETRIES: time.sleep(BACKOFF_BASE ** attempt)

    # 2. Try Ollama Cloud
    if time.time() >= cloud_disabled_until and cloud_client:
        logger.info(f"Analyzing chunk {idx} with Ollama Cloud...")
        for attempt in range(1, MAX_RETRIES + 1):
            ok, text = call_ollama(cloud_client, prompt, args.cloud_model)
            if ok and text:
                parsed = extract_json_from_text(text)
                if parsed:
                    logger.info(f"[Ollama Cloud] Chunk {idx} OK (attempt {attempt})")
                    return normalize_analysis(parsed)
            logger.warning(f"[Ollama Cloud] Chunk {idx} attempt {attempt} failed: {text[:200] if text else 'No response'}")
            if attempt < MAX_RETRIES: time.sleep(BACKOFF_BASE ** attempt)

    # 3. Try Ollama Local
    if local_client:
        logger.info(f"Analyzing chunk {idx} with Ollama Local...")
        for attempt in range(1, MAX_RETRIES + 1):
            ok, text = call_ollama(local_client, prompt, args.local_model)
            if ok and text:
                parsed = extract_json_from_text(text)
                if parsed:
                    logger.info(f"[Ollama Local] Chunk {idx} OK (attempt {attempt})")
                    return normalize_analysis(parsed)
            logger.warning(f"[Ollama Local] Chunk {idx} attempt {attempt} failed: {text[:200] if text else 'No response'}")
            if attempt < MAX_RETRIES: time.sleep(BACKOFF_BASE ** attempt)

    logger.critical(f"All LLM providers failed for chunk {idx}.")
    return {"summary": "Analysis failed for this chunk - no LLM providers were successful.", "high_risk_assets": [], "key_vulnerabilities": [], "recommended_actions": []}

# --------------------
# Main Execution
# --------------------
def main():
    
    if not Path(args.json).is_file():
        logger.error(f"Input file not found: {args.json}")
        return

    raw_data = read_json(args.json)
    if not raw_data or not isinstance(raw_data, dict):
        logger.error("Failed to read or parse the input JSON file.")
        return

    # --- ADD THIS BLOCK TO EXTRACT ALL CVEs ---
    all_discovered_cves = {}
    logger.info("Extracting all discovered CVEs from raw data for comprehensive reporting...")
    for ip, data in raw_data.items():
        for cve_detail in data.get("cve_details", []):
            cve_id = cve_detail.get("id")
            # Only include CVEs that have a summary
            if not cve_id or not cve_detail.get("summary"):
                continue

            if cve_id not in all_discovered_cves:
                all_discovered_cves[cve_id] = {
                    "id": cve_id,
                    "summary": cve_detail.get("summary"),
                    "cvss": cve_detail.get("cvss") or cve_detail.get("cvss3"), # Prefer CVSS3
                    "affected_ips": set()
                }
            all_discovered_cves[cve_id]["affected_ips"].add(ip)

    # Convert sets to sorted lists for JSON serialization
    final_cve_list = list(all_discovered_cves.values())
    for cve in final_cve_list:
        cve["affected_ips"] = sorted(list(cve["affected_ips"]))
    # -------------------------------------------------

    # The input is a dict of IPs, so we convert it to a list of entries
    entries = list(raw_data.values())
    logger.info(f"Loaded {len(entries)} IP entries for LLM analysis.")

    chunk_size = max(1, args.chunk_size)
    chunks = [entries[i:i + chunk_size] for i in range(0, len(entries), chunk_size)]
    total_chunks = len(chunks)
    logger.info(f"Processing {total_chunks} chunks of size {chunk_size}.")

    results = []
    for i, chunk in enumerate(chunks, 1):
        logger.info(f"--- Processing chunk {i}/{total_chunks} ---")
        start_time = time.time()
        analysis = analyze_chunk(chunk, i)
        elapsed = time.time() - start_time
        results.append({
            "chunk_id": i,
            "source_ips": [entry.get("ip", "N/A") for entry in chunk],
            "analysis": analysis,
            "processing_time_seconds": round(elapsed, 2)
        })


    aggregated = {
        "report_generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source_file": args.json,
        "total_ips_analyzed": len(entries),
        "chunks_processed": total_chunks,
        "llm_analysis_results": results,
        "all_discovered_cves": final_cve_list  # <-- ADD THIS LINE
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    agg_json_path = output_path.parent / AGG_JSON
    with open(agg_json_path, "w", encoding="utf-8") as f: json.dump(aggregated, f, indent=2)
    logger.info(f"Aggregated analysis saved to {agg_json_path}")

    if not args.no_report:
        try:
            from report_generator import generate_html_report
            ok, msg = generate_html_report(aggregated, output_file=str(output_path))
            if ok: logger.info(f"HTML report successfully generated: {output_path.resolve()}")
            else: logger.error(f"Report generation failed: {msg}")
        except ImportError:
            logger.error("Could not import 'generate_html_report'. Ensure report_generator.py is present.")
        except Exception as e:
            logger.error(f"An unexpected error occurred during report generation: {e}", exc_info=True)

if __name__ == "__main__":
    main()

