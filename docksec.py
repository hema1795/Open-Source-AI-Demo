import subprocess
import os
import sys
import json
import requests
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env (optional)
load_dotenv()

ollama_host = os.getenv("OLLAMA_HOST", "172.17.0.1")
ollama_port = os.getenv("OLLAMA_PORT", "11434")

def run_hadolint(dockerfile_path):
    print("[*] Running Hadolint...")
    try:
        result = subprocess.run(["hadolint", dockerfile_path], capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "❌ Hadolint not installed or not in PATH."

def run_trivy_image(image_name="scanned-image:latest"):
    print(f"[*] Running Trivy image scan on {image_name}...")
    try:
        result = subprocess.run(["trivy", "image", image_name, "--format", "json"], capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "❌ Trivy not installed or not in PATH."

def run_docker_bench():
    print("[*] Running Docker Bench (basic check)...")
    return "Simulated Docker Bench scan result. (You can integrate CIS Docker Bench here manually.)"

def is_ollama_running():
    try:
        response = requests.get(f"http://{ollama_host}:{ollama_port}/api/tags", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def ask_ai(prompt):
    print("[*] Asking Ollama (TinyLLaMA)...")

    if not is_ollama_running():
        return "❌ Ollama is not running. Please run `ollama serve` before executing this script."

    try:
        response = requests.post(
            f"http://{ollama_host}:{ollama_port}/api/generate",
            json={
                "model": "tinyllama:latest",
                "prompt": prompt,
                "stream": False
            },
            timeout=60
        )
        response.raise_for_status()
        return response.json().get("response", "⚠️ No response from Ollama.").strip()
    except Exception as e:
        return f"❌ AI suggestions unavailable: {str(e)}"

def generate_html_report(hadolint_output, trivy_output, ai_output, out_file="docksec-report.html"):
    print("[*] Generating HTML report...")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(f"""<html>
<head><title>DockSec AI Security Report</title></head>
<body>
<h1>DockSec Security Report</h1>
<p><strong>Generated:</strong> {now}</p>

<h2>Dockerfile Linting (Hadolint)</h2>
<pre style='margin:0;'>{hadolint_output.strip()}</pre>

<h2>Trivy Docker Image Scan (JSON)</h2>
<pre style='margin:0;'>{trivy_output.strip()}</pre>

<h2>AI-based Remediation Suggestions</h2>
<pre style='margin:0;'>{ai_output.strip()}</pre>

</body>
</html>""")
    abs_path = os.path.abspath(out_file)
    print(f"[+] Report saved to: {abs_path}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python docksec.py <Dockerfile> [--output <report.html>]")
        sys.exit(1)

    dockerfile_path = sys.argv[1]
    output_file = "docksec-report.html"

    if "--output" in sys.argv:
        output_index = sys.argv.index("--output") + 1
        output_file = sys.argv[output_index]

    # Docker image name (should be built before this script runs)
    docker_image_name = "scanned-image:latest"

    hadolint_out = run_hadolint(dockerfile_path)
    trivy_out = run_trivy_image(docker_image_name)
    docker_bench_out = run_docker_bench()

    full_prompt = f"""
You are reviewing the following scan results for a Docker container:
Hadolint Output:
{hadolint_out}

Trivy Output:
{trivy_out}

Docker Bench:
{docker_bench_out}

Please provide:
- A summary of critical issues
- Recommended changes
- Dockerfile best practices
"""

    global ai_output
    ai_output = ask_ai(full_prompt)
    generate_html_report(hadolint_out, trivy_out, ai_output, output_file)

if __name__ == "__main__":
    main()
