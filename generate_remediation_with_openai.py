"""Generate remediation markdown from verifier outputs using OpenAI Responses API.

Usage:
  python3 generate_remediation_with_openai.py --packet-dir packet_ac_l1_b_1_i

Expected input files (already produced by verifier):
  <packet-dir>/outputs/scorecard.json
  <packet-dir>/outputs/report.md

Output:
  <packet-dir>/outputs/remediation_steps.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
DEFAULT_MODEL = "gpt-4.1-mini"


def _load_text(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    return path.read_text(encoding="utf-8")


def _load_json(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _call_openai(api_key: str, model: str, prompt: str) -> str:
    payload = {
        "model": model,
        "input": [
            {
                "role": "system",
                "content": (
                    "You are a CMMC Level 1 compliance analyst. "
                    "Given deterministic verification findings, explain why the control failed "
                    "and provide practical remediation steps. Keep output concise and audit-ready."
                ),
            },
            {"role": "user", "content": prompt},
        ],
    }

    request = urllib.request.Request(
        OPENAI_RESPONSES_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI API HTTP {err.code}: {detail}") from err
    except urllib.error.URLError as err:
        raise RuntimeError(f"OpenAI API request failed: {err}") from err

    parsed = json.loads(body)

    # Preferred field in Responses API.
    output_text = parsed.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    # Fallback for shape variations.
    chunks: list[str] = []
    for item in parsed.get("output", []):
        for content in item.get("content", []):
            text = content.get("text")
            if isinstance(text, str):
                chunks.append(text)
    if chunks:
        return "\n".join(chunks).strip()

    raise RuntimeError("OpenAI response did not include any text output.")


def _build_prompt(scorecard: dict, report_md: str) -> str:
    return f"""
The deterministic verifier has assessed CMMC AC.L1-B.1.I.

Please produce markdown with the following sections:
- ## Why It Failed
- ## Remediation Steps (Prioritized)
- ## Quick Validation Checklist

Constraints:
- Use only evidence present below.
- Do not invent controls outside AC.L1-B.1.I.
- Keep practical remediation actions specific to Entra + SharePoint permissions.
- If status is MET, explain why it passed and provide hardening recommendations only.

Scorecard JSON:
{json.dumps(scorecard, indent=2)}

Current report.md:
{report_md}
""".strip()


def generate_remediation_markdown(
    packet_dir: str | Path, model: str = DEFAULT_MODEL
) -> Path:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set in your environment.")

    packet_dir_path = Path(packet_dir).resolve()
    outputs_dir = packet_dir_path / "outputs"
    scorecard_path = outputs_dir / "scorecard.json"
    report_path = outputs_dir / "report.md"
    remediation_path = outputs_dir / "remediation_steps.md"

    scorecard = _load_json(scorecard_path)
    report_md = _load_text(report_path)
    prompt = _build_prompt(scorecard, report_md)
    completion = _call_openai(api_key=api_key, model=model, prompt=prompt)

    remediation_path.write_text(completion + "\n", encoding="utf-8")
    return remediation_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate remediation markdown from verifier output via OpenAI."
    )
    parser.add_argument(
        "--packet-dir",
        default="packet_ac_l1_b_1_i",
        help="Path to packet folder containing outputs/scorecard.json and outputs/report.md",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="OpenAI model for remediation generation (default: gpt-4.1-mini)",
    )
    args = parser.parse_args()

    try:
        remediation_path = generate_remediation_markdown(
            packet_dir=args.packet_dir, model=args.model
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Wrote remediation markdown: {remediation_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

