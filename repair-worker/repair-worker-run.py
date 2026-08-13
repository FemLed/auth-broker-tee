#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

from minisweagent.agents.default import DefaultAgent
from minisweagent.environments.local import LocalEnvironment, LocalEnvironmentConfig
from minisweagent.exceptions import Submitted
from minisweagent.models.litellm_model import LitellmModel

REPO_ROOT = Path("/workspace/repo")
SUBMIT_COMMAND = "tee_repair_submit"
FORBIDDEN_COMMAND_PATTERNS = [
    r"\bgit\s+(add|commit|push|merge|rebase|tag)\b",
    r"\bgh\s+",
    r"\bgcloud\s+run\s+(deploy|services\s+update|services\s+replace)\b",
    r"\bgcloud\s+compute\s+instances\s+(create|delete|reset|set-)\b",
    r"\bgcloud\s+kms\b",
    r"\bgcloud\s+iam\b",
]


def env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None or value == "":
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def run(command: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(command)}):\n{result.stdout}\n{result.stderr}")
    return result


def sha256_text(value: str) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def stable_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def post_artifact(envelope: dict):
    callback_url = os.getenv("TEE_REPAIR_CALLBACK_URL", "")
    token = os.getenv("TEE_REPAIR_CALLBACK_TOKEN", "")
    if not callback_url or not token:
        return
    body = json.dumps(envelope).encode("utf-8")
    request = urllib.request.Request(
        callback_url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "AuthBrokerTEE-RepairWorker",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        response.read()


def clone_repo(owner: str, repo: str, branch: str):
    if REPO_ROOT.exists():
        run(["rm", "-rf", str(REPO_ROOT)])
    repo_url = f"https://github.com/{owner}/{repo}.git"
    run(["git", "clone", "--depth", "1", "--branch", branch, repo_url, str(REPO_ROOT)])


class RepairEnvironmentConfig(LocalEnvironmentConfig):
    forbidden_patterns: list[str] = FORBIDDEN_COMMAND_PATTERNS


class RepairEnvironment(LocalEnvironment):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, config_class=RepairEnvironmentConfig)

    def execute(self, action: dict, cwd: str = "") -> dict:
        command = action.get("command", "")
        if command.strip().startswith(SUBMIT_COMMAND):
            payload = parse_submit(command)
            raise Submitted({
                "role": "exit",
                "content": json.dumps(payload, sort_keys=True),
                "extra": {"structured_submission": payload},
            })
        for pattern in self.config.forbidden_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return {
                    "output": f"Action blocked by auth-broker repair-worker policy: {command}",
                    "returncode": 1,
                    "exception_info": "",
                }
        return super().execute(action, cwd)


def parse_submit(command: str) -> dict:
    raw = command[len(SUBMIT_COMMAND):].strip()
    if raw.startswith("'") and raw.endswith("'"):
        raw = raw[1:-1]
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise RuntimeError("tee_repair_submit payload must be a JSON object")
    for field in ["title", "summary", "tests"]:
        if field not in payload:
            raise RuntimeError(f"tee_repair_submit payload missing {field}")
    return payload


def run_agent(prompt: str, base_branch: str) -> dict:
    model_name = os.getenv("TEE_REPAIR_MODEL", "vertex_ai/gemini-3.7-flash")
    model_kwargs = {
        "vertex_project": os.getenv("VERTEXAI_PROJECT", os.getenv("GCP_PROJECT_ID")),
        "vertex_location": os.getenv("VERTEXAI_LOCATION", "global"),
        "temperature": 1.0,
        "reasoning_effort": "high",
        "tools": [{"googleSearch": {}}],
    }
    system_template = (
        "You are an untrusted auth-broker-tee repair worker in an isolated Cloud Run Job. "
        "You may inspect and edit files and run verification commands. "
        "You must not run git add, git commit, git push, gh, gcloud deploy, gcloud iam, or gcloud kms. "
        "You cannot approve, activate, deploy active governance, route traffic, rotate keys, or mutate TEE-owned state. "
        f"When done, run exactly `{SUBMIT_COMMAND} '{{\"title\":\"short title\",\"summary\":\"what changed\",\"tests\":[\"commands run\"]}}'`."
    )
    instance_template = (
        "Repository root: {{repo_root}}\n"
        "Base branch: {{base_branch}}\n\n"
        "{{task}}\n\n"
        "Your changes must be minimal and proposal-bound. Finish with tee_repair_submit JSON."
    )
    environment = RepairEnvironment(cwd=str(REPO_ROOT))
    agent = DefaultAgent(
        LitellmModel(model_name=model_name, model_kwargs=model_kwargs),
        environment,
        system_template=system_template,
        instance_template=instance_template,
        step_limit=0,
        cost_limit=0,
        output_path=Path("/workspace/repair-worker.traj.json"),
    )
    result = agent.run(prompt, repo_root=str(REPO_ROOT), base_branch=base_branch)
    return result.get("extra", {}).get("structured_submission") or {"summary": str(result)}


def build_artifact_envelope(submission: dict, proposal_digest: str, prompt_digest: str) -> dict:
    diff = run(["git", "diff", "--binary"], cwd=REPO_ROOT).stdout
    tests = submission.get("tests") if isinstance(submission.get("tests"), list) else []
    build_summary = {
        "title": submission.get("title") or "Repair auth-broker-tee",
        "summary": submission.get("summary", "Repair worker completed."),
    }
    test_summary = {"tests": tests}
    trajectory_path = Path("/workspace/repair-worker.traj.json")
    trajectory = trajectory_path.read_text() if trajectory_path.exists() else ""
    return {
        "schema": "femled.tee.repair_worker.artifact_envelope.v1",
        "runId": os.getenv("TEE_REPAIR_JOB_ID", "unknown"),
        "proposalDigest": proposal_digest,
        "promptDigest": prompt_digest,
        "sourceBundleDigest": sha256_text(diff),
        "buildSummaryDigest": sha256_text(stable_json(build_summary)),
        "testSummaryDigest": sha256_text(stable_json(test_summary)),
        "trajectoryArtifactDigest": sha256_text(trajectory) if trajectory else None,
        "modelProbeDigest": submission.get("modelProbeDigest"),
        "modelCatalogEvidenceDigest": submission.get("modelCatalogEvidenceDigest"),
        "modelPolicyDiffDigest": submission.get("modelPolicyDiffDigest"),
    }


def main() -> int:
    owner = os.getenv("GITHUB_REPO_OWNER", "FemLed")
    repo = os.getenv("GITHUB_REPO_NAME", "auth-broker-tee")
    base_branch = os.getenv("TEE_REPAIR_BASE_BRANCH", "master")
    prompt = env("TEE_REPAIR_PROMPT")
    proposal_digest = env("TEE_REPAIR_PROPOSAL_DIGEST")
    prompt_digest = env("TEE_REPAIR_PROMPT_DIGEST")
    clone_repo(owner, repo, base_branch)
    submission = run_agent(prompt, base_branch)
    post_artifact(build_artifact_envelope(submission, proposal_digest, prompt_digest))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(error, file=sys.stderr)
        raise
