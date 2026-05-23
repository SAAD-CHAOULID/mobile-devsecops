from fastapi import FastAPI, Request, HTTPException
import hmac
import hashlib
import subprocess
import os
import json

app = FastAPI()

# =========================
# CONFIG
# =========================

GITHUB_SECRET = "secret_github_webhook"

REPO_DIR = "/home/mobexler/devsecops-v3/repo"

# =========================
# VERIFY SIGNATURE
# =========================

def verify_signature(payload: bytes, signature_header: str):

    if not signature_header:
        return False

    if not signature_header.startswith("sha256="):
        return False

    expected_signature = "sha256=" + hmac.new(
        GITHUB_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    print("EXPECTED :", expected_signature)
    print("RECEIVED :", signature_header)

    return hmac.compare_digest(
        expected_signature,
        signature_header
    )

# =========================
# WEBHOOK
# =========================

@app.post("/webhook/github")
async def github_webhook(request: Request):

    payload = await request.body()

    signature = request.headers.get(
        "X-Hub-Signature-256",
        ""
    )

    # Verify GitHub signature
    if not verify_signature(payload, signature):
        raise HTTPException(
            status_code=401,
            detail="Signature HMAC invalide"
        )

    # Verify event type
    event = request.headers.get(
        "X-GitHub-Event",
        ""
    )

    if event != "push":
        return {
            "status": "ignored",
            "event": event
        }

    # Parse JSON
    data = json.loads(payload)

    print("===== PUSH EVENT =====")
    print(json.dumps(data, indent=4))

    repo_name = data["repository"]["name"]

    print(f"Repository: {repo_name}")

    # =========================
    # GIT PULL
    # =========================

    if os.path.exists(REPO_DIR):

        result = subprocess.run(
            ["git", "-C", REPO_DIR, "pull"],
            capture_output=True,
            text=True
        )

        print(result.stdout)
        print(result.stderr)

    return {
        "status": "success",
        "repo": repo_name
    }
