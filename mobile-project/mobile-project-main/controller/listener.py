import hmac, hashlib, subprocess, os, glob
from fastapi import APIRouter, Request, HTTPException, BackgroundTasks
from config import GITHUB_SECRET, REPOS_STORAGE, APK_STORAGE
from pipeline import run_pipeline

router = APIRouter()

def _verify_signature(payload: bytes, sig_header: str) -> bool:
    if not sig_header or not sig_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
    GITHUB_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header)

def _find_apk(repo_dir: str) -> str | None:
    matches = glob.glob(f"{repo_dir}/**/*.apk", recursive=True)
    return matches[0] if matches else None

def _clone_repo(clone_url: str, dest: str, branch: str) -> None:
    if os.path.exists(dest):
        subprocess.run(["rm", "-rf", dest], check=True)
    subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", branch, clone_url, dest],
        check=True, timeout=120,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    )

@router.post("/webhook/github")
async def github_webhook(request: Request, bg: BackgroundTasks):
    payload_bytes = await request.body()

    sig = request.headers.get("X-Hub-Signature-256", "")
    if not _verify_signature(payload_bytes, sig):
        raise HTTPException(401, "Signature HMAC invalide")

    event = request.headers.get("X-GitHub-Event", "")
    if event != "push":
        return {"status": "ignored", "event": event}

    data = await request.json() if not payload_bytes else __import__("json").loads(payload_bytes)
    repo_name = data["repository"]["name"]
    clone_url  = data["repository"]["clone_url"]
    branch     = data.get("ref", "refs/heads/main").split("/")[-1]
    commit     = data.get("after", "unknown")

    dest = f"{REPOS_STORAGE}/{repo_name}"
    _clone_repo(clone_url, dest, branch)

    apk_path = _find_apk(dest)
    apk_filename = None
    if apk_path:
        import shutil
        apk_filename = f"{repo_name}_{commit[:8]}.apk"
        shutil.copy2(apk_path, f"{APK_STORAGE}/{apk_filename}")

    bg.add_task(run_pipeline, {
        "repo":         repo_name,
        "clone_url":    clone_url,
        "branch":       branch,
        "commit":       commit,
        "repo_path":    dest,
        "apk_filename": apk_filename,
    })

    return {"status": "accepted", "repo": repo_name, "commit": commit}


@router.post("/trigger/manual")
async def manual_trigger(request: Request, bg: BackgroundTasks):
    """Déclenche le pipeline sans clone git — pour tests frontend."""
    data = await request.json()
    bg.add_task(run_pipeline, {
        "repo":         data.get("repo", "manual"),
        "clone_url":    "",
        "branch":       data.get("branch", "main"),
        "commit":       data.get("commit", "manual"),
        "repo_path":    "",
        "apk_filename": data.get("apk_filename", None),
        "services":     data.get("services", None),
    })
    return {"status": "accepted", "repo": data.get("repo")}
