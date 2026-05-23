from pydantic import BaseModel
from typing import Optional

class PipelineContext(BaseModel):
    repo: str
    clone_url: str
    branch: str
    commit: str
    repo_path: str
    apk_filename: Optional[str] = None
