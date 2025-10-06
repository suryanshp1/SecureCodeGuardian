import git, os
from pathlib import Path

def clone_repo(url: str) -> str:
    path = f"/tmp/{Path(url).stem}"
    git.Repo.clone_from(url, path)
    return path

def parse_code_files(base_path: str) -> list:
    files = []
    for ext in (".py", ".js", ".java", ".go", ".rb", ".kt", ".swift", ".ts", ".c", ".cpp", ".h", ".cs"):
        files.extend(Path(base_path).rglob(f"*{ext}"))
    return files
