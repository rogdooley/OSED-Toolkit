# Tools Bootstrap Helper

Use `Tools/_bootstrap.py` when your script is outside the repository root and
still needs to import modules like `Tools.pattern` or `Tools.egghunter`.

## Why

Python resolves imports from `sys.path`. If your script runs from another
directory, `from Tools...` may fail unless repo root is added first.

## Script Example

```python
from pathlib import Path
import importlib.util

# Load bootstrap helper directly from repo path if you know it.
# If your script is inside the repo tree, you can also use `__file__` with the
# helper once imported.
bootstrap_path = Path("/home/roger/Documents/OSED/OSED-Toolkit/Tools/_bootstrap.py")
spec = importlib.util.spec_from_file_location("tools_bootstrap", bootstrap_path)
bootstrap = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(bootstrap)

bootstrap.ensure_tools_on_path(start=__file__)

from Tools.pattern.config import PatternConfig
from Tools.pattern.generator import PatternGenerator

config = PatternConfig(word_size=4, endianness="little")
pattern = PatternGenerator(config).create(300)
print(pattern.decode("ascii"))
```

## If Script Is Inside Repo Tree

If your script is somewhere under the same repository, use this shorter pattern:

```python
from pathlib import Path
import sys

for p in [Path(__file__).resolve().parent, *Path(__file__).resolve().parents]:
    if (p / "Tools" / "_bootstrap.py").exists():
        sys.path.insert(0, str(p))
        break

from Tools._bootstrap import ensure_tools_on_path
ensure_tools_on_path(start=__file__)

from Tools.egghunter import choose_hunter
```

## API

- `find_repo_root(marker_dir="Tools", start=None) -> Path`
- `ensure_tools_on_path(start=None) -> Path`

Both functions are in:
`/home/roger/Documents/OSED/OSED-Toolkit/Tools/_bootstrap.py`
