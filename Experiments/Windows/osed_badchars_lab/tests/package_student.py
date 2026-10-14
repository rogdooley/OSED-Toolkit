from pathlib import Path
import shutil
def package_student(root: Path, output: Path) -> None:
    if output.exists(): shutil.rmtree(output)
    output.mkdir(parents=True)
    for relative in ("tools","Documentation/student"):
        source=root/relative
        if source.exists(): shutil.copytree(source,output/relative)
    for executable in (root/"dist/instructor/Release").glob("*.exe") if (root/"dist/instructor/Release").exists() else ():
        shutil.copy2(executable,output/executable.name)
