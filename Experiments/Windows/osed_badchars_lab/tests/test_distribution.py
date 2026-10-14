from pathlib import Path
def test_student_packager_excludes_instructor_material(tmp_path):
    import importlib.util
    root=Path(__file__).resolve().parents[1]; spec=importlib.util.spec_from_file_location("package_student",root/"tests/package_student.py");m=importlib.util.module_from_spec(spec);assert spec.loader;spec.loader.exec_module(m)
    m.package_student(root,tmp_path)
    assert (tmp_path/"Documentation/student").exists()
    assert not (tmp_path/"Documentation/instructor").exists()
