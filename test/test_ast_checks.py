from aplinter.ast_checks import make_ast_annotations_for_file, KNOWN_BAD_ATTRS
from aplinter.types import AnnotationType, Severity
from .common import get_annotation_for_type


def write_py_file(tmp_path, content):
    path = tmp_path / "test.py"
    path.write_text(content)
    return str(path)


def get_attr_access_annotations(tmp_path, content):
    path = write_py_file(tmp_path, content)
    return get_annotation_for_type(make_ast_annotations_for_file(path), AnnotationType.SUS_ATTR_ACCESS)


def get_sus_call_annotations(tmp_path, content):
    path = write_py_file(tmp_path, content)
    return get_annotation_for_type(make_ast_annotations_for_file(path), AnnotationType.SUS_CALL)


def get_sus_import_annotations(tmp_path, content):
    path = write_py_file(tmp_path, content)
    return get_annotation_for_type(make_ast_annotations_for_file(path), AnnotationType.SUS_IMPORT)

def test_getattr_non_literal(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, "getattr(module, some_var)\n")
    assert len(annotations) == 1
    assert annotations[0].severity == Severity.HIGH
    assert "non-literal" in annotations[0].desc


def test_getattr_string_concat(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, 'getattr(module, "p" + "ickle")\n')
    assert len(annotations) == 1
    assert annotations[0].severity == Severity.HIGH
    assert "non-literal" in annotations[0].desc


def test_getattr_known_bad_literal(tmp_path):
    for attr in KNOWN_BAD_ATTRS:
        annotations = get_attr_access_annotations(tmp_path, f'getattr(module, "{attr}")\n')
        assert len(annotations) == 1, f"Expected 1 annotation for {attr}"
        assert annotations[0].severity == Severity.VERY_HIGH
        assert attr in annotations[0].desc


def test_getattr_safe_literal(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, 'getattr(obj, "name")\n')
    assert len(annotations) == 0


def test_getattr_no_second_arg(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, 'getattr(obj)\n')
    assert len(annotations) == 0


def test_getattr_positions(tmp_path):
    content = """x = 1
getattr(mod, var)
y = getattr(mod, "pickle")
"""
    annotations = get_attr_access_annotations(tmp_path, content)
    assert len(annotations) == 2
    assert annotations[0].line == 2
    assert annotations[0].col_start == 0
    assert annotations[1].line == 3
    assert annotations[1].col_start == 4


def test_non_py_file_skipped(tmp_path):
    path = tmp_path / "test.txt"
    path.write_text('getattr(module, var)\n')
    annotations = list(make_ast_annotations_for_file(str(path)))
    assert len(annotations) == 0


def test_syntax_error_skipped(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, "def (broken syntax\n")
    assert len(annotations) == 0


def test_nested_getattr(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, 'getattr(getattr(mod, var1), var2)\n')
    assert len(annotations) == 2


def test_getattr_fstring_arg(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, 'getattr(mod, f"prefix_{name}")\n')
    assert len(annotations) == 1
    assert "non-literal" in annotations[0].desc


def test_setattr_non_literal(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, "setattr(obj, some_var, value)\n")
    assert len(annotations) == 1
    assert annotations[0].severity == Severity.HIGH
    assert "setattr" in annotations[0].desc
    assert "non-literal" in annotations[0].desc


def test_setattr_known_bad_literal_not_flagged(tmp_path):
    for attr in KNOWN_BAD_ATTRS:
        annotations = get_attr_access_annotations(tmp_path, f'setattr(obj, "{attr}", value)\n')
        assert len(annotations) == 0


def test_setattr_safe_literal(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, 'setattr(obj, "name", value)\n')
    assert len(annotations) == 0


def test_delattr_non_literal(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, "delattr(obj, some_var)\n")
    assert len(annotations) == 1
    assert annotations[0].severity == Severity.HIGH
    assert "delattr" in annotations[0].desc
    assert "non-literal" in annotations[0].desc


def test_delattr_safe_literal(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, 'delattr(obj, "name")\n')
    assert len(annotations) == 0


def test_globals_call(tmp_path):
    annotations = get_sus_call_annotations(tmp_path, "x = globals()\n")
    assert len(annotations) == 1
    assert "globals()" in annotations[0].desc


def test_locals_call(tmp_path):
    annotations = get_sus_call_annotations(tmp_path, "x = locals()\n")
    assert len(annotations) == 1
    assert "locals()" in annotations[0].desc


def test_vars_call(tmp_path):
    annotations = get_sus_call_annotations(tmp_path, "x = vars()\n")
    assert len(annotations) == 1
    assert "vars()" in annotations[0].desc


def test_sus_call_positions(tmp_path):
    content = """x = 1
globals()
y = locals()
"""
    annotations = get_sus_call_annotations(tmp_path, content)
    assert len(annotations) == 2
    assert annotations[0].line == 2
    assert annotations[0].col_start == 0
    assert annotations[1].line == 3
    assert annotations[1].col_start == 4


def test_no_false_positive_on_other_calls(tmp_path):
    annotations = get_sus_call_annotations(tmp_path, "print('hello')\nlen(x)\n")
    assert len(annotations) == 0


def test_sys_modules_access(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, "import sys\nx = sys.modules['os']\n")
    assert len(annotations) == 1
    assert "sys.modules" in annotations[0].desc


def test_sys_modules_position(tmp_path):
    content = """import sys
x = sys.modules
"""
    annotations = get_attr_access_annotations(tmp_path, content)
    assert len(annotations) == 1
    assert annotations[0].line == 2
    assert annotations[0].col_start == 4


def test_sys_modules_no_false_positive(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, "sys.path\n")
    assert len(annotations) == 0


def test_modules_on_other_object(tmp_path):
    annotations = get_attr_access_annotations(tmp_path, "foo.modules\n")
    assert len(annotations) == 0


def test_import_builtins(tmp_path):
    annotations = get_sus_import_annotations(tmp_path, "import builtins\n")
    assert len(annotations) == 1
    assert "builtins" in annotations[0].desc


def test_from_builtins_import(tmp_path):
    annotations = get_sus_import_annotations(tmp_path, "from builtins import eval\n")
    assert len(annotations) == 1
    assert "builtins" in annotations[0].desc


def test_normal_import_not_flagged(tmp_path):
    annotations = get_sus_import_annotations(tmp_path, "import json\n")
    assert len(annotations) == 0
