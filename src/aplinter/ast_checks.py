import ast

from aplinter.types import ReviewAnnotation, AnnotationType, Severity

KNOWN_BAD_ATTRS = frozenset({
    "pickle", "subprocess", "socket", "requests", "urllib3",
    "os", "shutil", "ctypes",
    "__builtins__", "__subclasses__", "__import__",
})

ATTR_ACCESS_FUNCTIONS = frozenset({"getattr", "setattr", "delattr"})
SUS_FUNCTIONS = frozenset({"globals", "locals", "vars"})
SUS_IMPORTS = frozenset({"builtins"})


class SusCallChecker(ast.NodeVisitor):
    def __init__(self):
        self.annotations = []

    def _check_attr_access(self, node):
        if not (isinstance(node.func, ast.Name) and node.func.id in ATTR_ACCESS_FUNCTIONS and len(node.args) >= 2):
            return

        func_name = node.func.id
        attr_arg = node.args[1]
        if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
            if func_name == "getattr" and attr_arg.value in KNOWN_BAD_ATTRS:
                self.annotations.append(ReviewAnnotation(
                    Severity.VERY_HIGH, AnnotationType.SUS_ATTR_ACCESS,
                    f"getattr used with known dangerous attribute: {attr_arg.value}",
                    line=node.lineno, col_start=node.col_offset, col_end=node.end_col_offset,
                ))
        elif not isinstance(attr_arg, ast.Constant):
            self.annotations.append(ReviewAnnotation(
                Severity.HIGH, AnnotationType.SUS_ATTR_ACCESS,
                f"{func_name} used with non-literal attribute name",
                line=node.lineno, col_start=node.col_offset, col_end=node.end_col_offset,
            ))

    def _check_sus_function(self, node):
        if not (isinstance(node.func, ast.Name) and node.func.id in SUS_FUNCTIONS):
            return

        self.annotations.append(ReviewAnnotation(
            Severity.HIGH, AnnotationType.SUS_CALL,
            f"Use of {node.func.id}()",
            line=node.lineno, col_start=node.col_offset, col_end=node.end_col_offset,
        ))

    def visit_Attribute(self, node):
        if (node.attr == "modules"
                and isinstance(node.value, ast.Name)
                and node.value.id == "sys"):
            self.annotations.append(ReviewAnnotation(
                Severity.HIGH, AnnotationType.SUS_ATTR_ACCESS,
                "Access to sys.modules",
                line=node.lineno, col_start=node.col_offset, col_end=node.end_col_offset,
            ))
        self.generic_visit(node)

    def _check_import_name(self, name, node):
        module = name.split(".")[0]
        if module in SUS_IMPORTS:
            self.annotations.append(ReviewAnnotation(
                Severity.HIGH, AnnotationType.SUS_IMPORT,
                f"Import of {name}",
                line=node.lineno, col_start=node.col_offset, col_end=node.end_col_offset,
            ))

    def visit_Import(self, node):
        for alias in node.names:
            self._check_import_name(alias.name, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self._check_import_name(node.module, node)
        self.generic_visit(node)

    def visit_Call(self, node):
        self._check_attr_access(node)
        self._check_sus_function(node)
        self.generic_visit(node)


def make_ast_annotations_for_file(file_path):
    if not file_path.endswith(".py"):
        return

    with open(file_path, "r") as fd:
        try:
            tree = ast.parse(fd.read(), filename=file_path)
        except SyntaxError:
            return

    checker = SusCallChecker()
    checker.visit(tree)
    yield from checker.annotations
