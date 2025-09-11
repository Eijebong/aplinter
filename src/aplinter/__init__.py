import sys
import zipfile
import tempfile
import os
import enum
from bandit.core import manager
from bandit.core import config
from collections import defaultdict
from pathlib import Path
import json


class ReviewReport:
    def __init__(self):
        self._files = defaultdict(lambda: [])

    def add_annotations(self, file_path, annotations):
        annotations = list(annotations)
        if annotations:
            self._files[file_path].extend(annotations)

    def to_json(self):
        def _default(obj):
            return getattr(obj, "to_json")()

        return json.dumps(self._files, default=_default)


class Severity(enum.Enum):
    CRITICAL = 60
    VERY_HIGH = 50
    HIGH = 40
    MEDIUM = 30
    LOW = 20
    VERY_LOW = 10

    def to_json(self):
        return self.value


class AnnotationType(enum.Enum):
    TYPE_CONTENT_MISMATCH = 0
    FILE_TYPE = 1
    BANDIT = 2
    SUS_STRING = 3

    def to_json(self):
        return self.value


class ReviewAnnotation:
    def __init__(self, severity, ty, desc):
        self.ty = ty
        self.desc = desc
        self.severity = severity
        self.line = None
        self.col_start = None
        self.col_end = None
        self.extra = None

    def to_json(self):
        return self.__dict__


def map_bandit_severity(issue):
    print(issue.__dict__)
    return Severity.LOW

def make_bandit_annotations_for_file(file_path):
    b_mgr = manager.BanditManager(config.BanditConfig(), 'bandit')
    b_mgr.files_list = [file_path]
    b_mgr.run_tests()

    for issue in b_mgr.get_issue_list():
        severity = map_bandit_severity(issue)
        annotation = ReviewAnnotation(severity, AnnotationType.BANDIT, issue.text)
        annotation.line = issue.lineno
        annotation.col_start = issue.col_offset
        annotation.col_end = issue.end_col_offset
        annotation.extra = issue.test_id
        yield annotation


MUST_BE_TEXT_EXT = (".py", ".json", ".yaml", ".txt", ".md", "")
WARN_EXT = (".so", ".pyd", ".dll", ".exe", ".apworld")

def make_file_lint_annotations_for_file(file_path):
    name, extension = os.path.splitext(file_path)

    if extension in MUST_BE_TEXT_EXT:
        with open(file_path, "rb") as fd:
            try:
                content = fd.read().decode('utf-8')
                lines = content.splitlines()
                for line_num, line in enumerate(lines, 1):
                    for sus_string in ('__import__', ):
                        col_start = line.find(sus_string)
                        while col_start != -1:
                            col_end = col_start + len(sus_string)
                            annotation = ReviewAnnotation(Severity.VERY_HIGH, AnnotationType.SUS_STRING, f"Found suspicious string in file: {sus_string}")
                            annotation.line = line_num
                            annotation.col_start = col_start
                            annotation.col_end = col_end
                            yield annotation
                            # Look for more occurrences of the same string on the same line
                            col_start = line.find(sus_string, col_end)
            except UnicodeDecodeError:
                yield ReviewAnnotation(Severity.CRITICAL, AnnotationType.TYPE_CONTENT_MISMATCH, "The file should be a text file but isn't")

    if extension in WARN_EXT:
        if extension in ('.apworld', ):
            severity = Severity.HIGH
        else:
            severity = Severity.CRITICAL

        yield ReviewAnnotation(severity, AnnotationType.FILE_TYPE, f"This file has the extension {extension[1:]} and should probably not be in there")


def get_annotations_for_file(file_path):
    yield from make_bandit_annotations_for_file(file_path)
    yield from make_file_lint_annotations_for_file(file_path)


def make_annotations_for_dir(target):
    report = ReviewReport()

    for dirpath, _, filenames in os.walk(target):
        for filename in filenames:
            rel_dir = os.path.relpath(dirpath, target)
            rel_file = os.path.join(rel_dir, filename)
            absolute_path = os.path.join(dirpath, filename)

            annotations = get_annotations_for_file(absolute_path)
            report.add_annotations(rel_file, annotations)

    return report

def lint(apworld_path, output_dir):
    apworld_name = Path(apworld_path).stem
    with tempfile.TemporaryDirectory() as dst, open(apworld_path, "rb") as fd:
        zipfile.ZipFile(fd).extractall(dst)
        report = make_annotations_for_dir(dst)

    with open(os.path.join(output_dir, f"{apworld_name}.aplint"), "w") as fd:
        fd.write(report.to_json())

def main():
    if len(sys.argv) != 3:
        print("Usage: codereview.py <apworld_path> <output_dir>")
        sys.exit(1)
    lint(sys.argv[1], sys.argv[2])

if __name__ == "__main__":
    main()
