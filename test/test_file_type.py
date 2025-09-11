import tempfile
import pytest
import itertools

from aplinter import make_file_lint_annotations_for_file, MUST_BE_TEXT_EXT, WARN_EXT, AnnotationType
from .common import get_annotation_for_type


@pytest.mark.parametrize(
    "ext",
    (
        MUST_BE_TEXT_EXT + WARN_EXT + ('unknown', '.unknown')
    )
)
def test_forbidden_binary_for_type_bom(ext):
    with tempfile.NamedTemporaryFile("wb", suffix=ext) as fd:
        fd.write(b"\xef\xbb\xbf")
        fd.flush()
        annotations = list(make_file_lint_annotations_for_file(fd.name))
        assert not get_annotation_for_type(annotations, AnnotationType.TYPE_CONTENT_MISMATCH)


@pytest.mark.parametrize(
    "ext,should_annotate",
    (
        itertools.chain(itertools.zip_longest(MUST_BE_TEXT_EXT, (), fillvalue=True), itertools.zip_longest(WARN_EXT, (), fillvalue=False), (('unknown', True), ('.unknown', False)))
    )
)
def test_forbidden_binary_for_type(ext, should_annotate):
    with tempfile.NamedTemporaryFile("wb", suffix=ext) as fd:
        fd.write(b"\xff\xcc")
        fd.flush()
        annotations = get_annotation_for_type(make_file_lint_annotations_for_file(fd.name), AnnotationType.TYPE_CONTENT_MISMATCH)


        if should_annotate:
            assert len(annotations) == 1
        else:
            assert not annotations


@pytest.mark.parametrize(
    "ext",
    (
        MUST_BE_TEXT_EXT
    )
)
def test_sus_strings(ext):
    test_content = """line 1 normal content
line 2 has __import__ here
line 3 normal
line 4 with __import__ at start
line 5 has multiple __import__ and __import__ occurrences"""

    with tempfile.NamedTemporaryFile("w", suffix=ext, delete=False) as fd:
        fd.write(test_content)
        fd.flush()

        annotations = get_annotation_for_type(make_file_lint_annotations_for_file(fd.name), AnnotationType.SUS_STRING)

        assert len(annotations) == 4

        expected_positions = [
            (2, 11, 21),  # line 2, col 11-21
            (4, 12, 22),  # line 4, col 12-22
            (5, 20, 30),  # line 5, first occurrence col 20-30
            (5, 35, 45),  # line 5, second occurrence col 35-45
        ]

        actual_positions = [(ann.line, ann.col_start, ann.col_end) for ann in annotations]

        assert actual_positions == expected_positions

        for ann in annotations:
            assert ann.desc == "Found suspicious string in file: __import__"
