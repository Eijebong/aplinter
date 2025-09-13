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
line 5 has multiple __import__ and __import__ occurrences
line 6 has # nosec comment
line 7 contains nosec without hash
line 8 has #nosec without space
line 9 contains # bandit: skip here"""

    with tempfile.NamedTemporaryFile("w", suffix=ext, delete=False) as fd:
        fd.write(test_content)
        fd.flush()

        annotations = get_annotation_for_type(make_file_lint_annotations_for_file(fd.name), AnnotationType.SUS_STRING)

        assert len(annotations) == 11

        expected_positions = [
            (2, 11, 21),  # line 2, __import__ col 11-21
            (4, 12, 22),  # line 4, __import__ col 12-22
            (5, 20, 30),  # line 5, first __import__ col 20-30
            (5, 35, 45),  # line 5, second __import__ col 35-45
            (6, 13, 18),  # line 6, nosec col 13-18
            (6, 11, 18),  # line 6, # nosec col 11-18
            (7, 16, 21),  # line 7, nosec col 16-21
            (8, 12, 17),  # line 8, nosec col 12-17
            (8, 11, 17),  # line 8, #nosec col 11-17
            (9, 18, 25),  # line 9, bandit: col 18-25
            (9, 16, 25),  # line 9, # bandit: col 16-25
        ]

        actual_positions = [(ann.line, ann.col_start, ann.col_end) for ann in annotations]

        assert actual_positions == expected_positions
