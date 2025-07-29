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
    pass
