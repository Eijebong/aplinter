import enum


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
    SUS_ATTR_ACCESS = 4
    SUS_CALL = 5
    SUS_IMPORT = 6

    def to_json(self):
        return self.value


class ReviewAnnotation:
    def __init__(self, severity, ty, desc, *, line=None, col_start=None, col_end=None, extra=None):
        self.ty = ty
        self.desc = desc
        self.severity = severity
        self.line = line
        self.col_start = col_start
        self.col_end = col_end
        self.extra = extra

    def to_json(self):
        return self.__dict__
