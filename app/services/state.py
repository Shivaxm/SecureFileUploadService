from enum import Enum


class FileState(str, Enum):
    PENDING_UPLOAD = "PENDING_UPLOAD"
    UPLOADING = "UPLOADING"
    SCANNING = "SCANNING"
    AVAILABLE = "AVAILABLE"
    QUARANTINED = "QUARANTINED"
    DELETED = "DELETED"


ALLOWED_TRANSITIONS: dict[FileState, set[FileState]] = {
    FileState.PENDING_UPLOAD: {FileState.UPLOADING},
    FileState.UPLOADING: {FileState.SCANNING, FileState.DELETED},
    FileState.SCANNING: {FileState.AVAILABLE, FileState.QUARANTINED},
    FileState.AVAILABLE: {FileState.DELETED},
    FileState.QUARANTINED: {FileState.DELETED},
    FileState.DELETED: set(),
}


def can_transition(current: FileState, target: FileState) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, set())

