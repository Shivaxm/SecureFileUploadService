from enum import Enum


class FileState(str, Enum):
    INITIATED = "INITIATED"
    UPLOADED = "UPLOADED"
    SCANNING = "SCANNING"
    ACTIVE = "ACTIVE"
    QUARANTINED = "QUARANTINED"
    REJECTED = "REJECTED"


ALLOWED_TRANSITIONS: dict[FileState, set[FileState]] = {
    FileState.INITIATED: {FileState.UPLOADED, FileState.REJECTED, FileState.QUARANTINED},
    FileState.UPLOADED: {FileState.SCANNING, FileState.ACTIVE, FileState.QUARANTINED},
    FileState.SCANNING: {FileState.ACTIVE, FileState.QUARANTINED},
    FileState.ACTIVE: set(),
    FileState.QUARANTINED: {FileState.REJECTED},
    FileState.REJECTED: set(),
}


def can_transition(current: FileState, target: FileState) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, set())

