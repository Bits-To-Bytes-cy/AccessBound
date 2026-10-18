"""Synthetic lab data. Never use real or production data here."""
from copy import deepcopy

_SEED_USERS = {
    "alice": {"username": "alice", "role": "customer", "display_name": "Alice Lab User"},
    "bob": {"username": "bob", "role": "customer", "display_name": "Bob Lab User"},
    "admin": {"username": "admin", "role": "admin", "display_name": "Lab Administrator"},
}

_SEED_ACCOUNTS = {
    101: {
        "id": 101,
        "owner": "alice",
        "balance": 1200,
        "nickname": "Alice test account",
        "private_marker": "ALICE_PRIVATE_CANARY_AB101",
    },
    102: {
        "id": 102,
        "owner": "bob",
        "balance": 2450,
        "nickname": "Bob test account",
        "private_marker": "BOB_PRIVATE_CANARY_AB102",
    },
}

_SEED_PROJECTS = {
    201: {"id": 201, "owner": "alice", "name": "Alice Lab Project"},
    202: {"id": 202, "owner": "bob", "name": "Bob Lab Project"},
}

_SEED_DOCUMENTS = {
    301: {"id": 301, "project_id": 201, "title": "Alice notes", "marker": "ALICE_DOC_CANARY_AB301"},
    302: {"id": 302, "project_id": 202, "title": "Bob private notes", "marker": "BOB_DOC_CANARY_AB302"},
}


def _fresh(seed):
    return deepcopy(seed)

USERS = _fresh(_SEED_USERS)
ACCOUNTS = _fresh(_SEED_ACCOUNTS)
PROJECTS = _fresh(_SEED_PROJECTS)
DOCUMENTS = _fresh(_SEED_DOCUMENTS)


def reset_state():
    """Reset all mutable state to the known baseline for deterministic tests."""
    global USERS, ACCOUNTS, PROJECTS, DOCUMENTS
    USERS = _fresh(_SEED_USERS)
    ACCOUNTS = _fresh(_SEED_ACCOUNTS)
    PROJECTS = _fresh(_SEED_PROJECTS)
    DOCUMENTS = _fresh(_SEED_DOCUMENTS)
