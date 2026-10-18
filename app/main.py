"""Deliberately vulnerable FastAPI endpoints for a localhost-only test lab.

IMPORTANT: X-Lab-User simulates identity for repeatable authorization tests.
It is client-controlled and must never be treated as production authentication.
"""
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app import state

app = FastAPI(
    title="AccessBound Lab API",
    version="0.1.0",
    description=(
        "Intentionally vulnerable local training API. Use only on localhost. "
        "X-Lab-User is a test fixture, not real authentication."
    ),
)


class AccountUpdate(BaseModel):
    nickname: str = Field(min_length=1, max_length=80)


class LabReport(BaseModel):
    title: str = Field(min_length=1, max_length=120)


def current_user(x_lab_user: Optional[str] = Header(default=None)) -> dict:
    if not x_lab_user:
        raise HTTPException(status_code=401, detail="Missing X-Lab-User lab identity")
    user = state.USERS.get(x_lab_user)
    if user is None:
        raise HTTPException(status_code=401, detail="Unknown lab identity")
    return user


def can_access_owner(user: dict, owner: str) -> bool:
    return user["username"] == owner or user["role"] == "admin"


@app.get("/")
def root():
    return {
        "name": "AccessBound Lab API",
        "warning": "Intentionally vulnerable lab. Run only on localhost.",
        "docs": "/docs",
    }


@app.get("/lab/vulnerable/accounts/{account_id}")
def vulnerable_read_account(account_id: int, user: Optional[str] = Header(default=None, alias="X-Lab-User")):
    """Deliberate BOLA: any known lab identity can read any account."""
    # Keep explicit lookup here so missing/invalid lab identities are rejected.
    if not user or user not in state.USERS:
        raise HTTPException(status_code=401, detail="Missing or unknown lab identity")
    account = state.ACCOUNTS.get(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return {**account, "requested_by": user}


@app.get("/lab/secure/accounts/{account_id}")
def secure_read_account(account_id: int, user: Optional[str] = Header(default=None, alias="X-Lab-User")):
    """Secure control: only the owner or the lab admin can read the account."""
    if not user or user not in state.USERS:
        raise HTTPException(status_code=401, detail="Missing or unknown lab identity")
    identity = state.USERS[user]
    account = state.ACCOUNTS.get(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")
    if not can_access_owner(identity, account["owner"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {**account, "requested_by": user}


@app.patch("/lab/vulnerable/accounts/{account_id}")
def vulnerable_update_account(
    account_id: int,
    update: AccountUpdate,
    user: Optional[str] = Header(default=None, alias="X-Lab-User"),
):
    """Deliberate BOLA: a customer can modify another customer's nickname."""
    if not user or user not in state.USERS:
        raise HTTPException(status_code=401, detail="Missing or unknown lab identity")
    account = state.ACCOUNTS.get(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")
    account["nickname"] = update.nickname
    return {"updated": True, "account_id": account_id, "nickname": account["nickname"], "requested_by": user}


@app.patch("/lab/secure/accounts/{account_id}")
def secure_update_account(
    account_id: int,
    update: AccountUpdate,
    user: Optional[str] = Header(default=None, alias="X-Lab-User"),
):
    """Secure control: only the owner or the lab admin can update the nickname."""
    if not user or user not in state.USERS:
        raise HTTPException(status_code=401, detail="Missing or unknown lab identity")
    identity = state.USERS[user]
    account = state.ACCOUNTS.get(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")
    if not can_access_owner(identity, account["owner"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    account["nickname"] = update.nickname
    return {"updated": True, "account_id": account_id, "nickname": account["nickname"], "requested_by": user}


@app.post("/lab/vulnerable/admin/reports")
def vulnerable_create_admin_report(report: LabReport, user: Optional[str] = Header(default=None, alias="X-Lab-User")):
    """Deliberate BFLA: a customer can invoke a lab admin-only function."""
    if not user or user not in state.USERS:
        raise HTTPException(status_code=401, detail="Missing or unknown lab identity")
    return {"created": True, "report_title": report.title, "requested_by": user, "lab_only": True}


@app.post("/lab/secure/admin/reports")
def secure_create_admin_report(report: LabReport, user: Optional[str] = Header(default=None, alias="X-Lab-User")):
    """Secure control: only a lab admin may invoke this function."""
    if not user or user not in state.USERS:
        raise HTTPException(status_code=401, detail="Missing or unknown lab identity")
    if state.USERS[user]["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"created": True, "report_title": report.title, "requested_by": user, "lab_only": True}


@app.get("/lab/vulnerable/projects/{project_id}/documents/{document_id}")
def vulnerable_read_nested_document(
    project_id: int,
    document_id: int,
    user: Optional[str] = Header(default=None, alias="X-Lab-User"),
):
    """Deliberate nested authorization flaw: verifies linkage, not project ownership."""
    if not user or user not in state.USERS:
        raise HTTPException(status_code=401, detail="Missing or unknown lab identity")
    project = state.PROJECTS.get(project_id)
    document = state.DOCUMENTS.get(document_id)
    if not project or not document or document["project_id"] != project_id:
        raise HTTPException(status_code=404, detail="Document not found")
    return {**document, "project_name": project["name"], "requested_by": user}


@app.get("/lab/secure/projects/{project_id}/documents/{document_id}")
def secure_read_nested_document(
    project_id: int,
    document_id: int,
    user: Optional[str] = Header(default=None, alias="X-Lab-User"),
):
    """Secure control: checks both document linkage and project ownership."""
    if not user or user not in state.USERS:
        raise HTTPException(status_code=401, detail="Missing or unknown lab identity")
    identity = state.USERS[user]
    project = state.PROJECTS.get(project_id)
    document = state.DOCUMENTS.get(document_id)
    if not project or not document or document["project_id"] != project_id:
        raise HTTPException(status_code=404, detail="Document not found")
    if not can_access_owner(identity, project["owner"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {**document, "project_name": project["name"], "requested_by": user}
