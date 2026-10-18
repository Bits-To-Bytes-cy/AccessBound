"""These tests verify the intentionally seeded ground truth, not scanner accuracy."""


def test_vulnerable_read_exposes_bobs_canary_to_alice(client):
    response = client.get("/lab/vulnerable/accounts/102", headers={"X-Lab-User": "alice"})
    assert response.status_code == 200
    assert response.json()["owner"] == "bob"
    assert response.json()["private_marker"] == "BOB_PRIVATE_CANARY_AB102"


def test_secure_read_denies_alice_access_to_bobs_account(client):
    response = client.get("/lab/secure/accounts/102", headers={"X-Lab-User": "alice"})
    assert response.status_code == 403


def test_vulnerable_update_allows_alice_to_modify_bobs_nickname(client):
    response = client.patch(
        "/lab/vulnerable/accounts/102",
        headers={"X-Lab-User": "alice"},
        json={"nickname": "changed-by-alice-in-lab"},
    )
    assert response.status_code == 200
    assert response.json()["nickname"] == "changed-by-alice-in-lab"


def test_secure_update_denies_alice_from_modifying_bobs_nickname(client):
    response = client.patch(
        "/lab/secure/accounts/102",
        headers={"X-Lab-User": "alice"},
        json={"nickname": "must-not-change"},
    )
    assert response.status_code == 403


def test_vulnerable_admin_function_allows_customer(client):
    response = client.post(
        "/lab/vulnerable/admin/reports",
        headers={"X-Lab-User": "alice"},
        json={"title": "lab-only test"},
    )
    assert response.status_code == 200
    assert response.json()["created"] is True


def test_secure_admin_function_denies_customer(client):
    response = client.post(
        "/lab/secure/admin/reports",
        headers={"X-Lab-User": "alice"},
        json={"title": "lab-only test"},
    )
    assert response.status_code == 403


def test_vulnerable_nested_resource_exposes_bobs_document(client):
    response = client.get(
        "/lab/vulnerable/projects/202/documents/302",
        headers={"X-Lab-User": "alice"},
    )
    assert response.status_code == 200
    assert response.json()["marker"] == "BOB_DOC_CANARY_AB302"


def test_secure_nested_resource_denies_alice_bobs_document(client):
    response = client.get(
        "/lab/secure/projects/202/documents/302",
        headers={"X-Lab-User": "alice"},
    )
    assert response.status_code == 403


def test_owner_can_access_own_account(client):
    response = client.get("/lab/secure/accounts/101", headers={"X-Lab-User": "alice"})
    assert response.status_code == 200
    assert response.json()["owner"] == "alice"


def test_admin_can_access_bobs_account(client):
    response = client.get("/lab/secure/accounts/102", headers={"X-Lab-User": "admin"})
    assert response.status_code == 200
    assert response.json()["owner"] == "bob"


def test_missing_lab_identity_is_rejected(client):
    response = client.get("/lab/secure/accounts/101")
    assert response.status_code == 401


def test_vulnerable_read_exposes_alices_canary_to_bob(client):
    response = client.get("/lab/vulnerable/accounts/101", headers={"X-Lab-User": "bob"})
    assert response.status_code == 200
    assert response.json()["owner"] == "alice"
    assert response.json()["private_marker"] == "ALICE_PRIVATE_CANARY_AB101"


def test_secure_read_denies_bob_access_to_alices_account(client):
    response = client.get("/lab/secure/accounts/101", headers={"X-Lab-User": "bob"})
    assert response.status_code == 403


def test_owner_can_access_own_nested_document(client):
    response = client.get("/lab/secure/projects/201/documents/301", headers={"X-Lab-User": "alice"})
    assert response.status_code == 200
    assert response.json()["marker"] == "ALICE_DOC_CANARY_AB301"


def test_bob_can_access_own_nested_document(client):
    response = client.get("/lab/secure/projects/202/documents/302", headers={"X-Lab-User": "bob"})
    assert response.status_code == 200
    assert response.json()["marker"] == "BOB_DOC_CANARY_AB302"


def test_vulnerable_nested_resource_exposes_alices_document_to_bob(client):
    response = client.get("/lab/vulnerable/projects/201/documents/301", headers={"X-Lab-User": "bob"})
    assert response.status_code == 200
    assert response.json()["marker"] == "ALICE_DOC_CANARY_AB301"


def test_secure_nested_resource_denies_bob_alices_document(client):
    response = client.get("/lab/secure/projects/201/documents/301", headers={"X-Lab-User": "bob"})
    assert response.status_code == 403


def test_nested_resource_rejects_parent_child_mismatch_vulnerable(client):
    response = client.get("/lab/vulnerable/projects/201/documents/302", headers={"X-Lab-User": "alice"})
    assert response.status_code == 404


def test_nested_resource_rejects_parent_child_mismatch_secure(client):
    response = client.get("/lab/secure/projects/201/documents/302", headers={"X-Lab-User": "alice"})
    assert response.status_code == 404
