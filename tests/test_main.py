import os
import requests

import vault_dump.main

import mock
import pytest

@pytest.fixture(autouse=True)
def mock_shutil():
    with mock.patch("vault_dump.main.shutil") as _fixture:
        yield _fixture

@pytest.fixture(autouse=True)
def mock_request():
    with mock.patch("vault_dump.main.requests.request") as _fixture:
        yield _fixture

@pytest.fixture(autouse=True)
def mock_path():
    with mock.patch('vault_dump.main.Path') as _fixture:
        yield _fixture

@pytest.fixture(autouse=True)
def mock_os():
    with mock.patch('vault_dump.main.os') as _fixture:
        yield _fixture


def test_no_authentication_token_provided(mock_os):
    mock_os.getenv = mock.Mock(return_value = None)
    with pytest.raises(Exception) as e:
        vault_dump.main.main()

    assert "You need to provide a vault token" in str(e)


def test_invalid_authentication_token_provided(mock_os, mock_request):
    mock_request.return_value = mock.Mock(json=mock.Mock(return_value = {"errors": ["permission denied"]}))
    with pytest.raises(Exception) as e:
        vault_dump.main.main()

    assert "Permission denied. Did you provide a valid Vault Token" in str(e)


def test_get_policies(mock_request, mock_shutil, mock_path):
    def mock_responses(*args, **kwargs):
        if args[-1].endswith("policy"):
            return mock.Mock(json=mock.Mock(return_value={"policies": ["a", "b", "c", "root"]}))
        else: # e.g. "/v1/policy/foo"
            return mock.Mock(json=mock.Mock(return_value={"rules": f"{args[-1][-1]}_policy_text"}))
    mock_request.side_effect = mock_responses
    vault_dump.main.get_policies(".", "token", "addr")


def test_get_auth_backends(mock_request, mock_shutil, mock_path):
    def mock_responses(*args, **kwargs):
        if args[-1].endswith("auth"):
            return mock.Mock(json=mock.Mock(return_value=
                {"data": {"ldap_no_config": {"k1": "v1", "type": "ldap"}, "token_with_config": {"k2": "v2", "type": "token"}}}))
        else: # e.g. "/auth/foo/config"
            if "ldap" in args[-1]:
                return mock.Mock(status_code=404, json=mock.Mock(return_value={}))
            else: # otherwise it's for token or any other auth backend
                return mock.Mock(json=mock.Mock(return_value={"data":{}}))
    mock_request.side_effect = mock_responses
    with mock.patch("vault_dump.main.get_auth_roles"), mock.patch("vault_dump.main.get_ldap_entities"): # tested separately
        vault_dump.main.get_auth_backends(".", "token", "addr")


@pytest.mark.parametrize("entity_type, status_code", [pytest.param("users", 200), pytest.param("groups", 200), pytest.param("other", 404)])
def test_get_ldap_entities(mock_request, mock_shutil, mock_path, entity_type, status_code):
    def mock_responses(*args, **kwargs):
        if args[-1].endswith("users"):
            return mock.Mock(status_code=status_code, json=mock.Mock(return_value=
                {"data": {"keys": {"user1": {"k1": "v1"}, "user2": {"k2": "v2"}}}}))
        elif "users" in args[-1]:
            return mock.Mock(status_code=status_code, json=mock.Mock(return_value=
                {"data": {"keys": {"user1": {"k1": "v1"}}}}))
        elif args[-1].endswith("groups"):
            return mock.Mock(status_code=status_code, json=mock.Mock(return_value=
                {"data": {"keys": {"group1": {"k1": "v1"}, "group1": {"k2": "v2"}}}}))
        elif "groups" in args[-1]:
            return mock.Mock(status_code=status_code, json=mock.Mock(return_value=
                {"data": {"keys": {"group1": {"k1": "v1"}}}}))
        else:
            return mock.Mock(status_code=status_code, json=mock.Mock(return_value={}))
    mock_request.side_effect = mock_responses
    vault_dump.main.get_ldap_entities(".", "token", "addr", entity_type)


@pytest.mark.parametrize("auth_type, status_code", [pytest.param("token", 404), pytest.param("ldap", 200)])
def test_get_auth_roles(mock_request, mock_shutil, mock_path, auth_type, status_code):
    def mock_responses(*args, **kwargs):
        if args[-1].endswith("roles"):
            return mock.Mock(status_code=status_code, json=mock.Mock(return_value=
                {"data": {"keys": {"key1_no_config": {"k1": "v1"}, "key2_with_config": {"k2": "v2"}}}}))
        else: # e.g. /v1/auth/aws/roles/abc
            return mock.Mock(json=mock.Mock(return_value={"data":{}}))
    mock_request.side_effect = mock_responses
    vault_dump.main.get_auth_roles(".", "token", "addr", "auth_path", auth_type)


@pytest.mark.parametrize("list_status_code, get_status_code", [pytest.param(403, 200), pytest.param(200, 403), pytest.param(200, 200)])
def test_get_pki_roles(mock_request, mock_shutil, mock_path, list_status_code, get_status_code):
    def mock_responses(*args, **kwargs):
        if args[-1].endswith("roles"):
            return mock.Mock(status_code=list_status_code, json=mock.Mock(return_value={"data":{"keys": ['role1', 'role2'],}}))
        elif "roles/" in args[-1]:
            return mock.Mock(status_code=get_status_code, json=mock.Mock(return_value={"data":{}}))
        else:
            return mock.Mock(json=mock.Mock(return_value={}))
    mock_request.side_effect = mock_responses
    vault_dump.main.get_pki_roles(".", "token", "addr", "mount_path/")


@pytest.mark.parametrize("list_status_code, get_status_code", [pytest.param(403, 200), pytest.param(200, 403), pytest.param(200, 200)])
def test_get_pki_certs(mock_request, mock_shutil, mock_path, list_status_code, get_status_code):
    def mock_responses(*args, **kwargs):
        if args[-1].endswith("certs"):
            return mock.Mock(status_code=list_status_code, json=mock.Mock(return_value={"data":{"keys": ['cert1', 'cert2'],}}))
        else:
            return mock.Mock(json=mock.Mock(return_value={}))
    mock_request.side_effect = mock_responses
    vault_dump.main.get_pki_certs(".", "token", "addr", "mount_path/")


def test_get_mounts(mock_request, mock_shutil, mock_path):
    def mock_responses(*args, **kwargs):
        if args[-1].endswith("mounts"):
            return mock.Mock(json=mock.Mock(return_value=
                {
                    "data": {
                        "key1_no_config": {"k1": "v1", "type": "pki"},
                        "key2_with_config": {"k2": "v2", "type": "other"},
                        "key3_with_config": {"k3": "v3", "type": "pki"}
                    }
                }))
        else: # ends in /config or /urs or /crl
            if "key1" in args[-1]:
                return mock.Mock(status_code=404, json=mock.Mock(return_value={}))
            elif "key2" in args[-1]:
                return mock.Mock(json=mock.Mock(return_value={"data":{"key": "value\nwith\nnewlines\n"}}))
            else: # key3
                return mock.Mock(json=mock.Mock(return_value={"data":{}}))
    mock_request.side_effect = mock_responses
    with mock.patch("vault_dump.main.get_pki_roles"), \
         mock.patch("vault_dump.main.get_pki_certs"): # both functions tested separately
        vault_dump.main.get_mounts(".", "token", "addr")


def test_get_audit_backends(mock_request, mock_shutil, mock_path):
    def mock_responses(*args, **kwargs):
        return mock.Mock(json=mock.Mock(return_value=
            {"data": {"key1_no_config": {"k1": "v1"}, "key2_with_config": {"k2": "v2"}}}))
    mock_request.side_effect = mock_responses
    vault_dump.main.get_audit_backends(".", "token", "addr")


def test_main(mock_request, mock_os, mock_shutil, mock_path):
    mock_shutil.rmtree = mock.Mock(side_effect=FileNotFoundError)
    vault_dump.main.main()
