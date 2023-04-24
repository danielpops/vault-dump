import os
import pathlib
import re
import requests
import subprocess

import vault_dump.main

import mock
import pytest

def is_responsive(url):
    try:
        response = requests.get(url)
        if response.status_code == 200: # pragma: nobranch
            return True
    except requests.exceptions.ConnectionError as e:
        return False # pragma: nocover

@pytest.fixture(scope="session")
def vault_service(docker_ip, docker_services):
    """Ensure that HTTP service is up and responsive."""

    port = docker_services.port_for("vault", 8200)
    url = "http://{}:{}".format(docker_ip, port)
    docker_services.wait_until_responsive(
        timeout=30.0, pause=0.1, check=lambda: is_responsive(url)
    )
    output = subprocess.run(["docker-compose", "-f", "./tests/docker-compose.yml", "-p", docker_services._docker_compose._compose_project_name, "logs"], capture_output=True)

    assert requests.get(url).status_code == 200

    token = re.search("Root Token: ([^\.]+\.\w+)", str(output)).groups()[0]

    return {"token": token, "url": url}


def test_main_no_authentication_token_provided(vault_service):
    with mock.patch.dict(os.environ, {"VAULT_ADDR": vault_service["url"]}):
        with pytest.raises(Exception) as e:
            vault_dump.main.main()

        assert e

def test_main_invalid_authentication_token_provided(vault_service):
    with mock.patch.dict(os.environ, {"VAULT_TOKEN": "bad_token", "VAULT_ADDR": vault_service["url"]}):
        with pytest.raises(Exception) as e:
            vault_dump.main.main()

        assert e

def test_main_no_data(vault_service):
    with mock.patch.dict(os.environ, {"VAULT_TOKEN": vault_service["token"], "VAULT_ADDR": vault_service["url"]}):

        vault_dump.main.main()

def test_main_policy(vault_service):
    policy_text = '''
    path "auth/token/lookup-self" {
        capabilities = ["read"]
    }'''
    requests.put(vault_service["url"] + "/v1/sys/policy/test", data={"policy": policy_text}, headers={"X-VAULT-TOKEN": vault_service["token"]})
    with mock.patch.dict(os.environ, {"VAULT_TOKEN": vault_service["token"], "VAULT_ADDR": vault_service["url"]}):
        vault_dump.main.main()
        output_policy_file = pathlib.Path("./configuration/sys/policy/test.hcl")
        assert output_policy_file.exists()
        with output_policy_file.open() as f:
            assert policy_text == f.read()
