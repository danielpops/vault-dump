from pathlib import Path
import shutil
import os
import requests
import sys
import urllib3
import yaml

# Disable warnings for ignoring cert verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

yaml.SafeDumper.original_represent_str = yaml.SafeDumper.represent_str

# https://stackoverflow.com/a/45004775/542442
def fix_newline_yaml_shenanigans(dumper: yaml.SafeDumper, data: str) -> str:
    if '\n' in data:
        return dumper.represent_scalar(u'tag:yaml.org,2002:str', data, style='|')
    return dumper.original_represent_str(data)

yaml.add_representer(str, fix_newline_yaml_shenanigans, Dumper=yaml.SafeDumper)


def make_request(token: str, vault_addr: str, path: str, verb: str = "GET"):

    print(f"Making {verb} request to {vault_addr}/{path}")
    response = requests.request(verb, f"{vault_addr}/{path}", verify=False, headers={"X-VAULT-TOKEN": token})

    if "errors" in response.json() and "permission denied" in response.json()["errors"]:
        raise Exception("Permission denied. Did you provide a valid Vault Token and/or do you have sufficient privileges on the vault server?")

    return response

def main():

    config_root = "./configuration"
    vault_token = os.getenv("VAULT_TOKEN")
    if not vault_token:
        raise Exception("You need to provide a vault token via the VAULT_TOKEN environment variable")

    config_root_path = Path(f"{config_root}")
    try:
        shutil.rmtree(str(config_root_path.expanduser().absolute()))
    except FileNotFoundError:
        pass

    vault_addr = os.getenv("VAULT_ADDR", "http://localhost:8200")


    # policies
    get_policies(config_root, vault_token, vault_addr)

    # auth methods
    get_auth_backends(config_root, vault_token, vault_addr)

    # audit backends
    get_audit_backends(config_root, vault_token, vault_addr)

    # mounts (used for secrets engines)
    get_mounts(config_root, vault_token, vault_addr)


def get_policies(config_root, vault_token, vault_addr):
    get_policies_response = make_request(vault_token, vault_addr, "v1/sys/policy")

    policy_names = get_policies_response.json()["policies"]

    for policy_name in policy_names:
        # Built-in ones that don't need to be represented here and have no actual content
        if policy_name in ["root"]:
            continue
        policy_file = Path(f"{config_root}/sys/policy/{policy_name}.hcl")
        policy_file.parent.mkdir(parents=True, exist_ok=True)
        get_policy_response = make_request(vault_token, vault_addr, f"v1/sys/policy/{policy_name}")
        policy_text = get_policy_response.json()["rules"]
        with(policy_file.open("w+")) as f:
            f.write(policy_text)

def get_auth_backends(config_root, vault_token, vault_addr):
    get_auth_backends_response = make_request(vault_token, vault_addr, "v1/sys/auth")

    auth_methods = get_auth_backends_response.json()["data"]
    for auth_path, auth_details in auth_methods.items():
        auth_config_file = Path(f"{config_root}/sys/auth/{auth_path[:-1]}.yaml")
        auth_config_file.parent.mkdir(parents=True, exist_ok=True)
        with(auth_config_file.open("w+")) as f:
            f.write(yaml.safe_dump(auth_details))

        # some auth backends have additional configuration, e.g. ldap or kubernetes
        # Rather than itemize each one of those, just try to lookup config for each path and ignore errors
        get_auth_extra_config_response = make_request(vault_token, vault_addr, f"v1/auth/{auth_path}config")
        if not get_auth_extra_config_response.status_code in [403, 404]:
            extra_auth_config_file = Path(f"{config_root}/auth/{auth_path}config.yaml")
            extra_auth_config_file.parent.mkdir(parents=True, exist_ok=True)
            with(extra_auth_config_file.open("w+")) as f:
                f.write(yaml.safe_dump(get_auth_extra_config_response.json()["data"]))

        get_auth_roles(config_root, vault_token, vault_addr, auth_path, auth_details["type"])

        # ldap has separate configurations for users and groups
        if auth_path.startswith("ldap"):
            for ldap_entity in ["groups", "users"]:
                get_ldap_entities(config_root, vault_token, vault_addr, ldap_entity)

        if auth_details["type"] == "aws-ec2":
            list_sts_accounts = make_request(vault_token, vault_addr, f"v1/auth/{auth_path}config/sts", "LIST")
            if list_sts_accounts.status_code not in [403, 404]:
                list_sts_data = list_sts_accounts.json()
                for account_id in list_sts_data['data']['keys']:
                    get_sts_settings = make_request(vault_token, vault_addr, f"v1/auth/{auth_path}config/sts/{account_id}")
                    sts_file = Path(f"{config_root}/auth/{auth_path}config/sts/{account_id}.yaml")
                    sts_file.parent.mkdir(parents=True, exist_ok=True)
                    with sts_file.open("w+") as f:
                        f.write(yaml.safe_dump(get_sts_settings.json()["data"]))

def get_ldap_entities(config_root, vault_token, vault_addr, ldap_entity):
    list_ldap_entities_response = make_request(vault_token, vault_addr, f"v1/auth/ldap/{ldap_entity}", "LIST")
    if not list_ldap_entities_response.status_code in [403, 404]:
        for entity_name in list_ldap_entities_response.json()["data"]["keys"]:
            get_ldap_entity_response = make_request(vault_token, vault_addr, f"v1/auth/ldap/{ldap_entity}/{entity_name}")

            ldap_entity_file = Path(f"{config_root}/auth/ldap/{ldap_entity}/{entity_name}.yaml")
            ldap_entity_file.parent.mkdir(parents=True, exist_ok=True)
            with(ldap_entity_file.open("w+")) as f:
                f.write(yaml.safe_dump(get_ldap_entity_response.json()["data"]))


def get_auth_roles(config_root, vault_token, vault_addr, auth_path, auth_backend_type):
    # each auth backend may have roles defined for them
    # enumerate them all and get their configuration details
    role_or_roles = "role" if auth_backend_type in ["kubernetes"] else "roles"
    list_roles_response = make_request(vault_token, vault_addr, f"v1/auth/{auth_path}{role_or_roles}", "LIST")
    if not list_roles_response.status_code in [403, 404]:
        for role_name in list_roles_response.json()["data"]["keys"]:
            # This is necessary because of a silly inconsistency in the vault API
            role_or_roles = "roles" if auth_backend_type in ["token"] else "role"
            get_role_response = make_request(vault_token, vault_addr, f"v1/auth/{auth_path}{role_or_roles}/{role_name}")

            role_config_file = Path(f"{config_root}/auth/{auth_path}{role_or_roles}/{role_name}.yaml")
            role_config_file.parent.mkdir(parents=True, exist_ok=True)
            with(role_config_file.open("w+")) as f:
                f.write(yaml.safe_dump(get_role_response.json()["data"]))


def get_pki_roles(config_root, vault_token, vault_addr, mount_path):
    # each pki backend may have roles defined for them
    # enumerate them all and get their configuration details
    list_roles_response = make_request(vault_token, vault_addr, f"v1/{mount_path}roles", "LIST")
    if not list_roles_response.status_code in [403, 404]:
        for role_name in list_roles_response.json()["data"]["keys"]:
            get_role_response = make_request(vault_token, vault_addr, f"v1/{mount_path}roles/{role_name}")

            # In some edge case, the actual role might not exist (or be accessible?) despite being included in the LIST command above
            if get_role_response.status_code in [403, 404]:
                # Just skip it if that happens
                print(f"Could not access role pki secret backend role {role_name} for pki secret backend {mount_path}")
                continue

            role_config_file = Path(f"{config_root}/{mount_path}roles/{role_name}.yaml")
            role_config_file.parent.mkdir(parents=True, exist_ok=True)
            with(role_config_file.open("w+")) as f:
                f.write(yaml.safe_dump(get_role_response.json()["data"]))


def get_mounts(config_root, vault_token, vault_addr):
    get_mounts_response = make_request(vault_token, vault_addr, "v1/sys/mounts")

    mounts = get_mounts_response.json()["data"]
    for mount_path, mount_details in mounts.items():
        mount_config_file = Path(f"{config_root}/sys/mounts/{mount_path[:-1]}.yaml")
        mount_config_file.parent.mkdir(parents=True, exist_ok=True)
        with(mount_config_file.open("w+")) as f:
            f.write(yaml.safe_dump(mount_details))

        # some mounts have additional configuration, e.g. ldap or kubernetes
        # Rather than itemize each one of those, just try to lookup config for each path and ignore errors
        get_mount_extra_config_response = make_request(vault_token, vault_addr, f"v1/mount/{mount_path}config")
        if not get_mount_extra_config_response.status_code in [403, 404]:
            extra_mount_config_file = Path(f"{config_root}/mount/{mount_path}config.yaml")
            extra_mount_config_file.parent.mkdir(parents=True, exist_ok=True)
            with(extra_mount_config_file.open("w+")) as f:
                f.write(yaml.safe_dump(get_mount_extra_config_response.json()["data"]))

        if mount_details["type"] == "pki":
            # CA secret backends might have /v1/name/config/urls and /v1/name/config/crl endpoints
            get_pki_urls_response = make_request(vault_token, vault_addr, f"v1/{mount_path}config/urls")
            if get_pki_urls_response.status_code not in [403, 404]:
                pki_urls_config_file = Path(f"{config_root}/{mount_path}config/urls.yaml")
                pki_urls_config_file.parent.mkdir(parents=True, exist_ok=True)
                with(pki_urls_config_file.open("w+")) as f:
                    f.write(yaml.safe_dump(get_pki_urls_response.json()["data"]))

            get_pki_crl_response = make_request(vault_token, vault_addr, f"v1/{mount_path}config/crl")
            if get_pki_crl_response.status_code not in [403, 404]:
                pki_crl_config_file = Path(f"{config_root}/{mount_path}config/crl.yaml")
                pki_crl_config_file.parent.mkdir(parents=True, exist_ok=True)
                with(pki_crl_config_file.open("w+")) as f:
                    f.write(yaml.safe_dump(get_pki_crl_response.json()["data"]))

            # They may also likely have role definitions
            get_pki_roles(config_root, vault_token, vault_addr, mount_path)
            get_pki_certs(config_root, vault_token, vault_addr, mount_path)


def get_audit_backends(config_root, vault_token, vault_addr):
    get_audit_backends_response = make_request(vault_token, vault_addr, "v1/sys/audit")

    audit_methods = get_audit_backends_response.json()["data"]
    for audit_path, audit_details in audit_methods.items():
        audit_config_file = Path(f"{config_root}/sys/audit/{audit_path[:-1]}.yaml")
        audit_config_file.parent.mkdir(parents=True, exist_ok=True)
        with(audit_config_file.open("w+")) as f:
            f.write(yaml.safe_dump(audit_details))


def get_pki_certs(config_root, vault_token, vault_addr, mount_path):
    # This will dump out a list of certificate IDs for a given PKI backend
    pki_certs_response = make_request(vault_token, vault_addr, f"v1/{mount_path}/certs", "LIST")
    if pki_certs_response.status_code in [403, 404]:
        print('Error for getting certs from', mount_path)
        return
    response = pki_certs_response.json()
    certs = response.get('data', {}).get('keys', [])
    if certs:
        certs_file = Path(f"{config_root}/{mount_path}/certs.yaml")
        certs_file.parent.mkdir(parents=True, exist_ok=True)
        with(certs_file.open("w+")) as f:
            f.write(yaml.safe_dump(certs))


if __name__ == "__main__":
    main()
