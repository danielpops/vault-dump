set -euo pipefail

# This script iterates through all the files dumped to ./configuration and hits the live server
# In most (but not all) cases, we should be able to GET the resource
# e.g. individual mounts don't have a READ endpoint and same with auth endpoints

for i in $(find ./configuration -type f | sort -u); do path=$(echo $i | sed 's/\.\/configuration//g' | sed 's/\..*$//g'); echo $path; curl -s -k -H "X-VAULT-TOKEN: ${VAULT_TOKEN}" ${VAULT_ADDR}/v1${path} | jq .data ; done
