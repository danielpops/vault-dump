# vault-dump
Tool that dumps all the vault configurations of a live running vault server to disk in yaml format

This does not actually dump any secret material, only configuration

TODO:
- Refactor a bunch
- Create proper class(es) instead of one everything thrown into a single `main.py`
- Command line argument parsing
- Test on more live vault instances which might have more entity types than the ones I've tested with
