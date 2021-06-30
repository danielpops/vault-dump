
test:
	@tox -- tests/test_main.py

itest:
	@tox -- tests/test_vault_integration.py

virtualenv_run:
	tox -e virtualenv_run
