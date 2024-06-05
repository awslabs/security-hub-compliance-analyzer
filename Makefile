# -----
# File: /Makefile
# Created Date: Wednesday August 16th 2023
# -----
#

VENV           = .venv
VENV_PYTHON    = $(VENV)/bin/python
SYSTEM_PYTHON  = $(or $(shell which python3), $(shell which python))
# If virtualenv exists, use it. If not, find python using PATH
PYTHON         = $(or $(wildcard $(VENV_PYTHON)), $(SYSTEM_PYTHON))
SHELL := /bin/bash

.PHONY: test init deploy

venv/bin/activate: requirements-development.txt requirements-deploy.txt
	$(PYTHON) -m venv $(VENV)
	$(SHELL) -c "source $(VENV)/bin/activate; pip install --requirement requirements-development.txt"
	$(SHELL) -c "source $(VENV)/bin/activate; pip install --requirement requirements-deploy.txt"

init: venv/bin/activate

deploy:
	$(SHELL) update_aws_wrangler.sh
	cdk deploy
	$(SHELL) upload_aws_securityhub_controls.sh

clean:
	rm -rf __pycache__
	rm -rf .venv
	rm -rf cdk.out
	rm -rf assets/lambda/layers/awswrangler/*.zip
