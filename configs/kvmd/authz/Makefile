BUNDLE_DIR := bundle
BUNDLE_OUT := kvmd-authz.tar.gz

.PHONY: bundle test clean

# Build the deployable bundle tarball.
# Deploy kvmd-authz.tar.gz to your bundle server's /bundles/ directory.
bundle:
	opa build \
		--bundle $(BUNDLE_DIR) \
		--output $(BUNDLE_OUT)
	@echo "Built $(BUNDLE_OUT)"

# Run Rego policy unit tests.
test:
	opa test $(BUNDLE_DIR)/policy/authz.rego ../../../testenv/authz-tests/authz_test.rego --verbose

# Evaluate a decision locally against the bundled data without a running OPA
# server. Useful for checking what a specific user/device/action resolves to.
# Usage: make eval USER=bob DEVICE=switch-example ACTION=hid.write PORT=1
eval:
	opa eval \
		--bundle $(BUNDLE_DIR) \
		--format pretty \
		'data.kvmd.authz.allow' \
		--input - <<< '{ \
			"user":      "$(USER)", \
			"device_id": "$(DEVICE)", \
			"action":    "$(ACTION)", \
			"resource":  {"active_port": $(PORT)} \
		}'

clean:
	rm -f $(BUNDLE_OUT)
