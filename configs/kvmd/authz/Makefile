BUNDLE_DIR := bundle
BUNDLE_OUT := kvmd-authz.tar.gz

.PHONY: bundle test eval clean

# Build the deployable bundle tarball.
# Deploy kvmd-authz.tar.gz to your bundle server's /bundles/ directory.
bundle:
	opa build \
		--bundle $(BUNDLE_DIR) \
		--output $(BUNDLE_OUT)
	@echo "Built $(BUNDLE_OUT)"

# Run Rego policy unit tests.
# Test data is inline in authz_test.rego (mock via 'with data as ...').
# The bundle data files are NOT loaded here — only the policy is needed.
test:
	opa test $(BUNDLE_DIR)/policy/authz.rego ../../../testenv/authz-tests/authz_test.rego --verbose

# Evaluate a decision locally against the bundled data without a running OPA
# server. Useful for checking what a specific user/device/action resolves to.
# Usage: make eval USER=admin DEVICE=switch-example ACTION=hid.write PORT=1
# ("admin" is the only static user this example bundle actually ships --
# swap in a real user/device from your own data.json.)
# NOTE: `opa eval --input` takes a real file path, not a "-" stdin marker
# like most CLI tools (it literally does open("-") and fails with "no such
# file or directory") -- /dev/stdin is the correct way to pipe input in.
# The JSON itself also has to be built as a single line: a multi-line
# single-quoted shell string does NOT interpret backslash-newline as a line
# continuation (that's only true inside double quotes or unquoted), so a
# multi-line single-quoted "heredoc-style" JSON literal is invalid JSON --
# OPA will fail to parse it. Both of these were wrong before and this
# target silently never worked.
eval:
	@echo '{"user": "$(USER)", "device_id": "$(DEVICE)", "action": "$(ACTION)", "resource": {"active_port": $(PORT)}}' | \
	opa eval \
		--bundle $(BUNDLE_DIR) \
		--format pretty \
		--input /dev/stdin \
		'data.kvmd.authz.allow'

clean:
	rm -f $(BUNDLE_OUT)
