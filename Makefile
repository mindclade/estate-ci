.PHONY: check policy-check test test-race web-check validate-source

check: test web-check validate-source

policy-check:
	python3 tools/verify_source_inventory.py
	python3 -m unittest discover -s tools/tests -p 'test_*.py'

test:
	go vet ./cmd/... ./internal/...
	go test -count=1 ./cmd/... ./internal/...

test-race:
	go test -race -count=1 ./cmd/... ./internal/...

web-check:
	cd web && npm run lint && npm run typecheck && npm test && npm run build && ! rg -n 'local-development' .next/server .next/static .next/standalone

validate-source:
	test -z "$$(gofmt -l cmd internal)"
	go mod tidy -diff
	python3 -m json.tool api/openapi.json >/dev/null
	find config schemas ci generated -name '*.json' -print0 | xargs -0 -n1 python3 -m json.tool >/dev/null
	$(MAKE) policy-check
	! rg -n --hidden --glob '!web/package-lock.json' '(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,})' .
