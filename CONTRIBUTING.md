# Contributing

Keep changes within the fixed estate-ci contracts. New generic dispatch surfaces, arbitrary commands,
caller-selected branches, browser credentials, database dependencies, mutable audit writes, and
repository-local copies of the organization required workflow are out of scope.

Before opening a pull request, run:

```bash
make check
make test-race
docker build --pull=false --network=none -f Dockerfile.api .
docker build --pull=false -f Dockerfile.web .
```

Add negative tests for boundary changes. Contract fields are versioned and canonicalized; changing a
v1 field or its normalization is a compatibility change and requires a new schema version. Generated
Nix/Bazel policy files must be upgraded together from the reviewed organization revision and pass the
inventory verifier.

The central organization workflow owns `Pull request / required`. Do not add a workflow with that
name or check context to this repository.
