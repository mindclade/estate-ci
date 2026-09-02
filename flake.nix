{
  description = "Pinned system toolchain for github.com/mindclade/estate-ci";

  nixConfig = {
    substituters = [ "https://cache.nixos.org/" ];
    trusted-public-keys = [ "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=" ];
    require-sigs = true;
  };

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/83199d0d373dd3ac2b9a1996b1d0263f76ab7a4c";

  outputs =
    { self, nixpkgs }:
    let
      policy = import ./generated/nix-bazel-policy.nix;
      manifestDefaults = builtins.fromJSON (
        builtins.readFile ./generated/toolchain-manifest.defaults.json
      );
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
      forAllSystems =
        function:
        builtins.listToAttrs (
          map (system: {
            name = system;
            value = function system (import nixpkgs { inherit system; });
          }) systems
        );
    in
    assert policy.generated.authority_repository == "mindclade/.github";
    assert policy.generated.authority_revision == "49a015c2c0cdd6a75a5756eb8c1e95b49d117917";
    assert manifestDefaults.authority.revision == policy.generated.authority_revision;
    assert nixpkgs.rev == policy.spec.nixpkgs.revision;
    assert nixpkgs.narHash == policy.spec.nixpkgs.nar_hash;
    assert builtins.all (system: builtins.elem system policy.spec.systems) systems;
    {
      packages = forAllSystems (
        system: pkgs:
        let
          # estate-ci is a Buildkite-only Go and Next.js control-plane service. It
          # declares no Bazel toolchain, so the manifest records that explicitly
          # rather than inheriting a version it never uses.
          toolchainManifest = pkgs.writeTextDir "share/mindclade/toolchain-manifest.json" (
            builtins.toJSON {
              schema_version = "mindclade-toolchain.v1";
              repository = "mindclade/estate-ci";
              policy_authority = manifestDefaults.authority;
              inherit system;
              nixpkgs = {
                revision = nixpkgs.rev;
                nar_hash = nixpkgs.narHash;
              };
              flake_lock_sha256 = builtins.hashFile "sha256" "${self}/flake.lock";
              bazel = null;
              native_cc_store_path = "${pkgs.stdenv.cc}";
            }
          );
          toolchainPackages =
            with pkgs;
            [
              bash
              cacert
              coreutils
              cosign
              findutils
              git
              google-cloud-sdk
              grype
              gnugrep
              gnumake
              gnused
              go_1_26
              jq
              just
              nodejs_24
              osv-scanner
              python313
              ripgrep
              shellcheck
              stdenv.cc
              syft
              toolchainManifest
              zizmor
            ]
            ++ lib.optionals stdenv.hostPlatform.isDarwin [ darwin.libresolv ];
          toolchain = pkgs.buildEnv {
            name = "mindclade-estate-ci-toolchain";
            paths = toolchainPackages;
            pathsToLink = [
              "/bin"
              "/share"
            ];
            ignoreCollisions = false;
          };
        in
        {
          inherit toolchain;
          "toolchain-manifest" = toolchainManifest;
          default = toolchain;
        }
      );

      devShells = forAllSystems (
        system: pkgs:
        let
          toolchain = self.packages.${system}.toolchain;
          darwinDeploymentTarget = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin "14.0";
          locale = if pkgs.stdenv.hostPlatform.isDarwin then "en_US.UTF-8" else "C.UTF-8";
          common = {
            packages = [ toolchain ];
            MACOSX_DEPLOYMENT_TARGET = darwinDeploymentTarget;
            CC = "${pkgs.stdenv.cc}/bin/cc";
            CXX = "${pkgs.stdenv.cc}/bin/c++";
            CGO_ENABLED = "0";
            GOTOOLCHAIN = "local";
            LANG = locale;
            LC_ALL = locale;
            TZ = "UTC";
          };
        in
        {
          default = pkgs.mkShell common;
          ci = pkgs.mkShell (common // { CI = "true"; });
        }
      );

      formatter = forAllSystems (_: pkgs: pkgs.nixfmt);

      checks = forAllSystems (
        system: pkgs:
        let
          toolchain = self.packages.${system}.toolchain;
        in
        {
          toolchain =
            pkgs.runCommand "mindclade-estate-ci-toolchain-check"
              {
                nativeBuildInputs = [ toolchain ];
              }
              ''
                set -euo pipefail
                test "$(go version | awk '{print $3}')" = "go1.26.7"
                test "$(just --version)" = "just 1.58.0"
                test "$(zizmor --version)" = "zizmor 1.29.0"
                test "$(osv-scanner --version | awk '/^osv-scanner version:/ {print $3}')" = "2.5.0"
                test "$(python3 -c 'import platform; print(platform.python_version())')" = "3.13.15"
                jq -e '.schema_version == "mindclade-toolchain.v1" and .bazel == null and .policy_authority.revision == "49a015c2c0cdd6a75a5756eb8c1e95b49d117917"' \
                  ${toolchain}/share/mindclade/toolchain-manifest.json >/dev/null
                mkdir -p "$out"
                printf '%s\n' '${nixpkgs.rev}' > "$out/nixpkgs-revision"
              '';
        }
      );
    };
}
