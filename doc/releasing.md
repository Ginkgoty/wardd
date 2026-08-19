# Release process

wardd has two release channels. Both channels build and test native packages
on GitHub-hosted runners; package publication occurs only after every matrix
job succeeds.

## Channels and version ordering

| Channel | Trigger | GitHub release | Package version example | Retention |
|---|---|---|---|---|
| Nightly | Every push to `main`, or manual dispatch from `main` | Mutable `nightly` prerelease | DEB `0.1.0~nightly.202608191530.abc123def456-1`; RPM `0.1.0-0.nightly.202608191530.abc123def456.el9` | Replaced after the next successful build |
| Stable | A pushed `vMAJOR.MINOR.PATCH` tag | Immutable full release | DEB `0.1.0-1`; RPM `0.1.0-1.el9` | Permanent |

The DEB `~nightly` and RPM `0.nightly` forms sort before the corresponding
stable package. The program reports a nightly identity such as
`0.1.0-nightly.202608191530.abc123def456` from `wardd --version` and
`wardctl --version`.

The nightly workflow cancels an older in-progress nightly run when a newer
commit arrives. It first builds all four packages, then deletes and recreates
the `nightly` prerelease and tag at the successful commit. A failed build never
replaces the last usable nightly release.

Stable releases are not overwritten. GitHub automatically exposes source ZIP
and tar archives for the release tag; the workflow uploads the four native
packages and `SHA256SUMS`. It also records signed GitHub artifact attestations
for the packages identified by that checksum manifest.

## Build matrix

The reusable `.github/workflows/_packages.yml` workflow runs the same phases
for both channels:

1. Build DEB packages natively on Ubuntu 24.04 `amd64` and `arm64` runners.
2. Build RPM packages in Rocky Linux 9 containers on `x86_64` and `aarch64`
   runners.
3. Build the C17 binaries and architecture-specific BPF object in `Release`
   mode.
4. Run every enabled CTest test before packaging.
5. Ask CPack to resolve shared-library dependencies and build the native
   package.
6. Inspect package metadata and file manifests before uploading workflow
   artifacts.

Package lifecycle scripts create wardd's tmpfiles paths and reload systemd.
They never enable the service, create an active configuration, attach XDP, or
change host/cloud firewall rules.

## Stable release gates

Before tagging a stable release:

1. Ensure the nightly workflow for the intended commit is green.
2. Test that nightly build on representative Ubuntu and RHEL/Rocky hosts,
   including package install/upgrade/removal, Nginx integration, reboot,
   observation mode, enforcement, and XDP detachment.
3. Confirm cloud-console or equivalent recovery and verify IPv4/IPv6 CN and
   non-CN behavior without disrupting required outbound connections.
4. Review security-sensitive changes, generated package contents, runtime
   dependencies, and `SHA256SUMS`.
5. Update `project(... VERSION ...)` in `CMakeLists.txt` to the intended
   semantic version and merge that change to `main`.
6. Decide and document the repository-wide software license before the first
   public stable release. Until then RPM metadata intentionally reports
   `Unspecified`; the BPF program's kernel-facing GPL declaration is not a
   repository-wide license grant.

The stable workflow enforces three additional invariants:

- the tag must exactly match `vMAJOR.MINOR.PATCH` without leading zeroes or a
  prerelease suffix;
- the tag version must match the CMake project version;
- the tagged commit must be contained in `origin/main`.

## Create a stable release

Run the validator from a clean checkout at the intended commit:

```sh
scripts/validate-release-tag.sh v0.1.0
ctest --test-dir build --output-on-failure
```

Prefer a signed annotated tag. The push starts the stable workflow:

```sh
git switch main
git pull --ff-only
git tag -s v0.1.0 -m "wardd v0.1.0"
git push origin v0.1.0
```

If signing infrastructure is not yet available, an annotated tag (`git tag
-a`) still records release intent but does not provide signer verification.
Repository owners may configure required reviewers on the `stable-release`
GitHub environment to add an approval gate before publication.

After the workflow completes, verify the release:

```sh
gh release view v0.1.0
gh release download v0.1.0 --pattern 'wardd-*' --pattern 'wardd_*' \
  --pattern SHA256SUMS --dir wardd-v0.1.0
cd wardd-v0.1.0
sha256sum --check SHA256SUMS
for package in ./*.deb ./*.rpm; do
  gh attestation verify --repo Ginkgoty/wardd "$package"
done
```

## Failure and correction policy

- A nightly failure leaves the previous nightly release untouched. Fix the
  cause and push a new `main` commit or manually rerun the workflow.
- A stable validation or build failure creates no GitHub release. If the tag
  itself is correct, fix only transient infrastructure issues and rerun the
  failed workflow.
- Never move or overwrite a stable tag after it has been published. If code,
  metadata, dependencies, or package contents are wrong, increment the patch
  version and publish a new release.
- If a stable tag was pushed accidentally and no release was published or
  consumed, deleting it is a repository-owner decision. Record the incident;
  do not automate tag deletion in the stable workflow.
