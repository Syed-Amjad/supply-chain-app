# supply-chain-app

Two FastAPI services, deliberately small. **The pipeline is the artifact here,
not the application.**

| Service | Port | Role |
|---|---|---|
| `api` | 8000 | Upstream. `/whoami` reports the mTLS peer identity Istio presents, which is what makes layer 6 observable rather than merely configured. |
| `web` | 8001 | Calls `api` — the second hop that gives the AuthorizationPolicy something to authorize. `/fetch` performs an outbound request to a caller-supplied URL. |

## `/fetch` is a deliberate SSRF

It is the most dangerous-looking function in either repository and it is there
on purpose. The claim this project makes is not *"my code has no SSRF"* — it is
*"a compromised workload cannot reach anything it was not declared to reach."*
Proving the second needs a workload that really does attempt an arbitrary
outbound request. `scripts/attack-05-egress-exfiltration.sh` in the GitOps repo
drives it. The long comment on the function explains the three independent
controls that stop it.

**Do not copy that function into anything real.**

## What the pipeline does

`.github/workflows/build-sign.yml`, in this order:

1. **Build and push**, capturing the digest the registry returned
2. **SBOM** of the pushed image, by digest, in SPDX JSON (`syft`)
3. **Scan**, failing the build on **fixable** HIGH/CRITICAL (`trivy`)
4. **Sign the digest**, keylessly, with this workflow's OIDC identity (`cosign`)
5. **Attest the SBOM**, bound to the same digest and identity
6. **Verify** both from scratch, in the same run
7. **Write the digests** into `zerotrust-gitops`

A signature produced before the scan would mean *"this was built here"*. Produced
after, it means *"this was built here and passed the gate"* — which is the claim
the admission policy relies on.

### Three decisions worth defending

**Signed by digest, never by tag.** A tag is a mutable pointer. Whoever can push
to the registry can move `:v1` to different bytes after you scanned them, so
signing a tag signs a promise somebody else is allowed to break.

**`provenance: false` on the build.** buildx otherwise attaches a SLSA
attestation, which turns the push into an OCI image *index* with two manifests.
cosign then signs the index digest, and the signature verifies by hand while
still being refused at admission. That is a very long evening.

**`--ignore-unfixed` on the scan.** Without it this build does not pass:
`python:3.12-slim` carries HIGH and CRITICAL CVEs with no published fix. A gate
that fails every build for something no code change can fix gets switched off,
and then it is not catching the fixable ones either. Fixable findings gate;
everything else is reported.

## There is a deliberately unsigned image

`publish-unsigned-control` pushes `ghcr.io/syed-amjad/zt-unsigned-control:latest`
with **no signature**, on every run. It is the negative control for attack 1.
Reaching for `nginx:latest` instead would test the *registry allowlist* rather
than the signature check — a different policy, passing for the wrong reason.

That job has no `id-token: write` permission. Not an oversight: it must not be
*able* to sign.

## Required repository configuration

| Kind | Name | Value |
|---|---|---|
| Variable | `GITOPS_REPO` | `Syed-Amjad/zerotrust-gitops` |
| Secret | `GITOPS_TOKEN` | Fine-grained PAT, **contents: write on `zerotrust-gitops` only** |

`GITHUB_TOKEN` cannot reach another repository, which is why the PAT exists.
Scope it to that one repo — it is the only external write this pipeline has.

**After the first green run, make the GHCR packages public.** Cosign stores each
signature as a `sha256-<hex>.sig` tag in the same repository as the image, so a
private package means Kyverno cannot fetch the signature it is being asked to
verify. The failure reads like a policy bug.

## Local run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r api/requirements.txt -r web/requirements.txt
uvicorn main:app --app-dir api --port 8000 &
API_URL=http://localhost:8000 uvicorn main:app --app-dir web --port 8001 &
curl -s localhost:8001/ | jq
```

`/whoami` will report `"mtls": false` locally. That is correct — there is no
sidecar, so there is no peer certificate. It is also the exact signal that
catches a broken Istio CNI installation in the cluster, where the sidecar is
present and traffic is not being redirected through it.
