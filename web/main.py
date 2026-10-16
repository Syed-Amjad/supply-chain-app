"""
web service — the downstream half, and the attack surface.

Two endpoints matter:

  /          calls api over the cluster network. The second hop is what gives
             layer 6 something to authorize: an AuthorizationPolicy that allows
             the `web` ServiceAccount to reach `api` and denies everything else
             is only testable if a legitimate second hop exists.

  /fetch     performs an outbound HTTP request to a URL supplied by the caller.
             This is a deliberate, self-inflicted SSRF. It is the single most
             dangerous-looking thing in this repository and it is here on
             purpose — see the long comment on it below.
"""

import os

import httpx
from fastapi import FastAPI, Query, Request

app = FastAPI(title="web", version="1.0")

VERSION = os.getenv("APP_VERSION", "v1")
SERVICE = "web"
API_URL = os.getenv("API_URL", "http://api.zt-prod.svc.cluster.local:8000")


@app.get("/health")
def health():
    return {"status": "ok", "service": SERVICE, "version": VERSION}


@app.get("/")
async def index(request: Request):
    """
    Calls api and returns what it said.

    ---------------------------------------------------------------------------
    THE HEADERS ARE FORWARDED ON PURPOSE, and that is a correction of a real
    defect from the previous project.

    In the GitOps platform, Istio was configured to route canary traffic on an
    `x-canary` header. The VirtualService was correct, the gateway received the
    header, and the routing never happened — because this function had no
    Request parameter and forwarded nothing. The header died at the first hop.
    It shipped as an open defect.

    The lesson generalises past canaries: a header-based control is only worth
    the weakest hop in the chain. Here that matters for tracing the identity of
    a request across both services, so the forwarding is explicit and the
    allowlist is explicit with it. Forwarding *every* header would re-introduce
    a different bug — hop-by-hop headers like Connection, and the inbound Host,
    must not be copied onto a new request.
    ---------------------------------------------------------------------------
    """
    forward = {
        k: v
        for k, v in request.headers.items()
        if k.lower() in {"x-request-id", "x-canary", "traceparent", "tracestate"}
    }
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            r = await c.get(f"{API_URL}/data", headers=forward)
            upstream, err = r.json(), None
    except Exception as exc:
        upstream, err = None, f"{type(exc).__name__}: {exc}"

    return {
        "service": SERVICE,
        "version": VERSION,
        "forwarded": forward,
        "upstream": upstream,
        "upstream_error": err,
    }


@app.get("/fetch")
async def fetch(url: str = Query(..., description="Absolute URL to request")):
    """
    Makes an outbound request to an arbitrary URL. A deliberate SSRF.

    ===========================================================================
    WHY A KNOWINGLY VULNERABLE ENDPOINT IS IN A SECURITY PROJECT
    ===========================================================================

    The claim this project makes is not "my code has no SSRF". It is "a
    compromised workload cannot reach anything it was not declared to reach".
    Those are different claims, and only the second one survives contact with
    an application somebody else wrote.

    Demonstrating the second claim requires a workload that genuinely tries to
    make an arbitrary outbound request. Simulating it with a curl from
    `kubectl exec` would not be the same test: an exec'd shell and the service
    process are in the same network namespace, so that would actually work —
    but it proves the control holds for a human with cluster credentials, which
    is not the threat being modelled. The threat is a request arriving from
    outside and the application honouring it. So the application honours it.

    What stops it is layer 6: Istio runs with

        meshConfig.outboundTrafficPolicy.mode: REGISTRY_ONLY

    so a sidecar refuses any destination not present in the mesh registry, and
    the only external hosts in the registry are the ones declared as
    ServiceEntry objects in istio/egress-allowlist.yaml. The expected results:

      /fetch?url=https://api.github.com/zen           200  — declared, allowed
      /fetch?url=https://example.com/                 502  — not declared, blocked
      /fetch?url=http://169.254.169.254/latest/meta-data/   blocked, and see below

    The last one is worth running twice. Istio blocks it because the link-local
    address is not in the registry. Underneath that, the instance also enforces
    IMDSv2 with a hop limit of 1, so even with the mesh out of the way the
    request cannot leave the pod network namespace with a usable TTL — and the
    instance has no IAM role attached, so there would be nothing to read. Three
    independent reasons the same attack fails is what defence in depth is
    supposed to look like when you actually test it.

    ---------------------------------------------------------------------------
    A limitation stated plainly: this endpoint is unauthenticated and takes a
    URL from the query string. In the lab that is the point. It is reachable
    only from inside the cluster and the box has no inbound port open but SSH.
    Do not copy this function into anything real.
    ---------------------------------------------------------------------------
    """
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as c:
            r = await c.get(url)
        return {
            "service": SERVICE,
            "requested": url,
            "status": r.status_code,
            "body_head": r.text[:200],
            "blocked": False,
        }
    except Exception as exc:
        # An Istio REGISTRY_ONLY refusal surfaces here as an httpx transport
        # error or an upstream 502, not as a tidy "denied" message. Both are
        # reported verbatim rather than translated, because the raw text is
        # what you will actually see in the demonstration.
        return {
            "service": SERVICE,
            "requested": url,
            "status": None,
            "error": f"{type(exc).__name__}: {exc}",
            "blocked": True,
        }
