"""
api service — the upstream half of the demo pair.

Deliberately small. The platform is the portfolio piece, not the application.
In this project the application has one job beyond answering: it must be the
thing that gets SIGNED, SCANNED and ADMITTED, so what matters about it is its
image, not its code.

It does carry one feature the previous project's equivalent did not: /whoami
reports the mTLS peer identity Istio presents in the forwarded client
certificate. That is what turns "the AuthorizationPolicy is applied" into
"this request arrived as this SPIFFE identity", which is the difference between
a configuration and an observation.
"""

import os

from fastapi import FastAPI, Request

app = FastAPI(title="api", version="1.0")

VERSION = os.getenv("APP_VERSION", "v1")
SERVICE = "api"


@app.get("/health")
def health():
    return {"status": "ok", "service": SERVICE, "version": VERSION}


@app.get("/data")
def data():
    return {"service": SERVICE, "version": VERSION, "payload": [1, 2, 3]}


@app.get("/whoami")
def whoami(request: Request):
    """
    Reports the caller identity as the mesh sees it.

    Istio's sidecar sets X-Forwarded-Client-Cert on mTLS connections. It
    contains the peer SPIFFE URI, which looks like:

        spiffe://cluster.local/ns/zt-prod/sa/web

    That string is the whole point of layer 6. A NetworkPolicy can only say
    "a pod with label app=web"; any workload author can write that label. The
    SPIFFE identity comes from the ServiceAccount token and the certificate
    istiod issued for it, which a workload cannot assert on its own.

    Returns peer=None when the header is absent, which is itself informative:
    it means the request did NOT arrive over mTLS, so either the caller has no
    sidecar or traffic redirection is not working. See the note about the k3s
    CNI paths in scripts/00-bootstrap-cluster.sh.
    """
    xfcc = request.headers.get("x-forwarded-client-cert")
    peer = None
    if xfcc:
        for part in xfcc.split(";"):
            if part.startswith("URI="):
                peer = part[4:]
                break
    return {
        "service": SERVICE,
        "version": VERSION,
        "peer": peer,
        "mtls": peer is not None,
    }
