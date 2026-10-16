# Non-root by construction, and in this project that is not a preference.
#
# Pod Security Admission runs at the `restricted` level on the namespaces this
# lands in, and a Kyverno policy checks the same properties independently. An
# image that wants root is rejected at admission before anything runs, so it is
# cheaper to build it correctly than to discover it at deploy time.
FROM python:3.12-slim

# ---------------------------------------------------------------------------
# NUMERIC UID, not just a name.
#
# runAsNonRoot is evaluated by the kubelet against the image config. It cannot
# resolve a USERNAME to a uid without pulling and inspecting /etc/passwd, so an
# image whose USER is a name fails the check at container start with:
#
#   Error: container has runAsNonRoot and image has non-numeric user (appuser),
#   cannot verify user is non-root
#
# That failure happens AFTER admission, so every policy in this repo passes and
# the pod still never starts. Setting a numeric USER is the fix.
# ---------------------------------------------------------------------------
RUN useradd -u 10001 -m appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

USER 10001
EXPOSE 8000

# --proxy-headers so the client address survives the Istio sidecar.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
