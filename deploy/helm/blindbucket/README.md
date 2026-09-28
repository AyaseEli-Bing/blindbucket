# blindbucket Helm chart

Runs the gateway as a shared service: a Deployment behind a Service, reached over
the cluster network by clients in other pods.

**Prefer the sidecar where you can.** Between client and gateway the body is
plaintext. [deploy/kubernetes-sidecar.yaml](../../kubernetes-sidecar.yaml) keeps
that hop inside one pod, on loopback, and needs no TLS. This chart puts it on the
network, so it serves S3 over TLS only and **refuses to render without a
certificate**. Everyone who can reach the Service and holds a client credential
gets plaintext; `networkPolicy` narrows the first half of that.

## Before installing

The chart creates no Secret. Anything given as a value is stored in the Helm
release, and usually in version control, so every key and credential is referenced
by the name of a Secret that already exists:

| Value | Secret contents |
|---|---|
| `tls.existingSecret` | `tls.crt`, `tls.key` (type `kubernetes.io/tls`, as cert-manager writes it) |
| `keys.keyringSecret` | `keyring.json`, from `blindbucket keygen` |
| `keys.passphraseSecret` | `passphrase` (with `keys.provider=file`) |
| `keys.vault.tokenSecret` | `token` (with `keys.provider=vault`) |
| `keys.awskms.credentialsSecret` | `access_key_id`, `secret_access_key` (with `keys.provider=awskms`) |
| `upstream.existingSecret` | `access_key_id`, `secret_access_key` for the provider |
| `clients[].existingSecret` | `access_key_id`, `secret_access_key` a client signs with |

```sh
kubectl create secret generic blindbucket-keyring --from-file=keyring.json
kubectl create secret generic blindbucket-passphrase --from-literal=passphrase='...'
kubectl create secret generic blindbucket-upstream \
  --from-literal=access_key_id=... --from-literal=secret_access_key=...
kubectl create secret generic backup-job-s3 \
  --from-literal=access_key_id=... --from-literal=secret_access_key=...
```

## Installing

```sh
helm install blindbucket deploy/helm/blindbucket \
  --set tls.existingSecret=blindbucket-tls \
  --set upstream.endpoint=https://s3.eu-central-1.amazonaws.com \
  --set upstream.region=eu-central-1 \
  --set upstream.existingSecret=blindbucket-upstream \
  --set keys.keyringSecret=blindbucket-keyring \
  --set keys.passphraseSecret=blindbucket-passphrase \
  --set 'clients[0].name=backup-job' \
  --set 'clients[0].existingSecret=backup-job-s3' \
  --set 'clients[0].buckets={backups}'
```

A client then needs `AWS_ENDPOINT_URL=https://blindbucket-blindbucket.<namespace>.svc`
and a certificate it trusts for that name. [values.yaml](values.yaml) documents
every setting.

## What it leaves out, and why

- **The audit log and rollback detection.** Each is a file per instance that has
  to outlive the pod: a StatefulSet with a claim per replica, not a Deployment.
  The audit log's worth also depends on where it is shipped, which a chart cannot
  decide.
- **Certificate reloading.** The gateway reads its certificate at startup. A
  certificate cert-manager renews takes effect with the next rollout, so pair it
  with something that restarts on Secret changes, or roll out before expiry.
- **Secrets.** See above.

## Monitoring

`serviceMonitor.enabled` and `prometheusRule.enabled` create the Prometheus
Operator resources. The rules are [deploy/prometheus/alerts.yaml](../../prometheus/alerts.yaml),
with the job label set to the release's Service; `make chart` fails if the chart's
copy drifts from it.

## Tested

- `make chart`: lint, render with every optional part on, validate against the
  Kubernetes schemas and the Prometheus Operator CRDs, and require that it refuses
  to render without TLS.
- `make chart-e2e` ([test/helm/kind.sh](../../../test/helm/kind.sh)): a kind
  cluster with MinIO, the chart installed from the checkout, and the AWS CLI in
  another pod putting a 20 MiB multipart object through it over TLS and reading it
  back with an identical SHA-256. MinIO is then asked directly, and has to hold a
  blindbucket segment. Both run in CI.
