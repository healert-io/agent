# Healert Agent

**Kubernetes audit log friction detection agent for the Healert Friction Intelligence Platform.**

Tails the Kubernetes audit log, detects platform bypass events against configurable rules,
and sends friction events to the self-hosted Healert backend. Surfaces in Backstage as
per-service Friction Scores and Heatmaps via `@backstage-community/plugin-healert`.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-0.1.1-green.svg)](https://github.com/healert/agent/releases)
[![Go](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)

---

## Overview

```
Kubernetes Audit Log  (/var/log/k3s-audit.log)
      |  NDJSON events, tailed from EOF — one line at a time
      v
Healert Go Agent                          <- this repo
  isInternalSystemActor()  filter controllers, detect human operators
  matchRules()             evaluate all rules (AND logic per rule)
  send()                   POST /events with API key auth
      |
      v
Healert Backend                              github.com/healert/backend
  FastAPI + SQLite
  Exponential decay scoring
      |
      v
Backstage Plugin              @backstage-community/plugin-healert
  FrictionScoreCard + FrictionHeatmap per catalog entity
```

The agent is a **single Go binary with zero external dependencies**.
It runs as a **local process** (development) or a **Kubernetes DaemonSet** (production).

---

## Repository Structure

```
healert-agent/
|
+-- main.go         Go agent — 1,498 lines, zero external dependencies
|                   9 sections:
|                   1. Configuration    env var loading and validation
|                   2. Rule Types       Rule, RuleMatch, RulesConfig structs
|                   3. Rules Loader     YAML parser, validator, config block
|                   4. Audit Types      AuditEvent, FrictionEvent structs
|                   5. Detection        isInternalSystemActor, matchRule,
|                                       matchRules, normaliseWorkloadName
|                   6. Description      renderDescription, sanitiseLogValue
|                   7. Backend Client   send(), healthCheck(), 10s timeout
|                   8. Log Tailer       tailLog(), processLine(), bufio.Reader
|                   9. Entry Point      main(), banner, health check
|
+-- rules.yaml      Detection rules — 520 lines
|                   config block:  global ignore_namespaces
|                   5 active rules + 10+ optional rules
|                   Rule types: TYPE 1 workload, TYPE 2 shared resource,
|                               TYPE 3 cluster, TYPE 4 network, TYPE 5 storage
|
+-- healert.sh      Management script — 2,788 lines, 17 commands
|                   start [backend|agent|kubernetes]
|                   stop  [backend|agent|kubernetes]
|                   update kubernetes
|                   configure [--audit-log|--rules|--namespace]
|                   configure scoring [--threshold|--half-life|--retention]
|                   validate, restart, reset, status, logs, test, version, help
|
+-- Dockerfile      Multi-stage distroless build — 255 lines
|                   Stage 1: golang:1.22-alpine  (builder)
|                   Stage 2: gcr.io/distroless/static:nonroot (final)
|                   Result:  ~25MB, no shell, uid=65532
|                   Features: OCI labels, multi-arch, private registry support
|
+-- daemonset.yaml  Kubernetes DaemonSet — 388 lines
|                   Resources: Namespace, ServiceAccount, NetworkPolicy, DaemonSet
|                   Security:  nonroot uid=65532, readOnlyRootFilesystem, drop ALL
|                   Features:  K8S_NAMESPACE Downward API, system-node-critical priority
|                              30s termination grace period, rolling update strategy
|
+-- go.mod          Go module (zero external dependencies)
|
+-- .env.example    Configuration template
|
+-- LICENSE         Apache-2.0, Copyright 2026 Healert OU
```

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Go | 1.22+ | Compile the agent binary |
| Python 3 | 3.8+ | Backend runtime (managed by healert.sh) |
| pip | Any | Python package manager |
| curl | Any | Health checks and API calls |
| Kubernetes | Any | k3s, kubeadm, EKS, GKE, AKS |
| Audit logging | Enabled | See Audit Log Setup section |

---

## Quick Start

```bash
# 1. Clone and compile
git clone https://github.com/healert/agent.git
cd agent
go build -o healert-agent main.go

# 2. Check dependencies
./healert.sh deps

# 3. Configure directories
./healert.sh init

# 4. Generate API key and configure both sides
./healert.sh setup

# 5. Set audit log path (k3s)
./healert.sh configure --audit-log /var/log/k3s-audit.log

# 6. Validate rules
./healert.sh validate

# 7. Start backend and agent
./healert.sh start

# 8. Verify pipeline
./healert.sh test
```

---

## Audit Log Setup

### k3s

```bash
# Create audit policy
sudo mkdir -p /etc/k3s
sudo cp audit-policy.yaml /etc/k3s/audit-policy.yaml

# Enable audit logging
sudo mkdir -p /etc/systemd/system/k3s.service.d
sudo tee /etc/systemd/system/k3s.service.d/audit.conf << CONF
[Service]
ExecStart=
ExecStart=/usr/local/bin/k3s server \
  --kube-apiserver-arg=audit-log-path=/var/log/k3s-audit.log \
  --kube-apiserver-arg=audit-policy-file=/etc/k3s/audit-policy.yaml \
  --kube-apiserver-arg=audit-log-maxage=7 \
  --kube-apiserver-arg=audit-log-maxbackup=3 \
  --kube-apiserver-arg=audit-log-maxsize=100
CONF

sudo systemctl daemon-reload
sudo systemctl restart k3s
sleep 15

# Set permissions
sudo groupadd healert 2>/dev/null || true
sudo usermod -aG healert $USER
sudo chown root:healert /var/log/k3s-audit.log
sudo chmod 640 /var/log/k3s-audit.log
```

### kubeadm

```bash
# Add to kube-apiserver.yaml under spec.containers.command:
# - --audit-log-path=/var/log/kubernetes/audit/audit.log
# - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
```

---

## Commands Reference

### Local Mode

| Command | Description |
|---|---|
| `./healert.sh init` | Configure backend and agent directories |
| `./healert.sh deps` | Check and install all dependencies |
| `./healert.sh setup` | Generate API key, configure both sides |
| `./healert.sh setup rotate` | Rotate existing API key |
| `./healert.sh configure` | Update agent settings interactively |
| `./healert.sh configure --audit-log PATH` | Set audit log path |
| `./healert.sh configure --rules PATH` | Set rules.yaml path |
| `./healert.sh configure --namespace NS` | Set Backstage entity namespace |
| `./healert.sh configure scoring` | Update scoring parameters interactively |
| `./healert.sh configure scoring --threshold N` | Points for score=100 (default: 50) |
| `./healert.sh configure scoring --half-life N` | Decay half-life in days (default: 7) |
| `./healert.sh configure scoring --retention N` | Event window in days (default: 30) |
| `./healert.sh configure scoring --reset` | Restore default scoring parameters |
| `./healert.sh start` | Start backend and agent |
| `./healert.sh start backend` | Start backend only |
| `./healert.sh start agent` | Start agent only |
| `./healert.sh stop` | Stop backend and agent |
| `./healert.sh stop backend` | Stop backend only |
| `./healert.sh stop agent` | Stop agent only |
| `./healert.sh restart` | Validate rules, stop and start both |
| `./healert.sh validate` | Validate rules.yaml |
| `./healert.sh reset` | Delete and recreate database |
| `./healert.sh reset --confirm` | Reset without confirmation prompt |
| `./healert.sh status` | Show health and running state |
| `./healert.sh logs` | Tail live logs from all processes |
| `./healert.sh test` | Send test event, verify full pipeline |
| `./healert.sh version` | Show version, copyright, license |
| `./healert.sh help` | Show all commands with descriptions |

### Kubernetes DaemonSet

| Command | Description |
|---|---|
| `./healert.sh start kubernetes` | Deploy agent as Kubernetes DaemonSet |
| `./healert.sh stop kubernetes` | Remove DaemonSet and healert-system namespace |
| `./healert.sh update kubernetes` | Apply latest config with rolling restart |

---

## Configuration

### Agent

| Variable | Default | Description |
|---|---|---|
| `HEALERT_BACKEND_URL` | `http://localhost:8000` | Backend URL |
| `HEALERT_HOST` | `127.0.0.1` | Backend bind host — set to `0.0.0.0` for DaemonSet mode |
| `AUDIT_LOG_PATH` | `/var/log/k3s-audit.log` | Audit log path |
| `ENTITY_NAMESPACE` | `default` | Fallback namespace for cluster-scoped resources |
| `RULES_PATH` | required | Detection rules file path |
| `HEALERT_API_KEY` | required | Bearer token for backend auth |
| `K8S_NAMESPACE` | auto (Downward API) | Agent namespace — auto-excluded from detection |

> **DaemonSet mode**: Pods cannot reach `127.0.0.1` on the host. Set `HEALERT_HOST=0.0.0.0`
> so the backend accepts connections from the Docker bridge and pod network:
> ```bash
> ./healert.sh stop backend
> export HEALERT_HOST=0.0.0.0
> ./healert.sh start backend
> Verify backend listens on 0.0.0.0
> ss -tlnp | grep 8000
> ```

### Scoring

| Variable | Default | Description |
|---|---|---|
| `SCORE_CRITICAL_THRESHOLD` | `50` | Weighted points for score=100 |
| `SCORE_DECAY_HALF_LIFE` | `7` | Event weight half-life in days |
| `SCORE_RETENTION_DAYS` | `30` | Event window in days |

**Tuning guide:**

```bash
./healert.sh configure scoring --threshold 20 --half-life 3   # strict
./healert.sh configure scoring --threshold 50 --half-life 7   # default
./healert.sh configure scoring --threshold 100 --half-life 14 # lenient
```

---

## Detection Rules

Rules are defined in `rules.yaml`. The agent loads them at startup and evaluates
every rule against every audit log event (AND logic per rule).

### Global Namespace Exclusion

Add system namespaces to the config block to exclude them from ALL rules:

```yaml
config:
  ignore_namespaces:
    - kube-system
    - kube-public
    - kube-node-lease
    - cert-manager
    - istio-system
    - argocd
    # Add your system namespaces here
```

The agent automatically excludes its own namespace (K8S_NAMESPACE) from all detections.

### Active Rules (v0.1.1)

| Rule | Severity | Type | What It Detects |
|---|---|---|---|
| `kubectl-exec` | High | TYPE 1 Workload | Interactive shell access to pods |
| `pipeline-skip` | High | TYPE 1 Workload | Policy bypass annotation on deployments |
| `config-drift` | High | TYPE 1 Workload | Direct write operations on workload resources |
| `port-forward` | Medium | TYPE 1 Workload | Direct port-forward to pods |
| `emergency-access` | Medium | TYPE 2 Shared | Direct secret access |

### Auto-Namespace Entity Resolution (v0.1.1)

The agent uses the Kubernetes event namespace directly as the Backstage catalog namespace:

```
pod in "default"    -> component:default/payments-api    (auto)
pod in "staging"    -> component:staging/payments-api    (auto)
pod in "production" -> component:production/payments-api (auto)
```

Zero configuration required. Works for any number of namespaces.

### Scoring Formula

```
Score = min(100, round(weighted_total / threshold x 100))
weighted_total = sum(points x 0.5^(age_days / half_life))
```

| Severity | Points |
|---|---|
| high | 10 |
| medium | 6 |
| low | 3 |

---

## Kubernetes Production Deployment

### Step 1 — Build and import image

```bash
docker build -t ghcr.io/healert/agent:0.1.1 .
docker push ghcr.io/healert/agent:0.1.1

# For k3s (local registry):
docker save ghcr.io/healert/agent:0.1.1 | sudo k3s ctr images import -
```

### Step 2 — Configure daemonset.yaml

```yaml
# Set your backend host IP (not 127.0.0.1 — pods cannot reach loopback)
- name: HEALERT_BACKEND_URL
  value: "http://192.168.x.x:8000"

# Update image tag
image: ghcr.io/healert/agent:0.1.1
```

### Step 3 — Deploy

```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
./healert.sh start kubernetes
```

### Step 4 — Verify

```bash
kubectl get pods -n healert-system -o wide
kubectl logs -n healert-system -l app=healert-agent --tail=20
```

Expected:
```
Healert Agent v0.1.1
Rules:      5 loaded
Ignored namespaces (8):
  - kube-system
  ...
  - healert-system   <- auto-added from K8S_NAMESPACE
Backend OK -- version=0.1.1 auth=enabled
Tailing "/var/log/k3s-audit.log" from end-of-file
```

### Update Without Downtime

```bash
# After changing daemonset.yaml or rotating API key:
./healert.sh update kubernetes
```

---

## Security

| Property | Implementation |
|---|---|
| API key storage | `.env` with `chmod 600` — never committed to git |
| API key injection | Environment variable — never in `ps aux` output |
| Backend binding | `127.0.0.1` by default — not exposed to network |
| Kubernetes Secret | API key stored as K8s Secret — not plain env var |
| Agent user | Runs as nonroot uid=65532 (distroless) |
| Filesystem | `readOnlyRootFilesystem: true` |
| Capabilities | `drop: ALL` — zero Linux capabilities |
| Network | NetworkPolicy: egress to backend:8000 and DNS only |
| Audit log | Read-only hostPath mount |
| Shell execution | Zero exec.Command() calls in agent binary |
| Path validation | Absolute paths only, no `..` traversal |
| Input sanitisation | `sanitiseLogValue()` prevents log injection |
| HTTP timeout | 10 seconds on all outbound requests |
| Script hardening | `set -euo pipefail`, `umask 077` |
| Graceful shutdown | SIGTERM/SIGINT handler — clean exit on rolling update |
| Namespace isolation | Agent auto-excludes its own namespace |
| Priority class | `system-node-critical` — never evicted under pressure |

---

## Audit Log Paths

| Distribution | Path |
|---|---|
| k3s | `/var/log/k3s-audit.log` |
| kubeadm | `/var/log/kubernetes/audit/audit.log` |
| Vanilla Kubernetes | `/var/log/audit/audit.log` |

---

## Related Repositories

| Repo | Description |
|---|---|
| [healert-io/backend](https://github.com/healert/backend) | FastAPI + SQLite backend |
| [backstage/community-plugins](https://github.com/backstage/community-plugins) | Backstage plugin (`@backstage-community/plugin-healert`) |

---

## License

Apache License 2.0 -- Copyright 2026 Healert OÜ

See [LICENSE](./LICENSE) for the full license text.
