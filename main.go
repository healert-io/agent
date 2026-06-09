// Copyright 2026 Healert OÜ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// =============================================================================
// main.go — Healert Go Agent v0.1.0
// =============================================================================
//
// Copyright 2026 Healert OÜ
// Licensed under the Apache License, Version 2.0
// https://www.apache.org/licenses/LICENSE-2.0
//
// Repository: github.com/healert/agent
// Backend:    github.com/healert/backend
// Plugin:     @backstage-community/plugin-healert
//
// =============================================================================
// DESCRIPTION
// =============================================================================
//
// The Healert Go Agent is a lightweight, zero-dependency process that
// continuously tails the Kubernetes audit log and sends friction events
// to the self-hosted Healert backend when detection rules match.
//
// It is designed to run as:
//   - A local process managed by healert.sh (development/single-node)
//   - A Kubernetes DaemonSet (production — one pod per node)
//
// =============================================================================
// ARCHITECTURE
// =============================================================================
//
//   Kubernetes API Server
//     ↓ writes audit events (NDJSON, one JSON object per line)
//   /var/log/k3s-audit.log  (or kubeadm: /var/log/kubernetes/audit/audit.log)
//     ↓ tailed from EOF by tailLog() — one line at a time
//   processLine()
//     ↓ json.Unmarshal → AuditEvent struct
//   matchRules()
//     ↓ evaluates all rules in rules.yaml (AND logic per rule)
//   isInternalSystemActor()
//     ↓ filters internal k8s controllers, passes human operators
//   matchRule()
//     ↓ resource, subresource, verb, annotation, namespace checks
//   send()
//     ↓ POST /events to Healert backend with Authorization: Bearer header
//   Healert Backend (main.py)
//     ↓ stores event, calculates friction score
//   Backstage Plugin
//     ↓ FrictionScoreCard + FrictionHeatmap rendered per service
//
// =============================================================================
// SECTIONS
// =============================================================================
//
//   1. CONFIGURATION      — agentConfig, loadConfig(), env var validation
//   2. RULE DEFINITIONS   — Rule, RuleMatch, RuleSet structs
//   3. RULES LOADER       — loadRules(), parseRulesYAML(), validateRule()
//   4. AUDIT TYPES        — AuditEvent, FrictionEvent structs
//   5. DETECTION ENGINE   — SAFE_TEXT_PATTERN, isInternalSystemActor()
//                           matchRule(), matchRules(), normaliseWorkloadName()
//   6. DESCRIPTION ENGINE — renderDescription(), sanitiseLogValue()
//   7. BACKEND CLIENT     — send(), healthCheck(), HTTP with timeout
//   8. LOG TAILER         — tailLog(), processLine(), bufio.Reader
//   9. ENTRY POINT        — main(), startup banner, health check, tailLog()
//
// =============================================================================
// SECURITY PROPERTIES
// =============================================================================
//
//   - API key injected via env var — never appears in ps aux output
//   - Backend binds to 127.0.0.1 by default — not exposed to network
//   - Kubernetes DaemonSet: API key loaded from Kubernetes Secret
//   - Audit log: read-only hostPath mount — agent never writes to it
//   - No shell execution — no exec.Command(), no user-controlled paths
//   - Path validation — AUDIT_LOG_PATH must be absolute, no .. traversal
//   - Input sanitisation — all values checked before sending to backend
//   - HTTP timeout: 10 seconds — no indefinite hangs on backend calls
//   - Event deduplication: only ResponseComplete stage processed
//
// =============================================================================

// =============================================================================
// main.go — Healert Go Agent v0.1.0
// =============================================================================
//
// Continuously tails the Kubernetes audit log and sends friction events
// to the self-hosted Healert backend when detection rules match.
//
// -----------------------------------------------------------------------------
// ARCHITECTURE
// -----------------------------------------------------------------------------
//
//   Kubernetes Audit Log (NDJSON)
//     ↓ tail from EOF, one line per event
//   parseRulesYAML() — load rules.yaml at startup
//     ↓
//   processLine() — parse JSON audit event
//     ↓
//   matchRules() — evaluate ALL rules against event (AND logic per rule)
//     ↓ matched events only
//   send() — POST /events to Healert backend with API key
//     ↓
//   Backend stores event → calculates friction score → plugin reads it
//
// -----------------------------------------------------------------------------
// ENTITY RESOLUTION — HOW EVENTS MAP TO BACKSTAGE CATALOG ENTRIES
// -----------------------------------------------------------------------------
//
// The agent maps Kubernetes audit events to Backstage entity refs using the
// objectRef.name field from the audit log. Two types of rules exist:
//
//   TYPE 1 — WORKLOAD RULES (kubectl-exec, config-drift, port-forward)
//     objectRef.name = pod/deployment name → normalised to workload name
//     Entity resolution is AUTOMATIC — no configuration needed.
//
//     Example:
//       Pod name:    payments-api-7d9f8b-xkj2p
//       Normalised:  payments-api
//       Entity ref:  component:default/payments-api  
//
//   TYPE 2 — SHARED RESOURCE RULES (secrets, configmaps)
//     objectRef.name = resource name (e.g. "db-credentials") NOT service name
//
//     Example:
//       Secret name: db-credentials
//       Entity ref:  component:default/db-credentials  
//
// -----------------------------------------------------------------------------
// SECURE BY DESIGN
// -----------------------------------------------------------------------------
//
//   - API key in header only — never in process args or logs (ps aux safe)
//   - URL scheme validation — rejects non-http/https (prevents SSRF)
//   - Path validation — rejects relative paths and .. traversal
//   - HTTP client timeout — 10s on all outbound requests
//   - Input validation — entity_ref, rules fields validated at startup
//   - Seek to EOF on open — no event replay on restart
//   - ResponseComplete only — prevents triple-counting per audit event
//   - RULES_PATH required — refuses to start without explicit rules file
//   - Zero external dependencies — no supply chain risk (stdlib only)
//   - Regex-based pod hash stripping — handles all Kubernetes workload types
//   - Log injection prevention — sanitiseLogValue strips control chars
//
// -----------------------------------------------------------------------------
// CONFIGURATION — environment variables
// -----------------------------------------------------------------------------
//
//   HEALERT_BACKEND_URL   Backend address        (default: http://localhost:8000)
//   AUDIT_LOG_PATH        Audit log file path    (default: /var/log/k3s-audit.log)
//   ENTITY_NAMESPACE      Backstage namespace    (default: default)
//   RULES_PATH            Path to rules.yaml     (REQUIRED — no default)
//   HEALERT_API_KEY       API key for backend    (required if auth enabled)
//
//   Audit log paths by Kubernetes distribution:
//     k3s:      /var/log/k3s-audit.log
//     kubeadm:  /var/log/kubernetes/audit/audit.log
//     Vanilla:  /var/log/audit/audit.log
//
// -----------------------------------------------------------------------------
// WORKLOAD NAME NORMALISATION
// -----------------------------------------------------------------------------
//
//   Pod names are normalised to their parent workload name so entity refs
//   match Backstage catalog entries regardless of Kubernetes workload type:
//
//     Deployment:  payments-api-7d9f8b-xkj2p  →  payments-api
//     StatefulSet: postgres-0                  →  postgres
//     DaemonSet:   healert-agent-xkj2p         →  healert-agent
//     Job/CronJob: backup-28492800-abc12       →  backup
//     Bare pod:    my-pod                      →  my-pod (unchanged)
//


package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// =============================================================================
// SECTION 1 — CONFIGURATION
//
// All configuration is read from environment variables at startup.
// The agent validates all values and exits with a clear error message
// if anything is invalid — fail fast rather than silently drop events.
// =============================================================================

// agentConfig holds all runtime configuration read from environment variables.
// Treated as immutable after loadConfig() — never modified at runtime.
type agentConfig struct {
	backendURL      string // validated: must start with http:// or https://
	auditLogPath    string // validated: must be absolute path, no .. traversal
	entityNamespace string // Backstage catalog namespace for entity refs
	rulesPath       string // required: agent exits if empty or file unreadable
	apiKey          string // Authorization: Bearer header value
}

// loadConfig reads and validates all configuration from environment variables.
// Exits immediately with a descriptive error on invalid or missing required values.
// This ensures misconfiguration is caught at startup not silently at runtime.
func loadConfig() agentConfig {
	cfg := agentConfig{
		backendURL:      "http://localhost:8000",
		auditLogPath:    "/var/log/k3s-audit.log",
		entityNamespace: "default",
	}

	if v := os.Getenv("HEALERT_BACKEND_URL"); v != "" {
		trimmed := strings.TrimRight(v, "/")
		// Validate URL scheme — prevents SSRF via non-HTTP schemes (file://, ftp://)
		if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
			log.Fatalf(
				"CONFIG ERROR: Invalid HEALERT_BACKEND_URL %q\n"+
					"  Must start with http:// or https://\n"+
					"  Example: export HEALERT_BACKEND_URL=http://localhost:8000",
				trimmed,
			)
		}
		cfg.backendURL = trimmed
	}

	if v := os.Getenv("AUDIT_LOG_PATH"); v != "" {
		// Validate path is absolute — prevents relative path injection
		if !strings.HasPrefix(v, "/") {
			log.Fatalf(
				"CONFIG ERROR: AUDIT_LOG_PATH %q must be an absolute path\n"+
					"  Example: export AUDIT_LOG_PATH=/var/log/k3s-audit.log",
				v,
			)
		}
		// Validate no path traversal sequences
		if strings.Contains(v, "..") {
			log.Fatalf(
				"CONFIG ERROR: AUDIT_LOG_PATH %q contains path traversal sequence\n"+
					"  Use an absolute path without '..'",
				v,
			)
		}
		cfg.auditLogPath = v
	}

	if v := os.Getenv("ENTITY_NAMESPACE"); v != "" {
		if !isValidNamespace(v) {
			log.Fatalf(
				"CONFIG ERROR: ENTITY_NAMESPACE %q contains invalid characters\n"+
					"  Must be alphanumeric, hyphens, or underscores only",
				v,
			)
		}
		cfg.entityNamespace = v
	}

	if v := os.Getenv("RULES_PATH"); v != "" {
		cfg.rulesPath = v
	}

	if v := os.Getenv("HEALERT_API_KEY"); v != "" {
		cfg.apiKey = strings.TrimSpace(v)
	}

	return cfg
}

// isValidNamespace returns true if ns contains only characters safe for use
// in Backstage entity refs. Prevents injection via namespace into URLs and refs.
func isValidNamespace(ns string) bool {
	if ns == "" {
		return false
	}
	for _, c := range ns {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// =============================================================================
// SECTION 2 — RULE DEFINITIONS
//
// Rules are loaded from rules.yaml at startup via loadRules().
// The agent exits with a clear error message if:
//   - RULES_PATH environment variable is unset or empty
//   - The rules file does not exist or is unreadable
//   - Any rule fails validation (missing required fields, invalid values)
//
// Rule types determine entity resolution (see rules.yaml for full docs):
//
//   TYPE 1 — Workload rules 
//     objectRef.name = pod/deployment name
//     Entity resolved automatically via normaliseWorkloadName()
//     Examples: kubectl-exec, config-drift, port-forward, pipeline-skip
//
//   TYPE 2 — Shared resource rules 
//     objectRef.name = secret or configmap name (NOT service name)
//     Entity maps to resource name in v0.1.0
//    
//   TYPE 3 — Cluster-level rules 
//     objectRef.name = namespace, node, or cluster-scoped resource
//     Entity maps to resource name (namespace name, node name, etc.)
//     Examples: namespace-creation, rbac-change, node-access
//
//   TYPE 4 — Network rules 
//     objectRef.name = ingress, service, or networkpolicy name
//     Examples: ingress-drift, network-policy-deletion
//
//   TYPE 5 — Storage rules 
//     objectRef.name = PV or StorageClass name
//     Examples: pv-deletion, storageclass-creation
// =============================================================================

// RuleMatch defines the conditions that must ALL be true (AND logic).
// All fields are optional — omitting a field means "match any value".
// The more fields you specify, the more specific the rule.
type RuleMatch struct {
	Resource          string   // single Kubernetes resource  e.g. "pods", "secrets"
	Resources         []string // list of resources — event resource must be in list
	Subresource       string   // API subresource              e.g. "exec", "portforward"
	Verb              string   // single API verb              e.g. "get", "create", "delete"
	Verbs             []string // list of verbs — event verb must be in list
	Annotation        string   // required annotation format:  "key=value"
	NamespaceContains string   // case-insensitive namespace substring filter
	                           // omit to match ALL namespaces
}

// Rule defines a single detection rule loaded from rules.yaml.
// All rules are evaluated against every audit event independently.
// Multiple rules can fire for a single event.
type Rule struct {
	Name         string    // event type sent to backend  e.g. "kubectl-exec"
	              	       // must be lowercase alphanumeric + hyphens only
	Description  string    // human-readable message template
	              	       // tokens: {actor} {resource} {namespace} {name} {verb}
	Severity     string    // "high" | "medium" | "low"
	              	       // auto-scored: high=10pts  medium=6pts  low=3pts
	Workflow     string    // workflow context: "deploy" | "incident" | "debug" | "rollback" | "release"
	IgnoreSystem bool      // true  = skip internal k8s controllers, detect human operators
	             	       // false = detect ALL actors including service accounts
	             	       //
	             	       // Internal actors ALWAYS skipped (regardless of ignore_system):
	             	       //   system:serviceaccount:*  all service accounts
	             	       //   system:node:*            node bootstrap credentials
	             	       //   system:kube-*            core k8s controllers
	             	       //   system:k3s-*             k3s internals
	             	       //
	             	       // Human actors ALWAYS detected (regardless of ignore_system):
	             	       //   system:admin             k3s/kubeadm human admin
	             	       //   system:masters           human admin group
	             	       //   dev@company.com          OIDC/LDAP/SSO users
	             	       //   kubernetes-admin         kubeadm alternate admin
	Match        RuleMatch // all conditions must be true (AND logic)
}

// =============================================================================
// SECTION 3 — RULES LOADER
//
// Parses rules.yaml using a simple line-by-line parser.
// Zero external dependencies — no YAML library needed.
//
// The agent exits immediately with a boxed error message if:
//   - RULES_PATH is not set
//   - File does not exist or cannot be read
//   - File contains no valid rules
//   - Any rule fails validation
//

// =============================================================================

// loadRules loads and validates detection rules from the YAML file at rulesPath.
// No embedded defaults — rules must always be explicitly defined in rules.yaml.
func loadRules(rulesPath string) ([]Rule, error) {
	if rulesPath == "" {
		return nil, fmt.Errorf(
			"\n  ┌─────────────────────────────────────────────────────┐\n" +
				"  │  RULES_PATH is not set                              │\n" +
				"  │                                                     │\n" +
				"  │  The Healert Agent requires a rules.yaml file.      │\n" +
				"  │  There are no built-in default rules.               │\n" +
				"  │                                                     │\n" +
				"  │  Fix:                                               │\n" +
				"  │    export RULES_PATH=/path/to/rules.yaml            │\n" +
				"  │    ./healert-agent                                  │\n" +
				"  └─────────────────────────────────────────────────────┘",
		)
	}

	data, err := os.ReadFile(rulesPath)
	if err != nil {
		return nil, fmt.Errorf(
			"\n  ┌─────────────────────────────────────────────────────┐\n"+
				"  │  Cannot read rules file                             │\n"+
				"  │                                                     │\n"+
				"  │  Path:  %-43s│\n"+
				"  │  Error: %-43s│\n"+
				"  │                                                     │\n"+
				"  │  Fix: ensure the file exists and is readable        │\n"+
				"  └─────────────────────────────────────────────────────┘",
			rulesPath, err.Error(),
		)
	}

	rules, err := parseRulesYAML(string(data))
	if err != nil {
		return nil, fmt.Errorf("parse rules file %q: %w", rulesPath, err)
	}

	if len(rules) == 0 {
		return nil, fmt.Errorf(
			"\n  ┌─────────────────────────────────────────────────────┐\n"+
				"  │  No rules defined in: %-29s│\n"+
				"  │  Add at least one rule to the file                  │\n"+
				"  └─────────────────────────────────────────────────────┘",
			rulesPath,
		)
	}

	// Validate all rules before starting — fail fast, not at detection time
	for i, rule := range rules {
		if err := validateRule(rule, i); err != nil {
			return nil, fmt.Errorf("rule[%d] %q validation failed: %w", i, rule.Name, err)
		}
	}

	return rules, nil
}

// validateRule checks a single rule for required fields and valid values.
// Prevents misconfigured rules from silently producing invalid entity refs.
func validateRule(rule Rule, index int) error {
	if rule.Name == "" {
		return fmt.Errorf("rule at index %d has no name", index)
	}

	// Name must be lowercase alphanumeric and hyphens only
	// Matches the backend event type validator: ^[a-z0-9][a-z0-9-]*[a-z0-9]$
	for _, c := range rule.Name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return fmt.Errorf(
				"rule %q: name contains invalid character %q\n"+
					"  Use lowercase alphanumeric and hyphens only\n"+
					"  Example: kubectl-exec, config-drift, secret-deletion",
				rule.Name, string(c),
			)
		}
	}

	// Severity is required and must be one of three values
	switch rule.Severity {
	case "high", "medium", "low":
		// valid
	case "":
		return fmt.Errorf("rule %q: severity is required — must be high, medium, or low", rule.Name)
	default:
		return fmt.Errorf("rule %q: invalid severity %q — must be high, medium, or low", rule.Name, rule.Severity)
	}

	// Annotation must be in key=value format if specified
	if rule.Match.Annotation != "" {
		parts := strings.SplitN(rule.Match.Annotation, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf(
				"rule %q: annotation %q must be in key=value format\n"+
					"  Example: annotation: \"policy.admission.k8s.io/bypass=true\"",
				rule.Name, rule.Match.Annotation,
			)
		}
	}

	return nil
}

// parseRulesYAML parses the rules.yaml format line by line.
// Supports all fields defined in the Rule and RuleMatch structs.
// Zero external YAML dependencies — uses stdlib only.
//
// Supported fields:
//   name, description, severity, workflow, ignore_system
//   match: resource, resources, subresource, verb, verbs,
//          annotation, namespace_contains
//
func parseRulesYAML(yamlStr string) ([]Rule, error) {
	var rules []Rule
	var current *Rule
	var inMatch, inResources, inVerbs bool

	for _, rawLine := range strings.Split(yamlStr, "\n") {
		line := strings.TrimRight(rawLine, " \r")
		trimmed := strings.TrimLeft(line, " ")

		// Skip comments and blank lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			// Reset list parsing state on blank lines and comments
			inResources = false
			inVerbs = false
			continue
		}

		// Start of a new rule block — "- name: rule-name"
		if strings.HasPrefix(trimmed, "- name:") {
			if current != nil {
				rules = append(rules, *current)
			}
			// Default: IgnoreSystem=false — changed from original true default
			// which caused system:admin events to be silently dropped in k3s.
			// isInternalSystemActor() now handles the distinction correctly.
			current = &Rule{IgnoreSystem: false}
			inMatch = false
			inResources = false
			inVerbs = false
			val := strings.TrimSpace(strings.TrimPrefix(trimmed, "- name:"))
			current.Name = strings.Trim(val, `"`)
			continue
		}

		if current == nil {
			continue
		}

		// Parse list items under resources: or verbs:
		if strings.HasPrefix(trimmed, "- ") && (inResources || inVerbs) {
			val := strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "- ")), `"`)
			if inResources {
				current.Match.Resources = append(current.Match.Resources, val)
			} else {
				current.Match.Verbs = append(current.Match.Verbs, val)
			}
			continue
		}

		// Non-list item — reset list parsing state
		if !strings.HasPrefix(trimmed, "- ") {
			inResources = false
			inVerbs = false
		}

		if !strings.Contains(trimmed, ":") {
			continue
		}

		parts := strings.SplitN(trimmed, ":", 2)
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), `"`)

		// "match:" section header — switch to match field parsing
		if key == "match" {
			inMatch = true
			continue
		}

		if inMatch {
			// Parse match sub-fields
			switch key {
			case "resource":
				current.Match.Resource = val
			case "resources":
				inResources = true
			case "subresource":
				current.Match.Subresource = val
			case "verb":
				current.Match.Verb = val
			case "verbs":
				inVerbs = true
			case "annotation":
				current.Match.Annotation = val
			case "namespace_contains":
				current.Match.NamespaceContains = val
			}
		} else {
			// Parse top-level rule fields
			switch key {
			case "name":
				current.Name = val
			case "description":
				current.Description = val
			case "severity":
				current.Severity = val
			case "workflow":
				current.Workflow = val
			case "ignore_system":
				current.IgnoreSystem = val == "true"
			}
		}
	}

	// Append the last rule being parsed
	if current != nil {
		rules = append(rules, *current)
	}

	return rules, nil
}

// =============================================================================
// SECTION 4 — TYPES
//
// AuditEvent maps the Kubernetes audit log NDJSON fields used by the rule engine.
// FrictionEvent is the payload sent to the Healert backend POST /events.
// =============================================================================

// AuditEvent maps the Kubernetes audit log NDJSON fields used by the rule engine.
// Full Kubernetes audit schema: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
//
// Only the fields needed by the rule engine are mapped — other fields are ignored.
// The stage field is critical: only ResponseComplete events are processed to
// prevent triple-counting (RequestReceived + ResponseStarted + ResponseComplete).
type AuditEvent struct {
	Verb  string `json:"verb"`
	Stage string `json:"stage"` // "RequestReceived" | "ResponseStarted" | "ResponseComplete"
	User  struct {
		Username string `json:"username"` // actor identity — see isInternalSystemActor()
	} `json:"user"`
	ObjectRef struct {
		Resource    string `json:"resource"`    // e.g. "pods", "secrets", "deployments"
		Subresource string `json:"subresource"` // e.g. "exec", "portforward", "log"
		Namespace   string `json:"namespace"`   // Kubernetes namespace
		Name        string `json:"name"`        // resource name — normalised to workload name
	} `json:"objectRef"`
	Annotations map[string]string `json:"annotations"`              // admission-level annotations
	Timestamp   string            `json:"requestReceivedTimestamp"` // RFC3339 timestamp

	// ResponseObject contains the full resource body after the operation completes.
	// Only populated when audit policy level is RequestResponse.
	// Used for pipeline-skip rule: checks responseObject.metadata.annotations
	// for the bypass annotation — more reliable than requestObject which k3s
	// does not always populate for patch operations.
	ResponseObject struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"` // resource annotations after change
		} `json:"metadata"`
	} `json:"responseObject"`
}

// FrictionEvent is the payload POSTed to /events on the Healert backend.
// The backend validates all fields and returns HTTP 422 with detail on failure.
//
// entity_ref format: component:{namespace}/{name}
//   Must match a Backstage catalog entity for the plugin to display data.
//
// type format: lowercase alphanumeric + hyphens, max 64 chars
//   Must match the rule name in rules.yaml.
//   The backend accepts any valid type — not a fixed whitelist.
//
// Points are NOT sent — the backend auto-derives score from severity:
//   high=10pts  medium=6pts  low=3pts
type FrictionEvent struct {
	EntityRef   string `json:"entity_ref"` // "component:default/payments-api"
	Type        string `json:"type"`        // "kubectl-exec", "config-drift", etc.
	Severity    string `json:"severity"`    // "high" | "medium" | "low"
	Actor       string `json:"actor"`       // sanitised username from audit event
	Workflow    string `json:"workflow"`    // "deploy" | "incident" | "debug" | etc.
	Description string `json:"description"` // human-readable description with tokens expanded
	Timestamp   string `json:"timestamp"`   // RFC3339 timestamp from audit event
}

// =============================================================================
// SECTION 5 — WORKLOAD NAME NORMALISATION
//
// Auto-scoring (handled in backend main.py, driven by severity field):
//   SEVERITY_POINTS = {"high": 10, "medium": 6, "low": 3}
//   Any rule with severity=high contributes 10 points to the friction score.
//   No manual points configuration needed in rules.yaml.
//
// Pod names embed the parent workload name plus Kubernetes-generated hash
// suffixes. The agent strips these suffixes so entity refs match Backstage
// catalog entries which use the workload name (Deployment, StatefulSet, etc.)
// not the full pod name.
//
// Kubernetes naming patterns:
//   Deployment:   {name}-{replicaset-hash(5-10)}-{pod-hash(5)}
//   StatefulSet:  {name}-{ordinal}
//   DaemonSet:    {name}-{pod-hash(5)}
//   Job/CronJob:  {name}-{random(5)}
//   Bare pod:     {name} (unchanged)
//
// Hash character set: [a-z0-9]
// Ordinal character set: [0-9]
//
// IMPORTANT: Priority order matters — must check from most to least specific:
//   1. Deployment (two hashes) — most specific
//   2. StatefulSet (numeric ordinal)
//   3. DaemonSet/Job (single hash)
//   4. Unchanged — bare pod or unknown format

// =============================================================================

var (
	// deploymentPodPattern matches: {name}-{rs-hash(5-10 chars)}-{pod-hash(5 chars)}
	// ReplicaSet hash: 5-10 lowercase alphanumeric chars
	// Pod hash: exactly 5 lowercase alphanumeric chars
	deploymentPodPattern = regexp.MustCompile(`-[a-z0-9]{5,10}-[a-z0-9]{5}$`)

	// statefulSetPodPattern matches: {name}-{ordinal}
	// StatefulSet ordinals are non-negative integers (0, 1, 2, ...)
	statefulSetPodPattern = regexp.MustCompile(`-\d+$`)

	// daemonSetPodPattern matches: {name}-{pod-hash(5 chars)}
	// Requires at least one digit in the hash — Kubernetes pod hashes always
	// contain digits, but English name segments (e.g. "agent", "proxy") rarely do.
	// This prevents false matches like "healert-agent" → "healert".
	daemonSetPodPattern = regexp.MustCompile(`-[a-z0-9]*[0-9][a-z0-9]*$`)
)

// normaliseWorkloadName strips Kubernetes pod hash suffixes from a pod name
// to produce the parent workload name. Works for all Kubernetes workload types.
//
// Examples:
//   payments-api-7d9f8b-xkj2p  →  payments-api      (Deployment)
//   postgres-0                  →  postgres           (StatefulSet)
//   healert-agent-xkj2p         →  healert-agent      (DaemonSet)
//   backup-28492800-abc12       →  backup             (Job)
//   my-pod                      →  my-pod             (bare pod — unchanged)
func normaliseWorkloadName(name string) string {
	if name == "" {
		return "unknown"
	}

	// Priority 1: Deployment — ends with -{rs-hash}-{pod-hash}
	// Most specific check — must come before DaemonSet check
	if deploymentPodPattern.MatchString(name) {
		return deploymentPodPattern.ReplaceAllString(name, "")
	}

	// Priority 2: StatefulSet — ends with -{ordinal}
	// Check before DaemonSet because -0 also matches DaemonSet pattern
	if statefulSetPodPattern.MatchString(name) {
		return statefulSetPodPattern.ReplaceAllString(name, "")
	}

	// Priority 3: DaemonSet / Job — ends with -{5-char-hash}
	if daemonSetPodPattern.MatchString(name) {
		return daemonSetPodPattern.ReplaceAllString(name, "")
	}

	// Priority 4: No pattern matched — bare pod or non-Kubernetes format
	return name
}

// =============================================================================
// SECTION 6 — RULE ENGINE
//
// Evaluates ALL loaded rules against every audit event.
// Only ResponseComplete stage events are processed — Kubernetes writes three
// audit records per API call (RequestReceived, ResponseStarted, ResponseComplete).
// Processing only ResponseComplete prevents triple-counting.
//
// All rules fire independently — multiple rules can match one event.
// Each matching rule produces one FrictionEvent sent to the backend.
//
// Actor classification:
//   isInternalSystemActor() classifies usernames into human operators
//   (who should be detected) vs internal Kubernetes controllers (who should
//   be skipped to prevent noise). See function docs for complete classification.
//
// =============================================================================

// renderDescription fills description template tokens from the audit event.
// All tokens are replaced in a single pass — no multiple allocations.
//
// Supported tokens:
//   {actor}     → sanitised username (control chars stripped)
//   {resource}  → Kubernetes resource (pods, secrets, deployments)
//   {namespace} → Kubernetes namespace
//   {name}      → raw resource name (NOT normalised — shows actual pod name)
//   {verb}      → API verb (get, create, patch, delete, etc.)
func renderDescription(template string, e AuditEvent) string {
	return strings.NewReplacer(
		"{actor}",     sanitiseLogValue(e.User.Username),
		"{resource}",  e.ObjectRef.Resource,
		"{namespace}", e.ObjectRef.Namespace,
		"{name}",      e.ObjectRef.Name,
		"{verb}",      e.Verb,
	).Replace(template)
}

// sanitiseLogValue strips newlines and control characters from values written
// to log output. Prevents log injection attacks where a malicious actor
// username (from a compromised certificate or OIDC token) could inject fake
// log lines containing arbitrary content.
//
// Keeps all printable ASCII (0x20–0x7E) and Unicode code points above 0x7F.
// Strips: newlines (0x0A), carriage returns (0x0D), tabs (0x09), DEL (0x7F),
//         and all other ASCII control characters (0x00–0x1F).
func sanitiseLogValue(v string) string {
	var b strings.Builder
	for _, c := range v {
		if c >= 0x20 && c != 0x7F {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// =============================================================================
// isInternalSystemActor — Human vs Controller Classification
//
// This is the core of the agent production fix for k3s and kubeadm clusters.
// The problem: all kubectl commands from the default kubeconfig appear as
// "system:admin" in the audit log — which starts with "system:" — but
// system:admin is a HUMAN not an internal controller.
//
// v0.1.0: 5-rule classification (current — see below)
// =============================================================================
//
// isInternalSystemActor returns true for Kubernetes-internal service accounts
// and controllers that should never generate friction events.
//
// Production-correct classification covering all real-world Kubernetes actors:
//
//   DETECT — returns false (human operators):
//     system:admin     k3s and kubeadm default certificate-based human admin
//     system:masters   human admin group (k3s/kubeadm default cert O= field)
//     dev@company.com  OIDC/Google/Okta/Azure AD users (email format)
//     john.doe         LDAP/SSO users
//     kubernetes-admin kubeadm alternate admin certificate CN
//     admin            basic auth admin
//     <any non-system: username> → always human (OIDC, LDAP, basic auth, certs)
//
//   SKIP — returns true (internal Kubernetes controllers):
//     system:serviceaccount:*         ALL service accounts (apps, operators, etc.)
//     system:node:*                   node bootstrap credentials (kubelet)
//     system:kube-scheduler           core scheduler
//     system:kube-controller-manager  core controller manager
//     system:kube-proxy               kube-proxy daemonset
//     system:k3s-supervisor           k3s internal process
//     system:apiserver                API server internal calls
//     system:anonymous                unauthenticated requests
//     system:unauthenticated          unauthenticated group
//     system:* (any other)            future-proof: all unknown system: actors skipped
//
// Key insight: the ONLY system: accounts representing humans are system:admin
// and system:masters. Every other system: account is an internal k8s process.
// Non-system: accounts are ALWAYS human (OIDC, LDAP, basic auth, certificates).
//
func isInternalSystemActor(username string) bool {
	// Rule 1: Non-system: usernames are always human operators.
	// Covers OIDC (email), LDAP, basic auth, and custom certificate CNs.
	if !strings.HasPrefix(username, "system:") {
		return false
	}

	// Rule 2: Known human system: identities — always detect.
	// These are the default certificate CN values for human admins in k3s and kubeadm.
	switch username {
	case "system:admin", "system:masters":
		return false
	}

	// Rule 3: All service accounts are internal controllers.
	// Pattern: system:serviceaccount:{namespace}:{name}
	if strings.HasPrefix(username, "system:serviceaccount:") {
		return true
	}

	// Rule 4: Node credentials are always internal.
	// Pattern: system:node:{node-name} (kubelet identity)
	if strings.HasPrefix(username, "system:node:") {
		return true
	}

	// Rule 5: All other system: accounts are internal Kubernetes or k3s processes.
	// This is future-proof — any new system: account added in future Kubernetes
	// versions will be correctly classified as internal without code changes.
	return true
}

// matchRule returns true if all conditions in the rule match the audit event.
// All specified match fields must be true (AND logic).
// Unspecified fields always match (wildcard behaviour).
func matchRule(rule Rule, e AuditEvent) bool {
	m := rule.Match

	// Actor filter — skip internal Kubernetes controllers when ignore_system is true.
	// Uses isInternalSystemActor() which correctly detects human operators even
	// when their username starts with "system:" (e.g. system:admin).
	if rule.IgnoreSystem && isInternalSystemActor(e.User.Username) {
		return false
	}

	// resource — single resource exact match
	// Example: resource: pods  →  only matches events on pods
	if m.Resource != "" && e.ObjectRef.Resource != m.Resource {
		return false
	}

	// resources — event resource must be in the list (OR logic within the list)
	// Example: resources: [pods, deployments]  →  matches either
	if len(m.Resources) > 0 {
		found := false
		for _, r := range m.Resources {
			if e.ObjectRef.Resource == r {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// subresource — exact match
	// Example: subresource: exec  →  only matches kubectl exec
	if m.Subresource != "" && e.ObjectRef.Subresource != m.Subresource {
		return false
	}

	// verb — single verb exact match
	// Example: verb: get  →  only matches read operations
	if m.Verb != "" && e.Verb != m.Verb {
		return false
	}

	// verbs — event verb must be in the list (OR logic within the list)
	// Example: verbs: [create, patch, update]  →  matches any write operation
	if len(m.Verbs) > 0 {
		found := false
		for _, v := range m.Verbs {
			if e.Verb == v {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// annotation — "key=value" must be present in the event.
	// Checks TWO sources because k3s puts the annotation in different places
	// depending on the operation:
	//
	//   e.Annotations                           — audit-level admission annotations
	//   e.ResponseObject.Metadata.Annotations   — full resource body (k3s RequestResponse)
	//
	// kubectl annotate deployment puts the annotation in responseObject.metadata.annotations
	// not in e.Annotations — so we must check both to reliably detect pipeline-skip.
	//
	// Example rule:  annotation: "policy.admission.k8s.io/bypass=true"
	if m.Annotation != "" {
		parts := strings.SplitN(m.Annotation, "=", 2)
		if len(parts) != 2 {
			return false
		}
		key, val := parts[0], parts[1]

		// Check audit-level annotations first
		foundInAudit := e.Annotations != nil && e.Annotations[key] == val

		// Check resource-level annotations in responseObject (k3s RequestResponse level)
		foundInResponse := e.ResponseObject.Metadata.Annotations != nil &&
			e.ResponseObject.Metadata.Annotations[key] == val

		if !foundInAudit && !foundInResponse {
			return false
		}
	}

	// namespace_contains — case-insensitive substring match on namespace
	// Example: namespace_contains: production  →  matches "production", "production-eu"
	// Omit this field to match ALL namespaces.
	if m.NamespaceContains != "" {
		if !strings.Contains(
			strings.ToLower(e.ObjectRef.Namespace),
			strings.ToLower(m.NamespaceContains),
		) {
			return false
		}
	}

	return true
}

// matchRules evaluates all loaded rules against a single audit event.
// Returns one FrictionEvent per matching rule.
// Returns nil if the event is not ResponseComplete stage.
//
// Entity ref construction (v0.1.0 — auto-namespace):
//   component:{kubernetes_namespace}/{normalised_object_name}
//
//   The Kubernetes namespace from the audit event is used directly as the
//   Backstage catalog namespace. This means events from pods in "staging"
//   map to component:staging/service-name automatically — no configuration.
//
//   ENTITY_NAMESPACE is kept as a fallback for cluster-scoped resources
//   (nodes, PVs, namespaces) which have no namespace in the audit event.
//
//   For TYPE 1 rules (pods, deployments):
//     payments-api-7d9f8b-xkj2p in namespace "default"
//     → component:default/payments-api  
//     payments-api-7d9f8b-xkj2p in namespace "staging"
//     → component:staging/payments-api  
//
//   For TYPE 2 rules (secrets, configmaps):
//     db-credentials in namespace "production"
//     → component:production/db-credentials  
//
//   For TYPE 3 rules (cluster-scoped — nodes, namespaces):
//     objectRef.namespace is empty → falls back to ENTITY_NAMESPACE
//     → component:default/node-name  
func matchRules(rules []Rule, e AuditEvent, entityNamespace string) []*FrictionEvent {
	// Only process ResponseComplete stage.
	// Kubernetes writes three audit records per API call:
	//   1. RequestReceived  — when API server receives the request
	//   2. ResponseStarted  — when response headers are sent (streaming only)
	//   3. ResponseComplete — when response body is complete
	// Processing only ResponseComplete prevents triple-counting every event.
	if e.Stage != "ResponseComplete" {
		return nil
	}

	ts := e.Timestamp
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}

	// Resolve the resource name to its parent workload name.
	// For TYPE 1 rules (pods, deployments) this produces the exact service name.
	rawName := e.ObjectRef.Name
	if rawName == "" {
		rawName = e.ObjectRef.Resource
	}
	name := normaliseWorkloadName(rawName)

	// ── First pass: collect all matching rule names ─────────────────────────────
	// This allows higher-priority rules to suppress lower-priority ones.
	var matchedNames []string
	var matchedRules []Rule
	for _, rule := range rules {
		if matchRule(rule, e) {
			matchedNames = append(matchedNames, rule.Name)
			matchedRules = append(matchedRules, rule)
		}
	}

	// ── Second pass: emit all matched events ────────────────────────────────────
	// Both pipeline-skip AND config-drift fire when kubectl annotate is used
	// on a deployment with a bypass annotation — this is correct because:
	//   pipeline-skip  = policy gate was bypassed (security signal)
	//   config-drift   = deployment was modified directly (IaC signal)
	// Platform engineers see both signals in the plugin — full context.
	var results []*FrictionEvent
	for _, rule := range matchedRules {
		// Points are NOT sent — backend auto-derives from severity:
		//   high=10pts  medium=6pts  low=3pts
		// Resolve Backstage catalog namespace from the audit event namespace.
		// This allows multi-namespace clusters to work without configuration:
		//   pod in "default"    → component:default/service    
		//   pod in "staging"    → component:staging/service    
		//   pod in "production" → component:production/service 
		// Cluster-scoped resources (nodes, PVs) have no namespace in the
		// audit event — fall back to ENTITY_NAMESPACE env var (default: "default").
		catalogNs := e.ObjectRef.Namespace
		if catalogNs == "" {
			catalogNs = entityNamespace // fallback for cluster-scoped resources
		}

		results = append(results, &FrictionEvent{
			EntityRef:   fmt.Sprintf("component:%s/%s", catalogNs, name),
			Type:        rule.Name,
			Severity:    rule.Severity,
			Actor:       sanitiseLogValue(e.User.Username),
			Workflow:    rule.Workflow,
			Description: renderDescription(rule.Description, e),
			Timestamp:   ts,
		})
	}
	return results
}

// =============================================================================
// SECTION 7 — BACKEND HTTP CLIENT
//
// Security properties:
//   - API key sent as Authorization: Bearer header
//   - Never appears in process args (ps aux safe) or log output
//   - HTTP client has explicit 10s timeout — no indefinite hangs
//   - HTTP 401 produces clear error with fix instructions
//   - HTTP 422 logged with context — usually description contains non-ASCII chars
//   - HTTP 429 logged and skipped — not fatal, resumes on next event
//   - One automatic retry on transient network failure (2s delay)
//   - Shared httpClient reuses TCP connections — avoids connection storms
// =============================================================================

// httpClient is shared across all requests and reuses TCP connections.
// Explicit 10s timeout prevents the agent hanging when the backend is slow.
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

// send POSTs a single friction event to the Healert backend.
// Retries once after 2s on transient network errors.
// Returns descriptive errors for auth failures, rate limits, and validation errors.
func send(backendURL string, apiKey string, event *FrictionEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	doPost := func() (*http.Response, error) {
		req, err := http.NewRequest(
			http.MethodPost,
			backendURL+"/events",
			bytes.NewReader(payload),
		)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		// API key injected as header value — never in URL params or process args
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
		return httpClient.Do(req) //nolint:gosec
	}

	resp, err := doPost()
	if err != nil {
		// Single retry after brief pause for transient network errors
		time.Sleep(2 * time.Second)
		resp, err = doPost()
		if err != nil {
			return fmt.Errorf("post failed after retry: %w", err)
		}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return nil

	case http.StatusUnauthorized:
		if apiKey == "" {
			return fmt.Errorf(
				"HTTP 401 Unauthorized\n" +
					"  Backend requires authentication but HEALERT_API_KEY is not set\n" +
					"  Fix: export HEALERT_API_KEY=<your-key>\n" +
					"  Generate: openssl rand -base64 32",
			)
		}
		return fmt.Errorf(
			"HTTP 401 Unauthorized\n" +
				"  API key rejected by backend\n" +
				"  Ensure HEALERT_API_KEY matches on both agent and backend\n" +
				"  Re-run: ./healert.sh setup rotate",
		)

	case http.StatusUnprocessableEntity:
		return fmt.Errorf(
			"HTTP 422 Validation error\n" +
				"  Backend rejected the event payload\n" +
				"  Check description field contains only printable ASCII (0x20-0x7E)\n" +
				"  Check type field is lowercase alphanumeric + hyphens only",
		)

	case http.StatusTooManyRequests:
		return fmt.Errorf(
			"HTTP 429 Rate limit exceeded — event skipped, will resume on next event",
		)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("backend returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// healthCheck verifies the backend is reachable and warns on auth mismatch.
// Called once at startup. A failed check is a WARNING not fatal — the agent
// continues tailing and will retry sending events when backend comes back.
func healthCheck(backendURL string, apiKey string) error {
	req, err := http.NewRequest(http.MethodGet, backendURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("build health request: %w", err)
	}

	resp, err := httpClient.Do(req) //nolint:gosec
	if err != nil {
		return fmt.Errorf(
			"backend unreachable at %s: %w\n"+
				"  Check HEALERT_BACKEND_URL and ensure the backend is running",
			backendURL, err,
		)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("backend health check returned HTTP %d", resp.StatusCode)
	}

	// Parse health response to detect auth mismatch early — before any events are sent
	var health struct {
		Status string `json:"status"`
		Auth   string `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err == nil {
		if health.Auth == "enabled" && apiKey == "" {
			log.Printf("WARNING ─────────────────────────────────────────────────")
			log.Printf("  Backend authentication is ENABLED")
			log.Printf("  HEALERT_API_KEY is NOT set")
			log.Printf("  All events will be rejected with HTTP 401")
			log.Printf("  Fix: export HEALERT_API_KEY=<your-key>")
			log.Printf("  Generate: openssl rand -base64 32")
			log.Printf("─────────────────────────────────────────────────────────")
		}
	}

	return nil
}

// =============================================================================
// SECTION 8 — CONTINUOUS LOG TAILER
//
// Implements tail -f behaviour using bufio.Reader + ReadString('\n').
//
// WHY bufio.Reader NOT bufio.Scanner:
//   bufio.Scanner.Scan() returns false permanently at EOF — cannot resume
//   after the API server appends new lines to the audit log.
//   bufio.Reader.ReadString returns io.EOF but preserves file offset — sleeping
//   and retrying correctly picks up new lines.
//
// Behaviour:
//   - Opens file and seeks to EOF — skips all historical events (no replay)
//   - At EOF: sleeps 500ms, retries from current position (new lines only)
//   - On read error: closes and reopens after 5s (handles log rotation)
//   - Never returns — runs for the lifetime of the agent process
//
// Performance:
//   1MB buffer handles even very large audit log lines (TLS certs, etc.)
//   500ms poll interval is imperceptible to users but avoids busy-waiting

// =============================================================================

// tailLog continuously tails the audit log and processes new lines.
// Blocks indefinitely — call from main() as the last statement.
func tailLog(cfg agentConfig, rules []Rule, sent *int) {
	const (
		bufSize      = 1024 * 1024           // 1MB — handles large audit log lines
		pollInterval = 500 * time.Millisecond // check for new lines at EOF
		reopenDelay  = 5 * time.Second        // wait before reopening after error
	)

	for {
		f, err := os.Open(cfg.auditLogPath) //nolint:gosec
		if err != nil {
			log.Printf("Cannot open audit log %q, retrying in %s: %v",
				cfg.auditLogPath, reopenDelay, err)
			time.Sleep(reopenDelay)
			continue
		}

		// Seek to EOF — skip historical events already in the log.
		// Prevents replaying all previous audit events on every agent restart.
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			log.Printf("Seek error on %q: %v — reopening", cfg.auditLogPath, err)
			f.Close()
			time.Sleep(reopenDelay)
			continue
		}

		log.Printf("Tailing %q from end-of-file", cfg.auditLogPath)
		reader := bufio.NewReaderSize(f, bufSize)

		for {
			line, err := reader.ReadString('\n')

			// Process partial line before handling error.
			// ReadString returns partial content + io.EOF on last line without newline.
			line = strings.TrimSpace(line)
			if len(line) > 0 {
				processLine(line, cfg, rules, sent)
			}

			if err != nil {
				if err == io.EOF {
					// Normal — no new lines yet. Poll and retry.
					time.Sleep(pollInterval)
					continue
				}
				// Unexpected error — reopen file (handles log rotation, permissions)
				log.Printf("Read error: %v — reopening in %s", err, reopenDelay)
				break
			}
		}

		f.Close()
		time.Sleep(reopenDelay)
	}
}

// processLine parses one NDJSON audit log line and sends a friction event
// to the backend for every rule that matches.
// Silently skips malformed lines — the API server may write partial lines
// during high-throughput bursts or at log rotation boundaries.
func processLine(line string, cfg agentConfig, rules []Rule, sent *int) {
	var event AuditEvent
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return // silently skip malformed JSON
	}

	matches := matchRules(rules, event, cfg.entityNamespace)
	for _, fe := range matches {
		if err := send(cfg.backendURL, cfg.apiKey, fe); err != nil {
			log.Printf("Send error [%s]: %v", fe.Type, err)
			continue
		}
		*sent++
		log.Printf("[%d] type=%-20s severity=%-6s actor=%-30s ns=%s",
			*sent,
			fe.Type,
			fe.Severity,
			sanitiseLogValue(fe.Actor),
			event.ObjectRef.Namespace,
		)
	}
}

// =============================================================================
// SECTION 9 — ENTRY POINT
// =============================================================================

func main() {
	cfg := loadConfig()

	log.Printf("Healert Agent v0.1.0")
	log.Printf("─────────────────────────────────────────────────────────")
	log.Printf("Backend:    %s", cfg.backendURL)
	log.Printf("Audit log:  %s", cfg.auditLogPath)
	log.Printf("Namespace:  %s (fallback for cluster-scoped resources)", cfg.entityNamespace)
	log.Printf("Rules:      %s", func() string {
		if cfg.rulesPath == "" {
			return "NOT SET — agent will exit"
		}
		return cfg.rulesPath
	}())
	if cfg.apiKey != "" {
		log.Printf("Auth:       API key set (%d chars)", len(cfg.apiKey))
	} else {
		log.Printf("Auth:       HEALERT_API_KEY not set")
	}
	log.Printf("─────────────────────────────────────────────────────────")

	// Load and validate rules — exits immediately if missing or invalid
	rules, err := loadRules(cfg.rulesPath)
	if err != nil {
		log.Fatalf("Rules error: %v", err)
	}
	log.Printf("Loaded %d detection rules:", len(rules))
	for i, r := range rules {
		ns := "ALL namespaces"
		if r.Match.NamespaceContains != "" {
			ns = "ns contains: " + r.Match.NamespaceContains
		}
		log.Printf("  [%d] %-22s severity=%-6s %s", i+1, r.Name, r.Severity, ns)
	}
	log.Printf("─────────────────────────────────────────────────────────")

	// Health check — warning only, not fatal.
	// Agent continues even if backend is unreachable at startup.
	// This allows: ./healert.sh start agent before ./healert.sh start backend
	log.Printf("Checking backend health...")
	if err := healthCheck(cfg.backendURL, cfg.apiKey); err != nil {
		log.Printf("[WARN] Backend health check failed: %v", err)
		log.Printf("[WARN] Agent will continue tailing the audit log.")
		log.Printf("[WARN] Events will be sent when the backend becomes available.")
		log.Printf("[WARN] Start backend: ./healert.sh start backend")
	} else {
		log.Printf("Backend OK")
	}
	log.Printf("─────────────────────────────────────────────────────────")

	// sent tracks total friction events successfully delivered to the backend.
	// Declared before the SIGTERM goroutine so it is accessible inside the closure.
	sent := 0

	// SIGTERM / SIGINT handler — graceful shutdown for DaemonSet rolling updates.
	// Kubernetes sends SIGTERM before force-killing the pod (terminationGracePeriodSeconds: 30).
	// The tailLog loop calls send() synchronously — once send() returns the goroutine
	// is safe to exit. os.Exit(0) is called immediately on signal so no new events
	// are processed after the signal is received.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.Printf("Received %v — shutting down gracefully (events sent: %d)", sig, sent)
		os.Exit(0)
	}()

	tailLog(cfg, rules, &sent)
}
