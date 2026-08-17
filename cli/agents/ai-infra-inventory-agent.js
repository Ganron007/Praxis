/**
 * AI Infrastructure Inventory Agent
 * =================================
 *
 * Completes Praxis's view of the AI system beyond application code — the
 * three production layers where AI actually runs:
 *
 *   Lane 1  Model gateways     — LiteLLM / Portkey / Helicone / Cloudflare
 *                                AI Gateway / OpenRouter configs. The choke
 *                                point through which all LLM traffic flows.
 *   Lane 2  AI infrastructure  — self-hosted LLM runtimes (Ollama, vLLM, TGI,
 *                                SGLang, Triton, llama.cpp, NIM, ...) in
 *                                Docker/K8s/Helm/compose/Terraform, and
 *                                managed AI compute (Bedrock/SageMaker/Vertex).
 *   Lane 3  AI API endpoints   — OpenAPI specs + framework routes (FastAPI,
 *                                Flask, Express, Spring, Django) with auth-style
 *                                capture and {id}-path BOLA candidates.
 *
 * Inventory findings are MEDIUM/LOW — they map the attack surface rather
 * than assert a vulnerability. Risk indicators (exposed keys, no-auth
 * runtimes) escalate to HIGH.
 */

import fs from 'fs';
import path from 'path';
import { BaseAgent, createFinding } from './base-agent.js';

// =============================================================================
// LANE 1 — MODEL GATEWAYS
// =============================================================================

const GATEWAY_CHECKS = [
  {
    rule: 'AI_GATEWAY_LITELLM',
    title: 'LiteLLM Proxy Gateway Detected',
    glob: ['**/litellm*.yaml', '**/litellm*.yml', '**/config.yaml', '**/config.yml'],
    regex: /model_list\s*:/i,
    severity: 'medium',
    description: 'A LiteLLM proxy config with model_list routes LLM traffic. The proxy is the choke point: a misconfiguration (open admin, missing master key, unverified model routes) exposes every prompt and response passing through it.',
    fix: 'Review model_list entries and auth (master key, per-key budgets). Pin model versions and set egress controls.',
  },
  {
    rule: 'AI_GATEWAY_PORTKEY',
    title: 'Portkey Gateway Configuration Detected',
    glob: ['**/portkey-config.json', '**/.portkey*'],
    regex: /(?:provider|virtual_keys?|api_key)\s*:/i,
    severity: 'medium',
    description: 'Portkey gateway config found. Portkey configs commonly contain virtual API keys — treat as credential material.',
    fix: 'Never commit virtual keys. Move to secrets manager and rotate any committed value.',
  },
  {
    rule: 'AI_GATEWAY_HELICONE',
    title: 'Helicone Proxy Endpoint Detected',
    regex: /oai\.helicone\.ai|helicone\.ai\/v1/i,
    severity: 'medium',
    description: 'LLM calls route through the Helicone observability proxy — all prompt/response traffic transits a third party.',
    fix: 'Verify the Helicone account and data-retention settings; exclude sensitive prompts from logging.',
  },
  {
    rule: 'AI_GATEWAY_CLOUDFLARE_AI',
    title: 'Cloudflare AI Gateway Detected',
    regex: /gateway\.ai\.cloudflare\.com/i,
    severity: 'low',
    description: 'LLM traffic routes through Cloudflare AI Gateway.',
    fix: 'Review gateway logs retention and per-app egress policy.',
  },
  {
    rule: 'AI_GATEWAY_OPENROUTER',
    title: 'OpenRouter Usage Detected',
    regex: /openrouter\.ai\/api|OPENROUTER_API_KEY/i,
    severity: 'medium',
    description: 'OpenRouter (multi-model gateway) is configured. All prompts route through a third-party aggregator.',
    fix: 'Verify model routing policy and keep API keys out of committed files.',
  },
];

// =============================================================================
// LANE 2 — AI INFRASTRUCTURE / IaC
// =============================================================================

const RUNTIME_IMAGES = [
  'ollama', 'ghcr.io/ollama', 'vllm', 'vllm/vllm-openai',
  'text-generation-inference', 'ghcr.io/huggingface/text-generation-inference',
  'sglang', 'lmsysorg/sglang', 'triton', 'nvcr.io/nvidia/tritonserver',
  'nvidia-nim', 'nvcr.io/nvidia/nim', 'localai', 'llama.cpp',
  'ghcr.io/ggml-org/llama.cpp', 'lorax', 'aphrodite', 'openllm',
  'xinference', 'ray-llm', 'infinity', 'fastchat',
];
const RUNTIME_IMAGE_RE = new RegExp(`(?:FROM|image:)\\s*[\"']?(${RUNTIME_IMAGES.map(i => i.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})`, 'i');

const MANAGED_COMPUTE = [
  { rule: 'AI_MANAGED_BEDROCK', regex: /aws_bedrock_provisioned_model_throughput|aws_bedrock_custom_model/i, title: 'AWS Bedrock Provisioned Model', description: 'Terraform provisions AWS Bedrock model capacity — committed throughput is a billing + model-governance surface.' },
  { rule: 'AI_MANAGED_SAGEMAKER', regex: /aws_sagemaker_endpoint\s*["']?[a-zA-Z0-9_-]*(?:llm|model|inference|endpoint)/i, title: 'AWS SageMaker LLM Endpoint', description: 'Terraform provisions a SageMaker endpoint for an LLM — verify IAM scope and endpoint auth.' },
  { rule: 'AI_MANAGED_VERTEX', regex: /google_vertex_ai_endpoint/i, title: 'Google Vertex AI Endpoint', description: 'Terraform provisions a Vertex AI endpoint — verify network policy and model provenance.' },
];

// =============================================================================
// LANE 3 — AI API ENDPOINTS
// =============================================================================

const FRAMEWORK_ROUTE_RE = [
  { name: 'FastAPI/Starlette', regex: /@(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']/g },
  { name: 'Flask', regex: /@(?:app|bp)\.route\s*\(\s*["']([^"']+)["']/g },
  { name: 'Express', regex: /(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']/g },
  { name: 'Spring', regex: /@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g },
  { name: 'Django', regex: /(?:path|re_path)\s*\(\s*["']([^"']+)["']/g },
];

const BOLA_SEGMENT = /[\/{][^{}\/]*(?:\{|:)[a-zA-Z_][a-zA-Z0-9_]*[\}][^{}\/]*/;

// =============================================================================
// AGENT
// =============================================================================

export class AiInfraInventoryAgent extends BaseAgent {
  constructor() {
    super(
      'AiInfraInventoryAgent',
      'Maps the production AI system: model gateways, self-hosted/managed AI infrastructure, and AI API endpoints',
      'llm'
    );
  }

  shouldRun() {
    return true; // these layers exist in most modern AI-bearing repos
  }

  async analyze(context) {
    const { files = [], rootPath } = context;
    const findings = [];

    const read = (f) => {
      try { return fs.readFileSync(f, 'utf8'); } catch { return ''; }
    };

    // ── Lane 1: model gateways ─────────────────────────────────────────────
    for (const check of GATEWAY_CHECKS) {
      for (const file of files) {
        const rel = path.relative(rootPath, file).replace(/\\/g, '/');
        if (check.glob) {
          const matches = check.glob.some(g => {
            const parts = g.replace(/\*\*\//g, '').split('/');
            const last = parts[parts.length - 1];
            return (last.includes('*') ? new RegExp(`^${last.replace(/\*/g, '.*')}$`).test(path.basename(file)) : last === path.basename(file));
          });
          if (!matches) continue;
        }
        const content = read(file);
        if (!check.regex.test(content)) continue;
        findings.push(createFinding({
          file,
          line: 1,
          severity: check.severity,
          category: this.category,
          rule: check.rule,
          title: check.title,
          description: check.description,
          matched: check.rule,
          confidence: 'high',
          cwe: 'CWE-1357',
          owasp: 'ASI10',
          fix: check.fix,
        }));
      }
    }

    // ── Lane 2: AI infrastructure ──────────────────────────────────────────
    for (const file of files) {
      const rel = path.relative(rootPath, file).replace(/\\/g, '/');
      const isIaC = /(?:Dockerfile|docker-compose[^/]*\.ya?ml|\.ya?ml|\.tf|k8s|helm|deployment)/i.test(rel);
      if (!isIaC) continue;
      const content = read(file);
      if (!content) continue;

      const runtimeMatch = RUNTIME_IMAGE_RE.exec(content);
      if (runtimeMatch) {
        findings.push(createFinding({
          file,
          line: 1,
          severity: 'medium',
          category: this.category,
          rule: 'AI_INFRA_RUNTIME_DEPLOYMENT',
          title: `Self-Hosted LLM Runtime (${runtimeMatch[1]})`,
          description: `The repo deploys ${runtimeMatch[1]}, a self-hosted LLM runtime. Operational responsibility: the deployment must enforce endpoint auth, egress limits, model provenance, and patching — a publicly reachable unauthenticated inference endpoint is a direct data/model theft surface.`,
          matched: runtimeMatch[1],
          confidence: 'high',
          cwe: 'CWE-306',
          owasp: 'ASI06',
          fix: 'Authenticate the inference endpoint, restrict network egress, pin runtime/model versions, and monitor inference logs.',
        }));
      }

      for (const mc of MANAGED_COMPUTE) {
        if (mc.regex.test(content)) {
          findings.push(createFinding({
            file,
            line: 1,
            severity: 'medium',
            category: this.category,
            rule: mc.rule,
            title: mc.title,
            description: mc.description,
            matched: mc.rule,
            confidence: 'high',
            cwe: 'CWE-1357',
            owasp: 'ASI10',
            fix: 'Review IAM/network policies around the managed AI resource.',
          }));
        }
      }
    }

    // ── Lane 3: API endpoints ─────────────────────────────────────────────
    for (const file of files) {
      const rel = path.relative(rootPath, file).replace(/\\/g, '/');
      const isSpec = /openapi|swagger/i.test(rel) && /\.(json|ya?ml)$/.test(rel);
      if (isSpec) {
        const content = read(file);
        let spec = null;
        try { spec = JSON.parse(content); } catch { /* yaml specs not parsed — see FRAMEWORK_ROUTE_RE */ }
        if (spec) {
          const paths = spec.paths || {};
          const securitySchemes = spec.components?.securitySchemes || spec.securityDefinitions || {};
          const authStyles = Object.values(securitySchemes).map(s => s.type || s.scheme || 'unknown');
          const routeEntries = [];
          for (const [p, methods] of Object.entries(paths)) {
            for (const m of Object.keys(methods || {})) {
              if (['get', 'post', 'put', 'patch', 'delete'].includes(m.toLowerCase())) routeEntries.push({ path: p, method: m });
            }
          }
          if (routeEntries.length > 0) {
            const bola = routeEntries.filter(r => BOLA_SEGMENT.test(r.path));
            findings.push(createFinding({
              file,
              line: 1,
              severity: 'low',
              category: this.category,
              rule: 'AI_API_SPEC_INVENTORY',
              title: `API Spec: ${routeEntries.length} Routes (auth: ${authStyles.length ? authStyles.join(',') : 'none declared'})`,
              description: `OpenAPI/Swagger spec exposes ${routeEntries.length} routes. Auth styles declared: ${authStyles.length ? authStyles.join(', ') : 'NONE — every route may be unauthenticated'}. This is the attack-surface map for the AI service.`,
              matched: `${routeEntries.length} routes`,
              confidence: 'high',
              cwe: 'CWE-1059',
              owasp: 'ASI02',
              fix: 'Ensure every route has an explicit auth scheme; review the spec for admin/debug routes.',
            }));
            if (bola.length > 0) {
              findings.push(createFinding({
                file,
                line: 1,
                severity: 'medium',
                category: this.category,
                rule: 'AI_API_BOLA_CANDIDATE',
                title: `BOLA Candidates: ${bola.length} Object-ID Path Route(s)`,
                description: `Route(s) with object-id path segments (e.g. ${bola[0].path}) are classic Broken Object Level Authorization candidates — every object access must be ownership-checked.`,
                matched: bola.slice(0, 3).map(r => r.path).join(', '),
                confidence: 'medium',
                cwe: 'CWE-639',
                owasp: 'ASI02',
                fix: 'Verify per-object authorization checks (ownership/tenant scoping) on every flagged route.',
              }));
            }
          }
        }
        continue;
      }

      const ext = path.extname(file).toLowerCase();
      if (!['.py', '.js', '.ts', '.java'].includes(ext)) continue;
      const content = read(file);
      if (!content) continue;

      for (const fr of FRAMEWORK_ROUTE_RE) {
        fr.regex.lastIndex = 0;
        let m;
        let count = 0;
        const sample = [];
        while ((m = fr.regex.exec(content)) !== null) {
          count++;
          if (sample.length < 3) sample.push(m[1]);
        }
        if (count === 0) continue;
        const bolaCount = sample.filter(r => BOLA_SEGMENT.test(r)).length;
        findings.push(createFinding({
          file,
          line: 1,
          severity: 'low',
          category: this.category,
          rule: 'AI_API_FRAMEWORK_ROUTES',
          title: `${fr.name}: ${count} Route(s) Discovered${bolaCount ? `, ${bolaCount}+ with object-id segments` : ''}`,
          description: `Framework route discovery found ${count} routes (${sample.join(', ')}...). ${bolaCount ? 'Object-id segments present — check BOLA.' : ''}`,
          matched: sample.join(', '),
          confidence: 'high',
          cwe: 'CWE-1059',
          owasp: 'ASI02',
          fix: 'Map every route to an auth requirement. Flag admin/internal routes for review.',
        }));
      }
    }

    return findings;
  }
}

export default AiInfraInventoryAgent;
