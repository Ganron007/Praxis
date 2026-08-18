/**
 * Praxis AI Guardrail & Defense Framework Detector
 * ==================================================
 *
 * Detects active runtime guardrails, structured generation wrappers, and
 * content moderation defenses in AI/LLM and RAG pipelines.
 *
 * When an active guardrail protects an LLM prompt or RAG vector sink,
 * findings are downgraded or marked as mitigated to prevent false positives.
 */

// =============================================================================
// GUARDRAIL SIGNATURES
// =============================================================================

export const GUARDRAIL_FRAMEWORKS = [
  {
    name: 'NeMo Guardrails',
    category: 'input_output_rails',
    importPatterns: [/from\s+nemoguardrails\s+import/i, /import\s+nemoguardrails/i],
    usagePatterns: [/\bLLMRails\s*\(/i, /\bRailsConfig\s*\(/i, /\brails\.generate\s*\(/i],
  },
  {
    name: 'Llama Guard',
    category: 'moderation_classifier',
    importPatterns: [/llama_guard/i, /LlamaGuard/i],
    usagePatterns: [/\bLlamaGuard\s*\(/i, /\brun_llama_guard\s*\(/i, /\bcheck_moderation\s*\(/i],
  },
  {
    name: 'Outlines (Structured Generation)',
    category: 'structured_generation',
    importPatterns: [/import\s+outlines/i, /from\s+outlines\s+import/i],
    usagePatterns: [/\boutlines\.generate\.(?:choice|json|regex|format)\s*\(/i],
  },
  {
    name: 'Instructor / Structured Outputs',
    category: 'structured_output',
    importPatterns: [/import\s+instructor/i, /from\s+instructor\s+import/i],
    usagePatterns: [/\binstructor\.from_openai\s*\(/i, /\bresponse_model\s*=/i, /\bclient\.beta\.chat\.completions\.parse\s*\(/i],
  },
  {
    name: 'LangChain Moderation / Constitutional',
    category: 'pipeline_rails',
    importPatterns: [/OpenAIModerationChain/i, /ConstitutionalChain/i],
    usagePatterns: [/\bOpenAIModerationChain\s*\(/i, /\bConstitutionalChain\s*\(/i],
  },
  {
    name: 'Zod / Pydantic Schema Validation',
    category: 'schema_validation',
    importPatterns: [/from\s+pydantic\s+import/i, /import\s+\{\s*z\s*\}\s+from\s+['"]zod['"]/i, /require\s*\(\s*['"]zod['"]\s*\)/i],
    usagePatterns: [/\bclass\s+\w+\s*\(\s*BaseModel\s*\)/i, /\bz\.object\s*\(/i, /\bsafeParse\s*\(/i, /\bschema\.parse\s*\(/i],
  },
  {
    name: 'DOMPurify / HTML Sanitizer',
    category: 'content_sanitization',
    importPatterns: [/DOMPurify/i, /sanitize-html/i, /import\s+bleach/i],
    usagePatterns: [/\bDOMPurify\.sanitize\s*\(/i, /\bsanitizeHtml\s*\(/i, /\bbleach\.clean\s*\(/i],
  },
];

export class GuardrailDetector {
  /**
   * Scan code content for active guardrail frameworks.
   *
   * @param {string} code — Source code
   * @returns {object}    — { hasGuardrails: boolean, frameworks: string[], defenses: string[] }
   */
  static detect(code = '') {
    if (!code || typeof code !== 'string') {
      return { hasGuardrails: false, frameworks: [], defenses: [] };
    }

    const detectedFrameworks = [];
    const detectedDefenses = [];

    for (const fw of GUARDRAIL_FRAMEWORKS) {
      const hasImport = fw.importPatterns.some(p => p.test(code));
      const hasUsage = fw.usagePatterns.some(p => p.test(code));

      if (hasImport || hasUsage) {
        detectedFrameworks.push(fw.name);
        detectedDefenses.push(fw.category);
      }
    }

    return {
      hasGuardrails: detectedFrameworks.length > 0,
      frameworks: detectedFrameworks,
      defenses: Array.from(new Set(detectedDefenses)),
    };
  }

  /**
   * Check if a specific finding sink is protected by a guardrail.
   *
   * @param {object} finding — Finding object
   * @param {string} code    — File code content
   * @returns {object}       — { isProtected: boolean, guardrail: string|null, reason: string|null }
   */
  static checkProtection(finding, code = '') {
    const analysis = GuardrailDetector.detect(code);
    if (!analysis.hasGuardrails) {
      return { isProtected: false, guardrail: null, reason: null };
    }

    const findingRule = finding.rule || '';
    const findingCat = finding.category || '';

    // LLM / Prompt injection findings
    if (findingCat === 'llm' || findingRule.includes('PROMPT') || findingRule.includes('AGENT')) {
      const aiGuard = analysis.frameworks.find(f =>
        f.includes('NeMo') || f.includes('Llama Guard') || f.includes('Outlines') || f.includes('Instructor') || f.includes('LangChain')
      );
      if (aiGuard) {
        return {
          isProtected: true,
          guardrail: aiGuard,
          reason: `Code uses active AI defense framework: ${aiGuard}`,
        };
      }
    }

    // RAG findings
    if (findingRule.includes('RAG') || findingCat === 'rag') {
      const schemaGuard = analysis.frameworks.find(f =>
        f.includes('Zod') || f.includes('Pydantic') || f.includes('DOMPurify') || f.includes('NeMo')
      );
      if (schemaGuard) {
        return {
          isProtected: true,
          guardrail: schemaGuard,
          reason: `RAG ingestion pipeline is guarded by ${schemaGuard}`,
        };
      }
    }

    return { isProtected: false, guardrail: null, reason: null };
  }
}

export default GuardrailDetector;
