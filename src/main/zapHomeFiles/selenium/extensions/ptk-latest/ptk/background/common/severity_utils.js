import { normalizeCwe, normalizeOwasp } from "./normalizeMappings.js"

const DEFAULT_SEVERITY = 'medium'
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

function applyMappingNormalization(meta) {
  if (!meta || typeof meta !== 'object') return
  meta.owasp = normalizeOwasp(meta.owasp)
  meta.cwe = normalizeCwe(meta.cwe)
}

function coerceSeverity(value) {
  if (value === null || value === undefined) return null
  const normalized = String(value).trim().toLowerCase()
  if (VALID_SEVERITIES.includes(normalized)) {
    return normalized
  }
  if (!Number.isNaN(Number(normalized))) {
    const numeric = Number(normalized)
    if (numeric >= 8) return 'high'
    if (numeric >= 5) return 'medium'
    if (numeric > 0) return 'low'
  }
  return null
}

export function normalizeSeverityValue(value, fallback = DEFAULT_SEVERITY) {
  return coerceSeverity(value) || fallback
}

export function normalizeChildDefinition(child, { engine = 'Engine', parentId = 'module' } = {}) {
  if (!child || typeof child !== 'object') return child
  const meta = child.metadata = child.metadata || {}

  if (meta.severity == null && Object.prototype.hasOwnProperty.call(child, 'severity')) {
    meta.severity = child.severity
  }

  if (meta.severity != null) {
    const normalized = coerceSeverity(meta.severity)
    if (normalized) {
      meta.severity = normalized
    } else {
      console.warn(`[PTK ${engine}] ${parentId || 'module'} child "${child.id || child.name || 'rule'}" has invalid severity "${meta.severity}", inheriting from parent`)
      delete meta.severity
    }
  }

  if (Object.prototype.hasOwnProperty.call(child, 'severity')) {
    delete child.severity
  }

  applyMappingNormalization(meta)

  return child
}

export function normalizeModuleDefinition(moduleDef, { engine = 'Engine', childKey } = {}) {
  if (!moduleDef || typeof moduleDef !== 'object') return moduleDef
  const meta = moduleDef.metadata = moduleDef.metadata || {}
  const normalized = coerceSeverity(meta.severity)
  if (normalized) {
    meta.severity = normalized
  } else {
    console.warn(`[PTK ${engine}] module "${moduleDef.id || moduleDef.name || 'unknown'}" missing metadata.severity; defaulting to "medium"`)
    meta.severity = DEFAULT_SEVERITY
  }

  applyMappingNormalization(meta)

  if (childKey && Array.isArray(moduleDef[childKey])) {
    moduleDef[childKey] = moduleDef[childKey].map((child, index) =>
      normalizeChildDefinition(child, { engine, parentId: moduleDef.id || `module-${index}` })
    )
  }

  return moduleDef
}

export function normalizeRulepack(rulepack, { engine = 'Engine', childKey } = {}) {
  if (!rulepack || typeof rulepack !== 'object') return rulepack
  const modules = rulepack.modules
  if (Array.isArray(modules)) {
    rulepack.modules = modules.map((mod) => normalizeModuleDefinition(mod, { engine, childKey }))
  } else if (modules && typeof modules === 'object') {
    Object.keys(modules).forEach((key) => {
      modules[key] = normalizeModuleDefinition(modules[key], { engine, childKey })
    })
  }
  return rulepack
}

export function resolveEffectiveSeverity({ override, moduleMeta = {}, attackMeta = {}, ruleMeta = {} } = {}) {
  return (
    coerceSeverity(override) ||
    coerceSeverity(ruleMeta.severity) ||
    coerceSeverity(attackMeta.severity) ||
    coerceSeverity(moduleMeta.severity) ||
    DEFAULT_SEVERITY
  )
}

export function getModuleSeverity(module) {
  return normalizeSeverityValue(module?.metadata?.severity)
}

export function getRuleSeverity(rule, module) {
  const moduleSeverity = getModuleSeverity(module)
  return normalizeSeverityValue(
    coerceSeverity(rule?.metadata?.severity) || moduleSeverity
  )
}

export function getAttackSeverity(attack, module) {
  const moduleSeverity = getModuleSeverity(module)
  const attackMeta = attack?.metadata || attack || {}
  return normalizeSeverityValue(
    coerceSeverity(attackMeta.severity) || moduleSeverity
  )
}

export function getEffectiveSeverity(engine, module, item) {
  switch (engine) {
    case 'DAST':
      return getAttackSeverity(item, module)
    case 'SAST':
    case 'IAST':
      return getRuleSeverity(item, module)
    default:
      return DEFAULT_SEVERITY
  }
}
