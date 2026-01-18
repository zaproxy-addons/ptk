import CryptoES from "../../../packages/crypto-es/index.js"
import { normalizeCwe, normalizeOwasp } from "../../common/normalizeMappings.js"
import { resolveFindingTaxonomy } from "../../common/resolveFindingTaxonomy.js"

const ENGINE_IAST = "IAST"
const DEFAULT_CATEGORY = "runtime_issue"
const SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]
const SEVERITY_RANK = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
}

export function createFindingFromIAST(details = {}, meta = {}) {
    const now = new Date().toISOString()
    const severity = normalizeSeverity(details?.severity)
    const category = inferCategoryFromIAST(details)
    const location = buildLocation(details)
    const sinkId = details?.sinkId || details?.sink || null
    const taintSource = details?.taintSource || details?.source || details?.matched || null
    const cwe = normalizeCwe(details?.cwe || details?.meta?.cwe)
    const owasp = normalizeOwasp(details?.owasp || details?.meta?.owasp)
    const ruleId = details?.ruleId || null
    const moduleId = details?.moduleId || null
    const moduleName = details?.moduleName || details?.meta?.moduleName || null
    const ruleName = details?.ruleName || details?.meta?.ruleName || null
    const message = details?.message || null
    const description = details?.description || details?.meta?.description || null
    const recommendation = details?.recommendation || details?.meta?.recommendation || null
    const links = details?.links || details?.meta?.links || null
    const contextKey = extractContextKey(details?.context)
    const fingerprint = buildFingerprint({
        url: location.url,
        sink: sinkId,
        category,
        source: taintSource,
        contextKey
    })
    const evidence = buildIASTEvidence(details)
    const confidenceDetails = resolveIastConfidence(details, evidence)
    if (confidenceDetails.signals.length) {
        evidence.confidenceSignals = confidenceDetails.signals
    }

    const finding = {
        id: `${fingerprint}:${details?.timestamp || Date.now()}`,
        fingerprint,
        category,
        severity,
        confidence: confidenceDetails.confidence,
        cwe,
        owasp,
        location,
        ruleId,
        ruleName,
        moduleId,
        moduleName,
        message,
        description,
        recommendation,
        links,
        sinkId,
        source: taintSource,
        taintSource,
        engines: [ENGINE_IAST],
        evidence: { iast: evidence },
        scanId: meta?.scanId || null,
        attackId: null,
        policyId: null,
        createdAt: now,
        updatedAt: now
    }
    resolveFindingTaxonomy({
        finding,
        ruleMeta: details?.meta?.ruleMeta || details?.meta || {},
        moduleMeta: details?.meta?.moduleMeta || details?.meta || {}
    })
    return finding
}

export function getIastEvidencePayload(finding = {}) {
    if (!finding) return null
    const evidence = finding.evidence
    if (!evidence) return null
    if (Array.isArray(evidence)) {
        return evidence.find(entry => entry && typeof entry === "object") || null
    }
    if (evidence.iast && typeof evidence.iast === "object") {
        return evidence.iast
    }
    if (typeof evidence === "object") {
        return evidence
    }
    return null
}

export function getFindingFingerprint(finding = {}) {
    if (finding?.fingerprint) return finding.fingerprint
    const evidence = getIastEvidencePayload(finding) || {}
    const fallbackSource = finding?.taintSummary?.primarySource || finding?.source || null
    const contextKey =
        extractContextKey(evidence?.context) ||
        extractContextKey(finding?.location) ||
        null
    return buildFingerprint({
        url: extractLocationUrl(finding?.location),
        sink: evidence?.sinkId || finding?.sinkId || null,
        category: finding?.category || null,
        source: evidence?.taintSource || fallbackSource,
        contextKey
    })
}

export function mergeFinding(existingFinding, newFinding) {
    if (!existingFinding) return newFinding
    if (!newFinding) return existingFinding

    existingFinding.severity = pickHigherSeverity(existingFinding.severity, newFinding.severity)
    existingFinding.category = existingFinding.category || newFinding.category
    existingFinding.location = existingFinding.location || newFinding.location
    existingFinding.cwe = mergeCweSets(existingFinding.cwe, newFinding.cwe)
    existingFinding.owasp = mergeOwaspSets(existingFinding.owasp, newFinding.owasp)
    existingFinding.ruleId = existingFinding.ruleId || newFinding.ruleId
    existingFinding.moduleId = existingFinding.moduleId || newFinding.moduleId
    existingFinding.moduleName = existingFinding.moduleName || newFinding.moduleName
    existingFinding.message = existingFinding.message || newFinding.message
    existingFinding.description = existingFinding.description || newFinding.description
    existingFinding.recommendation = existingFinding.recommendation || newFinding.recommendation
    existingFinding.links = existingFinding.links || newFinding.links || null
    existingFinding.sinkId = existingFinding.sinkId || newFinding.sinkId
    existingFinding.source = existingFinding.source || newFinding.source
    existingFinding.taintSource = existingFinding.taintSource || newFinding.taintSource
    existingFinding.scanId = existingFinding.scanId || newFinding.scanId
    existingFinding.updatedAt = newFinding.updatedAt || new Date().toISOString()
    existingFinding.engines = mergeEngines(existingFinding.engines, newFinding.engines)
    existingFinding.evidence = mergeEvidence(existingFinding.evidence, newFinding.evidence)

    return existingFinding
}

function mergeOwaspSets(base, incoming) {
    const combined = []
    if (Array.isArray(base)) combined.push(...base)
    if (Array.isArray(incoming)) combined.push(...incoming)
    if (!combined.length) return []
    return normalizeOwasp(combined)
}

function mergeCweSets(base, incoming) {
    const combined = []
    if (Array.isArray(base)) combined.push(...base)
    if (Array.isArray(incoming)) combined.push(...incoming)
    if (!combined.length) return []
    return normalizeCwe(combined)
}

function buildIASTEvidence(details = {}) {
    const sinkId = details?.sinkId || details?.sink || null
    const taintSource = details?.taintSource || details?.source || null
    return {
        sinkId,
        matched: details?.matched || null,
        taintSource,
        source: details?.source || null,
        sourceKind: details?.sourceKind || null,
        sourceKey: details?.sourceKey || null,
        sourceValuePreview: details?.sourceValuePreview || null,
        primarySource: details?.primarySource || null,
        secondarySources: details?.secondarySources || null,
        sources: Array.isArray(details?.sources) ? details.sources : (Array.isArray(details?.taintedSources) ? details.taintedSources : null),
        sink: details?.sink || null,
        sinkContext: details?.sinkContext || null,
        context: details?.context || {},
        schemaVersion: details?.schemaVersion || null,
        primaryClass: details?.primaryClass || null,
        sourceRole: details?.sourceRole || null,
        origin: details?.origin || null,
        observedAt: details?.observedAt || null,
        operation: details?.operation || null,
        detection: details?.detection || null,
        routing: details?.routing || null,
        trace: details?.trace || details?.flow || null,
        traceSummary: details?.traceSummary || null,
        flowSummary: details?.flowSummary || null,
        ruleId: details?.ruleId || null,
        moduleId: details?.moduleId || null,
        moduleName: details?.moduleName || null,
        message: details?.message || null,
        requestId: details?.requestId || details?.meta?.requestId || null
    }
}

function clampConfidence(value) {
    if (!Number.isFinite(value)) return null
    return Math.min(100, Math.max(0, Math.round(value)))
}

function resolveIastConfidence(details = {}, evidence = {}) {
    const signals = []
    const ruleMetaRaw = details?.meta?.ruleMeta?.metadata || details?.meta?.ruleMeta || {}
    const moduleMetaRaw = details?.meta?.moduleMeta?.metadata || details?.meta?.moduleMeta || {}
    const override =
        details?.confidence ??
        details?.meta?.confidence ??
        ruleMetaRaw.confidence ??
        ruleMetaRaw.confidenceDefault ??
        moduleMetaRaw.confidenceDefault

    if (Number.isFinite(override)) {
        const value = clampConfidence(override)
        return { confidence: value, signals: [`override:${value}`] }
    }

    let confidence = 90
    signals.push("base:90")

    const taintSource = evidence?.taintSource || details?.taintSource || details?.source || null
    const sinkId = evidence?.sinkId || details?.sinkId || details?.sink || null
    const trace = details?.trace || details?.flow || evidence?.trace || null
    const traceLen = Array.isArray(trace) ? trace.length : 0

    if (!taintSource) {
        confidence -= 15
        signals.push("missing:source:-15")
    }
    if (!sinkId) {
        confidence -= 10
        signals.push("missing:sink:-10")
    }
    if (traceLen === 0) {
        confidence -= 10
        signals.push("trace:none:-10")
    }

    return { confidence: clampConfidence(confidence), signals }
}

function normalizeSeverity(severity) {
    if (!severity && severity !== 0) return "info"
    const normalized = String(severity).toLowerCase()
    if (SEVERITY_LEVELS.includes(normalized)) return normalized
    if (!Number.isNaN(Number(normalized))) {
        const numeric = Number(normalized)
        if (numeric >= 8) return "high"
        if (numeric >= 5) return "medium"
        if (numeric > 0) return "low"
    }
    return "info"
}

function inferCategoryFromIAST(details = {}) {
    const sink = String(details?.sink || "").toLowerCase()
    const type = String(details?.type || "").toLowerCase()
    if (sink.includes("innerhtml") || sink.includes("document.write") || type.includes("xss")) {
        return "xss"
    }
    if (sink.includes("location") || sink.includes("href") || type.includes("redirect")) {
        return "open_redirect"
    }
    if (type) return type
    return DEFAULT_CATEGORY
}

function buildLocation(details = {}) {
    const location = details?.location
    if (location && typeof location === "object" && !Array.isArray(location)) {
        return {
            url: extractLocationUrl(location.url || location.href || null),
            scriptUrl: location.scriptUrl || null,
            line: sanitizeNumber(location.line),
            column: sanitizeNumber(location.column),
            domPath: location.domPath || null
        }
    }

    const context = details?.context || {}
    return {
        url: extractLocationUrl(location),
        scriptUrl: context.scriptUrl || null,
        line: sanitizeNumber(context.line),
        column: sanitizeNumber(context.column),
        domPath: context.domPath || context.element || null
    }
}

function buildFingerprint({ url = "", sink = "", category = "", source = "", contextKey = "" }) {
    const normalizedUrl = normalizeUrl(url)
    const payload = [normalizedUrl, sink || "", category || "", source || "", contextKey || ""].join("|")
    return CryptoES.SHA1(payload).toString(CryptoES.enc.Hex)
}

function normalizeUrl(url) {
    if (!url) return ""
    try {
        const u = new URL(url)
        u.hash = ""
        return u.toString()
    } catch (e) {
        return String(url)
    }
}

function extractContextKey(context = {}) {
    if (!context) return null
    if (typeof context !== "object") {
        try {
            return String(context)
        } catch (_) {
            return null
        }
    }
    return context.domPath || context.elementId || context.attribute || context.property || context.method || null
}

function sanitizeNumber(value) {
    if (Number.isFinite(value)) return value
    const parsed = Number(value)
    return Number.isFinite(parsed) ? parsed : null
}

function extractLocationUrl(location) {
    if (!location) return null
    if (typeof location === "string") return location
    if (typeof location === "object") {
        return location.url || location.href || null
    }
    return null
}

function mergeEngines(existing = [], incoming = []) {
    const merged = new Set()
    if (Array.isArray(existing)) existing.forEach(engine => merged.add(engine))
    if (Array.isArray(incoming)) incoming.forEach(engine => merged.add(engine))
    return Array.from(merged)
}

function mergeEvidence(existing, incoming) {
    const base = getIastEvidencePayload({ evidence: existing }) || {}
    const next = getIastEvidencePayload({ evidence: incoming }) || {}
    const merged = {
        requestId: next.requestId || base.requestId || null,
        sinkId: next.sinkId || base.sinkId || null,
        sourceId: next.sourceId || base.sourceId || null,
        taintSource: next.taintSource || base.taintSource || null,
        matched: next.matched || base.matched || null,
        trace: next.trace || base.trace || null,
        context: next.context || base.context || null,
        message: next.message || base.message || null
    }
    return { iast: merged }
}

function pickHigherSeverity(existing, incoming) {
    const existingKey = normalizeSeverity(existing)
    const incomingKey = normalizeSeverity(incoming)
    return SEVERITY_RANK[incomingKey] > SEVERITY_RANK[existingKey] ? incomingKey : existingKey
}
