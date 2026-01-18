/**
 * Infer engine from legacy result.type.
 */
import { normalizeCwe, normalizeOwasp, toLegacyOwaspString } from "../../../background/common/normalizeMappings.js"
import { normalizeFinding as normalizeFindingShape } from "./findingNormalizer.js"

function inferEngineFromType(type) {
    if (!type) return null
    const t = String(type).toLowerCase()
    if (t === "dast") return "DAST"
    if (t === "sast") return "SAST"
    if (t === "iast") return "IAST"
    return null
}

/**
 * Normalize stats object to always have severity counters.
 */
function normalizeStats(stats = {}) {
    return {
        findingsCount: stats.findingsCount || 0,
        critical: stats.critical || 0,
        high: stats.high || 0,
        medium: stats.medium || 0,
        low: stats.low || 0,
        info: stats.info || 0,
        ...stats
    }
}

/**
 * Normalize finding object.
 */
function normalizeFinding(f) {
    if (!f || typeof f !== "object") return f
    const base = normalizeFindingShape({ ...f }, { engine: f.engine })
    const loc = base.location || {}
    const engine = (base.engine || "").toUpperCase()
    const iastEvidence = engine === "IAST" && base.evidence && typeof base.evidence === "object"
        ? base.evidence.iast || null
        : null
    const normalizedOwasp = normalizeOwasp(base.owasp)
    const normalizedCwe = normalizeCwe(base.cwe)
    const owaspPrimary = normalizedOwasp.length ? normalizedOwasp[0] : null
    const owaspLegacy = toLegacyOwaspString(normalizedOwasp)
    const affectedUrls = engine === "IAST"
        ? (Array.isArray(iastEvidence?.affectedUrls) ? iastEvidence.affectedUrls.slice() : [])
        : (Array.isArray(base.affectedUrls) ? base.affectedUrls.slice() : [])
    const sinkSummary = engine === "IAST"
        ? (iastEvidence?.sinkSummary && typeof iastEvidence.sinkSummary === "object" ? iastEvidence.sinkSummary : null)
        : (base.sinkSummary || null)
    const taintSummary = engine === "IAST"
        ? (iastEvidence?.taintSummary && typeof iastEvidence.taintSummary === "object" ? iastEvidence.taintSummary : null)
        : (base.taintSummary || null)
    const sinkId = engine === "IAST"
        ? (iastEvidence?.sinkId || null)
        : (base.sinkId || null)
    const taintSource = engine === "IAST"
        ? (iastEvidence?.taintSource || null)
        : (base.taintSource || null)
    const source = engine === "IAST"
        ? (iastEvidence?.source || null)
        : (base.source || null)
    const runtimeUrl = engine === "IAST"
        ? (iastEvidence?.routing?.runtimeUrl || iastEvidence?.routing?.url || null)
        : null
    return {
        ...base,
        engine: engine || null,
        severity: (base.severity || "").toLowerCase() || "medium",
        owasp: normalizedOwasp,
        owaspPrimary,
        owaspLegacy,
        cwe: normalizedCwe,
        location: {
            url: runtimeUrl || loc.url || null,
            file: loc.file || null,
            line: loc.line || null,
            column: loc.column || null,
            pageUrl: loc.pageUrl || null,
            domPath: loc.domPath || null,
            elementId: loc.elementId || null,
            method: loc.method || null,
            param: loc.param || null
        },
        affectedUrls,
        sinkSummary,
        taintSummary,
        sinkId,
        taintSource,
        source
    }
}

function normalizeGroup(g) {
    if (!g || typeof g !== "object") return g
    return {
        ...g,
        engine: g.engine || null,
        severity: (g.severity || "").toLowerCase() || "medium",
        occurrenceIds: Array.isArray(g.occurrenceIds) ? g.occurrenceIds : []
    }
}

function normalizeAttackRecord(attack, attackIdx) {
    if (!attack || typeof attack !== "object") return null
    const attackId = attack.id || `atk-${attackIdx + 1}`
    return {
        ...attack,
        id: attackId
    }
}

function normalizeRequestRecord(record, index) {
    if (!record || typeof record !== "object") return null
    const attacks = Array.isArray(record.attacks)
        ? record.attacks.map((attack, idx) => normalizeAttackRecord(attack, idx)).filter(Boolean)
        : []
    return {
        id: record.id || `req-${index + 1}`,
        original: record.original || null,
        attacks
    }
}

function normalizeRequests(rawRequests = []) {
    return rawRequests
        .map((record, index) => normalizeRequestRecord(record, index))
        .filter(Boolean)
}

function normalizeLegacyDast(result) {
    const findings = []
    const items = Array.isArray(result.items) ? result.items : []
    const requests = []
    let attackSeq = 0
    items.forEach((item, requestIdx) => {
        if (!item) return
        const baseReq = item && item.original ? item.original : item?.request || {}
        const requestId = item.id ? `legacy-${item.id}` : `req-${requests.length + 1}`
        const requestRecord = {
            id: requestId,
            original: baseReq || null,
            attacks: []
        }
        const attacks = Array.isArray(item?.attacks) ? item.attacks : []
        attacks.forEach((attack, attackIdx) => {
            if (!attack) return
            attackSeq += 1
            const attackId = attack.id || `atk-${attackSeq}`
            const attackRecord = Object.assign({}, attack, { id: attackId })
            requestRecord.attacks.push(attackRecord)
            if (!attack.success) return
            const meta = attack.metadata || {}
            const req = attack.request || baseReq || {}
            const fid = `legacy-dast-${result.scanId || "scan"}-${requestIdx}-${attackIdx}`
            const attacked = meta.attacked
            const paramName = meta.param ||
                (typeof attacked === "string" ? attacked : attacked?.name) ||
                null
            findings.push(normalizeFinding({
                id: fid,
                engine: "DAST",
                scanId: result.scanId || null,
                moduleId: meta.moduleId || null,
                moduleName: meta.moduleName || meta.module || null,
                ruleId: meta.id || meta.attackId || attackId,
                ruleName: meta.name || meta.id || null,
                vulnId: meta.vulnId || meta.category || null,
                category: meta.category || null,
                severity: meta.severity || "medium",
                owasp: meta.owasp || null,
                cwe: meta.cwe || null,
                tags: meta.tags || [],
                location: {
                    url: req.url || req.href || null,
                    method: req.method || null,
                    param: paramName
                },
                evidence: {
                    dast: {
                        attackId: attackId,
                        requestId: requestId
                    }
                }
            }))
            attackRecord.findingId = fid
        })
        requests.push(requestRecord)
    })
    return {
        engine: "DAST",
        scanId: result.scanId || null,
        host: result.host || null,
        startedAt: result.startedAt || result.date || null,
        finishedAt: result.finishedAt || result.finished || null,
        stats: normalizeStats(result.stats || {}),
        findings,
        groups: [],
        requests,
        legacy: result
    }
}

function normalizeLegacySast(result) {
    const findings = []
    const items = Array.isArray(result.items) ? result.items : []
    items.forEach((item, idx) => {
        const ruleMeta = item.metadata || {}
        const moduleMeta = item.module_metadata || {}
        const fid = `legacy-sast-${result.scanId || "scan"}-${moduleMeta.id || "mod"}-${ruleMeta.id || idx}`
        findings.push(normalizeFinding({
            id: fid,
            engine: "SAST",
            scanId: result.scanId || null,
            moduleId: moduleMeta.id || null,
            moduleName: moduleMeta.name || null,
            ruleId: ruleMeta.rule_id || ruleMeta.id || null,
            ruleName: ruleMeta.name || ruleMeta.rule_id || ruleMeta.id || null,
            vulnId: moduleMeta.vulnId || moduleMeta.category || null,
            category: moduleMeta.category || null,
            severity: ruleMeta.severity || moduleMeta.severity || "medium",
            owasp: moduleMeta.owasp || null,
            cwe: moduleMeta.cwe || null,
            tags: moduleMeta.tags || [],
            location: {
                file: item.codeFile || item.file || null,
                line: item.sink?.loc?.start?.line || item.source?.loc?.start?.line || null,
                column: item.sink?.loc?.start?.column || item.source?.loc?.start?.column || null,
                pageUrl: item.pageUrl || item.pageCanon || null
            },
            evidence: {
                sast: {
                    codeSnippet: item.codeSnippet || null,
                    source: item.source || null,
                    sink: item.sink || null
                }
            }
        }))
    })
    return {
        engine: "SAST",
        scanId: result.scanId || null,
        host: result.host || null,
        startedAt: result.startedAt || result.date || null,
        finishedAt: result.finishedAt || result.finished || null,
        stats: normalizeStats(result.stats || {}),
        findings,
        groups: [],
        legacy: result
    }
}

function normalizeLegacyIast(result) {
    const findings = []
    const items = Array.isArray(result.items) ? result.items : []
    items.forEach((item, itemIdx) => {
        const category = item.category || null
        const severity = item.severity || "medium"
        const affectedUrl = Array.isArray(item.affectedUrls) ? item.affectedUrls[0] : null
        const evs = Array.isArray(item.evidence) ? item.evidence : []
        evs.forEach((ev, evIdx) => {
            const raw = ev?.raw || {}
            const ctx = ev?.context || {}
            const fid = `legacy-iast-${result.scanId || "scan"}-${itemIdx}-${evIdx}`
            findings.push(normalizeFinding({
                id: fid,
                engine: "IAST",
                scanId: result.scanId || null,
                moduleId: ev?.moduleId || null,
                moduleName: ev?.moduleName || null,
                ruleId: raw.ruleId || null,
                ruleName: raw.ruleId || null,
                vulnId: category || null,
                category,
                severity,
                owasp: raw.owasp || null,
                cwe: raw.cwe || null,
                tags: raw.tags || [],
                location: {
                    url: affectedUrl || ctx.url || null,
                    domPath: ctx.domPath || null,
                    elementId: ctx.elementId || null
                },
                evidence: {
                    iast: {
                        flow: ctx.flow || [],
                        matched: ev.matched || null,
                        sinkId: raw.sinkId || null,
                        taintSource: raw.source || null,
                        domPath: ctx.domPath || null,
                        elementOuterHTML: ctx.elementOuterHTML || null,
                        value: ctx.value || null
                    }
                }
            }))
        })
    })
    return {
        engine: "IAST",
        scanId: result.scanId || null,
        host: result.host || null,
        startedAt: result.startedAt || result.date || null,
        finishedAt: result.finishedAt || result.finished || null,
        stats: normalizeStats(result.stats || {}),
        findings,
        groups: [],
        legacy: result
    }
}

export function normalizeScanResult(scanResult) {
    const raw = scanResult || {}
    const engine = raw.engine || inferEngineFromType(raw.type)
    const findings = Array.isArray(raw.findings) ? raw.findings : []
    const groups = Array.isArray(raw.groups) ? raw.groups : []
    const normalizedRequests = engine === "DAST" ? normalizeRequests(raw.requests || []) : []
    if (findings.length || groups.length || (engine === "DAST" && normalizedRequests.length)) {
        return {
            engine,
            scanId: raw.scanId || null,
            host: raw.host || null,
            startedAt: raw.startedAt || raw.date || null,
            finishedAt: raw.finishedAt || raw.finished || null,
            stats: normalizeStats(raw.stats || {}),
            findings: findings.map(normalizeFinding),
            groups: groups.map(normalizeGroup),
            requests: normalizedRequests,
            legacy: raw
        }
    }
    if (engine === "DAST") return normalizeLegacyDast(raw)
    if (engine === "SAST") return normalizeLegacySast(raw)
    if (engine === "IAST") return normalizeLegacyIast(raw)
    return {
        engine,
        scanId: raw.scanId || null,
        host: raw.host || null,
        startedAt: raw.startedAt || raw.date || null,
        finishedAt: raw.finishedAt || raw.finished || null,
        stats: normalizeStats(raw.stats || {}),
        findings: [],
        groups: [],
        requests: [],
        legacy: raw
    }
}
