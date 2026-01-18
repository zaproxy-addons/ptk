import CryptoES from "../packages/crypto-es/index.js"
import { createScanResultEnvelope } from "./common/scanResults.js"
import normalizeFinding from "./common/findingNormalizer.js"

function deepClone(value) {
    try {
        return JSON.parse(JSON.stringify(value))
    } catch (_) {
        return value
    }
}

function ensureNonEmptyString(value) {
    if (value === undefined || value === null) return null
    const str = String(value).trim()
    return str.length ? str : null
}

function normalizeUrlForGrouping(rawUrl) {
    if (!rawUrl) return ""
    try {
        const parsed = new URL(rawUrl, rawUrl.startsWith("http") ? undefined : "http://placeholder")
        return `${parsed.protocol}//${parsed.host}${parsed.pathname}`
    } catch (_) {
        const safe = String(rawUrl)
        const idx = safe.search(/[?#]/)
        return idx >= 0 ? safe.slice(0, idx) : safe
    }
}

function buildGroupId({ engine, scanId, vulnId, category, url, sinkId, ruleId, moduleId }) {
    const normalizedUrl = normalizeUrlForGrouping(url)
    const payload = [
        engine || "",
        scanId || "",
        vulnId || "",
        category || "",
        normalizedUrl || "",
        sinkId || "",
        ruleId || "",
        moduleId || ""
    ].join("|")
    const hash = CryptoES.SHA256(payload).toString(CryptoES.enc.Hex)
    return `${engine || "SCAN"}::${hash}`
}

function defaultStats() {
    return {
        findingsCount: 0,
        attacksCount: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    }
}

class ScanResultStore {
    constructor() {
        this._scans = new Map()
    }

    createScan({ engine, scanId, host, startedAt, settings = {}, policyId = null, extraFields = {} } = {}) {
        if (!engine) throw new Error("engine is required to create scan")
        if (!scanId) throw new Error("scanId is required to create scan")
        const envelope = createScanResultEnvelope({
            engine,
            scanId,
            host,
            startedAt,
            settings
        })
        envelope.policyId = policyId || null
        envelope.tabId = extraFields.tabId || null
        envelope.stats = defaultStats()
        Object.keys(extraFields || {}).forEach(key => {
            if (key === "tabId") return
            envelope[key] = extraFields[key]
        })
        this._scans.set(scanId, envelope)
        return envelope
    }

    hydrateScan(envelope = {}, { engineFallback = null, extraFields = {} } = {}) {
        if (!envelope) return null
        const scanId = envelope.scanId || envelope.id || null
        const engine = envelope.engine || engineFallback
        if (!scanId || !engine) return null
        const scan = this.createScan({
            engine,
            scanId,
            host: envelope.host || null,
            startedAt: envelope.startedAt || envelope.date || new Date().toISOString(),
            settings: envelope.settings || {},
            policyId: envelope.policyId || null,
            extraFields: {
                ...extraFields,
                httpEvents: Array.isArray(envelope.httpEvents) ? envelope.httpEvents : (extraFields.httpEvents || []),
                runtimeEvents: Array.isArray(envelope.runtimeEvents) ? envelope.runtimeEvents : (extraFields.runtimeEvents || []),
                requests: Array.isArray(envelope.requests) ? envelope.requests : (extraFields.requests || []),
                pages: Array.isArray(envelope.pages) ? envelope.pages : (extraFields.pages || []),
                files: Array.isArray(envelope.files) ? envelope.files : (extraFields.files || [])
            }
        })
        scan.finishedAt = envelope.finishedAt || envelope.finished || null
        scan.stats = { ...defaultStats(), ...(envelope.stats || {}) }
        scan.groups = Array.isArray(envelope.groups) ? envelope.groups : []
        scan.items = Array.isArray(envelope.items) ? envelope.items : []
        const findings = Array.isArray(envelope.findings) ? envelope.findings : []
        scan.findings = []
        findings.forEach(f => {
            this.upsertFinding({
                scanId,
                engine,
                finding: f,
                moduleMeta: {},
                ruleMeta: {}
            })
        })
        return scan
    }

    getScan(scanId) {
        if (!scanId) return null
        return this._scans.get(scanId) || null
    }

    deleteScan(scanId) {
        if (!scanId) return
        this._scans.delete(scanId)
    }

    setFinished(scanId, finishedAt = new Date().toISOString()) {
        const scan = this.getScan(scanId)
        if (!scan) return
        scan.finishedAt = finishedAt || new Date().toISOString()
    }

    upsertFinding({ scanId, engine, finding, moduleMeta = {}, ruleMeta = {} } = {}) {
        if (!scanId || !engine || !finding) return null
        const scan = this.getScan(scanId)
        if (!scan) return null
        const normalized = normalizeFinding({
            engine,
            scanId,
            finding,
            moduleMeta: moduleMeta?.metadata || moduleMeta,
            ruleMeta: ruleMeta?.metadata || ruleMeta
        })
        if (!Array.isArray(scan.findings)) {
            scan.findings = []
        }

        // Initialize indexes for O(1) lookups if not present
        if (!scan._findingIdIndex) {
            scan._findingIdIndex = new Map()
            scan._findingFingerprintIndex = new Map()
            // Build indexes from existing findings
            scan.findings.forEach((f, idx) => {
                if (f?.id) scan._findingIdIndex.set(f.id, idx)
                if (f?.fingerprint) scan._findingFingerprintIndex.set(f.fingerprint, idx)
            })
        }

        // O(1) lookup instead of O(n) findIndex
        let existingIdx = -1
        if (normalized.id && scan._findingIdIndex.has(normalized.id)) {
            existingIdx = scan._findingIdIndex.get(normalized.id)
        } else if (normalized.fingerprint && scan._findingFingerprintIndex.has(normalized.fingerprint)) {
            existingIdx = scan._findingFingerprintIndex.get(normalized.fingerprint)
        }

        if (existingIdx >= 0) {
            // Update existing finding - adjust stats if severity changed
            const oldFinding = scan.findings[existingIdx]
            const oldSeverity = String(oldFinding?.severity || "info").toLowerCase()
            const newSeverity = String(normalized.severity || "info").toLowerCase()

            scan.findings[existingIdx] = { ...oldFinding, ...normalized, updatedAt: normalized.updatedAt }

            // Incremental stats update if severity changed
            if (oldSeverity !== newSeverity) {
                this._adjustStat(scan, oldSeverity, -1)
                this._adjustStat(scan, newSeverity, +1)
            }
        } else {
            // New finding - add to array and indexes
            const newIdx = scan.findings.length
            scan.findings.push(normalized)

            // Update indexes
            if (normalized.id) scan._findingIdIndex.set(normalized.id, newIdx)
            if (normalized.fingerprint) scan._findingFingerprintIndex.set(normalized.fingerprint, newIdx)

            // Incremental stats update
            this._adjustStat(scan, String(normalized.severity || "info").toLowerCase(), +1)
            scan.stats.findingsCount++

            // Incremental group update
            this._addFindingToGroup(scan, normalized)
        }

        return normalized
    }

    // Incremental stat adjustment - O(1) instead of O(n)
    _adjustStat(scan, severity, delta) {
        if (!scan.stats) scan.stats = defaultStats()
        const sev = String(severity || "info").toLowerCase()
        if (Object.prototype.hasOwnProperty.call(scan.stats, sev)) {
            scan.stats[sev] = Math.max(0, (scan.stats[sev] || 0) + delta)
        } else {
            scan.stats.info = Math.max(0, (scan.stats.info || 0) + delta)
        }
    }

    // Incremental group addition - O(1) instead of O(n)
    _addFindingToGroup(scan, finding) {
        if (!finding) return

        // Initialize group map for O(1) lookups if not present
        if (!scan._groupMap) {
            scan._groupMap = new Map()
            // Build map from existing groups
            if (Array.isArray(scan.groups)) {
                scan.groups.forEach(g => {
                    if (g?.id) scan._groupMap.set(g.id, g)
                })
            }
        }

        const sinkId = finding?.evidence?.iast?.sinkId
            || finding?.evidence?.dast?.attackId
            || finding?.evidence?.sast?.sinkId
            || finding.sinkId
            || null
        const runtimeUrl = finding?.location?.runtimeUrl
            || finding?.evidence?.iast?.routing?.runtimeUrl
            || finding?.evidence?.iast?.routing?.url
            || finding?.location?.url
            || null
        const groupId = buildGroupId({
            engine: finding.engine,
            scanId: finding.scanId,
            vulnId: finding.vulnId,
            category: finding.category,
            url: runtimeUrl,
            sinkId,
            ruleId: finding.ruleId,
            moduleId: finding.moduleId
        })

        let group = scan._groupMap.get(groupId)
        if (!group) {
            group = {
                id: groupId,
                engine: finding.engine,
                scanId: finding.scanId,
                vulnId: finding.vulnId,
                category: finding.category,
                severity: finding.severity,
                correlationKey: finding.correlationKey || null,
                location: {
                    url: (finding.engine === 'IAST' ? runtimeUrl : normalizeUrlForGrouping(runtimeUrl)) || null,
                    runtimeUrl: runtimeUrl || null,
                    file: finding?.location?.file || null,
                    param: finding?.location?.param || null,
                    sink: sinkId || null
                },
                occurrenceIds: [],
                count: 0
            }
            scan._groupMap.set(groupId, group)
            if (!Array.isArray(scan.groups)) scan.groups = []
            scan.groups.push(group)
        }

        const occurrenceId = finding.id || `${group.id}::${group.occurrenceIds.length + 1}`
        group.occurrenceIds.push(occurrenceId)
        group.count = group.occurrenceIds.length
    }

    // Full recalculation - only used during hydration or when needed
    _recalculateStats(scan) {
        const stats = defaultStats()
        const findings = Array.isArray(scan.findings) ? scan.findings : []
        findings.forEach(finding => {
            if (!finding) return
            stats.findingsCount += 1
            const severity = String(finding.severity || "info").toLowerCase()
            if (Object.prototype.hasOwnProperty.call(stats, severity)) {
                stats[severity] = (stats[severity] || 0) + 1
            } else {
                stats.info = (stats.info || 0) + 1
            }
        })
        scan.stats = stats
    }

    // Full rebuild - only used during hydration or when needed
    _rebuildGroups(scan) {
        const groups = new Map()
        const findings = Array.isArray(scan.findings) ? scan.findings : []
        findings.forEach(finding => {
            if (!finding) return
            const sinkId = finding?.evidence?.iast?.sinkId
                || finding?.evidence?.dast?.attackId
                || finding?.evidence?.sast?.sinkId
                || finding.sinkId
                || null
            const runtimeUrl = finding?.location?.runtimeUrl
                || finding?.evidence?.iast?.routing?.runtimeUrl
                || finding?.evidence?.iast?.routing?.url
                || finding?.location?.url
                || null
            const groupId = buildGroupId({
                engine: finding.engine,
                scanId: finding.scanId,
                vulnId: finding.vulnId,
                category: finding.category,
                url: runtimeUrl,
                sinkId,
                ruleId: finding.ruleId,
                moduleId: finding.moduleId
            })
            if (!groups.has(groupId)) {
                groups.set(groupId, {
                    id: groupId,
                    engine: finding.engine,
                    scanId: finding.scanId,
                    vulnId: finding.vulnId,
                    category: finding.category,
                    severity: finding.severity,
                    correlationKey: finding.correlationKey || null,
                    location: {
                        url: (finding.engine === 'IAST' ? runtimeUrl : normalizeUrlForGrouping(runtimeUrl)) || null,
                        runtimeUrl: runtimeUrl || null,
                        file: finding?.location?.file || null,
                        param: finding?.location?.param || null,
                        sink: sinkId || null
                    },
                    occurrenceIds: [],
                    count: 0
                })
            }
            const group = groups.get(groupId)
            const occurrenceId = finding.id || `${group.id}::${group.occurrenceIds.length + 1}`
            group.occurrenceIds.push(occurrenceId)
            group.count = group.occurrenceIds.length
        })
        scan.groups = Array.from(groups.values())
        // Also update the group map for future incremental updates
        scan._groupMap = groups
    }

    exportScanResult(scanId) {
        const scan = this.getScan(scanId)
        if (!scan) return null
        this._assertFindingIntegrity(scan)
        return deepClone(scan)
    }

    listScans() {
        return Array.from(this._scans.values()).map(entry => deepClone(entry))
    }

    _assertFindingIntegrity(scan) {
        const findings = Array.isArray(scan.findings) ? scan.findings : []
        findings.forEach(finding => {
            if (!finding) return
            const category = ensureNonEmptyString(finding.category)
            if (!category) {
                throw new Error(`[PTK ScanStore] Finding ${finding.id || "unknown"} missing category (metadata missing or not loaded)`)
            }
            const vulnId = ensureNonEmptyString(finding.vulnId)
            if (!vulnId) {
                throw new Error(`[PTK ScanStore] Finding ${finding.id || "unknown"} missing vulnId (metadata missing or not loaded)`)
            }
            if (finding.moduleId === "iast_dom_xss" && vulnId.toLowerCase() === "other") {
                throw new Error("[PTK ScanStore] IAST DOM XSS findings require a module vulnId (metadata missing or not loaded)")
            }
        })
    }
}

export const scanResultStore = new ScanResultStore()

export default scanResultStore
