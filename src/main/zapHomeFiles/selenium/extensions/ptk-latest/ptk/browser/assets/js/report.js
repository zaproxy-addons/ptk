/* Author: Denis Podgurskii */
import { ptk_controller_index } from "../../../controller/index.js"
import { ptk_controller_sca } from "../../../controller/sca.js"
import { ptk_controller_rattacker } from "../../../controller/rattacker.js"
import { ptk_controller_iast } from "../../../controller/iast.js"
import { ptk_controller_sast } from "../../../controller/sast.js"
import { ptk_utils, ptk_jwtHelper } from "../../../background/utils.js"
import { ptk_decoder } from "../../../background/decoder.js"
import * as rutils from "../js/rutils.js"
import { normalizeScanResult } from "../js/scanResultViewModel.js"
import { default as dompurify } from "../../../packages/dompurify/purify.es.mjs"

const jwtHelper = new ptk_jwtHelper()
const decoder = new ptk_decoder()

var tokens = new Array()
var tokenAdded = false

const SAST_ALLOWED_TAGS = ['p', 'ul', 'li', 'code', 'strong', 'em', 'a', 'br', 'pre'];
const SAST_ALLOWED_ATTRS = ['href', 'target', 'rel'];
const REPORT_SEVERITY_STYLES = {
    critical: { color: "red", icon: "fire", label: "Critical" },
    high: { color: "red", icon: "exclamation triangle", label: "High" },
    medium: { color: "orange", icon: "exclamation triangle", label: "Medium" },
    low: { color: "yellow", icon: "exclamation triangle", label: "Low" },
    info: { color: "blue", icon: "info circle", label: "Info" }
}

function sanitizeRichText(html) {
    if (!html) return ""
    return dompurify.sanitize(html, { ALLOWED_TAGS: SAST_ALLOWED_TAGS, ALLOWED_ATTR: SAST_ALLOWED_ATTRS })
}

function escapeText(value, fallback = "—") {
    if (value === undefined || value === null || value === "") return fallback
    return ptk_utils.escapeHtml(String(value))
}

function resolveConfidenceValue(...candidates) {
    for (const value of candidates) {
        if (value === undefined || value === null || value === "") continue
        const num = Number(value)
        if (Number.isFinite(num)) {
            return Math.max(0, Math.min(100, num))
        }
    }
    return null
}

function formatConfidence(confidence) {
    if (!Number.isFinite(confidence)) return null
    return Math.round(confidence)
}

function renderConfidenceLine(confidence) {
    const value = formatConfidence(confidence)
    if (value === null) return ""
    return `<p><b>Confidence:</b> ${value}</p>`
}

function getSeverityMeta(severity) {
    const normalized = String(severity || "").toLowerCase()
    const defaults = REPORT_SEVERITY_STYLES[normalized] || {
        color: "grey",
        icon: "info circle",
        label: severity ? severity : "Info"
    }
    return {
        color: defaults.color,
        icon: `<i class="${defaults.icon} ${defaults.color} icon"></i>`,
        label: defaults.label
    }
}

const SEVERITY_RANKING = ["critical", "high", "medium", "low", "info"]
function severityRank(severity) {
    const normalized = String(severity || "").toLowerCase()
    const index = SEVERITY_RANKING.indexOf(normalized)
    return index === -1 ? SEVERITY_RANKING.length : index
}

function formatPoint(point) {
    if (!point || typeof point.line !== "number") return ""
    const column = typeof point.column === "number" ? `:C${point.column}` : ""
    return `L${point.line}${column}`
}

function formatRange(loc) {
    if (!loc) return ""
    const start = formatPoint(loc.start || loc)
    const end = formatPoint(loc.end || loc)
    if (start && end && start !== end) return `${start} → ${end}`
    return start || end
}

function normalizeSnippet(snippet) {
    if (!snippet) return ""
    return String(snippet).replace(/\r\n?/g, "\n").trim()
}

function renderSnippetBlock(snippet) {
    const normalized = normalizeSnippet(snippet)
    if (!normalized) return `<div class="ui grey text">Snippet unavailable</div>`
    return `<pre><code>${ptk_utils.escapeHtml(normalized)}</code></pre>`
}

function formatTraceList(trace) {
    const steps = Array.isArray(trace) && trace.length ? trace : null
    if (!steps) return ""
    const items = steps.map((step, idx) => {
        const label = step?.kind || (idx === 0 ? "source" : (idx === steps.length - 1 ? "sink" : "step"))
        const labelHtml = `<strong>${escapeText(label)}</strong>`
        const nodeLabel = step?.label ? `<code>${ptk_utils.escapeHtml(step.label)}</code>` : ""
        const locationParts = []
        if (step?.file) locationParts.push(escapeText(step.file))
        const locText = formatRange(step?.loc)
        if (locText) locationParts.push(escapeText(locText))
        const location = locationParts.length ? `<span>${locationParts.join(" ")}</span>` : ""
        const chunks = [labelHtml]
        if (nodeLabel) chunks.push(nodeLabel)
        if (location) chunks.push(location)
        return `<li>${chunks.join(" — ")}</li>`
    }).join("")
    return `<ul class="sast-trace-list">${items}</ul>`
}

function safeHttpLink(url) {
    if (!url) return ""
    try {
        const parsed = new URL(url)
        if (parsed.protocol === "http:" || parsed.protocol === "https:") {
            return parsed.href
        }
    } catch (e) {
        return ""
    }
    return ""
}

function renderReferenceLinks(links = {}) {
    const entries = Object.entries(links)
        .map(([label, href]) => {
            const safeHref = safeHttpLink(href)
            if (!safeHref) return null
            return `<li><a target="_blank" rel="noopener noreferrer" href="${ptk_utils.escapeHtml(safeHref)}">${ptk_utils.escapeHtml(safeHref)}</a></li>`
        })
        .filter(Boolean)
    if (!entries.length) return ""
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>References</strong></div>
                <ul>${entries.join("")}</ul>
            </div>`
}

function buildEndpointColumn(label, endpoint, nameKey, fileKey, locKey, snippetKey) {
    if (!endpoint) return ""
    const name = endpoint[nameKey] || endpoint.label
    const file = endpoint[`${fileKey}Full`] || endpoint[fileKey]
    const loc = endpoint[locKey]
    const snippet = endpoint[snippetKey]

    return `<div class="column">
                <div class="ui segment" style="overflow: overlay;">
                    <div class="ui tiny header">${escapeText(label)}</div>
                    <div><b>Name:</b> ${escapeText(name)}</div>
                    <div><b>File:</b> ${escapeText(file)}</div>
                    <div><b>Location:</b> ${escapeText(formatRange(loc), "—")}</div>
                    ${renderSnippetBlock(snippet)}
                </div>
            </div>`
}

function renderSourceSinkSections(item) {
    const source = buildEndpointColumn("Source", item.source, "sourceName", "sourceFile", "sourceLoc", "sourceSnippet")
    const sink = buildEndpointColumn("Sink", item.sink, "sinkName", "sinkFile", "sinkLoc", "sinkSnippet")
    if (!source && !sink) return ""
    return `<div class="sast-section">
                <div class="ui two column stackable grid">
                    ${source || ""}
                    ${sink || ""}
                </div>
            </div>`
}

function renderTraceSection(item) {
    const trace = item.trace && item.trace.length ? item.trace : (item.taintTrace || [])
    const traceHtml = formatTraceList(trace)
    if (!traceHtml) return ""
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>Taint Trace</strong></div>
                ${traceHtml}
            </div>`
}

function renderCombinedSnippet(snippet) {
    if (!snippet) return ""
    return `<div class="sast-section">
                <div class="sast-section-title">Code Context</div>
                ${renderSnippetBlock(snippet)}
            </div>`
}

function renderSastFinding(item, index) {
    const severityMeta = getSeverityMeta(item.metadata?.severity || item.severity)
    const ruleName = item.metadata?.name || item.name || item.module_metadata?.name || `Finding #${index + 1}`
    const ruleNumberLabel = `Rule ${index + 1}`
    const ruleId = item.metadata?.id || item.rule_id || item.module_metadata?.id || "N/A"
    const moduleName = item.module_metadata?.name || item.module_metadata?.id || ""
    const confidence = resolveConfidenceValue(item.confidence, item.metadata?.confidence)
    const confidenceLine = renderConfidenceLine(confidence)
    const description = sanitizeRichText(item.metadata?.description || item.module_metadata?.description || "")
    const recommendation = sanitizeRichText(item.metadata?.recommendation || item.module_metadata?.recommendation || "")
    const references = renderReferenceLinks(item.metadata?.links || item.module_metadata?.links || {})
    const color = severityMeta.color || ""
    return `
        <div class="card sast-report-card" data-index="${index}" style="width: 100%;">
            <div class="content">
                <div class="ui ${color} message" style="margin-bottom: 0px;">
                    <div class="header">
                    
                        ${severityMeta.icon}
                        <span class="sast-rule-number">${escapeText(ruleNumberLabel)}:</span>
                        ${escapeText(ruleName)}

                    </div>

                            <p><b>Rule:</b> ${escapeText(ruleId)}</span>
                            ${moduleName ? `<span><b>Module:</b> ${escapeText(moduleName)}</p>` : ""}
                            ${confidenceLine}

                </div>

                ${renderSourceSinkSections(item)}
                ${renderTraceSection(item)}
                ${description ? `<div class="sast-section"><div class="sast-section-title"><strong>Description</strong></div>${description}</div>` : ""}
                ${recommendation ? `<div class="sast-section"><div class="sast-section-title"><strong>Recommendation</strong></div>${recommendation}</div>` : ""}
                ${references}
            </div>
        </div>
    `
}

function getIastEvidence(item) {
    if (!item || !item.evidence) return null
    if (item.evidence.iast && typeof item.evidence.iast === "object") {
        return item.evidence.iast
    }
    if (Array.isArray(item.evidence)) {
        return item.evidence.find(e => e && typeof e === "object") || null
    }
    if (typeof item.evidence === "object") {
        return item.evidence
    }
    return null
}

function normalizeIastValue(value) {
    if (value === undefined || value === null) return ""
    if (Array.isArray(value)) {
        return value.map(entry => {
            if (entry === undefined || entry === null) return ""
            if (typeof entry === "string") return entry
            try {
                return JSON.stringify(entry, null, 2)
            } catch (e) {
                return String(entry)
            }
        }).filter(Boolean).join("\n")
    }
    if (typeof value === "object") {
        try {
            return JSON.stringify(value, null, 2)
        } catch (e) {
            return String(value)
        }
    }
    return String(value)
}

function renderIastMetaSection(rows = []) {
    const entries = rows
        .filter(row => row && row.value)
        .map(row => `<div><strong>${escapeText(row.label)}:</strong> ${row.value}</div>`)
    if (!entries.length) return ""
    return `<div class="sast-section iast-meta">
                ${entries.join("")}
            </div>`
}

function renderIastContextSection(context = {}, snippetValue = "") {
    const safeContext = context && typeof context === "object" ? context : {}
    const rows = []
    if (safeContext.element) rows.push(`<div><strong>Element:</strong> ${escapeText(safeContext.element)}</div>`)
    if (safeContext.elementId) rows.push(`<div><strong>Element ID:</strong> ${escapeText(safeContext.elementId)}</div>`)
    if (safeContext.domPath) rows.push(`<div><strong>DOM Path:</strong> <code>${ptk_utils.escapeHtml(String(safeContext.domPath))}</code></div>`)
    if (safeContext.position) rows.push(`<div><strong>Position:</strong> ${escapeText(safeContext.position)}</div>`)
    if (safeContext.attribute) rows.push(`<div><strong>Attribute:</strong> ${escapeText(safeContext.attribute)}</div>`)
    const metaHtml = rows.join("")
    const snippet = snippetValue
        ? `<div class="iast-context-snippet">
                <div class="sast-section-title"><strong>Captured Value</strong></div>
                ${renderSnippetBlock(snippetValue)}
            </div>`
        : ""
    if (!metaHtml && !snippet) return ""
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>Context</strong></div>
                ${metaHtml}
                ${snippet}
            </div>`
}

function renderIastFlowSection(flow = []) {
    if (!Array.isArray(flow) || !flow.length) return ""
    const nodes = flow.map((node = {}, idx) => {
        const stage = node?.stage
            ? String(node.stage).toUpperCase()
            : (idx === 0 ? "SOURCE" : (idx === flow.length - 1 ? "SINK" : `STEP ${idx + 1}`))
        const label = node?.label || node?.key || `Node ${idx + 1}`
        const op = node?.op ? `<div class="iast-flow-op">Operation: ${escapeText(node.op)}</div>` : ""
        const dom = node?.domPath ? `<div class="iast-flow-dom">DOM: <code>${ptk_utils.escapeHtml(String(node.domPath))}</code></div>` : ""
        const location = node?.location ? `<div class="iast-flow-location">${escapeText(node.location)}</div>` : ""
        return `
            <div class="iast-flow-node">
                <div class="iast-flow-stage">${escapeText(stage)}</div>
                <div class="iast-flow-details">
                    <div class="iast-flow-label"><strong>${escapeText(label)}</strong></div>
                    ${op}
                    ${dom}
                    ${location}
                </div>
            </div>
        `
    }).join("")
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>Flow</strong></div>
                <div class="iast-flow-list">${nodes}</div>
            </div>`
}

function renderIastTraceSection(trace = []) {
    if (!Array.isArray(trace) || !trace.length) return ""
    const traceHtml = formatTraceList(trace)
    if (!traceHtml) return ""
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>Trace</strong></div>
                ${traceHtml}
            </div>`
}

function renderIastFinding(item, index) {
    if (!item) return ""
    const evidence = getIastEvidence(item) || {}
    const raw = evidence.raw || {}
    const meta = raw.meta || {}
    const original = item.__finding || item.finding || null
    const displayIndex = typeof index === "number" && !Number.isNaN(index)
        ? index
        : (typeof item.__index === "number" ? item.__index : 0)
    const attrIndex = typeof item.__index === "number" ? item.__index : displayIndex
    const severityValue = raw.severity || item.severity || original?.severity || "info"
    const severityMeta = getSeverityMeta(severityValue)
    const ruleName = meta.ruleName || original?.ruleName || original?.category || item.category || `IAST finding #${displayIndex + 1}`
    const ruleId = raw.ruleId || original?.ruleId || ""
    const moduleName = meta.moduleName || original?.moduleName || ""
    const category = original?.category || item.category || meta.type || ""
    const routingUrl = evidence?.routing?.runtimeUrl || evidence?.routing?.url || ""
    const url = routingUrl || item.location?.url || raw.location?.url || original?.location?.url || ""
    const safeUrl = safeHttpLink(url)
    const urlDisplay = safeUrl
        ? `<a href="${ptk_utils.escapeHtml(safeUrl)}" target="_blank" rel="noopener noreferrer">${ptk_utils.escapeHtml(safeUrl)}</a>`
        : (url ? escapeText(url) : "")
    const sourceLabel = evidence?.taintSource || raw.source || original?.source || "Not specified"
    const sinkLabel = evidence?.sinkId || raw.sinkId || original?.sink || "Not specified"
    const context = evidence?.context || raw.context || original?.context || {}
    const snippetValue = normalizeIastValue(context?.value ?? evidence?.matched)
    const flow = Array.isArray(context?.flow) && context.flow.length ? context.flow : []
    const trace = Array.isArray(evidence?.trace) && evidence.trace.length ? evidence.trace : []
    const description = sanitizeRichText(original?.description || meta.description || "")
    const recommendation = sanitizeRichText(original?.recommendation || meta.recommendation || "")
    const references = renderReferenceLinks(original?.links || meta.links || {})
    const confidence = resolveConfidenceValue(
        item.confidence,
        original?.confidence,
        item.metadata?.confidence,
        original?.metadata?.confidence
    )
    const severityAttr = ptk_utils.escapeHtml(String(severityValue || "").toLowerCase())
    const requestKeyAttr = item.requestKey ? ` data-request-key="${ptk_utils.escapeHtml(String(item.requestKey))}"` : ""
    const ruleMetaLine = [
        ruleId ? `<span><b>Rule:</b> ${escapeText(ruleId)}</span>` : "",
        moduleName ? `<span><b>Module:</b> ${escapeText(moduleName)}</span>` : ""
    ].filter(Boolean).join(" | ")
    const metaSection = renderIastMetaSection([
        { label: "Source", value: escapeText(sourceLabel) },
        { label: "Sink", value: escapeText(sinkLabel) },
        { label: "Category", value: category ? escapeText(category) : "" },
        { label: "URL", value: urlDisplay },
        { label: "Confidence", value: confidence !== null ? String(Math.round(confidence)) : "" }
    ])
    const contextSection = renderIastContextSection(context, snippetValue)
    const flowSection = renderIastFlowSection(flow)
    const traceSection = renderIastTraceSection(trace)
    return `
        <div class="card sast-report-card iast-report-card iast_attack_card" data-index="${attrIndex}" data-severity="${severityAttr}"${requestKeyAttr} style="width: 100%;">
            <div class="content">
                <div class="ui ${severityMeta.color} message" style="margin-bottom: 0px;">
                    <div class="header">
                        ${severityMeta.icon}
                        ${escapeText(ruleName)}
                    </div>
                    ${ruleMetaLine ? `<div class="iast-rule-meta">${ruleMetaLine}</div>` : ""}
                </div>
                ${metaSection}
                ${contextSection}
                ${flowSection || ""}
                ${traceSection || ""}
                ${description ? `<div class="sast-section"><div class="sast-section-title"><strong>Description</strong></div>${description}</div>` : ""}
                ${recommendation ? `<div class="sast-section"><div class="sast-section-title"><strong>Recommendation</strong></div>${recommendation}</div>` : ""}
                ${references}
            </div>
        </div>
    `
}

function normalizeScaList(value) {
    if (Array.isArray(value)) return value.filter(entry => entry !== undefined && entry !== null)
    if (value === undefined || value === null || value === "") return []
    return [value]
}

function formatScaLocationValue(file) {
    if (!file) return ""
    const link = safeHttpLink(file)
    const safeText = escapeText(file)
    if (link) {
        const href = ptk_utils.escapeHtml(link)
        return `<a href="${href}" target="_blank" rel="noopener noreferrer">${safeText}</a>`
    }
    return safeText
}

function buildScaVersionRangeFromNode(node) {
    if (!node || typeof node !== "object") return ""
    const segments = []
    if (node.atOrAbove) segments.push(`>= ${node.atOrAbove}`)
    if (node.above) segments.push(`> ${node.above}`)
    if (node.atOrBelow) segments.push(`<= ${node.atOrBelow}`)
    if (node.below) segments.push(`< ${node.below}`)
    return segments.join(" , ")
}

function formatScaVersionRange(finding) {
    const direct = buildScaVersionRangeFromNode(finding)
    if (direct) return direct
    if (finding && typeof finding.vulnerable === "object") {
        const nested = buildScaVersionRangeFromNode(finding.vulnerable)
        if (nested) return nested
    }
    return ""
}

function formatScaFixedVersions(finding) {
    if (!finding || typeof finding !== "object") return ""
    const candidates = [
        finding.fixedin,
        finding.fixedIn,
        finding.fixed,
        finding.fix,
        finding.fixVersion,
        finding.fixVersions,
        finding.resolved
    ]
    const values = candidates.flatMap(normalizeScaList).map(entry => String(entry || "").trim()).filter(Boolean)
    const unique = Array.from(new Set(values))
    return unique.join(", ")
}

function formatScaCweLinks(cwe) {
    const list = normalizeScaList(cwe)
    if (!list.length) return ""
    return list.map(code => {
        const raw = String(code || "")
        const numeric = raw.replace(/[^0-9]/g, "")
        const cweId = numeric || raw
        const href = `https://cwe.mitre.org/data/definitions/${encodeURIComponent(cweId)}.html`
        return `<a href="${ptk_utils.escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${ptk_utils.escapeHtml(raw)}</a>`
    }).join(", ")
}

function formatScaCveLinks(identifiers = {}) {
    const list = normalizeScaList(identifiers.CVE || identifiers.cve)
    if (!list.length) return ""
    return list.map(cve => {
        const safe = ptk_utils.escapeHtml(String(cve || ""))
        const href = `https://www.cvedetails.com/cve/${encodeURIComponent(String(cve || ""))}/`
        return `<a href="${ptk_utils.escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${safe}</a>`
    }).join(", ")
}

function formatScaPlainList(values) {
    const list = normalizeScaList(values).map(val => escapeText(String(val || ""))).filter(Boolean)
    if (!list.length) return ""
    return list.join(", ")
}

function formatScaLicenses(licenses) {
    const list = normalizeScaList(licenses).map(entry => escapeText(String(entry || ""))).filter(Boolean)
    return list.join(", ")
}

function formatScaCvss(finding) {
    if (!finding || typeof finding !== "object") return ""
    const cvss = finding.cvss || finding.cvssV3 || {}
    const score = finding.cvssScore ?? finding.score ?? cvss.score ?? cvss.baseScore
    const vector = finding.cvssVector || cvss.vectorString || cvss.vector
    if (score && vector) return `${score} (${vector})`
    if (score) return `${score}`
    return ""
}

function renderScaVersionInfo(component, finding) {
    const rows = []
    const version = component?.version || component?.installedVersion || ""
    const latest = component?.latest || component?.latestVersion || ""
    if (version) rows.push(`<div><strong>Detected version:</strong> ${escapeText(version)}</div>`)
    if (latest) rows.push(`<div><strong>Latest version:</strong> ${escapeText(latest)}</div>`)
    const range = formatScaVersionRange(finding)
    if (range) rows.push(`<div><strong>Affected versions:</strong> <code>${ptk_utils.escapeHtml(range)}</code></div>`)
    const fixed = formatScaFixedVersions(finding)
    if (fixed) rows.push(`<div><strong>Fixed in:</strong> ${escapeText(fixed)}</div>`)
    if (!rows.length) return ""
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>Version Info</strong></div>
                ${rows.join("")}
            </div>`
}

function buildScaEntries(list) {
    if (!Array.isArray(list)) return []
    const entries = []
    list.forEach(component => {
        if (!component) return
        const findings = Array.isArray(component.findings)
            ? component.findings
            : (Array.isArray(component.vulnerabilities) ? component.vulnerabilities : [])
        if (findings.length) {
            findings.forEach(finding => entries.push({ component, finding }))
            return
        }
        if (component.severity || component.identifiers || component.info) {
            entries.push({ component, finding: component })
        }
    })
    return entries
}

function renderScaIdentifierSection(finding) {
    const identifiers = finding?.identifiers || {}
    const fragments = []
    const cves = formatScaCveLinks(identifiers)
    if (cves) fragments.push(`<div><strong>CVE:</strong> ${cves}</div>`)
    const githubIds = formatScaPlainList(identifiers.githubID || identifiers.GHSA)
    if (githubIds) fragments.push(`<div><strong>GitHub:</strong> ${githubIds}</div>`)
    const issues = formatScaPlainList(identifiers.issue)
    if (issues) fragments.push(`<div><strong>Issue:</strong> ${issues}</div>`)
    const prs = formatScaPlainList(identifiers.PR)
    if (prs) fragments.push(`<div><strong>PR:</strong> ${prs}</div>`)
    const retid = identifiers.retid ? escapeText(String(identifiers.retid)) : ""
    if (retid) fragments.push(`<div><strong>ID:</strong> ${retid}</div>`)
    const cweLinks = formatScaCweLinks(finding?.cwe)
    if (cweLinks) fragments.push(`<div><strong>CWE:</strong> ${cweLinks}</div>`)
    if (!fragments.length) return ""
    return `<div class="sast-section">
                <div class="sast-section-title"><strong>Identifiers</strong></div>
                ${fragments.join("")}
            </div>`
}

function renderScaReferencesSection(finding) {
    const refs = normalizeScaList(finding?.info || finding?.references || finding?.urls)
        .map(ref => (typeof ref === "string" ? ref.trim() : ""))
        .filter(Boolean)
    if (!refs.length) return ""
    const linkMap = {}
    refs.forEach((href, idx) => {
        linkMap[`Reference ${idx + 1}`] = href
    })
    return renderReferenceLinks(linkMap)
}

function renderScaFinding(entry, index) {
    if (!entry) return ""
    const component = entry.component || {}
    const finding = entry.finding || {}
    const severityMeta = getSeverityMeta(finding.severity)
    const summary = finding?.identifiers?.summary || finding.summary || `Component vulnerability #${index + 1}`
    const componentName = component.component || component.name || component.library || component.package || component.module || "Unknown component"
    const version = component.version || component.installedVersion || component.libraryVersion || component.currentVersion || ""
    const fileValue = formatScaLocationValue(component.file || component.path || component.location)
    const licenses = formatScaLicenses(component.licenses)
    const cvss = formatScaCvss(finding)
    const metaRows = []
    metaRows.push({ label: "Component", value: escapeText(componentName) })
    if (version) metaRows.push({ label: "Version", value: escapeText(version) })
    if (fileValue) metaRows.push({ label: "File", value: fileValue })
    if (licenses) metaRows.push({ label: "Licenses", value: licenses })
    if (cvss) metaRows.push({ label: "CVSS", value: escapeText(cvss) })
    const metaSection = renderIastMetaSection(metaRows)
    const versionSection = renderScaVersionInfo(component, finding)
    const identifierSection = renderScaIdentifierSection(finding)
    const referencesSection = renderScaReferencesSection(finding)
    const description = sanitizeRichText(finding.description || finding?.identifiers?.description || "")
    const recommendation = sanitizeRichText(finding.recommendation || finding?.identifiers?.recommendation || "")
    return `
        <div class="card sast-report-card sca-report-card" data-index="${index}" style="width: 100%;">
            <div class="content">
                <div class="ui ${severityMeta.color} message" style="margin-bottom: 0px;">
                    <div class="header">
                        ${severityMeta.icon}
                        ${escapeText(summary)}
                    </div>
                    ${componentName ? `<div><b>Package:</b> ${escapeText(componentName)}</div>` : ""}
                </div>
                ${metaSection}
                ${versionSection}
                ${identifierSection}
                ${referencesSection}
                ${description ? `<div class="sast-section"><div class="sast-section-title"><strong>Description</strong></div>${description}</div>` : ""}
                ${recommendation ? `<div class="sast-section"><div class="sast-section-title"><strong>Recommendation</strong></div>${recommendation}</div>` : ""}
            </div>
        </div>
    `
}

function buildRawResponse(response = {}) {
    const parts = []
    const headersBlock = Array.isArray(response.headers) && response.headers.length
        ? response.headers.map(h => `${h.name}: ${h.value}`).join('\n')
        : ''
    if (response.statusLine) parts.push(response.statusLine)
    if (headersBlock) parts.push(headersBlock)
    if (parts.length) parts.push('')
    parts.push(typeof response.body === 'string' ? response.body : '')
    return parts.join('\n')
}

function resolveDastAttackContext(finding, viewModel) {
    const evidence = finding?.evidence?.dast || {}
    const requests = Array.isArray(viewModel?.requests) ? viewModel.requests : []
    const requestRecord = evidence.requestId != null
        ? requests.find((record) => String(record.id) === String(evidence.requestId))
        : null
    const attackRecord = requestRecord && evidence.attackId != null
        ? (requestRecord.attacks || []).find((attack) => String(attack.id) === String(evidence.attackId))
        : null
    return { requestRecord, attackRecord }
}

function mapDastFindingToLegacy(finding, viewModel) {
    const severity = String(finding?.severity || "medium")
    const severityTitle = severity.charAt(0).toUpperCase() + severity.slice(1)
    const { requestRecord, attackRecord } = resolveDastAttackContext(finding, viewModel)
    const originalSchema = requestRecord?.original || {}
    const request = originalSchema.request
        ? JSON.parse(JSON.stringify(originalSchema.request))
        : { raw: "", url: finding?.location?.url || "", method: finding?.location?.method || "GET" }
    if (!request.raw) {
        const method = request.method || "GET"
        const url = request.url || "/"
        request.raw = `${method} ${url} HTTP/1.1`
    }
    const response = attackRecord?.response
        ? JSON.parse(JSON.stringify(attackRecord.response))
        : (originalSchema.response ? JSON.parse(JSON.stringify(originalSchema.response)) : {})
    response.raw = buildRawResponse(response)
    const proof = attackRecord?.proof || ""
    return {
        info: {
            metadata: {
                name: finding?.ruleName || finding?.vulnId || finding?.category || "Finding",
                severity: severityTitle,
                confidence: Number.isFinite(finding?.confidence) ? finding.confidence : null
            },
            proof,
            request,
            response,
            success: true,
            confidence: Number.isFinite(finding?.confidence) ? finding.confidence : null
        },
        original: {
            request,
            response
        }
    }
}

function mapSastFindingToLegacy(finding) {
    const severity = String(finding?.severity || "medium")
    const severityTitle = severity.charAt(0).toUpperCase() + severity.slice(1)
    const evidence = finding?.evidence?.sast || {}
    const defaultSnippet = evidence.codeSnippet || ""
    const owaspLegacy = finding?.owaspLegacy || ""
    const cweText = Array.isArray(finding?.cwe)
        ? finding.cwe.join(", ")
        : (finding?.cwe || "")
    const source = evidence.source || {
        sourceName: finding?.source || finding?.ruleName || "Source",
        sourceFile: finding?.location?.file || "",
        sourceFileFull: finding?.location?.file || "",
        sourceLoc: null,
        sourceSnippet: defaultSnippet
    }
    const sink = evidence.sink || {
        sinkName: finding?.ruleName || "Sink",
        sinkFile: finding?.location?.file || "",
        sinkFileFull: finding?.location?.file || "",
        sinkLoc: null,
        sinkSnippet: defaultSnippet
    }
    return {
        metadata: {
            id: finding?.ruleId || "",
            name: finding?.ruleName || finding?.vulnId || "Finding",
            severity: severityTitle,
            description: finding?.description || "",
            recommendation: finding?.recommendation || "",
            links: finding?.links || {},
            confidence: Number.isFinite(finding?.confidence) ? finding.confidence : null
        },
        module_metadata: {
            id: finding?.moduleId || "",
            name: finding?.moduleName || "",
            severity: severityTitle,
            category: finding?.category || "",
            owasp: owaspLegacy,
            cwe: cweText,
            description: "",
            recommendation: "",
            links: {}
        },
        source,
        sink,
        trace: evidence.trace || finding?.trace || [],
        codeSnippet: evidence.codeSnippet || defaultSnippet,
        pageUrl: finding?.location?.pageUrl || finding?.location?.file || ""
    }
}

function mapIastFindingToLegacy(finding, index) {
    const severity = finding?.severity || "medium"
    const evidence = finding?.evidence?.iast || {}
    const context = {
        domPath: evidence.domPath || finding?.location?.domPath || null,
        elementId: finding?.location?.elementId || null,
        value: evidence.value || null,
        flow: evidence.flow || []
    }
    const raw = {
        meta: {
            ruleName: finding?.ruleName || finding?.category || "IAST Finding",
            moduleId: finding?.moduleId || null,
            moduleName: finding?.moduleName || null
        },
        severity,
        type: finding?.category || null,
        ruleId: finding?.ruleId || null,
        sinkId: evidence.sinkId || null,
        source: evidence.taintSource || null,
        context,
        matched: evidence.matched || null
    }
    return {
        __index: index,
        severity,
        category: finding?.category || null,
        location: { url: finding?.location?.url || null },
        requestKey: null,
        evidence: [{
            source: "IAST",
            raw,
            sinkId: evidence.sinkId || null,
            taintSource: evidence.taintSource || null,
            context,
            trace: context.flow
        }],
        confidence: Number.isFinite(finding?.confidence) ? finding.confidence : null,
        success: true,
        __finding: finding
    }
}

jQuery(function () {
    // -- Dashboard -- //
    const index_controller = new ptk_controller_index()
    const sca_controller = new ptk_controller_sca()
    const rattacker_controller = new ptk_controller_rattacker()
    const iast_controller = new ptk_controller_iast()
    const sast_controller = new ptk_controller_sast()


    $('#filter_all').on("click", function () {
        $('.attack_info').show()
        $('#filter_vuln').removeClass('active')
        $('#filter_all').addClass('active')
    })

    $('#filter_vuln').on("click", function () {
        $('.attack_info.nonvuln').hide()
        $('#filter_all').removeClass('active')
        $('#filter_vuln').addClass('active')
    })

    $('#print').on("click", function () {
        window.print()
    })

    $('.icon.hideshowreport').on("click", function () {
        if ($(this).hasClass('minus')) {
            $(this).removeClass('minus')
            $(this).addClass('plus')
            $(this).parent().next().hide()
        } else {
            $(this).removeClass('plus')
            $(this).addClass('minus')
            $(this).parent().next().show()
        }
    })

    async function bindInfo(host) {
        if (host) {
            $('#dashboard_message_text').html('<h2>OWASP PTK report:</h2>  ' + host)
        } else {
            $('#dashboard_message_text').html(`Reload the tab to activate tracking &nbsp;<i class="exclamation red  circle  icon"></i>`)
        }
    }

    async function bindOWASP() {
        const tab = index_controller.tab || {}
        let raw = tab.findings ? tab.findings : new Array()
        let dt = raw.map(item => [item[0]])
        let params = { "data": dt, "columns": [{ width: "100%" }] }
        let table = bindTable('#tbl_owasp', params)
        table.columns.adjust().draw()
        $('.loader.owasp').hide()
        updateReportDashboardVisibility()
    }

    async function bindCVEs() {
        let dt = new Array()
        const tab = index_controller.tab || {}
        if (Array.isArray(tab.cves)) {
            tab.cves.forEach(item => {
                const evidence = item.evidence || {}
                const evidenceText = `H:${evidence.headers || 0} / HTML:${evidence.html || 0} / JS:${evidence.js || 0}`
                const verifyText = item.verify?.moduleId ? `DAST module: ${item.verify.moduleId}` : ''
                dt.push([
                    item.id || item.title || '',
                    item.severity || '',
                    evidenceText,
                    verifyText
                ])
            })
        }
        let params = { "data": dt }
        bindTable('#tbl_cves', params)
        $('.loader.cves').hide()
        updateReportDashboardVisibility()
    }

    async function bindTechnologies() {
        let dt = new Array()
        const tab = index_controller.tab || {}
        if (tab.technologies)
            Object.values(tab.technologies).forEach(item => {
                dt.push([item.name, item.version, item.category || ''])
            })
        const priority = (category) => {
            const value = (category || '').toLowerCase()
            if (value.includes('waf')) {
                return 0
            }
            if (value.includes('security')) {
                return 1
            }
            return 2
        }
        dt.sort((a, b) => {
            const diff = priority(a[2]) - priority(b[2])
            if (diff !== 0) {
                return diff
            }
            return a[0].localeCompare(b[0])
        })
        let params = { "data": dt, "columns": [{ width: "45%" }, { width: "30%" }, { width: "25%" }] }
        bindTable('#tbl_technologies', params)
        $('.loader.technologies').hide()
        updateReportDashboardVisibility()
    }


    function bindCookies() {
        const tab = index_controller.tab || {}
        if (tab.cookies && Object.keys(tab.cookies).length) {
            $("a[data-tab='cookie']").show()
            $('#tbl_storage').DataTable().row.add(['Cookie', `<a href="#" class="storage_auth_link" data="cookie">View</a>`]).draw()


            let dt = new Array()
            Object.values(tab.cookies).forEach(item => {
                //Object.values(domain).forEach(item => {
                dt.push([item.domain, item.name, item.value, item.httpOnly])
                //})
            })
            dt.sort(function (a, b) {
                if (a[0] === b[0]) { return 0; }
                else { return (a[0] < b[0]) ? -1 : 1; }
            })
            var groupColumn = 0;
            let params = {
                data: dt,
                columnDefs: [{
                    "visible": false, "targets": groupColumn
                }],
                "order": [[groupColumn, 'asc']],
                "drawCallback": function (settings) {
                    var api = this.api();
                    var rows = api.rows({ page: 'current' }).nodes();
                    var last = null;

                    api.column(groupColumn, { page: 'current' }).data().each(function (group, i) {
                        if (last !== group) {
                            $(rows).eq(i).before(
                                '<tr class="group" ><td colspan="3"><div class="ui grey ribbon label">' + group + '</div></td></tr>'
                            );
                            last = group;
                        }
                    });
                }
            }

            bindTable('#tbl_cookie', params)

            let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(dt), jwtHelper.sessionRegex)
            if (jwtToken) {
                let jwt = JSON.parse(decodedToken)
                tokens.push(['cookie', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
            }
        }
        $('.loader.storage').hide()
        bindTokens()
        updateReportDashboardVisibility()
    }

    async function bindTokens(data) {
        if (tokens.length > 0) {
            $("div[data-tab='tokens']").show()
            if (!tokenAdded) {
                $('#tbl_storage').DataTable().row.add(['Tokens', `<a href="#" class="storage_auth_link" data="tokens">View</a>`]).draw()
                tokenAdded = true
            }
            $("a[data-tab='tokens']").show()
            bindTable('#tbl_tokens', { data: tokens })
        }
    }

    function bindStorage() {
        let dt = new Array()
        const tab = index_controller.tab || {}
        const storage = tab.storage || {}
        Object.keys(storage).forEach(key => {
            let item = JSON.parse(storage[key])
            if (Object.keys(item).length > 0 && item[key] != "") {
                $(document).trigger("bind_" + key, item)
                $("a[data-tab='" + key + "']").show()
                let link = `<a href="#" class="storage_auth_link" data="${key}">View</a>`
                dt.push([key, link])
            }
        })
        for (let i = 0; i < dt.length; i++) {
            $('#tbl_storage').DataTable().row.add([dt[i][0], dt[i][1]]).draw()
        }
        $('.loader.storage').hide()

        bindTokens()
        updateReportDashboardVisibility()
    }

    function bindHeaders() {
        const tab = index_controller.tab || {}
        if (tab.requestHeaders && Object.keys(tab.requestHeaders).length) {
            let dt = new Array()
            Object.keys(tab.requestHeaders).forEach(name => {
                if (name.startsWith('x-') || name == 'authorization' || name == 'cookie') {
                    dt.push([name, tab.requestHeaders[name][0]])
                }
            })
            let params = {
                data: dt
            }

            bindTable('#tbl_headers', params)

            let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(dt), jwtHelper.headersRegex)
            if (jwtToken) {
                try {
                    let jwt = JSON.parse(decodedToken)
                    tokens.push(['headers', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
                } catch (e) { }
            }
            bindTokens()
            updateReportDashboardVisibility()
        }
    }

    function reportHasCardData() {
        const tab = index_controller.tab || {}
        const hasTech = Array.isArray(tab.technologies) && tab.technologies.length > 0
        const hasWaf = Array.isArray(tab.waf) ? tab.waf.length > 0 : !!tab.waf
        const hasCves = Array.isArray(tab.cves) && tab.cves.length > 0
        const hasOwasp = Array.isArray(tab.findings) && tab.findings.length > 0
        const hasHeaders = tab.requestHeaders && Object.keys(tab.requestHeaders).length > 0
        const hasStorage = tab.storage && Object.keys(tab.storage).length > 0
        const hasCookies = tab.cookies && Object.keys(tab.cookies).length > 0
        return hasTech || hasWaf || hasCves || hasOwasp || hasHeaders || hasStorage || hasCookies
    }

    function updateReportDashboardVisibility() {
        if (reportHasCardData()) {
            $('#dashboard').show()
        } else {
            $('#dashboard').hide()
        }
    }


    $(document).on("bind_localStorage", function (e, item) {
        if (Object.keys(item).length > 0) {
            $("div[data-tab='localStorage']").show()
            let output = JSON.stringify(item, null, 4)
            let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(item), jwtHelper.storageRegex)
            if (jwtToken) {
                let jwt = JSON.parse(decodedToken)
                tokens.push(['localStorage', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
            }
            $('#localStorageText').text(output.replace(/\\r?\\n/g, '<br/>'))
        }
    })

    $(document).on("bind_sessionStorage", function (e, item) {
        if (Object.keys(item).length > 0) {
            $("div[data-tab='sessionStorage']").show()
            let output = JSON.stringify(item, null, 4)
            let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(item), jwtHelper.storageRegex)
            if (jwtToken) {
                let jwt = JSON.parse(decodedToken)
                tokens.push(['localStorage', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
            }
            $('#sessionStorageText').text(output.replace(/\\r?\\n/g, '<br/>'))
        }
    })

    // -- IAST -- //

    function generateIAST(result) {
        const scanResult = result?.scanResult
        if (!scanResult) return
        const vm = normalizeScanResult(scanResult)
        result.scanViewModel = vm

        const findings = Array.isArray(vm.findings) ? vm.findings : []
        const stats = vm.stats || scanResult.stats || {}
        if (!findings.length && (!Array.isArray(scanResult.items) || !scanResult.items.length)) {
            $('.loader.iast').hide()
            return
        }

        $('#iast_report').show()
        $('#iast_report #vulns_count').text(stats.findingsCount ?? findings.length ?? 0)
        $('#iast_report #critical_count').text(stats.critical ?? scanResult.stats?.critical ?? 0)
        $('#iast_report #high_count').text(stats.high ?? scanResult.stats?.high ?? 0)
        $('#iast_report #medium_count').text(stats.medium ?? scanResult.stats?.medium ?? 0)
        $('#iast_report #low_count').text(stats.low ?? scanResult.stats?.low ?? 0)
        $('#iast_report #info_count').text(stats.info ?? scanResult.stats?.info ?? 0)

        const $container = $("#iast_report_items")
        $container.html("")

        const sortBySeverity = (a, b) => {
            const left = a?.severity || a?.metadata?.severity || "info"
            const right = b?.severity || b?.metadata?.severity || "info"
            return severityRank(left) - severityRank(right)
        }

        if (findings.length) {
            const mapped = findings.map((finding, idx) => {
                const legacy = mapIastFindingToLegacy(finding, idx)
                legacy.__finding = finding
                return legacy
            })
            mapped.sort(sortBySeverity)
            mapped.forEach((legacy, displayIndex) => {
                $container.append(renderIastFinding(legacy, displayIndex))
            })
        } else if (Array.isArray(scanResult.items) && scanResult.items.length) {
            const legacyItems = scanResult.items.map((item, idx) => {
                if (typeof item !== "object") return null
                const clone = { ...item }
                clone.__index = idx
                return clone
            }).filter(Boolean)
            legacyItems.sort(sortBySeverity)
            legacyItems.forEach((item, displayIndex) => {
                $container.append(renderIastFinding(item, displayIndex))
            })
        } else {
            $('.loader.iast').hide()
            return
        }

        $(".content.stacktrace").show()
        $('.loader.iast').hide()
    }

    // -- SAST -- //

    function generateSAST(result) {
        const scanResult = result?.scanResult
        if (!scanResult) return
        const vm = normalizeScanResult(scanResult)
        result.scanViewModel = vm
        const findings = Array.isArray(vm.findings) ? vm.findings : []
        const legacyItems = Array.isArray(scanResult.items) ? scanResult.items : []
        if (!findings.length && !legacyItems.length) {
            $('.loader.sast').hide()
            return
        }
        $('#sast_report').show()

        const ruleIds = new Set()
        const addRuleId = (item) => {
            if (!item) return
            const candidates = [
                item.ruleId,
                item.rule_id,
                item.metadata?.id,
                item.module_metadata?.id,
                item.moduleId
            ]
            const id = candidates.find(value => value !== undefined && value !== null && String(value).trim())
            if (id) ruleIds.add(String(id).trim())
        }

        const $container = $("#sast_report_items")
        $container.html("")
        if (findings.length) {
            const mapped = findings.map(mapSastFindingToLegacy)
            mapped.sort((a, b) => severityRank(a.metadata?.severity) - severityRank(b.metadata?.severity))
            mapped.forEach((item, index) => {
                $container.append(renderSastFinding(item, index))
                addRuleId(item)
            })
        } else {
            const sortedItems = [...legacyItems].sort((a, b) => {
                const aSeverity = a.metadata?.severity || a.severity
                const bSeverity = b.metadata?.severity || b.severity
                return severityRank(aSeverity) - severityRank(bSeverity)
            })
            sortedItems.forEach((item, index) => {
                $container.append(renderSastFinding(item, index))
                addRuleId(item)
            })
        }

        const stats = vm.stats || scanResult.stats || {}
        const computedRulesCount = ruleIds.size
        const resolvedRulesCount = computedRulesCount || stats.rulesCount || 0
        stats.rulesCount = resolvedRulesCount
        $('#sast_report #sast_rules_count').text(resolvedRulesCount)
        $('#sast_report #vulns_count').text(stats.findingsCount ?? findings.length ?? 0)
        $('#sast_report #critical_count').text(stats.critical ?? scanResult.stats?.critical ?? 0)
        $('#sast_report #high_count').text(stats.high ?? scanResult.stats?.high ?? 0)
        $('#sast_report #medium_count').text(stats.medium ?? scanResult.stats?.medium ?? 0)
        $('#sast_report #low_count').text(stats.low ?? scanResult.stats?.low ?? 0)
        $('#sast_report #info_count').text(stats.info ?? scanResult.stats?.info ?? 0)

        $(".content.stacktrace").show()
        $('.loader.sast').hide()
    }


    // -- SCA -- //

    function generateSCA(result) {
        const scanResult = result?.scanResult
        if (!scanResult) return
        const rawComponents = Array.isArray(scanResult.findings)
            ? scanResult.findings
            : (Array.isArray(scanResult.items) ? scanResult.items : [])
        if (!rawComponents.length || (Array.isArray(scanResult.findings) && scanResult.findings.length === 0)) {
            $('.loader.sca').hide()
            return
        }

        const $container = $("#sca_report_items")
        $container.html("")

        const entries = buildScaEntries(rawComponents)
        if (!entries.length) {
            $('.loader.sca').hide()
            return
        }

        $('#sca_report').show()
        if (entries.length) {
            entries.sort((a, b) => severityRank(a?.finding?.severity) - severityRank(b?.finding?.severity))
            entries.forEach((entry, index) => {
                $container.append(renderScaFinding(entry, index))
            })
        }

        const computedStats = {
            findingsCount: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0
        }
        const bucketSeverity = (value) => {
            const normalized = String(value || '').toLowerCase()
            if (normalized === 'critical') return 'critical'
            if (normalized === 'high') return 'high'
            if (normalized === 'medium') return 'medium'
            if (normalized === 'low') return 'low'
            return 'info'
        }
        rawComponents.forEach(component => {
            const vulns = Array.isArray(component?.findings)
                ? component.findings
                : (Array.isArray(component?.vulnerabilities) ? component.vulnerabilities : [])
            if (!vulns.length && component?.severity) {
                computedStats.findingsCount += 1
                const key = bucketSeverity(component.severity)
                computedStats[key] += 1
                return
            }
            vulns.forEach(vuln => {
                computedStats.findingsCount += 1
                const key = bucketSeverity(vuln?.severity)
                computedStats[key] += 1
            })
        })

        const stats = scanResult.stats || computedStats
        $('#sca_report #vulns_count').text(stats.findingsCount ?? computedStats.findingsCount)
        $('#sca_report #critical_count').text(stats.critical ?? computedStats.critical)
        $('#sca_report #high_count').text(stats.high ?? computedStats.high)
        $('#sca_report #medium_count').text(stats.medium ?? computedStats.medium)
        $('#sca_report #low_count').text(stats.low ?? computedStats.low)
        $('#sca_report #info_count').text(stats.info ?? computedStats.info)
        $('.loader.sca').hide()
    }

    // -- R-Attacker -- //

    function generateRattacker(result) {
        const scanResult = result?.scanResult
        if (!scanResult) return

        const vm = normalizeScanResult(scanResult)
        result.scanViewModel = vm

        const findings = Array.isArray(vm.findings) ? vm.findings : []
        const stats = vm.stats || scanResult.stats || {}
        const legacyItems = Array.isArray(scanResult.items) ? scanResult.items : []
        if (!findings.length && !legacyItems.length) {
            $('.loader.rattacker').hide()
            return
        }

        $('#rattacker_report').show()
        const $content = $("#rattacker_content")
        $content.html("")

        const severityLevels = ["critical", "high", "medium", "low", "info"]
        const matchesSeverity = (value, level) => String(value || "").toLowerCase() === level
        if (findings.length) {
            severityLevels.forEach(level => {
                findings
                    .filter(f => matchesSeverity(f.severity, level))
                    .forEach(finding => {
                        const legacy = mapDastFindingToLegacy(finding, vm)
                        $content.append(bindReportItem(legacy.info, legacy.original))
                    })
            })
        } else if (Array.isArray(scanResult.items) && scanResult.items.length) {
            severityLevels.forEach(level => {
                scanResult.items
                    .filter(item => item.attacks.some(a => a.success && matchesSeverity(a.metadata?.severity, level)))
                    .forEach(item => {
                        item.attacks.forEach(attack => {
                            if (attack.success && matchesSeverity(attack.metadata?.severity, level)) {
                                $content.append(bindReportItem(attack, item.original))
                            }
                        })
                    })
            })
        } else {
            $('.loader.rattacker').hide()
            return
        }

        $('#rattacker_report #attacks_count').text(stats.attacksCount ?? findings.length ?? 0)
        $('#rattacker_report #vulns_count').text(stats.findingsCount ?? findings.length ?? 0)
        $('#rattacker_report #critical_count').text(stats.critical ?? scanResult.stats?.critical ?? 0)
        $('#rattacker_report #high_count').text(stats.high ?? scanResult.stats?.high ?? 0)
        $('#rattacker_report #medium_count').text(stats.medium ?? scanResult.stats?.medium ?? 0)
        $('#rattacker_report #low_count').text(stats.low ?? scanResult.stats?.low ?? 0)
        $('#rattacker_report #info_count').text(stats.info ?? scanResult.stats?.info ?? 0)
        $('.loader.rattacker').hide()

        $(".codemirror_area").each(function (index) {
            let editor = CodeMirror.fromTextArea($(this)[0], {
                lineNumbers: false, lineWrapping: true, mode: "message/http",
                scrollbarStyle: 'native'
            })
            editor.setSize('auto', '400px')
        })
        $(".codemirror_area_html").each(function (index) {
            let editor = CodeMirror.fromTextArea($(this)[0], {
                lineNumbers: false, lineWrapping: true, mode: "text/html",
                scrollbarStyle: 'native'
            })
            editor.setSize('auto', '400px')
        })

    }


    function bindReportItem(info, original) {
        //let icon = '', proof = '', attackClass = 'nonvuln', color = ''
        let proof = '', color = ''

        let misc = rutils.getMisc(info)
        let icon = misc.icon, order = misc.order, attackClass = misc.attackClass
        const severityMeta = getSeverityMeta(info.metadata?.severity || info.severity)
        const confidence = resolveConfidenceValue(info.confidence, info.metadata?.confidence)
        const confidenceLine = renderConfidenceLine(confidence)

        if (info.proof)
            proof = `<div class="description"><p>Proof: <b><i name="proof">${ptk_utils.escapeHtml((info.proof))}</i></b></p></div>`
        //let headers = info.response.statusLine + '\n' + info.response.headers.map(x => x.name + ": " + x.value).join('\n')
        if (info.success) {
            color = severityMeta.color || ""
        }
        let target = original?.request?.url ? original.request.url : ""
        let request = info.request?.raw ? info.request.raw : original.request.raw
        let response = info.response?.raw
            ? info.response.raw
            : (original.response ? buildRawResponse(original.response) : '')
        let item = `<div class="attack_info ${attackClass} ui segment">
                        <div class="ui ${color} message" style="margin-bottom: 0px;">
                            <div class="content">
                                <div class="header">
                                    ${icon}
                                    <a href="${target}" target="_blank">${target}</a>
                                </div>
                                <p>Attack: ${ptk_utils.escapeHtml(info.metadata.name)} </p>
                                ${confidenceLine}
                                ${proof}
                            </div>
                        </div>
                    <div class="two fields" >
                        <div class="one field" style="min-width: 50% !important;">
                            <textarea class="codemirror_area" style="width:100%;  border: solid 1px #cecece; padding: 1px;">${ptk_utils.escapeHtml(request)}</textarea>
                        </div>
                        <div class="one field" style="min-width: 50% !important;">
                            <textarea class="codemirror_area_html" style="width:100%;  border: solid 1px #cecece; padding: 1px;">${ptk_utils.escapeHtml(response)}</textarea>
                        </div>
                    </div></div>`

        return item
    }

    const params = new URLSearchParams(window.location.search)

    const normalizeHost = (value) => {
        if (!value) return null
        try {
            const str = String(value).trim()
            if (!str) return null
            if (/^https?:\/\//i.test(str)) {
                return new URL(str).host
            }
            return new URL(`http://${str}`).host
        } catch (e) {
            return null
        }
    }

    const hostsMatch = (left, right) => {
        const normalizedLeft = normalizeHost(left)
        const normalizedRight = normalizeHost(right)
        if (!normalizedLeft || !normalizedRight) return true
        return normalizedLeft === normalizedRight
    }

    if (params.has('rattacker_report')) {
        $('#dashboard').hide()
        $('#rattacker_report').show()
        rattacker_controller.init().then(function (result) {
            bindInfo(result?.scanResult?.host)
            generateRattacker(result)
        })
    } else if (params.has('iast_report')) {
        $('#dashboard').hide()
        $('#iast_report').show()
        iast_controller.init().then(function (result) {
            bindInfo(result?.scanResult?.host)
            generateIAST(result)
        })
    } else if (params.has('sast_report')) {
        $('#dashboard').hide()
        $('#sast_report').show()
        sast_controller.init().then(function (result) {
            bindInfo(result?.scanResult?.host)
            generateSAST(result)
        })
    } else if (params.has('sca_report')) {
        $('#dashboard').hide()
        $('#sca_report').show()
        sca_controller.init().then(function (result) {
            bindInfo(result?.scanResult?.host)
            generateSCA(result)
        })
    } else if (params.has('full_report')) {
        index_controller.get().then(() => {
            index_controller.tab = index_controller.tab || {}
            let host = null
            $('#dashboard').show()
            browser.storage.local.get('tab_full_info').then(function (result) {
                const info = result?.tab_full_info || {}
                if (Object.prototype.hasOwnProperty.call(info, 'tabId')) {
                    index_controller.tab.tabId = info.tabId
                }
                if (Object.prototype.hasOwnProperty.call(info, 'url')) {
                    index_controller.url = info.url
                }
                if (Object.prototype.hasOwnProperty.call(info, 'technologies')) {
                    index_controller.tab.technologies = info.technologies || []
                }
                if (Object.prototype.hasOwnProperty.call(info, 'waf')) {
                    index_controller.tab.waf = info.waf || null
                }
                if (Object.prototype.hasOwnProperty.call(info, 'cves')) {
                    index_controller.tab.cves = info.cves || []
                }
                if (Object.prototype.hasOwnProperty.call(info, 'findings')) {
                    index_controller.tab.findings = info.findings || []
                }
                if (Object.prototype.hasOwnProperty.call(info, 'requestHeaders')) {
                    index_controller.tab.requestHeaders = info.requestHeaders || {}
                }
                if (Object.prototype.hasOwnProperty.call(info, 'storage')) {
                    index_controller.tab.storage = info.storage || {}
                }
                if (Object.prototype.hasOwnProperty.call(info, 'cookies')) {
                    index_controller.tab.cookies = info.cookies || {}
                }

                let host = null
                try {
                    host = index_controller.url ? new URL(index_controller.url).host : null
                } catch (_) {
                    host = null
                }
                bindInfo(host)
                bindOWASP()
                bindTechnologies()
                bindCVEs()
                bindCookies()
                bindStorage()
                bindHeaders()

                if (result?.tab_full_info) {
                    browser.storage.local.remove('tab_full_info')
                }

                rattacker_controller.init().then(function (result) {
                    if (hostsMatch(host, result?.scanResult?.host))
                        generateRattacker(result)
                })
                iast_controller.init().then(function (result) {
                    if (hostsMatch(host, result?.scanResult?.host))
                        generateIAST(result)
                })

                sast_controller.init().then(function (result) {
                    if (hostsMatch(host, result?.scanResult?.host))
                        generateSAST(result)
                })

                sca_controller.init().then(function (result) {
                    if (hostsMatch(host, result?.scanResult?.host))
                        generateSCA(result)
                })
            })
        })
    }


})
