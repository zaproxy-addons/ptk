/* Author: Denis Podgurskii */

const __PTK_IAST_DBG__ = () => {};
let __IAST_DISABLE_HOOKS__ = false;
// Dynamic IAST modules + rule registry, populated from background at runtime.
let IAST_MODULES = null;
const IAST_RULE_INDEX = {
    bySinkId: Object.create(null),
    byRuleId: Object.create(null),
};
let __IAST_LAST_MODULES_REQUEST__ = 0;
const IAST_HOOK_GROUPS = {
    enabled: new Set(),
    installed: new Set()
};
const IAST_SANITIZED_VALUES = new Map();
const IAST_SANITIZED_TTL_MS = 30000;
const IAST_SANITIZED_MAX = 200;
const IAST_TAINT_TTL_MS = 60000;
const IAST_TAINT_MAX = 2000;
const IAST_TAINT_STORE = {
    nextSourceId: 1,
    nextTaintId: 1,
    stringMap: new Map(),
    objectMap: typeof WeakMap !== 'undefined' ? new WeakMap() : null
};
const IAST_MUTATION_QUEUE = [];
const IAST_MUTATION_BUDGET = {
    tokens: 2,
    max: 2,
    intervalMs: 1000,
    lastRefill: Date.now()
};
let IAST_MUTATION_FLUSH_SCHEDULED = false;
const IAST_MUTATION_BATCH_SIZE = 2;
const IAST_MUTATION_QUEUE_MAX = 50;
const IAST_TAINT_ACTIVITY_WINDOW_MS = 5000;
const IAST_HEAVY_COOLDOWN_MS = 4000;
const IAST_HEAVY_MAX_PER_SEC = 8;
let IAST_HEAVY_COUNT = 0;
let IAST_HEAVY_RESET_AT = Date.now();
let IAST_HEAVY_PAUSED_UNTIL = 0;
let IAST_SCAN_STRATEGY = 'SMART';
const IAST_SMART_DEDUP_TTL_MS = 60000;
const IAST_FINDING_DEDUP_MAX = 5000;
const IAST_FINDING_DEDUP = new Map();
const IAST_SINK_SEEN = new Map();
const IAST_NETWORK_HEADER_WINDOW_MS = 60000;
const IAST_NETWORK_HEADER_FREQUENCY_MAX = 12;
const IAST_NETWORK_HEADER_TRACKER = new Map();
const IAST_EVIDENCE_SCHEMA_VERSION = 'iast-evidence@1';
const IAST_DETECTION_SCHEMA_VERSION = 'iast-detection@1';
const IAST_TRUST_SCHEMA_VERSION = 'iast-trust@1';
const IAST_PRIMARY_CLASSES = Object.freeze({
    TAINT_FLOW: 'taint_flow',
    OBSERVATION: 'observation',
    HYBRID: 'hybrid',
    POLICY_VIOLATION: 'policy_violation'
});
const IAST_SOURCE_ROLES = Object.freeze({
    ORIGIN: 'origin',
    OBSERVED: 'observed',
    DERIVED: 'derived',
    UNKNOWN: 'unknown'
});
const IAST_DATA_KINDS = Object.freeze({
    TOKEN: 'token',
    JWT: 'jwt',
    SESSION_ID: 'session_id',
    API_KEY: 'api_key',
    CREDENTIAL: 'credential',
    PII: 'pii',
    UNKNOWN: 'unknown'
});
const IAST_REASON_CODES = Object.freeze({
    JWT_HEURISTIC: 'jwt_heuristic',
    TOKEN_HEURISTIC: 'token_heuristic',
    AUTH_HEADER_SAME_ORIGIN: 'auth_header_same_origin',
    COOKIE_HEADER_ATTEMPT: 'forbidden_header_attempt_cookie',
    AUTH_HEADER_SAME_ORIGIN_RISKY: 'auth_header_same_origin_risky',
    WEBSOCKET_SAME_HOST: 'websocket_same_host',
    SAME_HOST_EXFIL: 'same_host_exfil_observation',
    SINK_POLICY_MATCH: 'sink_policy_match',
    FLOW_MATCH: 'flow_match',
    UNKNOWN: 'unknown'
});
const IAST_TRUST_LEVELS = Object.freeze({
    SAME_ORIGIN: 'same_origin',
    FIRST_PARTY: 'first_party',
    THIRD_PARTY: 'third_party',
    UNKNOWN: 'unknown'
});
const IAST_TRUST_DECISIONS = Object.freeze({
    ALLOW: 'allow',
    WARN: 'warn',
    BLOCK: 'block'
});

function resetIastRuleIndex() {
    IAST_MODULES = null;
    IAST_RULE_INDEX.bySinkId = Object.create(null);
    IAST_RULE_INDEX.byRuleId = Object.create(null);
}

function initIastRuleIndex(modulesJson) {
    resetIastRuleIndex();
    if (!modulesJson || !Array.isArray(modulesJson.modules)) {
        __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: invalid modulesJson', modulesJson);
        return;
    }

    IAST_MODULES = modulesJson;

    for (const mod of modulesJson.modules) {
        const moduleId = mod.id;
        const moduleName = mod.name;
        const moduleMeta = mod.metadata || {};

        if (!Array.isArray(mod.rules)) continue;

        for (const rule of mod.rules) {
            const entry = {
                moduleId,
                moduleName,
                moduleMeta,
                ruleId: rule.id,
                ruleName: rule.name,
                sinkId: rule.sinkId || null,
                ruleMeta: rule.metadata || {},
                hook: rule.hook || null,
                conditions: rule.conditions || {},
            };

            if (entry.sinkId) {
                if (!IAST_RULE_INDEX.bySinkId[entry.sinkId]) {
                    IAST_RULE_INDEX.bySinkId[entry.sinkId] = [];
                }
                IAST_RULE_INDEX.bySinkId[entry.sinkId].push(entry);
            }
            if (entry.ruleId) {
                IAST_RULE_INDEX.byRuleId[entry.ruleId] = entry;
            }
        }
    }

    enableHookGroupsFromModules(modulesJson);

    //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: rule index initialised', IAST_RULE_INDEX);
}

function mergeLinks(baseLinks, overrideLinks) {
    const result = Object.assign({}, baseLinks || {})
    if (overrideLinks && typeof overrideLinks === 'object') {
        Object.entries(overrideLinks).forEach(([key, value]) => {
            if (key) result[key] = value
        })
    }
    return Object.keys(result).length ? result : null
}

const IAST_SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info']

function normalizeIastSeverityValue(value, fallback = 'medium') {
    if (value === null || value === undefined) return fallback
    const normalized = String(value).trim().toLowerCase()
    if (IAST_SEVERITY_LEVELS.includes(normalized)) return normalized
    if (!Number.isNaN(Number(normalized))) {
        const numeric = Number(normalized)
        if (numeric >= 8) return 'high'
        if (numeric >= 5) return 'medium'
        if (numeric > 0) return 'low'
    }
    return fallback
}

function resolveIastEffectiveSeverity({ override, moduleMeta = {}, ruleMeta = {} } = {}) {
    if (override !== null && override !== undefined) {
        return normalizeIastSeverityValue(override)
    }
    if (ruleMeta?.severity != null) {
        return normalizeIastSeverityValue(ruleMeta.severity)
    }
    if (moduleMeta?.severity != null) {
        return normalizeIastSeverityValue(moduleMeta.severity)
    }
    return 'medium'
}

function getIastRuleBySinkId(sinkId) {
    return sinkId ? IAST_RULE_INDEX.bySinkId[sinkId]?.[0] || null : null;
}

function getIastRulesBySinkId(sinkId) {
    return sinkId ? IAST_RULE_INDEX.bySinkId[sinkId] || [] : [];
}

function getIastRuleByRuleId(ruleId) {
    return ruleId ? IAST_RULE_INDEX.byRuleId[ruleId] || null : null;
}

window.addEventListener('message', (event) => {
    const data = event.data || {}
    if (data.channel === 'ptk_background_iast2content_modules') {
        if (data.scanStrategy) setIastScanStrategy(data.scanStrategy);
        if (!data.iastModules) return;
        initIastRuleIndex(data.iastModules)
        //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: modules received from bridge')
    }
    if (data.channel === 'ptk_background_iast2content_token_origin') {
        if (Array.isArray(data.tokens)) {
            data.tokens.forEach(entry => {
                if (!entry || !entry.value) return;
                addTokenOrigin(entry.value, entry.origin || null);
            });
        }
    }
})

// On load, request the current IAST modules from background (helps after reloads)
try {
    requestModulesFromBackground(true)
} catch (_) {
    // ignore if not in extension context
}

function requestModulesFromBackground(force = false) {
    const now = Date.now();
    if (!force && now - __IAST_LAST_MODULES_REQUEST__ < 2000) {
        return;
    }
    __IAST_LAST_MODULES_REQUEST__ = now;
    try {
        window.postMessage({ channel: 'ptk_content_iast_request_modules' }, '*');
    } catch (e) {
        __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: modules request exception', e);
    }
}

function normalizeScanStrategy(value) {
    const normalized = String(value || '').trim().toUpperCase();
    return normalized === 'SMART' ? 'SMART' : 'COMPREHENSIVE';
}

function setIastScanStrategy(value) {
    const next = normalizeScanStrategy(value);
    if (next === IAST_SCAN_STRATEGY) return;
    IAST_SCAN_STRATEGY = next;
    IAST_FINDING_DEDUP.clear();
    IAST_SINK_SEEN.clear();
}

function isSmartScanStrategy() {
    return IAST_SCAN_STRATEGY === 'SMART';
}

function isHookGroupEnabled(groupId) {
    return IAST_HOOK_GROUPS.enabled.has(groupId);
}

function refillMutationBudget() {
    const now = Date.now();
    const elapsed = now - IAST_MUTATION_BUDGET.lastRefill;
    if (elapsed < IAST_MUTATION_BUDGET.intervalMs) return;
    const refill = Math.floor(elapsed / IAST_MUTATION_BUDGET.intervalMs);
    if (refill <= 0) return;
    IAST_MUTATION_BUDGET.tokens = Math.min(
        IAST_MUTATION_BUDGET.max,
        IAST_MUTATION_BUDGET.tokens + refill
    );
    IAST_MUTATION_BUDGET.lastRefill = now;
}

function takeMutationToken() {
    refillMutationBudget();
    if (IAST_MUTATION_BUDGET.tokens <= 0) return false;
    IAST_MUTATION_BUDGET.tokens -= 1;
    return true;
}

function scheduleMutationFlush() {
    if (IAST_MUTATION_FLUSH_SCHEDULED) return;
    IAST_MUTATION_FLUSH_SCHEDULED = true;
    const flush = () => {
        IAST_MUTATION_FLUSH_SCHEDULED = false;
        if (!IAST_MUTATION_QUEUE.length) return;
        if (!takeMutationToken()) {
            setTimeout(scheduleMutationFlush, IAST_MUTATION_BUDGET.intervalMs);
            return;
        }
        const batch = IAST_MUTATION_QUEUE.splice(0, IAST_MUTATION_BATCH_SIZE);
        batch.forEach(({ node, trigger }) => {
            try {
                traverseAndReport(node, trigger);
            } catch (_) { }
        });
        if (IAST_MUTATION_QUEUE.length) scheduleMutationFlush();
    };
    if (typeof window.requestIdleCallback === 'function') {
        window.requestIdleCallback(flush, { timeout: 200 });
    } else {
        setTimeout(flush, 0);
    }
}

function markTaintActivity() {
    window.__IAST_LAST_TAINT_AT__ = Date.now();
}

function hasRecentTaintActivity() {
    const last = window.__IAST_LAST_TAINT_AT__ || 0;
    return Date.now() - last <= IAST_TAINT_ACTIVITY_WINDOW_MS;
}

function allowHeavyHook() {
    const now = Date.now();
    if (now < IAST_HEAVY_PAUSED_UNTIL) return false;
    if (now - IAST_HEAVY_RESET_AT >= 1000) {
        IAST_HEAVY_RESET_AT = now;
        IAST_HEAVY_COUNT = 0;
    }
    IAST_HEAVY_COUNT += 1;
    if (IAST_HEAVY_COUNT > IAST_HEAVY_MAX_PER_SEC) {
        IAST_HEAVY_PAUSED_UNTIL = now + IAST_HEAVY_COOLDOWN_MS;
        return false;
    }
    return true;
}

function installHookGroup(groupId) {
    if (IAST_HOOK_GROUPS.installed.has(groupId)) return;
    IAST_HOOK_GROUPS.installed.add(groupId);
    if (groupId === 'hook.sanitizers') {
        installSanitizerHooks();
    }
}

function installSanitizerHooks() {
    if (window.__IAST_SANITIZER_HOOKED__) return;
    window.__IAST_SANITIZER_HOOKED__ = true;
    const wrapDomPurify = () => {
        if (!window.DOMPurify || typeof window.DOMPurify.sanitize !== 'function') return false;
        if (window.DOMPurify.__ptk_wrapped__) return true;
        const orig = window.DOMPurify.sanitize.bind(window.DOMPurify);
        window.DOMPurify.sanitize = function (...args) {
            const result = orig(...args);
            recordSanitizedValue(result, 'san.domPurify');
            return result;
        };
        window.DOMPurify.__ptk_wrapped__ = true;
        return true;
    };
    if (wrapDomPurify()) return;
    let attempts = 0;
    const timer = setInterval(() => {
        attempts += 1;
        if (wrapDomPurify() || attempts > 40) {
            clearInterval(timer);
        }
    }, 500);
}

function getHookGroupsForSink(sinkId) {
    const groups = new Set();
    if (!sinkId) return groups;
    if (['dom.innerHTML', 'dom.outerHTML', 'dom.insertAdjacentHTML', 'document.write', 'nav.iframe.srcdoc', 'dom.inline_event'].includes(sinkId)) {
        groups.add('hook.dom.htmlStrings');
    }
    if (['dom.mutation', 'script.element.src'].includes(sinkId)) {
        groups.add('hook.dom.mutations');
    }
    if (['dom.attr.href', 'dom.attr.src', 'dom.attr.action', 'dom.attr.formaction', 'nav.iframe.src', 'nav.iframe.srcdoc', 'nav.location.href', 'http.image.src', 'script.element.src'].includes(sinkId)) {
        groups.add('hook.dom.attributes');
    }
    if (sinkId.startsWith('code.')) {
        groups.add('hook.code.exec');
    }
    if (sinkId.startsWith('nav.location.') || sinkId.startsWith('nav.window.open') || sinkId.startsWith('nav.history.') || sinkId === 'nav.navigation.navigate') {
        groups.add('hook.nav.redirects');
    }
    if (sinkId.startsWith('http.') || sinkId.startsWith('csrf.')) {
        groups.add('hook.net.exfil');
    }
    if (sinkId.startsWith('realtime.')) {
        groups.add('hook.net.exfil');
    }
    if (sinkId.startsWith('clipboard.')) {
        groups.add('hook.net.exfil');
    }
    if (sinkId.startsWith('storage.')) {
        groups.add('hook.storage');
    }
    if (sinkId.startsWith('postmessage.') || sinkId.startsWith('channel.')) {
        groups.add('hook.postMessage');
    }
    if (sinkId.startsWith('log.console.')) {
        groups.add('hook.console.leaks');
    }
    if (sinkId.startsWith('worker.') || sinkId === 'script.element.src') {
        groups.add('hook.script.loading');
    }
    if (sinkId === 'client.json.parse') {
        groups.add('hook.client.json');
    }
    if (sinkId === 'document.domain') {
        groups.add('hook.dom.attributes');
    }
    return groups;
}

function enableHookGroupsFromModules(modulesJson) {
    const enabled = new Set();
    if (modulesJson && Array.isArray(modulesJson.modules)) {
        modulesJson.modules.forEach(mod => {
            if (!Array.isArray(mod.rules)) return;
            mod.rules.forEach(rule => {
                getHookGroupsForSink(rule.sinkId).forEach(group => enabled.add(group));
                const ruleMeta = rule.metadata || {};
                const ruleSources = Array.isArray(rule.sources) ? rule.sources : (Array.isArray(ruleMeta.sources) ? ruleMeta.sources : []);
                if (ruleSources.includes('postMessage')) {
                    enabled.add('hook.postMessage');
                }
                const sanitizers = Array.isArray(rule.sanitizersAllowed)
                    ? rule.sanitizersAllowed
                    : (Array.isArray(ruleMeta.sanitizersAllowed) ? ruleMeta.sanitizersAllowed : []);
                if (sanitizers.length) {
                    enabled.add('hook.sanitizers');
                }
            });
        });
    }
    IAST_HOOK_GROUPS.enabled = enabled;
    enabled.forEach(groupId => installHookGroup(groupId));
}

// Deduplication set for mutation hooks
const __IAST_REPORTED_NODES__ = new Set();

// Encoding helpers
function withoutHooks(fn) {
    const prev = __IAST_DISABLE_HOOKS__;
    __IAST_DISABLE_HOOKS__ = true;
    try {
        return fn();
    } finally {
        __IAST_DISABLE_HOOKS__ = prev;
    }
}

// Re-write htmlDecode & htmlEncode

function htmlDecode(input) {
    if (input == null) return input;
    const str = String(input);
    if (!str.includes('&')) return str;
    try {
        return withoutHooks(() => {
            const ta = document.createElement('textarea');
            ta.innerHTML = str;
            return ta.value;
        });
    } catch (_) {
        return str;
    }
}

function htmlEncode(input) {
    return withoutHooks(() => {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    });
}

let __IAST_MATCH_COUNT__ = 0;

function getDomPath(node) {
    try {
        if (!node || node.nodeType !== 1) return null;
        const parts = [];
        let el = node;
        while (el && el.nodeType === 1 && parts.length < 10) {
            let part = el.tagName.toLowerCase();
            if (el.id) {
                part += `#${el.id}`;
                parts.unshift(part);
                break;
            }
            if (el.classList && el.classList.length) {
                part += '.' + Array.from(el.classList).slice(0, 3).join('.');
            }
            if (el.parentElement) {
                const siblings = Array.from(el.parentElement.children).filter(c => c.tagName === el.tagName);
                if (siblings.length > 1) {
                    const idx = siblings.indexOf(el);
                    part += `:nth-of-type(${idx + 1})`;
                }
            }
            parts.unshift(part);
            el = el.parentElement;
        }
        return parts.length ? parts.join(' > ') : null;
    } catch (_) {
        return null;
    }
}

function computeDomPath(el) {
    try {
        if (!el || el.nodeType !== 1) return null;
        const segments = [];
        let node = el;
        let safety = 0;
        while (node && node.nodeType === 1 && safety < 50) {
            safety++;
            const tag = (node.tagName || '').toLowerCase();
            if (!tag) break;
            let part = tag;
            if (node.id) {
                part += `#${node.id}`;
            } else if (node.classList && node.classList.length) {
                part += '.' + Array.from(node.classList).slice(0, 3).join('.');
            }
            if (!node.id && node.parentElement) {
                let idx = 1;
                let sib = node;
                while ((sib = sib.previousElementSibling)) {
                    if (sib.tagName === node.tagName) idx++;
                }
                if (idx > 1) part += `:nth-of-type(${idx})`;
            }
            segments.unshift(part);
            node = node.parentElement;
            if (node === document.documentElement) {
                segments.unshift('html');
                break;
            }
        }
        return segments.join(' > ');
    } catch (_) {
        return null;
    }
}

function enrichContext(ctx = {}) {
    const context = Object.assign({}, ctx);
    const el = context.element;
    if (el && el.nodeType === 1) {
        context.tagName = el.tagName ? el.tagName.toLowerCase() : context.tagName;
        context.elementId = el.id || context.elementId || null;
        if (el.classList && el.classList.length) {
            context.elementClasses = Array.from(el.classList);
        }
        if (!context.domPath) {
            context.domPath = computeDomPath(el);
        }
        if (el.outerHTML && !context.elementOuterHTML) {
            const html = String(el.outerHTML);
            context.elementOuterHTML = html.length > 1024 ? html.slice(0, 1024) : html;
        }
    } else if (context.element && typeof context.element === 'string' && !context.domPath) {
        try {
            const tmp = document.createElement('div');
            tmp.innerHTML = context.element;
            const first = tmp.firstElementChild;
            const path = computeDomPath(first);
            if (path) context.domPath = path;
        } catch (_) { }
    }
    if (!context.domPath && context.target && context.target.nodeType === 1) {
        const path = computeDomPath(context.target);
        if (path) context.domPath = path;
    }
    delete context.element;
    delete context.target;
    return context;
}

// Taint collection
window.__IAST_TAINT_META__ = window.__IAST_TAINT_META__ || {};
window.__PTK_IAST_HAS_TAINT__ = window.__PTK_IAST_HAS_TAINT__ || false;
window.__PTK_IAST_PROPAGATION_ENABLED__ = window.__PTK_IAST_PROPAGATION_ENABLED__ === true;
const IAST_TOKEN_ORIGINS = new Map();
const IAST_TOKEN_ORIGIN_TTL_MS = 2 * 60 * 1000;
const IAST_TOKEN_ORIGIN_MAX = 200;
const IAST_ORIGIN_WAIT_MS = 200;

function getTaintMetaEntry(key) {
    if (!key) return null;
    return window.__IAST_TAINT_META__?.[key] || null;
}

function updateTaintMetaEntry(key, extras = {}) {
    if (!key) return null;
    const store = window.__IAST_TAINT_META__ = window.__IAST_TAINT_META__ || {};
    const current = store[key] || {};
    if (extras && typeof extras === 'object') {
        Object.entries(extras).forEach(([k, v]) => {
            if (v !== undefined && v !== null) {
                current[k] = v;
            }
        });
    }
    current.lastUpdated = Date.now();
    store[key] = current;
    return current;
}

function fnv1aHash(str) {
    let hash = 2166136261;
    for (let i = 0; i < str.length; i++) {
        hash ^= str.charCodeAt(i);
        hash = (hash * 16777619) >>> 0;
    }
    return hash.toString(16);
}

function fingerprintValue(value) {
    const str = String(value);
    const prefix = str.slice(0, 12);
    const suffix = str.slice(-12);
    return `${str.length}:${fnv1aHash(str)}:${prefix}:${suffix}`;
}

function pruneTaintStore() {
    if (IAST_TAINT_STORE.stringMap.size <= IAST_TAINT_MAX) return;
    const now = Date.now();
    for (const [key, entry] of IAST_TAINT_STORE.stringMap.entries()) {
        if (!entry || now - entry.time > IAST_TAINT_TTL_MS) {
            IAST_TAINT_STORE.stringMap.delete(key);
        }
        if (IAST_TAINT_STORE.stringMap.size <= IAST_TAINT_MAX) break;
    }
}

function addTokenOrigin(value, origin) {
    if (!value) return;
    const str = String(value);
    const now = Date.now();
    IAST_TOKEN_ORIGINS.set(str, { origin: origin || null, time: now });
    if (IAST_TOKEN_ORIGINS.size > IAST_TOKEN_ORIGIN_MAX) {
        for (const [key, entry] of IAST_TOKEN_ORIGINS.entries()) {
            if (!entry || now - entry.time > IAST_TOKEN_ORIGIN_TTL_MS) {
                IAST_TOKEN_ORIGINS.delete(key);
            }
            if (IAST_TOKEN_ORIGINS.size <= IAST_TOKEN_ORIGIN_MAX) break;
        }
    }
}

function getTokenOrigin(value) {
    if (!value) return null;
    const str = String(value);
    const entry = IAST_TOKEN_ORIGINS.get(str);
    if (!entry) return null;
    if (Date.now() - entry.time > IAST_TOKEN_ORIGIN_TTL_MS) {
        IAST_TOKEN_ORIGINS.delete(str);
        return null;
    }
    return entry.origin || null;
}

function classifyTaintKind(sourceKind, value, meta = {}) {
    if (meta.taintKind) return meta.taintKind;
    if ((sourceKind === 'cookie' || sourceKind === 'localStorage' || sourceKind === 'sessionStorage') && isTokenLikeValue(value)) {
        return 'secret';
    }
    if (sourceKind === 'query' || sourceKind === 'hashQuery' || sourceKind === 'hashRoute'
        || sourceKind === 'inline' || sourceKind === 'postMessage') {
        return 'user_input';
    }
    return 'unknown';
}

function guessLabel(value, meta = {}) {
    if (meta.label) return meta.label;
    if (isTokenLikeValue(value) && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(String(value))) {
        return 'jwt';
    }
    return null;
}

function createSource(value, sourceKind, meta = {}) {
    window.__PTK_IAST_HAS_TAINT__ = true;
    const sourceId = meta.sourceId || `s_${IAST_TAINT_STORE.nextSourceId++}`;
    const taintId = `t_${IAST_TAINT_STORE.nextTaintId++}`;
    const taint = {
        taintId,
        sourceId,
        sourceKind,
        taintKind: classifyTaintKind(sourceKind, value, meta),
        label: guessLabel(value, meta),
        createdAt: Date.now(),
        origin: { url: window.location.href },
        meta: Object.assign({}, meta),
        lineage: [{ op: 'source', at: Date.now(), meta: Object.assign({}, meta) }]
    };
    if (typeof value === 'object' && value !== null && IAST_TAINT_STORE.objectMap) {
        IAST_TAINT_STORE.objectMap.set(value, { taint, time: Date.now() });
    } else {
        const fp = fingerprintValue(value);
        IAST_TAINT_STORE.stringMap.set(fp, { taint, time: Date.now() });
        pruneTaintStore();
    }
    return taint;
}

function getTaintEntry(value) {
    if (!window.__PTK_IAST_HAS_TAINT__) return null;
    if (value === null || value === undefined) return null;
    if (typeof value === 'object' && value !== null && IAST_TAINT_STORE.objectMap) {
        const entry = IAST_TAINT_STORE.objectMap.get(value);
        return entry?.taint ? { taint: entry.taint, matchType: 'id' } : null;
    }
    const fp = fingerprintValue(value);
    const entry = IAST_TAINT_STORE.stringMap.get(fp);
    if (!entry) return null;
    if (Date.now() - entry.time > IAST_TAINT_TTL_MS) {
        IAST_TAINT_STORE.stringMap.delete(fp);
        return null;
    }
    return entry?.taint ? { taint: entry.taint, matchType: 'fingerprint' } : null;
}

function propagateTaint(outputValue, op, inputs = [], meta = {}) {
    if (!window.__PTK_IAST_PROPAGATION_ENABLED__ || !window.__PTK_IAST_HAS_TAINT__) return;
    const inputTaints = inputs.map(getTaintEntry).filter(Boolean).map(entry => entry.taint);
    if (!inputTaints.length) return;
    const primary = inputTaints[0];
    const taint = {
        taintId: `t_${IAST_TAINT_STORE.nextTaintId++}`,
        sourceId: primary.sourceId,
        sourceKind: primary.sourceKind,
        taintKind: primary.taintKind,
        label: primary.label,
        createdAt: Date.now(),
        origin: primary.origin,
        meta: Object.assign({}, primary.meta, meta),
        lineage: (primary.lineage || []).concat([{ op, at: Date.now(), meta }])
    };
    if (typeof outputValue === 'object' && outputValue !== null && IAST_TAINT_STORE.objectMap) {
        IAST_TAINT_STORE.objectMap.set(outputValue, { taint, time: Date.now() });
    } else {
        const fp = fingerprintValue(outputValue);
        IAST_TAINT_STORE.stringMap.set(fp, { taint, time: Date.now() });
        pruneTaintStore();
    }
}

function isTokenLikeValue(value) {
    if (value === null || value === undefined) return false;
    const str = String(value).trim();
    if (str.length < 12) return false;
    // JWT-like: three base64url segments
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(str) && str.length >= 30) {
        return true;
    }
    // Long hex
    if (/^[A-Fa-f0-9]+$/.test(str) && str.length >= 32) {
        return true;
    }
    // Long base64 / base64url-ish
    if (/^[A-Za-z0-9+/_=-]+$/.test(str) && str.length >= 24) {
        return true;
    }
    // Mixed classes and long enough
    const hasLower = /[a-z]/.test(str);
    const hasUpper = /[A-Z]/.test(str);
    const hasDigit = /[0-9]/.test(str);
    if (str.length >= 20 && ((hasLower && hasUpper) || (hasUpper && hasDigit) || (hasLower && hasDigit))) {
        return true;
    }
    return false;
}

function isInternalStorageKey(key) {
    return typeof key === 'string' && key.startsWith('ptk_iast_');
}

function getTokenDataKind(value) {
    if (value == null) return 'unknown';
    const str = String(value).trim();
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(str) && str.length >= 30) {
        return 'jwt';
    }
    return isTokenLikeValue(value) ? 'token' : 'unknown';
}

function buildRoutingMeta() {
    const runtimeUrl = window.location.href;
    const route = window.location.hash || null;
    return {
        runtimeUrl,
        route,
        urlPattern: route ? `${runtimeUrl.split('#')[0] || runtimeUrl}#${route.split('?')[0] || ''}` : null
    };
}

// Best-effort propagation for common string operations
(function () {
    if (window.__PTK_IAST_PROPAGATION_INSTALLED__) return;
    window.__PTK_IAST_PROPAGATION_INSTALLED__ = true;
    const wrapStringMethod = (name) => {
        const orig = String.prototype[name];
        if (!orig || orig.__ptk_iast_wrapped__) return;
        const wrapped = function (...args) {
            const result = orig.apply(this, args);
            try {
                if (!window.__PTK_IAST_PROPAGATION_ENABLED__ || !window.__PTK_IAST_HAS_TAINT__) {
                    return result;
                }
                propagateTaint(result, `String.${name}`, [this, ...args]);
            } catch (_) { }
            return result;
        };
        wrapped.__ptk_iast_wrapped__ = true;
        String.prototype[name] = wrapped;
    };
    [
        'concat',
        'slice',
        'substring',
        'substr',
        'replace',
        'replaceAll',
        'toLowerCase',
        'toUpperCase',
        'trim',
        'padStart',
        'padEnd'
    ].forEach(wrapStringMethod);

    const origToString = String.prototype.toString;
    if (origToString && !origToString.__ptk_iast_wrapped__) {
        const wrapped = function (...args) {
            const result = origToString.apply(this, args);
            try {
                if (!window.__PTK_IAST_PROPAGATION_ENABLED__ || !window.__PTK_IAST_HAS_TAINT__) {
                    return result;
                }
                propagateTaint(result, 'String.toString', [this]);
            } catch (_) { }
            return result;
        };
        wrapped.__ptk_iast_wrapped__ = true;
        String.prototype.toString = wrapped;
    }

    const origJsonParse = JSON.parse;
    if (origJsonParse && !origJsonParse.__ptk_iast_wrapped__) {
        const wrapped = function (text, ...rest) {
            const result = origJsonParse.call(this, text, ...rest);
            try {
                if (!window.__PTK_IAST_PROPAGATION_ENABLED__ || !window.__PTK_IAST_HAS_TAINT__) {
                    return result;
                }
                propagateTaint(result, 'JSON.parse', [text]);
            } catch (_) { }
            return result;
        };
        wrapped.__ptk_iast_wrapped__ = true;
        JSON.parse = wrapped;
    }

    if (typeof Headers !== 'undefined' && Headers.prototype && typeof Headers.prototype.set === 'function') {
        const origSet = Headers.prototype.set;
        if (!origSet.__ptk_iast_wrapped__) {
            const wrapped = function (name, value) {
                const result = origSet.call(this, name, value);
                try {
                    if (!window.__PTK_IAST_PROPAGATION_ENABLED__ || !window.__PTK_IAST_HAS_TAINT__) {
                        return result;
                    }
                    propagateTaint(this, 'Headers.set', [value], { headerName: name });
                } catch (_) { }
                return result;
            };
            wrapped.__ptk_iast_wrapped__ = true;
            Headers.prototype.set = wrapped;
        }
    }

    if (typeof FormData !== 'undefined' && FormData.prototype && typeof FormData.prototype.append === 'function') {
        const origAppend = FormData.prototype.append;
        if (!origAppend.__ptk_iast_wrapped__) {
            const wrapped = function (name, value, filename) {
                const result = origAppend.call(this, name, value, filename);
                try {
                    if (!window.__PTK_IAST_PROPAGATION_ENABLED__ || !window.__PTK_IAST_HAS_TAINT__) {
                        return result;
                    }
                    propagateTaint(this, 'FormData.append', [value], { fieldName: name });
                } catch (_) { }
                return result;
            };
            wrapped.__ptk_iast_wrapped__ = true;
            FormData.prototype.append = wrapped;
        }
    }
})();

function collectTaintedSources() {
    const raw = {};
    const add = (key, valRaw, metaOverride = null) => {
        if (!valRaw) return;
        let val = String(valRaw).trim().replace(/^#/, '');
        const hasAlnum = /[A-Za-z0-9]/.test(val);
        if (!hasAlnum && val !== '/') return;
        if ((key.startsWith('cookie:') || key.startsWith('localStorage:')) && !isTokenLikeValue(val)) {
            return;
        }
        const meta = Object.assign({}, metaOverride || describeSourceKey(key, val));
        const storedMeta = updateTaintMetaEntry(key, { taintKind: meta.taintKind, sourceKind: meta.sourceKind });
        const taint = createSource(val, meta.sourceKind || meta.type || 'unknown', Object.assign({}, meta, { sourceId: storedMeta?.sourceId || null }));
        updateTaintMetaEntry(key, { sourceId: taint.sourceId });
        raw[key] = val;
        registerTaintSource(key, val, Object.assign({}, meta, { sourceId: taint.sourceId }));
    };
    for (const [k, v] of new URLSearchParams(location.search)) add(`query:${k}`, v);
    purgeHashTaintEntries();
    collectHashSources().forEach(src => add(src.key, src.value, src.meta));
    if (document.referrer) add('referrer', document.referrer);
    document.cookie.split(';').forEach(c => {
        const [k, v] = c.split('=').map(s => s.trim());
        const decodedVal = decodeURIComponent(v || '');
        add(`cookie:${k}`, decodedVal, createCookieSourceMeta(k, decodedVal));
    });
    ['localStorage', 'sessionStorage'].forEach(store => {
        try {
            for (let i = 0; i < window[store].length; i++) {
                const key = window[store].key(i), val = window[store].getItem(key);
                if (isInternalStorageKey(key)) continue;
                add(`${store}:${key}`, val);
            }
        } catch { };
    });
    if (window.name) add('window.name', window.name);
    //console.info('[IAST] Collected taints', raw);
    return raw;
}
window.__IAST_TAINT_GRAPH__ = window.__IAST_TAINT_GRAPH__ || {};
window.__IAST_TAINTED__ = collectTaintedSources();

function captureStackTrace(label = 'IAST flow') {
    try {
        return (new Error(label)).stack;
    } catch (_) {
        return null;
    }
}

function captureElementMeta(el) {
    if (!el || typeof el !== 'object') return {};
    return {
        domPath: getDomPath(el),
        elementId: el.id || null,
        elementTag: el.tagName ? el.tagName.toLowerCase() : null
    };
}

function describeSourceKey(key, rawValue) {
    if (!key) return {};
    const meta = {
        label: key,
        detail: key,
        location: window.location.href,
        value: rawValue
    };
    if (key.startsWith('query:')) {
        meta.type = 'query';
        meta.label = `Query parameter "${key.slice(6)}"`;
        meta.detail = key.slice(6) || key;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'query';
    } else if (key.startsWith('cookie:')) {
        meta.type = 'cookie';
        meta.label = `Cookie "${key.slice(7)}"`;
        meta.detail = key.slice(7) || key;
        meta.sourceKind = 'cookie';
        meta.taintKind = isTokenLikeValue(rawValue) ? 'secret' : 'user_input';
    } else if (key.startsWith('localStorage:')) {
        meta.type = 'localStorage';
        meta.label = `localStorage["${key.slice(13)}"]`;
        meta.sourceKind = 'localStorage';
        meta.taintKind = isTokenLikeValue(rawValue) ? 'secret' : 'unknown';
    } else if (key.startsWith('sessionStorage:')) {
        meta.type = 'sessionStorage';
        meta.label = `sessionStorage["${key.slice(15)}"]`;
        meta.sourceKind = 'sessionStorage';
        meta.taintKind = isTokenLikeValue(rawValue) ? 'secret' : 'unknown';
    } else if (key === 'window.name') {
        meta.type = 'windowName';
        meta.label = 'window.name';
        meta.sourceKind = 'windowName';
    } else if (key === 'referrer') {
        meta.type = 'referrer';
        meta.label = 'document.referrer';
        meta.sourceKind = 'referrer';
    } else if (key === 'hash:route') {
        meta.type = 'hashRoute';
        meta.label = 'Location hash route';
        meta.detail = rawValue || key;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'hashRoute';
    } else if (key.startsWith('hash:param:')) {
        const paramName = key.slice('hash:param:'.length) || 'param';
        meta.type = 'hashQuery';
        meta.label = `Location hash parameter "${paramName}"`;
        meta.detail = paramName;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'hashQuery';
    } else if (key === 'postMessage' || key.startsWith('postMessage:')) {
        meta.type = 'postMessage';
        meta.label = key === 'postMessage' ? 'postMessage message' : `postMessage from ${key.slice('postMessage:'.length)}`;
        meta.detail = key;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'postMessage';
    } else if (key.startsWith('inline:')) {
        meta.type = 'inline';
        meta.label = `Inline value "${key.slice(7)}"`;
        meta.taintKind = 'user_input';
        meta.sourceKind = 'inline';
    }
    return meta;
}

function normalizeSourceEntry(entry, fallbackKey = null, fallbackRaw = null) {
    const provided = entry || {};
    const key = provided.key || provided.source || fallbackKey;
    if (!key) return null;
    const providedRaw = Object.prototype.hasOwnProperty.call(provided, 'raw')
        ? provided.raw
        : (Object.prototype.hasOwnProperty.call(provided, 'value') ? provided.value : undefined);
    const rawValue = providedRaw !== undefined ? providedRaw : fallbackRaw;
    const descriptor = describeSourceKey(key, rawValue);
    const storedMeta = getTaintMetaEntry(key) || {};
    const normalized = Object.assign({}, provided, {
        key,
        source: key,
        raw: rawValue,
        value: rawValue,
        label: provided.label || descriptor.label || key,
        detail: provided.detail || descriptor.detail || key,
        location: provided.location || descriptor.location || storedMeta.location || window.location.href,
        taintKind: provided.taintKind || storedMeta.taintKind || descriptor.taintKind || null,
        sourceKind: provided.sourceKind || storedMeta.sourceKind || descriptor.sourceKind || descriptor.type || null,
        sourceId: provided.sourceId || storedMeta.sourceId || null
    });
    normalized.__normalizedSource = true;
    return normalized;
}

function normalizeTaintedSources(sourceMatches, fallbackRaw = null) {
    if (!Array.isArray(sourceMatches)) return [];
    return sourceMatches
        .map(entry => normalizeSourceEntry(entry, entry?.key || entry?.source || null, entry?.raw ?? fallbackRaw))
        .filter(Boolean);
}

function formatSourceForReport(source) {
    if (!source) return 'Unknown source';
    const key = (source.key || source.source || '').toLowerCase();
    const detail = source.detail || source.label || key || 'source';
    const rawValue = source.value != null ? String(source.value) : (source.raw != null ? String(source.raw) : '');
    if (key.startsWith('hash:param:')) {
        return `location.hash parameter "${detail}" (value: "${rawValue}")`;
    }
    if (key === 'hash') {
        return `location.hash value "${rawValue || detail}"`;
    }
    if (key === 'hash:route') {
        return `location.hash route "${rawValue || detail}"`;
    }
    if (key.startsWith('query:param:') || key.startsWith('query:')) {
        return `location.search parameter "${detail}" (value: "${rawValue}")`;
    }
    if (key.startsWith('cookie:')) {
        return `document.cookie "${detail}" (value: "${rawValue}")`;
    }
    if (key.startsWith('body:param:')) {
        return `request body parameter "${detail}" (value: "${rawValue}")`;
    }
    if (source.label && rawValue !== '') {
        return `${source.label} (${rawValue})`;
    }
    if (source.label) return source.label;
    if (source.source || source.key) return source.source || source.key;
    return 'Unknown source';
}

const DOM_XSS_SINK_IDS = new Set([
    'dom.inline_event',
    'dom.innerHTML',
    'dom.outerHTML',
    'dom.insertAdjacentHTML',
    'dom.mutation',
    'document.write',
    'nav.iframe.srcdoc'
]);

function purgeHashTaintEntries() {
    const taints = window.__IAST_TAINTED__ || {};
    const meta = window.__IAST_TAINT_META__ || {};
    const graph = window.__IAST_TAINT_GRAPH__ || {};
    Object.keys(taints).forEach(key => {
        if (key === 'hash' || key.startsWith('hash:')) {
            delete taints[key];
            delete meta[key];
            delete graph[key];
        }
    });
}

function createHashSource({ key, label, op, detail, value, type }) {
    return {
        key,
        value,
        meta: {
            type: type || 'hash',
            label: label || key,
            detail: detail || key,
            op: op || 'hash',
            location: window.location.href,
            value,
            taintKind: 'user_input'
        }
    };
}

function createCookieSourceMeta(name, value, overrides = {}) {
    const detail = (name || '').trim() || 'cookie';
    return Object.assign({
        type: 'cookie',
        label: `Cookie "${detail}"`,
        detail,
        sourceKind: 'cookie',
        taintKind: 'user_input',
        op: 'document.cookie',
        location: window.location.href,
        value
    }, overrides);
}

function collectHashSources() {
    let raw = window.location.hash || '';
    if (raw.startsWith('#')) raw = raw.slice(1);
    try {
        raw = decodeURIComponent(raw);
    } catch (_) {
        raw = raw;
    }
    const normalized = (raw || '').trim();
    // Skip trivial hashes like "#" or "#/" to avoid tainting everything with base routes.
    if (!normalized || normalized === '/' || normalized === '#/' || normalized === '#') {
        return [];
    }
    const [routePartRaw, queryPartRaw] = normalized.split('?');
    const sources = [];
    const routePart = (routePartRaw || '').trim();
    if (routePart && routePart !== '/' && routePart !== '#/') {
        sources.push(createHashSource({
            key: 'hash:route',
            label: 'Location hash route',
            op: 'hashRoute',
            detail: routePart,
            value: routePart,
            type: 'hashRoute'
        }));
    }
    if (queryPartRaw && queryPartRaw.trim()) {
        const params = new URLSearchParams(queryPartRaw);
        for (const [name, value] of params.entries()) {
            const trimmedName = (name || '').trim();
            const trimmedVal = (value || '').trim();
            if (!trimmedName || !trimmedVal) continue;
            sources.push(createHashSource({
                key: `hash:param:${trimmedName}`,
                label: `Location hash parameter "${trimmedName}"`,
                op: 'hashParam',
                detail: trimmedName,
                value: trimmedVal,
                type: 'hashQuery'
            }));
        }
    }
    return sources;
}

function isMeaningfulSourceValue(value) {
    if (value == null) return false;
    const trimmed = String(value).trim();
    if (!trimmed) return false;
    if (trimmed.length < 3) return false;
    if (trimmed === '/' || trimmed === '#/' || trimmed === '#') return false;
    return true;
}

function isSourceMatchingValue(sourceValue, sinkValue) {
    if (!isMeaningfulSourceValue(sourceValue)) return false;
    const sinkStr = String(sinkValue || '');
    const sourceStr = String(sourceValue || '');
    if (!sinkStr || !sourceStr) return false;
    return sinkStr.indexOf(sourceStr) !== -1;
}

function resolveUrlRelative(url) {
    if (!url) return null;
    try {
        return new URL(url, window.location.href);
    } catch (_) {
        return null;
    }
}

function isCrossOriginUrl(url) {
    const resolved = resolveUrlRelative(url);
    if (!resolved) return false;
    return resolved.origin !== window.location.origin;
}

function looksLikeInternalRoute(url) {
    if (!url) return false;
    const str = String(url).trim();
    if (!str) return false;
    if (str === '/' || str === '#/' || str === '#') return true;
    if (str.startsWith('#/')) return true;
    if (str.startsWith('/')) return true;
    return false;
}

function shouldReportNavigationSink(targetUrl) {
    if (!targetUrl) return false;
    if (looksLikeInternalRoute(targetUrl)) {
        // Ignore internal SPA routes like /login or #/search to reduce noise.
        return false;
    }
    return isCrossOriginUrl(targetUrl);
}

function looksLikeXssPayload(value) {
    if (value == null) return false;
    const str = String(value);
    const trimmed = str.trim();
    if (!trimmed) return false;
    const lower = trimmed.toLowerCase();
    const hasAngleBrackets = /[<>]/.test(trimmed);
    const hasJsScheme = lower.includes('javascript:');
    const hasOnEvent = lower.includes('onerror') || lower.includes('onload') || lower.includes('onclick') || lower.includes('onmouseover');
    const hasDangerousTags = lower.includes('<script') || lower.includes('<img') || lower.includes('<svg') || lower.includes('<iframe');
    if (hasJsScheme || hasOnEvent || hasDangerousTags) return true;
    if (hasAngleBrackets && (hasOnEvent || hasDangerousTags)) return true;
    return false;
}

function isUserControlledSource(source) {
    if (!source) return false;
    if (source.taintKind === 'user_input') return true;
    const key = (source.key || source.source || '').toLowerCase();
    if (!key) return false;
    if (key.startsWith('hash:param:')) return true;
    if (key === 'hash:route' || key === 'hash') return true;
    if (key.startsWith('query:param:') || key.startsWith('query:')) return true;
    if (key.startsWith('cookie:')) return true;
    if (key.startsWith('body:param:') || key.startsWith('body:')) return true;
    if (key.startsWith('inline:')) return true;
    return false;
}

function isCookieSource(source) {
    if (!source) return false;
    if (source.sourceKind === 'cookie') return true;
    const key = (source.key || source.source || '').toLowerCase();
    if (!key) return false;
    return key.startsWith('cookie:');
}

function shouldReportDomXss(attrName, newValue, taintedSources = []) {
    const sources = Array.isArray(taintedSources) ? taintedSources : [];
    const attr = (attrName || '').toLowerCase();
    if (attr === 'routerlink' || attr === 'routerlinkactive' || attr === 'ng-reflect-router-link') {
        // Router attributes pointing to internal routes are not interesting sinks.
        return false;
    }
    const hasUserInput = sources.some(isUserControlledSource);
    const cookieSources = sources.filter(isCookieSource);
    const hasCookieSources = cookieSources.length > 0;

    if (hasCookieSources && sources.length === cookieSources.length) {
        const cookieHasXssPayload = cookieSources.some(src => looksLikeXssPayload(src?.value ?? src?.raw));
        if (!cookieHasXssPayload) {
            return false;
        }
    }

    if (hasUserInput) {
        if (attr === 'innerhtml' || attr === 'outerhtml' || !attr) {
            return true;
        }
        if (attr === 'href' || attr === 'src' || attr.startsWith('on')) {
            return true;
        }
        return false;
    }
    const valueStr = newValue == null ? '' : String(newValue);
    if ((attr === 'href' || attr === 'src') && !looksLikeXssPayload(valueStr)) {
        return false;
    }
    return looksLikeXssPayload(valueStr);
}

function isSuspiciousExfilUrl(url) {
    if (!url) return false;
    const str = String(url);
    if (isCrossOriginUrl(str)) return true;
    const lower = str.toLowerCase();
    if (lower.includes('callback') || lower.includes('webhook') || lower.includes('tracking') || lower.includes('pixel')) {
        return true;
    }
    if (lower.includes('token=') || lower.includes('session=') || lower.includes('auth=')) {
        return true;
    }
    return false;
}

function shouldSkipSinkByHeuristics(value, info = {}, context = {}, taintedSources = []) {
    const sinkId = info?.sinkId || info?.sink || null;
    if (!sinkId) return false;
    if (DOM_XSS_SINK_IDS.has(sinkId)) {
        const attrName = context.attribute || context.attr || context.attrName || context.eventType || null;
        const sources = Array.isArray(taintedSources) && taintedSources.length ? taintedSources : (context.taintedSources || []);
        if (!shouldReportDomXss(attrName, value, sources)) {
            return true;
        }
    }
    return false;
}

function registerTaintSource(key, value, meta = {}) {
    if (!key) return;
    markTaintActivity();
    updateTaintMetaEntry(key, { taintKind: meta.taintKind });
    window.__IAST_TAINT_GRAPH__[key] = {
        node: {
            key,
            label: meta.label || key,
            type: meta.type || 'source',
            detail: meta.detail || key,
            domPath: meta.domPath || null,
            elementId: meta.elementId || null,
            attribute: meta.attribute || null,
            location: meta.location || window.location.href,
            value,
            op: meta.op || meta.type || 'source',
            stack: meta.stack || captureStackTrace('IAST source'),
            timestamp: Date.now()
        },
        parents: []
    };
}

function registerTaintPropagation(key, value, matchResult, meta = {}) {
    if (!key) return;
    markTaintActivity();
    updateTaintMetaEntry(key, { taintKind: meta.taintKind });
    const parents = Array.isArray(matchResult?.allSources)
        ? matchResult.allSources
            .filter(src => src && src.source)
            .map(src => ({ key: src.source }))
        : [];
    window.__IAST_TAINT_GRAPH__[key] = {
        node: {
            key,
            label: meta.label || key,
            type: meta.type || 'propagation',
            detail: meta.detail || '',
            domPath: meta.domPath || null,
            elementId: meta.elementId || null,
            attribute: meta.attribute || null,
            location: meta.location || window.location.href,
            value,
            op: meta.op || 'propagation',
            stack: meta.stack || captureStackTrace(meta.op || 'propagation'),
            timestamp: Date.now()
        },
        parents
    };
}

function ensureTaintGraphEntry(key, value, meta = {}) {
    if (meta.parentsMatch) {
        registerTaintPropagation(key, value, meta.parentsMatch, meta);
    } else {
        registerTaintSource(key, value, meta);
    }
}

function buildTaintFlowChain(key, depth = 0, visited = new Set()) {
    if (!key || depth > 20 || visited.has(key)) return [];
    visited.add(key);
    const entry = window.__IAST_TAINT_GRAPH__?.[key];
    if (!entry) {
        return [{
            stage: depth === 0 ? 'source' : 'propagation',
            key,
            label: key,
            value: window.__IAST_TAINTED__?.[key] || null
        }];
    }
    const parents = entry.parents && entry.parents.length ? entry.parents : null;
    let parentChain = [];
    if (parents && parents.length) {
        parentChain = buildTaintFlowChain(parents[0].key, depth + 1, visited);
    }
    const node = Object.assign({
        stage: parents && parents.length ? 'propagation' : 'source',
        key: entry.node?.key || key,
        label: entry.node?.label || key,
        detail: entry.node?.detail || '',
        domPath: entry.node?.domPath || null,
        elementId: entry.node?.elementId || null,
        attribute: entry.node?.attribute || null,
        location: entry.node?.location || null,
        value: entry.node?.value || null,
        op: entry.node?.op || null,
        stack: entry.node?.stack || null,
        timestamp: entry.node?.timestamp || Date.now()
    });
    return parentChain.concat([node]);
}

function buildTaintFlow(match, sinkMeta = {}) {
    if (!match) return [];
    const chain = buildTaintFlowChain(match.source) || [];
    const sinkNode = {
        stage: 'sink',
        key: sinkMeta.sinkId || sinkMeta.sink || 'sink',
        label: sinkMeta.sink || sinkMeta.sinkId || 'sink',
        op: sinkMeta.ruleId || sinkMeta.type || 'sink',
        domPath: sinkMeta.domPath || null,
        elementId: sinkMeta.elementId || null,
        attribute: sinkMeta.attribute || null,
        location: sinkMeta.location || window.location.href,
        value: sinkMeta.value || null,
        detail: sinkMeta.detail || null
    };
    return chain.concat([sinkNode]);
}

function buildRuleBinding({ sinkId, ruleId, fallbackType }) {
    const ruleEntry = sinkId ? getIastRuleBySinkId(sinkId) : (ruleId ? getIastRuleByRuleId(ruleId) : null);
    const ruleMeta = ruleEntry?.ruleMeta || {};
    return {
        sink: sinkId || ruleEntry?.sinkId || ruleMeta?.sink || fallbackType || 'iast_sink',
        sinkId: ruleEntry?.sinkId || sinkId || null,
        ruleId: ruleEntry?.ruleId || ruleId || null,
        type: ruleMeta?.message || ruleEntry?.ruleName || ruleMeta?.category || fallbackType || 'iast_sink'
    };
}
// Dynamic monitoring (storage, cookie, window.name, hash)
(function () {
    const taints = window.__IAST_TAINTED__;
    const meta = window.__IAST_TAINT_META__;
    const record = (key, val, options = {}) => {
        if (!val) return;
        const s = String(val);
        const hasAlnum = /[A-Za-z0-9]/.test(s);
        if (!hasAlnum && s !== '/') return;
        taints[key] = s;
        const mergedMeta = Object.assign({}, describeSourceKey(key, s), options);
        const storedMeta = updateTaintMetaEntry(key, { taintKind: mergedMeta.taintKind, sourceKind: mergedMeta.sourceKind });
        const taint = createSource(s, mergedMeta.sourceKind || mergedMeta.type || 'unknown', Object.assign({}, mergedMeta, { sourceId: storedMeta?.sourceId || null }));
        updateTaintMetaEntry(key, { sourceId: taint.sourceId });
        ensureTaintGraphEntry(key, s, Object.assign({}, mergedMeta, { sourceId: taint.sourceId }));
        //console.info('[IAST] Updated source', key, s);
    };
    const refreshHashSources = () => {
        purgeHashTaintEntries();
        const sources = collectHashSources();
        sources.forEach(src => {
            record(src.key, src.value, Object.assign({}, src.meta));
        });
    };
    // Storage wrappers
    const proto = Storage.prototype;
    ['setItem', 'removeItem', 'clear'].forEach(fn => {
        const orig = proto[fn];
        proto[fn] = function (k, v) {
            const area = this === localStorage ? 'localStorage' : 'sessionStorage';
            if (fn === 'setItem') {
                if (!isHookGroupEnabled('hook.storage')) {
                    return orig.apply(this, arguments);
                }
                if (isInternalStorageKey(k)) {
                    return orig.apply(this, arguments);
                }
                if (area === 'localStorage' && !isTokenLikeValue(v)) {
                    return orig.apply(this, arguments);
                }
                const match = matchesTaint(v);
                const elMeta = captureElementMeta(document?.activeElement || null);
                const sinkId = area === 'localStorage' ? 'storage.localStorage.setItem' : 'storage.sessionStorage.setItem';
                const ruleId = area === 'localStorage' ? 'localstorage_token_persist' : 'sessionstorage_token_persist';
                const binding = buildRuleBinding({ sinkId, ruleId, fallbackType: 'storage-token-leak' });
                const dataKind = getTokenDataKind(v);
                const origin = getTokenOrigin(v);
                record(`${area}:${k}`, v, {
                    label: `${area}:${k}`,
                    type: area,
                    op: `${area}.setItem`,
                    domPath: elMeta.domPath,
                    elementId: elMeta.elementId,
                    parentsMatch: match
                });
                const reportObservation = (originValue) => {
                    maybeReportTaintedValue(v, binding, Object.assign({
                        storageKey: k,
                        storageArea: area,
                        value: v,
                        primaryClass: 'observation',
                        sourceRole: 'observed',
                        origin: originValue,
                        detection: {
                            reason: dataKind === 'jwt' ? 'jwt_heuristic' : 'token_heuristic',
                            dataKind,
                            confidence: 80,
                            details: {
                                matchedBy: dataKind === 'jwt' ? 'jwt_structure' : 'token_heuristic',
                                valuePreview: buildSourcePreview(v),
                                length: String(v || '').length
                            }
                        },
                        observedAt: { kind: area === 'localStorage' ? 'storage.localStorage' : 'storage.sessionStorage', key: k },
                        operation: { sinkId, sinkArgs: { key: k, area } }
                    }, elMeta), match);
                };
                if (origin) {
                    reportObservation(origin);
                } else {
                    setTimeout(() => {
                        reportObservation(getTokenOrigin(v));
                    }, IAST_ORIGIN_WAIT_MS);
                }
            }
            if (fn === 'removeItem') delete taints[`${this === localStorage ? 'localStorage' : 'sessionStorage'}:${k}`];
            if (fn === 'clear') Object.keys(taints)
                .filter(x => x.startsWith(this === localStorage ? 'localStorage:' : 'sessionStorage:'))
                .forEach(x => delete taints[x]);
            return orig.apply(this, arguments);
        };
    });
    // window.name
    if (typeof window.__defineSetter__ === 'function') {
        let cur = window.name;
        window.__defineSetter__('name', v => {
            cur = v;
            record('window.name', v, describeSourceKey('window.name', v));
        });
        window.__defineGetter__('name', () => cur);
    }
    // cookie
    const desc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (desc && desc.configurable) {
        Object.defineProperty(Document.prototype, 'cookie', {
            get() { return desc.get.call(document); },
            set(v) {
                if (!isHookGroupEnabled('hook.storage')) {
                    return desc.set.call(document, v);
                }
                const res = desc.set.call(document, v);
                const [p = ""] = v.split(';');
                const [k = "", rawVal = ""] = p.split('=');
                let decoded = '';
                try {
                    decoded = decodeURIComponent(rawVal || '');
                } catch (_) {
                    decoded = rawVal || '';
                }
                if (!isTokenLikeValue(decoded)) {
                    return res;
                }
                const match = matchesTaint(decoded);
                const elMeta = captureElementMeta(document?.activeElement || null);
                const binding = buildRuleBinding({
                    sinkId: 'storage.document.cookie',
                    ruleId: 'cookie_token_persist',
                    fallbackType: 'storage-token-leak'
                });
                const dataKind = getTokenDataKind(decoded);
                const origin = getTokenOrigin(decoded);
                record(`cookie:${k}`, decoded, Object.assign(
                    createCookieSourceMeta(k, decoded, { value: decoded }),
                    {
                        domPath: elMeta.domPath,
                        elementId: elMeta.elementId,
                        parentsMatch: match
                    }
                ));
                const reportObservation = (originValue) => {
                    maybeReportTaintedValue(decoded, binding, Object.assign({
                        cookieName: k,
                        rawCookie: v,
                        value: decoded,
                        primaryClass: 'observation',
                        sourceRole: 'observed',
                        origin: originValue,
                        detection: {
                            reason: dataKind === 'jwt' ? 'jwt_heuristic' : 'token_heuristic',
                            dataKind,
                            confidence: 80,
                            details: {
                                matchedBy: dataKind === 'jwt' ? 'jwt_structure' : 'token_heuristic',
                                valuePreview: buildSourcePreview(decoded),
                                length: String(decoded || '').length
                            }
                        },
                        observedAt: { kind: 'storage.cookie', cookieName: k },
                        operation: { sinkId: 'storage.document.cookie', sinkArgs: { cookieName: k } }
                    }, elMeta), match);
                };
                if (origin) {
                    reportObservation(origin);
                } else {
                    setTimeout(() => {
                        reportObservation(getTokenOrigin(decoded));
                    }, IAST_ORIGIN_WAIT_MS);
                }
                return res;
            },
            configurable: true
        });
    }
    // hashchange
    window.addEventListener('hashchange', () => {
        refreshHashSources();
    });

    // postMessage source
    window.addEventListener('message', (event) => {
        if (!isHookGroupEnabled('hook.postMessage')) return;
        try {
            const data = event?.data;
            if (data && typeof data === 'object') {
                if (data.ptk_iast || data.ptk_ws || data.source === 'ptk-automation') return;
                if (typeof data.channel === 'string' && data.channel.startsWith('ptk_')) return;
            }
            const payload = safeSerializeValue(event?.data);
            if (!payload) return;
            const origin = event?.origin || 'unknown';
            record(`postMessage:${origin}`, payload, {
                type: 'postMessage',
                label: `postMessage from ${origin}`,
                taintKind: 'user_input'
            });
        } catch (_) {
            // ignore postMessage source errors
        }
    });
})();

// Inline source capture: track user input events (input/change)
(function () {
    const isInputElement = (el) =>
        el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement;
    const lastInlineAt = new WeakMap();

    const recordInlineValue = (el) => {
        if (!el || !isInputElement(el)) return;
        const val = el.value;
        if (!val) return;
        if (String(val).length > 2000) return;
        const key = `inline:${el.id || el.name || el.tagName?.toLowerCase() || 'input'}`;
        const value = String(val);
        window.__IAST_TAINTED__[key] = value;
        updateTaintMetaEntry(key, { taintKind: 'user_input', sourceKind: 'inline' });
        const meta = Object.assign({
            type: 'inline',
            sourceKind: 'inline',
            label: `Inline value "${key.slice(7)}"`,
            taintKind: 'user_input'
        }, captureElementMeta(el));
        registerTaintSource(key, value, meta);
    };

    document.addEventListener('input', (event) => {
        if (event && event.isTrusted === false) return;
        const target = event?.target;
        if (!target) return;
        const now = Date.now();
        const last = lastInlineAt.get(target) || 0;
        if (now - last < 300) return;
        lastInlineAt.set(target, now);
        recordInlineValue(target);
    }, true);

    document.addEventListener('change', (event) => {
        recordInlineValue(event?.target);
    }, true);
})();


function matchesTaint(input) {
    if (__IAST_DISABLE_HOOKS__) return null;
    const taints = Object.entries(window.__IAST_TAINTED__ || {}).filter(([, v]) => v);
    if (!taints.length) return null;
    let rawStr = String(input || '');
    try { rawStr = htmlDecode(rawStr); } catch { }
    rawStr = rawStr.toLowerCase();
    if (!/[a-z0-9\/]/i.test(rawStr)) return null;

    // Fast path: skip if no taint token appears in the input
    let hasToken = false;
    for (const [key, val] of taints) {
        if (!val) continue;
        const token = String(val).trim().toLowerCase();
        if (!token) continue;
        if (rawStr.indexOf(token) !== -1) {
            hasToken = true;
            break;
        }
    }
    if (!hasToken) return null;

    const meta = window.__IAST_TAINT_META__ || {};
    const matches = [];

    const kindOf = (key) => {
        if (key.startsWith('query:')) return 'query';
        if (key === 'hash:route') return 'hashRoute';
        if (key.startsWith('hash:param:')) return 'hashQuery';
        if (key === 'referrer') return 'referrer';
        if (key.startsWith('cookie:')) return 'cookie';
        if (key.startsWith('localStorage:')) return 'localStorage';
        if (key.startsWith('sessionStorage:')) return 'sessionStorage';
        if (key === 'window.name') return 'windowName';
        if (key === 'postMessage' || key.startsWith('postMessage:')) return 'postMessage';
        if (key.startsWith('inline:')) return 'inline';
        return 'other';
    };

    const kindPriority = (kind) => {
        switch (kind) {
            case 'query': return 100;
            case 'hashQuery': return 90;
            case 'hashRoute': return 85;
            case 'inline': return 80;
            case 'localStorage': return 70;
            case 'sessionStorage': return 60;
            case 'cookie': return 50;
            case 'referrer': return 40;
            case 'windowName': return 30;
            case 'postMessage': return 30;
            default: return 10;
        }
    };

    const matchTypePriority = (matchType) => {
        switch (matchType) {
            case 'url-eq': return 3;
            case 'exact': return 2;
            case 'token': return 1;
            case 'substring': return 0;
            default: return 0;
        }
    };

    const looksLikeUrl = (s) => /^[a-z][\w+.-]+:\/\//i.test(s);

    for (const [sourceKey, rawVal] of taints) {
        if (!rawVal) continue;
        if (!isMeaningfulSourceValue(rawVal)) continue;
        let tv = String(rawVal).trim().toLowerCase().replace(/^#/, '').replace(/;$/, '');
        if (!tv) continue;

        let rawToMatch = rawStr;
        let tvToMatch = tv;
        let matchType = null;

        if (looksLikeUrl(tv) && looksLikeUrl(rawStr)) {
            try {
                rawToMatch = new URL(rawStr, location.href).href.toLowerCase();
                tvToMatch = new URL(tv, location.href).href.toLowerCase();
                if (rawToMatch === tvToMatch) matchType = 'url-eq';
            } catch (e) {
                rawToMatch = rawStr;
                tvToMatch = tv;
            }
        }

        if (!matchType) {
            if (/^[a-z0-9]+$/i.test(tv)) {
                const esc = tv.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
                const re = new RegExp(`\\b${esc}\\b`, 'i');
                if (re.test(rawToMatch)) matchType = 'exact';
            } else if (isSourceMatchingValue(tvToMatch, rawToMatch)) {
                matchType = 'substring';
            }
        }

        if (!matchType) continue;

        const kind = kindOf(sourceKey);
        const sourceMeta = meta[sourceKey] || {};
        const baseScore = kindPriority(kind) * 100 + matchTypePriority(matchType);
        const lastUpdated = typeof meta[sourceKey]?.lastUpdated === 'number' ? meta[sourceKey].lastUpdated : 0;
        const recencyBoost = lastUpdated ? Math.min(Math.floor(lastUpdated / 1000), 1_000_000) : 0;
        const score = baseScore * 1_000_000 + recencyBoost;

        matches.push({
            source: sourceKey,
            raw: rawVal,
            kind,
            matchType,
            score,
            lastUpdated,
            taintKind: sourceMeta.taintKind || null
        });
    }

    if (!matches.length) return null;
    matches.sort((a, b) => b.score - a.score);
    const primary = matches[0];
    __IAST_MATCH_COUNT__++
    //if (__IAST_MATCH_COUNT__ <= 20) __PTK_IAST_DBG__('taint match', { primary, total: matches.length, raw: input });
    return {
        source: primary.source,
        raw: primary.raw,
        allSources: matches
    };
}

(function flushBufferedFindings() {
    const key = 'ptk_iast_buffer';
    const data = localStorage.getItem(key);
    if (!data) return;
    let arr;
    try { arr = JSON.parse(data); } catch { arr = null; }
    if (Array.isArray(arr)) {
        arr.forEach(msg => {
            try { window.postMessage(msg, '*'); }
            catch (e) {/*ignore*/ }
        });
    }
    localStorage.removeItem(key);
})();


function reportFinding({ type, sink, sinkId = null, ruleId = null, category = null, severity: severityOverride = null, matched, source, sources = null, context = {} }) {
    // Require rule catalog
    if (!IAST_MODULES) {
        //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: skip finding, modules not loaded yet', { sinkId, ruleId });
        requestModulesFromBackground();
        return;
    }
    let ruleEntry = null;
    if (ruleId) {
        ruleEntry = getIastRuleByRuleId(ruleId);
    }
    if (!ruleEntry && sinkId) {
        ruleEntry = getIastRuleBySinkId(sinkId);
    }
    if (!ruleEntry) {
        //__PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: skip finding, rule not found', { sinkId, ruleId });
        requestModulesFromBackground();
        return;
    }

    const loc = window.location.href;
    let trace = '';
    try {
        trace = (new Error(`Sink: ${type}`)).stack;
    } catch (e) { }
    const cleanedTrace = cleanTraceFrames(trace);
    const attackId = window.__PTK_CURRENT_ATTACK_ID__ || null;
    const moduleMeta = ruleEntry.moduleMeta || {};
    const ruleMeta = ruleEntry.ruleMeta || {};
    const resolvedSeverity = resolveIastEffectiveSeverity({
        override: severityOverride,
        moduleMeta,
        ruleMeta
    });
    const resolvedCategory = category || ruleMeta.category || moduleMeta.category || null;
    const description = ruleMeta.description || moduleMeta.description || null;
    const recommendation = ruleMeta.recommendation || moduleMeta.recommendation || null;
    const mergedLinks = mergeLinks(moduleMeta.links, ruleMeta.links);
    const findingMeta = {
        ruleId: ruleEntry.ruleId,
        ruleName: ruleEntry.ruleName,
        moduleId: ruleEntry.moduleId,
        moduleName: ruleEntry.moduleName,
        cwe: ruleMeta.cwe || moduleMeta.cwe || null,
        owasp: ruleMeta.owasp || moduleMeta.owasp || null,
        message: ruleMeta.message || null,
        tags: ruleMeta.tags || [],
        description,
        recommendation,
        links: mergedLinks
    };
    let normalizedSources = Array.isArray(sources) && sources.length ? normalizeTaintedSources(sources, matched) : [];
    const normalizedPrimarySource = (() => {
        if (!source) return null;
        if (typeof source === 'string') {
            return normalizeSourceEntry({ source, raw: matched });
        }
        if (source.__normalizedSource) return source;
        return normalizeSourceEntry(source, source?.source || source?.key || null, source?.raw ?? matched);
    })();
    if (!normalizedSources.length && normalizedPrimarySource) {
        normalizedSources = [normalizedPrimarySource];
    }
    const decoratedSources = normalizedSources.map(entry => Object.assign({}, entry, {
        display: formatSourceForReport(entry),
        sourceValuePreview: buildSourcePreview(entry?.raw ?? entry?.value ?? matched)
    }));
    const formattedSource = normalizedPrimarySource ? formatSourceForReport(normalizedPrimarySource) : 'Unknown source';
    const sourceKey = normalizedPrimarySource?.key || (typeof source === 'string' ? source : null);
    const sourceKind = normalizedPrimarySource?.sourceKind || normalizedPrimarySource?.kind || null;
    const sourceValuePreview = buildSourcePreview(normalizedPrimarySource?.raw ?? matched);
    const primarySource = normalizedPrimarySource || (decoratedSources.length ? decoratedSources[0] : null);
    const secondarySources = decoratedSources.filter(entry => entry !== primarySource).map(entry => ({
        display: entry.display,
        key: entry.key || entry.source || null,
        sourceKind: entry.sourceKind || entry.kind || null,
        score: entry.score || null,
        sourceValuePreview: entry.sourceValuePreview || null
    }));
    const cookieDetails = context.rawCookie ? parseCookieAssignment(context.rawCookie) : null;
    const resolvedNetworkTarget = context?.networkTarget
        || buildNetworkTarget(context?.destUrl || context?.requestUrl || context?.url || null);
    const sinkContext = {
        requestUrl: context.requestUrl || null,
        method: context.method || null,
        headerName: context.headerName || null,
        destUrl: context.destUrl || resolvedNetworkTarget?.url || null,
        destHost: context.destHost || resolvedNetworkTarget?.host || null,
        destOrigin: context.destOrigin || resolvedNetworkTarget?.origin || null,
        isCrossOrigin: typeof context.isCrossOrigin === 'boolean' ? context.isCrossOrigin : (resolvedNetworkTarget?.isCrossOrigin ?? null),
        tagName: context.tagName || context.element?.tagName || null,
        domPath: context.domPath || null,
        attribute: context.attribute || null,
        elementId: context.elementId || null,
        cookieName: context.cookieName || cookieDetails?.name || null,
        cookieAttributes: cookieDetails?.attributes || null,
        storageKey: context.storageKey || null,
        storageArea: context.storageArea || null
    };
    const flowSummary = buildFlowSummary(context.flow);

    const operationMeta = context?.operation || {
        sinkId: sinkId || sink || null,
        sinkArgs: context?.sinkArgs || null
    };
    const observedAt = context?.observedAt || (() => {
        if ((sinkId || '').startsWith('storage.localStorage')) {
            return { kind: 'storage.localStorage', key: context.storageKey || null };
        }
        if ((sinkId || '').startsWith('storage.sessionStorage')) {
            return { kind: 'storage.sessionStorage', key: context.storageKey || null };
        }
        if ((sinkId || '').startsWith('storage.document.cookie')) {
            return { kind: 'storage.cookie', cookieName: context.cookieName || null };
        }
        return null;
    })();
    const detection = context?.detection || null;
    const normalizedDetection = (detection && typeof detection === 'object')
        ? Object.assign({ schemaVersion: IAST_DETECTION_SCHEMA_VERSION }, detection)
        : detection;
    const trust = context?.trust || null;
    const normalizedTrust = (trust && typeof trust === 'object')
        ? Object.assign({ schemaVersion: IAST_TRUST_SCHEMA_VERSION }, trust)
        : trust;
    const suppression = context?.suppression || null;
    const primaryClass = context?.primaryClass || (normalizedDetection ? IAST_PRIMARY_CLASSES.OBSERVATION : IAST_PRIMARY_CLASSES.TAINT_FLOW);
    const sourceRole = context?.sourceRole || (primaryClass === IAST_PRIMARY_CLASSES.OBSERVATION ? IAST_SOURCE_ROLES.OBSERVED : IAST_SOURCE_ROLES.ORIGIN);
    const details = {
        type: type,
        sink,
        sinkId: sinkId || sink || null,
        ruleId: ruleEntry.ruleId,
        ruleName: findingMeta.ruleName,
        moduleId: findingMeta.moduleId,
        moduleName: findingMeta.moduleName,
        matched,
        source: formattedSource,
        sourceKey,
        sourceKind,
        sourceValuePreview,
        sources: decoratedSources,
        primarySource,
        secondarySources,
        schemaVersion: IAST_EVIDENCE_SCHEMA_VERSION,
        primaryClass,
        sourceRole,
        origin: context?.origin || null,
        observedAt,
        operation: operationMeta,
        detection: normalizedDetection,
        trust: normalizedTrust,
        suppression,
        networkTarget: resolvedNetworkTarget || null,
        routing: buildRoutingMeta(),
        category: resolvedCategory,
        severity: resolvedSeverity,
        meta: findingMeta,
        context: enrichContext(context),
        sinkContext,
        flowSummary,
        location: loc,
        trace: cleanedTrace.trace,
        traceSummary: cleanedTrace.traceSummary,
        attackId: attackId,
        timestamp: Date.now(),
        description,
        recommendation,
        links: mergedLinks
    };
    // __PTK_IAST_DBG__('reportFinding', {
    //     sink: sinkId || sink || null,
    //     type,
    //     severity: resolvedSeverity,
    //     category: resolvedCategory,
    //     source: formattedSource,
    //     matched: matched ? String(matched).slice(0, 120) : '',
    //     location: loc
    // });

    // 1) Console output
    // console.groupCollapsed(`%cIAST%c ${type}`,
    //     'color:#d9534f;font-weight:bold', '');
    // console.log('• location:', loc);
    // console.log('• sink:    ', sink);
    // console.log('• source:  ', source);
    // console.log('• matched: ', matched);
    // // log any extra context fields
    // Object.entries(context).forEach(([k, v]) =>
    //     console.log(`• ${k}:       `, v)
    // );
    // console.groupEnd();


    // 2) PostMessage to background (sanitize non-cloneable payloads)
    const sanitized = {};
    Object.entries(details).forEach(([k, v]) => {
        if (v == null) {
            sanitized[k] = v;
        } else if (v instanceof Error) {
            sanitized[k] = v.toString();
        } else if (v instanceof Node) {
            sanitized[k] = v.outerHTML || v.textContent || String(v);
        } else if (typeof v === 'object') {
            try {
                sanitized[k] = structuredClone(v);
            } catch (e) {
                try {
                    sanitized[k] = JSON.parse(JSON.stringify(v));
                } catch (_) {
                    sanitized[k] = String(v);
                }
            }
        } else {
            sanitized[k] = v;
        }
    });
    try {
        withoutHooks(() => {
            const msg = {
                ptk_iast: 'finding_report',
                channel: 'ptk_content_iast2background_iast',
                finding: sanitized
            };
            const key = 'ptk_iast_buffer';
            let buf;
            try {
                buf = JSON.parse(localStorage.getItem(key) || '[]');
            } catch (_) {
                buf = [];
            }
            buf.push(msg);
            localStorage.setItem(key, JSON.stringify(buf));

            window.postMessage(msg, '*');
        })
    } catch (e) {
        console.warn('IAST reportFinding.postMessage failed:', e);
    }
}

function safeSerializeValue(value) {
    if (value == null) return '';
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    try {
        return JSON.stringify(value);
    } catch (_) {
        try {
            return String(value);
        } catch {
            return '';
        }
    }
}

function pruneSanitizedValues() {
    if (IAST_SANITIZED_VALUES.size <= IAST_SANITIZED_MAX) return;
    const now = Date.now();
    for (const [key, entry] of IAST_SANITIZED_VALUES.entries()) {
        if (!entry || now - entry.time > IAST_SANITIZED_TTL_MS) {
            IAST_SANITIZED_VALUES.delete(key);
        }
        if (IAST_SANITIZED_VALUES.size <= IAST_SANITIZED_MAX) break;
    }
}

function recordSanitizedValue(value, sanitizerId) {
    const serialized = safeSerializeValue(value);
    if (!serialized) return;
    const now = Date.now();
    const entry = IAST_SANITIZED_VALUES.get(serialized) || { time: now, sanitizers: new Set() };
    entry.time = now;
    entry.sanitizers.add(sanitizerId);
    IAST_SANITIZED_VALUES.set(serialized, entry);
    pruneSanitizedValues();
}

function getSanitizersForValue(value) {
    const serialized = safeSerializeValue(value);
    if (!serialized) return [];
    const entry = IAST_SANITIZED_VALUES.get(serialized);
    if (!entry) return [];
    if (Date.now() - entry.time > IAST_SANITIZED_TTL_MS) {
        IAST_SANITIZED_VALUES.delete(serialized);
        return [];
    }
    return Array.from(entry.sanitizers || []);
}

function sanitizeSourcesForRule(ruleEntry, sources) {
    const ruleMeta = ruleEntry?.ruleMeta || {};
    const allowed = Array.isArray(ruleEntry.sources)
        ? ruleEntry.sources
        : (Array.isArray(ruleMeta.sources) ? ruleMeta.sources : null);
    if (!allowed || !allowed.length) return sources;
    return sources.filter(src => {
        const kind = src?.sourceKind || src?.type || '';
        return kind && allowed.includes(kind);
    });
}

function shouldSuppressForSanitizer(ruleEntry, value) {
    const ruleMeta = ruleEntry?.ruleMeta || {};
    const allowed = Array.isArray(ruleEntry.sanitizersAllowed)
        ? ruleEntry.sanitizersAllowed
        : (Array.isArray(ruleMeta.sanitizersAllowed) ? ruleMeta.sanitizersAllowed : []);
    if (!allowed.length) return { suppress: false, observed: [] };
    const observed = getSanitizersForValue(value).filter(id => allowed.includes(id));
    if (!observed.length) return { suppress: false, observed: [] };
    const onSanitized = ruleEntry.onSanitized || ruleMeta.onSanitized || 'lower_confidence';
    return { suppress: onSanitized === 'suppress', observed };
}

function buildSourcePreview(value) {
    const str = safeSerializeValue(value);
    if (!str) return '';
    if (str.length <= 80) return str;
    return `${str.slice(0, 77)}...`;
}

function formatFlowNodeLabel(node) {
    if (!node) return '';
    let label = node.label || node.key || '';
    if (node.elementId) {
        label += `#${node.elementId}`;
    }
    if (node.attribute) {
        label += `.${node.attribute}`;
    }
    return label || '';
}

function buildFlowSummary(flow) {
    if (!Array.isArray(flow) || !flow.length) return null;
    const parts = flow.map(node => formatFlowNodeLabel(node)).filter(Boolean);
    if (!parts.length) return null;
    return parts.join(' -> ');
}

function cleanTraceFrames(trace) {
    if (!trace) return { trace: '', traceSummary: null };
    const lines = String(trace).split('\n');
    const frames = lines.slice(1).map(line => line.trim()).filter(Boolean);
    const filtered = frames.filter(line => {
        if (line.includes('chrome-extension://') || line.includes('moz-extension://')) return false;
        if (line.includes('ptk/content/iast.js')) return false;
        return true;
    });
    const trimmed = filtered.slice(0, 5);
    return {
        trace: trimmed.length ? [lines[0], ...trimmed].join('\n') : lines[0] || '',
        traceSummary: trimmed[0] || null
    };
}

function parseCookieAssignment(rawCookie) {
    if (!rawCookie) return null;
    const parts = String(rawCookie).split(';').map(part => part.trim()).filter(Boolean);
    if (!parts.length) return null;
    const [nameValue, ...attrs] = parts;
    const eqIndex = nameValue.indexOf('=');
    const name = eqIndex >= 0 ? nameValue.slice(0, eqIndex).trim() : nameValue.trim();
    const attributes = {};
    attrs.forEach(attr => {
        if (!attr) return;
        const [k, ...rest] = attr.split('=');
        const key = String(k || '').trim().toLowerCase();
        if (!key) return;
        const value = rest.length ? rest.join('=').trim() : true;
        attributes[key] = value;
    });
    return {
        name: name || null,
        attributes: Object.keys(attributes).length ? attributes : null
    };
}

function pruneFindingCache(cache) {
    if (cache.size <= IAST_FINDING_DEDUP_MAX) return;
    const now = Date.now();
    for (const [key, ts] of cache.entries()) {
        if (now - ts > IAST_SMART_DEDUP_TTL_MS) {
            cache.delete(key);
        }
        if (cache.size <= IAST_FINDING_DEDUP_MAX) break;
    }
}

function isCacheHit(cache, key) {
    const ts = cache.get(key);
    if (!ts) return false;
    if (Date.now() - ts > IAST_SMART_DEDUP_TTL_MS) {
        cache.delete(key);
        return false;
    }
    return true;
}

function markCache(cache, key) {
    cache.set(key, Date.now());
    pruneFindingCache(cache);
}

function buildFindingDedupKey({ ruleId, sinkId, sourceKey, location, elementId, attribute }) {
    return [
        ruleId || '',
        sinkId || '',
        sourceKey || '',
        location || '',
        elementId || '',
        attribute || ''
    ].join('|');
}

function isCrossOriginRequest(requestUrl) {
    if (!requestUrl) return false;
    try {
        const target = new URL(requestUrl, window.location.href);
        return target.origin !== window.location.origin;
    } catch (_) {
        return false;
    }
}

function resolveAbsoluteUrl(rawUrl, baseUrl = window.location.href) {
    if (!rawUrl) return null;
    try {
        return new URL(rawUrl, baseUrl).href;
    } catch (_) {
        return null;
    }
}

function buildNetworkTarget(rawUrl) {
    const resolved = resolveAbsoluteUrl(rawUrl);
    if (!resolved) return null;
    try {
        const parsed = new URL(resolved);
        const scheme = parsed.protocol ? parsed.protocol.replace(':', '') : null;
        return {
            url: resolved,
            host: parsed.host || null,
            origin: parsed.origin || null,
            scheme,
            isCrossOrigin: parsed.origin !== window.location.origin
        };
    } catch (_) {
        return null;
    }
}

function buildNetworkContext(rawUrl) {
    const target = buildNetworkTarget(rawUrl);
    if (!target) return null;
    return {
        networkTarget: target,
        destUrl: target.url,
        destHost: target.host,
        destOrigin: target.origin,
        isCrossOrigin: target.isCrossOrigin,
        scheme: target.scheme
    };
}

function buildSinkArgs(context = {}) {
    const args = {};
    if (context.headerName) args.headerName = context.headerName;
    if (context.requestUrl) args.requestUrl = context.requestUrl;
    if (context.method) args.method = context.method;
    if (context.url) args.url = context.url;
    if (context.destUrl) args.destUrl = context.destUrl;
    if (context.destOrigin) args.destOrigin = context.destOrigin;
    if (context.destHost) args.destHost = context.destHost;
    if (typeof context.isCrossOrigin === 'boolean') args.isCrossOrigin = context.isCrossOrigin;
    if (context.scheme) args.scheme = context.scheme;
    if (context.storageKey) args.storageKey = context.storageKey;
    if (context.storageArea) args.storageArea = context.storageArea;
    if (context.cookieName) args.cookieName = context.cookieName;
    if (context.key) args.key = context.key;
    return Object.keys(args).length ? args : null;
}

function isAuthHeaderName(name) {
    if (!name) return false;
    const lower = String(name).trim().toLowerCase();
    if (!lower) return false;
    if (lower === 'authorization' || lower === 'proxy-authorization') return true;
    if (lower === 'x-api-key' || lower === 'x-auth-token' || lower === 'x-access-token') return true;
    if (lower === 'x-csrf-token' || lower === 'x-xsrf-token') return true;
    return false;
}

function isCookieHeaderName(name) {
    if (!name) return false;
    const lower = String(name).trim().toLowerCase();
    return lower === 'cookie' || lower === 'set-cookie';
}

function getAuthHeaderAllowlist() {
    const fallback = ['authorization', 'proxy-authorization', 'x-api-key', 'x-auth-token', 'x-access-token', 'x-csrf-token', 'x-xsrf-token'];
    const override = Array.isArray(window?.__PTK_IAST_AUTH_HEADERS__)
        ? window.__PTK_IAST_AUTH_HEADERS__.map(v => String(v).toLowerCase().trim()).filter(Boolean)
        : null;
    return override && override.length ? override : fallback;
}

function isExpectedAuthHeader(name) {
    if (!name) return false;
    const lower = String(name).trim().toLowerCase();
    return getAuthHeaderAllowlist().includes(lower);
}

function isLikelyNonApiPath(destUrl) {
    if (!destUrl) return false;
    try {
        const parsed = new URL(destUrl, window.location.href);
        const path = parsed.pathname.toLowerCase();
        const extMatch = path.match(/\.([a-z0-9]+)$/);
        if (!extMatch) return false;
        const ext = extMatch[1];
        return ['css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'woff', 'woff2', 'ttf', 'eot', 'map', 'json'].includes(ext);
    } catch (_) {
        return false;
    }
}

function isSameHostTarget(target) {
    if (!target || !target.host) return false;
    return target.host === window.location.host;
}

function shouldDowngradeSameHostExfil(sinkId) {
    if (!sinkId) return false;
    return [
        'http.xhr.open',
        'http.xhr.send',
        'http.fetch.url',
        'http.fetch.headers',
        'http.navigator.sendBeacon',
        'http.image.src'
    ].includes(sinkId);
}

function isStorageObservationRisky(context, sinkId) {
    if (!sinkId) return false;
    if (sinkId.startsWith('storage.localStorage')) return true;
    if (sinkId.startsWith('storage.sessionStorage')) return false;
    if (sinkId === 'storage.document.cookie') {
        const details = context?.rawCookie ? parseCookieAssignment(context.rawCookie) : null;
        const attrs = details?.attributes || {};
        const hasSecure = Object.prototype.hasOwnProperty.call(attrs, 'secure');
        const hasSameSite = Object.prototype.hasOwnProperty.call(attrs, 'samesite');
        return !(hasSecure && hasSameSite);
    }
    return false;
}

function getIastSuppressionConfig() {
    if (window?.__PTK_IAST_SUPPRESSIONS__ && typeof window.__PTK_IAST_SUPPRESSIONS__ === 'object') {
        return window.__PTK_IAST_SUPPRESSIONS__;
    }
    try {
        const raw = localStorage.getItem('ptk_iast_suppressions');
        if (!raw) return null;
        const parsed = JSON.parse(raw);
        return parsed && typeof parsed === 'object' ? parsed : null;
    } catch (_) {
        return null;
    }
}

function evaluateIastSuppression({ ruleId, sinkId, context, detection }) {
    const config = getIastSuppressionConfig();
    const rules = Array.isArray(config?.rules) ? config.rules : [];
    if (!rules.length) return null;
    const destOrigin = context?.destOrigin || context?.networkTarget?.origin || null;
    const destUrl = context?.destUrl || context?.networkTarget?.url || context?.requestUrl || null;
    const headerName = context?.headerName ? String(context.headerName).toLowerCase() : null;
    const storageKey = context?.storageKey || context?.key || null;
    const reasonCode = detection?.reason || null;
    for (const rule of rules) {
        if (!rule || typeof rule !== 'object') continue;
        if (rule.ruleId && rule.ruleId !== ruleId) continue;
        if (rule.sinkId && rule.sinkId !== sinkId) continue;
        if (rule.destOrigin && destOrigin && rule.destOrigin !== destOrigin) continue;
        if (rule.headerName && headerName && String(rule.headerName).toLowerCase() !== headerName) continue;
        if (rule.storageKey && storageKey && String(rule.storageKey) !== String(storageKey)) continue;
        if (rule.reasonCode && reasonCode && String(rule.reasonCode) !== String(reasonCode)) continue;
        if (rule.pathPattern && destUrl) {
            try {
                const re = new RegExp(rule.pathPattern);
                if (!re.test(destUrl)) continue;
            } catch (_) {
                continue;
            }
        }
        return {
            suppressed: true,
            rule: rule.ruleId || null,
            sinkId: sinkId || null,
            reason: rule.reasonCode || null
        };
    }
    return null;
}

function buildNetworkDedupKey({ sinkId, headerName, destOrigin, location }) {
    if (!sinkId || !headerName || !destOrigin || !location) return null;
    return [
        'net',
        sinkId,
        String(headerName).toLowerCase(),
        destOrigin,
        location
    ].join('|');
}

function isHighFrequencyAuthHeader({ sinkId, headerName, destOrigin, location }) {
    if (!sinkId || !headerName || !destOrigin || !location) return false;
    const now = Date.now();
    const key = [sinkId, String(headerName).toLowerCase(), destOrigin, location].join('|');
    const entry = IAST_NETWORK_HEADER_TRACKER.get(key);
    if (!entry || now - entry.since > IAST_NETWORK_HEADER_WINDOW_MS) {
        IAST_NETWORK_HEADER_TRACKER.set(key, { since: now, count: 1 });
        return false;
    }
    entry.count += 1;
    if (now - entry.since > IAST_NETWORK_HEADER_WINDOW_MS) {
        entry.since = now;
        entry.count = 1;
        return false;
    }
    if (entry.count >= IAST_NETWORK_HEADER_FREQUENCY_MAX) {
        IAST_NETWORK_HEADER_TRACKER.set(key, { since: now, count: 1 });
        return true;
    }
    return false;
}

function maybeReportTaintedValue(value, info = {}, contextExtras = {}, matchOverride = null) {
    if (__IAST_DISABLE_HOOKS__) return false;
    const context = Object.assign({ value }, contextExtras);
    const match = matchOverride || matchesTaint(value);
    const taintEntry = getTaintEntry(value);
    const taintedSources = match ? normalizeTaintedSources(match.allSources, match.raw) : [];
    if (shouldSkipSinkByHeuristics(value, info, context, taintedSources)) return false;
    if (!match && !taintEntry) return false;
    if (typeof context.element === 'undefined') {
        context.element = document?.activeElement || null;
    }
    const location = window.location.href;
    if (!context.location) {
        context.location = location;
    }
    const sinkMeta = {
        sinkId: info.sinkId || info.sink || null,
        sink: info.sink || info.sinkId || null,
        ruleId: info.ruleId || null,
        domPath: context.domPath || (context.element ? getDomPath(context.element) : null),
        elementId: context.elementId || (context.element && context.element.id ? context.element.id : null),
        attribute: context.attribute || null,
        location,
        value
    };
    const flow = buildTaintFlow(match, sinkMeta);
    if (flow.length) {
        context.flow = flow;
    }
    const sinkId = info.sinkId || info.sink || null;
    const candidates = sinkId
        ? getIastRulesBySinkId(sinkId)
        : (info.ruleId ? [getIastRuleByRuleId(info.ruleId)].filter(Boolean) : []);
    if (!candidates.length) return false;
    const sinkArgs = buildSinkArgs(context);
    const sourceRefsFromSubstring = (sources) => sources.map(src => ({
        sourceId: src?.sourceId || null,
        taintId: src?.taintId || null,
        sourceKind: src?.sourceKind || null,
        taintKind: src?.taintKind || null,
        label: src?.label || null,
        matchType: 'substring',
        confidence: 60
    }));
    const sourceRefsFromTaint = (taintInfo) => [{
        sourceId: taintInfo?.sourceId || null,
        taintId: taintInfo?.taintId || null,
        sourceKind: taintInfo?.sourceKind || null,
        taintKind: taintInfo?.taintKind || null,
        label: taintInfo?.label || null,
        matchType: taintEntry?.matchType || 'id',
        confidence: taintEntry?.matchType === 'id' ? 95 : 80
    }];
    const isSmart = isSmartScanStrategy();
    const sinkPageKey = sinkId && location ? `${sinkId}|${location}` : null;
    if (isSmart && sinkPageKey && isCacheHit(IAST_SINK_SEEN, sinkPageKey)) {
        return false;
    }
    const networkDedupKey = buildNetworkDedupKey({
        sinkId,
        headerName: context.headerName || null,
        destOrigin: context.destOrigin || context?.networkTarget?.origin || null,
        location
    });
    if (isSmart && networkDedupKey && isCacheHit(IAST_FINDING_DEDUP, networkDedupKey)) {
        return false;
    }
    let reported = false;
    for (const ruleEntry of candidates) {
        const conditions = ruleEntry.conditions || {};
        if (conditions.requiresCrossOrigin) {
            const reqUrl = context.requestUrl || context.url || null;
            if (!isCrossOriginRequest(reqUrl)) {
                continue;
            }
        }
        const filteredSources = sanitizeSourcesForRule(ruleEntry, taintedSources);
        if (!filteredSources.length) continue;
        const sanitizerCheck = shouldSuppressForSanitizer(ruleEntry, value);
        if (sanitizerCheck.suppress) continue;
        const primarySource = filteredSources.length
            ? filteredSources[0]
            : (match.source ? normalizeSourceEntry({ source: match.source, raw: match.raw }) : null);
        const sourceKey = primarySource?.key || null;
        if (isSmart) {
            const dedupKey = buildFindingDedupKey({
                ruleId: ruleEntry.ruleId,
                sinkId,
                sourceKey,
                location,
                elementId: context.elementId || null,
                attribute: context.attribute || null
            });
            if (isCacheHit(IAST_FINDING_DEDUP, dedupKey)) {
                continue;
            }
        }
        const nextContext = Object.assign({}, context, {
            taintedSources: filteredSources,
            sinkArgs
        });
        const matchInfo = taintEntry
            ? { matchType: taintEntry.matchType || 'id', confidence: taintEntry.matchType === 'id' ? 95 : 80 }
            : { matchType: 'substring', confidence: 60 };
        nextContext.match = matchInfo;
        nextContext.sourceRefs = taintEntry
            ? sourceRefsFromTaint(taintEntry.taint)
            : sourceRefsFromSubstring(filteredSources);
        if (sanitizerCheck.observed.length) {
            nextContext.sanitizerObserved = sanitizerCheck.observed;
            nextContext.confidencePenalty = 25;
        }
        if (sinkId && (sinkId === 'http.xhr.setRequestHeader' || sinkId === 'http.fetch.headers')) {
            const target = nextContext?.networkTarget
                || buildNetworkTarget(nextContext.destUrl || nextContext.requestUrl || null)
                || (nextContext.destOrigin ? { origin: nextContext.destOrigin, isCrossOrigin: nextContext.isCrossOrigin } : null);
            const isSameOrigin = target && target.origin === window.location.origin && target.isCrossOrigin === false;
            const headerName = nextContext.headerName || null;
            if (isSameOrigin && headerName) {
                const hasKnownOrigin = Boolean(nextContext.origin) || nextContext.sourceRole === IAST_SOURCE_ROLES.ORIGIN;
                if (isCookieHeaderName(headerName)) {
                    nextContext.primaryClass = IAST_PRIMARY_CLASSES.OBSERVATION;
                    if (!hasKnownOrigin && !nextContext.sourceRole) {
                        nextContext.sourceRole = IAST_SOURCE_ROLES.OBSERVED;
                    }
                    nextContext.severityOverride = 'low';
                    nextContext.detection = Object.assign({}, nextContext.detection || {}, {
                        reason: IAST_REASON_CODES.COOKIE_HEADER_ATTEMPT,
                        dataKind: nextContext.detection?.dataKind || IAST_DATA_KINDS.TOKEN,
                        confidence: nextContext.detection?.confidence || 55
                    });
                } else if (isExpectedAuthHeader(headerName)) {
                    const destUrl = nextContext.destUrl || nextContext?.networkTarget?.url || nextContext.requestUrl || null;
                    const riskySameOrigin = isLikelyNonApiPath(destUrl) || isHighFrequencyAuthHeader({
                        sinkId,
                        headerName,
                        destOrigin: target.origin || nextContext.destOrigin || null,
                        location
                    });
                    nextContext.primaryClass = IAST_PRIMARY_CLASSES.OBSERVATION;
                    if (!hasKnownOrigin && !nextContext.sourceRole) {
                        nextContext.sourceRole = IAST_SOURCE_ROLES.OBSERVED;
                    }
                    nextContext.severityOverride = riskySameOrigin ? 'low' : 'info';
                    nextContext.detection = Object.assign({}, nextContext.detection || {}, {
                        reason: riskySameOrigin ? IAST_REASON_CODES.AUTH_HEADER_SAME_ORIGIN_RISKY : IAST_REASON_CODES.AUTH_HEADER_SAME_ORIGIN,
                        dataKind: nextContext.detection?.dataKind || IAST_DATA_KINDS.TOKEN,
                        confidence: nextContext.detection?.confidence || 60
                    });
                    nextContext.trust = Object.assign({}, nextContext.trust || {}, {
                        level: IAST_TRUST_LEVELS.SAME_ORIGIN,
                        decision: IAST_TRUST_DECISIONS.ALLOW
                    });
                }
            }
        }
        if (sinkId === 'realtime.websocket.send') {
            const target = nextContext?.networkTarget
                || buildNetworkTarget(nextContext.destUrl || nextContext.requestUrl || nextContext.url || null);
            if (target && isSameHostTarget(target)) {
                const hasKnownOrigin = Boolean(nextContext.origin) || nextContext.sourceRole === IAST_SOURCE_ROLES.ORIGIN;
                nextContext.primaryClass = IAST_PRIMARY_CLASSES.OBSERVATION;
                if (!hasKnownOrigin && !nextContext.sourceRole) {
                    nextContext.sourceRole = IAST_SOURCE_ROLES.OBSERVED;
                }
                nextContext.severityOverride = 'info';
                nextContext.detection = Object.assign({}, nextContext.detection || {}, {
                    reason: IAST_REASON_CODES.WEBSOCKET_SAME_HOST,
                    dataKind: nextContext.detection?.dataKind || IAST_DATA_KINDS.UNKNOWN,
                    confidence: nextContext.detection?.confidence || 50
                });
                nextContext.trust = Object.assign({}, nextContext.trust || {}, {
                    level: IAST_TRUST_LEVELS.SAME_ORIGIN,
                    decision: IAST_TRUST_DECISIONS.ALLOW
                });
            }
        }
        if (shouldDowngradeSameHostExfil(sinkId)) {
            const target = nextContext?.networkTarget
                || buildNetworkTarget(nextContext.destUrl || nextContext.requestUrl || nextContext.url || null);
            if (target && isSameHostTarget(target)) {
                const hasKnownOrigin = Boolean(nextContext.origin) || nextContext.sourceRole === IAST_SOURCE_ROLES.ORIGIN;
                nextContext.primaryClass = IAST_PRIMARY_CLASSES.OBSERVATION;
                if (!hasKnownOrigin && !nextContext.sourceRole) {
                    nextContext.sourceRole = IAST_SOURCE_ROLES.OBSERVED;
                }
                nextContext.severityOverride = 'info';
                nextContext.detection = Object.assign({}, nextContext.detection || {}, {
                    reason: IAST_REASON_CODES.SAME_HOST_EXFIL,
                    dataKind: nextContext.detection?.dataKind || IAST_DATA_KINDS.UNKNOWN,
                    confidence: nextContext.detection?.confidence || 50
                });
                nextContext.trust = Object.assign({}, nextContext.trust || {}, {
                    level: IAST_TRUST_LEVELS.SAME_ORIGIN,
                    decision: IAST_TRUST_DECISIONS.ALLOW
                });
            }
        }
        if ((nextContext.primaryClass === IAST_PRIMARY_CLASSES.OBSERVATION)
            && (sinkId && sinkId.startsWith('storage.'))
            && !nextContext.severityOverride) {
            nextContext.severityOverride = isStorageObservationRisky(nextContext, sinkId) ? 'low' : 'info';
        }
        const suppressionMatch = evaluateIastSuppression({
            ruleId: ruleEntry.ruleId,
            sinkId,
            context: nextContext,
            detection: nextContext.detection
        });
        if (suppressionMatch) {
            nextContext.suppression = suppressionMatch;
        }
        reportFinding({
            type: info.type || ruleEntry.ruleId || info.sinkId || 'iast_sink',
            sink: info.sink || sinkId || 'iast_sink',
            sinkId,
            ruleId: ruleEntry.ruleId,
            matched: match.raw,
            source: primarySource || match.source,
            sources: filteredSources,
            severity: nextContext.severityOverride || info.severity || null,
            context: nextContext
        });
        reported = true;
        if (isSmart) {
            if (sinkPageKey) {
                markCache(IAST_SINK_SEEN, sinkPageKey);
            }
            const dedupKey = buildFindingDedupKey({
                ruleId: ruleEntry.ruleId,
                sinkId,
                sourceKey,
                location,
                elementId: context.elementId || null,
                attribute: context.attribute || null
            });
            markCache(IAST_FINDING_DEDUP, dedupKey);
            if (networkDedupKey) {
                markCache(IAST_FINDING_DEDUP, networkDedupKey);
            }
            break;
        }
    }
    return reported;
}


// Inline-event scanner helper
function scanInlineEvents(htmlFragment) {
    let m;
    try {
        const doc = new DOMParser().parseFromString(htmlFragment, 'text/html');
        doc.querySelectorAll('*').forEach(el => {
            Array.from(el.attributes).forEach(attr => {
                const name = attr.name.toLowerCase();
                if (!name.startsWith('on')) return;
                const val = attr.value;
                m = matchesTaint(val);
                if (!m) return;

                maybeReportTaintedValue(val, {
                    type: 'dom-inline-event-handler',
                    sink: name,
                    sinkId: 'dom.inline_event',
                    ruleId: 'dom_inline_event_handler'
                }, {
                    element: el,
                    tag: el.tagName,
                    attribute: name,
                    eventType: name,
                    value: val
                }, m);
            });
        });
    } catch (e) {
        console.warn('[IAST] inline-event scan error', e);
    }
}


// Eval & Function hooks
; (function () {
    const originalEval = window.eval;
    window.eval = function (code) {
        if (!isHookGroupEnabled('hook.code.exec')) {
            return originalEval.call(this, code);
        }
        const m = matchesTaint(code);
        if (m) {
            maybeReportTaintedValue(code, {
                type: 'xss-via-eval',
                sink: 'eval',
                sinkId: 'code.eval',
                ruleId: 'eval_js_execution'
            }, {
                element: document?.activeElement || null,
                code: code
            }, m);
        }
        return originalEval.call(this, code);
    };
})();

; (function () {
    const OriginalFunction = window.Function;
    window.Function = new Proxy(OriginalFunction, {
        construct(target, args, newTarget) {
            if (!isHookGroupEnabled('hook.code.exec')) {
                return Reflect.construct(target, args, newTarget);
            }
            const body = args.slice(-1)[0] + '';
            const m = matchesTaint(body);
            if (m) {
                maybeReportTaintedValue(body, {
                    type: 'xss-via-Function',
                    sink: 'Function.constructor',
                    sinkId: 'code.function.constructor',
                    ruleId: 'function_constructor_execution'
                }, {
                    element: document?.activeElement || null,
                    code: body
                }, m);
            }
            return Reflect.construct(target, args, newTarget);
        },
        apply(target, thisArg, args) {
            if (!isHookGroupEnabled('hook.code.exec')) {
                return Reflect.apply(target, thisArg, args);
            }
            const body = args.slice(-1)[0] + '';
            const m = matchesTaint(body);
            if (m) {
                maybeReportTaintedValue(body, {
                    type: 'xss-via-Function',
                    sink: 'Function.apply',
                    sinkId: 'code.function.apply',
                    ruleId: 'function_apply_execution'
                }, { element: document?.activeElement || null, code: body }, m);
            }
            return Reflect.apply(target, thisArg, args);
        }
    });
})();

// JSON.parse sink
; (function () {
    const origParse = JSON.parse;
    JSON.parse = function (input, ...rest) {
        if (!isHookGroupEnabled('hook.client.json')) {
            return origParse.call(this, input, ...rest);
        }
        const m = matchesTaint(input);
        if (m) {
            const binding = buildRuleBinding({ sinkId: 'client.json.parse', fallbackType: 'json-parse' });
            maybeReportTaintedValue(input, binding, { value: input }, m);
        }
        return origParse.call(this, input, ...rest);
    };
})();

// document.domain manipulation sink
; (function () {
    if (typeof Document === 'undefined' || !Document.prototype) return;
    const desc = Object.getOwnPropertyDescriptor(Document.prototype, 'domain');
    if (desc && desc.set) {
        Object.defineProperty(Document.prototype, 'domain', {
            configurable: true,
            enumerable: desc.enumerable,
            get: desc.get,
            set(value) {
                if (!isHookGroupEnabled('hook.dom.attributes')) {
                    return desc.set.call(this, value);
                }
                const m = matchesTaint(value);
                if (m) {
                    const binding = buildRuleBinding({ sinkId: 'document.domain', fallbackType: 'document-domain' });
                    maybeReportTaintedValue(value, binding, { value }, m);
                }
                return desc.set.call(this, value);
            }
        });
    }
})();


// document.write
; (function () {
    const origWrite = document.write;

    document.write = function (...args) {
        if (!isHookGroupEnabled('hook.dom.htmlStrings')) {
            return origWrite.apply(document, args);
        }
        if (!allowHeavyHook()) {
            const html = args.join('');
            const m = matchesTaint(html);
            if (m) {
                maybeReportTaintedValue(html, {
                    type: 'xss-via-document.write',
                    sink: 'document.write',
                    sinkId: 'document.write',
                    ruleId: 'document_write_xss'
                }, { value: html, element: document?.activeElement || null }, m);
            }
            return origWrite.apply(document, args);
        }
        const html = args.join('');
        let fragment;
        try {
            // Parse the HTML into a DocumentFragment
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            fragment = doc.body;
            // Traverse and report any taint in attributes or text nodes
            traverseAndReport(fragment, 'document.write');
        } catch (e) {
            // Fallback to the old behavior if parsing fails
            const m = matchesTaint(html);
            if (m) {
                maybeReportTaintedValue(html, {
                    type: 'xss-via-document.write',
                    sink: 'document.write',
                    sinkId: 'document.write',
                    ruleId: 'document_write_xss'
                }, { value: html, element: document?.activeElement || null }, m);
                scanInlineEvents(html);
            }
        }
        return origWrite.apply(document, args);
    };

    // Helper: walk a DOM subtree and report the first taint per node
    function traverseAndReport(root, sink) {
        const seen = new Set();  // avoid duplicates
        postOrderTraverse(root, node => {
            if (node.nodeType === Node.TEXT_NODE) {
                const txt = node.textContent;
                const m = matchesTaint(txt);
                if (m && !seen.has(node)) {
                    maybeReportTaintedValue(txt, {
                        type: 'xss-via-document.write',
                        sink: 'document.write',
                        sinkId: 'document.write',
                        ruleId: 'document_write_xss'
                    }, { value: html, element: document?.activeElement || null }, m);
                    seen.add(node);
                }
            } else if (node.nodeType === Node.ELEMENT_NODE) {
                // check each attribute
                for (const { name, value } of Array.from(node.attributes)) {
                    const m = matchesTaint(value);
                    if (m && !seen.has(node)) {
                        maybeReportTaintedValue(value, {
                            type: 'xss-via-document.write',
                            sink: 'document.write',
                            sinkId: 'document.write',
                            ruleId: 'document_write_xss'
                        }, { value: html, element: document?.activeElement || null }, m);
                        seen.add(node);
                        break;
                    }
                }
                // inline‐event handlers
                scanInlineEvents(node.outerHTML);
            }
        });
    }

    // reuse your existing postOrderTraverse
    function postOrderTraverse(node, fn) {
        node.childNodes.forEach(c => postOrderTraverse(c, fn));
        fn(node);
    }
})();

// innerHTML/outerHTML
['innerHTML', 'outerHTML'].forEach(prop => {
    const desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
    Object.defineProperty(Element.prototype, prop, {
        get: desc.get,
        set(htmlString) {
            if (__IAST_DISABLE_HOOKS__ || !isHookGroupEnabled('hook.dom.htmlStrings')) {
                return desc.set.call(this, htmlString);
            }
            if (!allowHeavyHook()) {
                const m = matchesTaint(htmlString);
                if (m) {
                    maybeReportTaintedValue(htmlString, {
                        type: `xss-via-${prop}`,
                        sink: prop,
                        sinkId: prop === 'innerHTML' ? 'dom.innerHTML' : 'dom.outerHTML',
                        ruleId: prop === 'innerHTML' ? 'dom_innerhtml_xss' : 'dom_outerhtml_xss'
                    }, { value: htmlString, element: this, domPath: getDomPath(this) }, m);
                }
                return desc.set.call(this, htmlString);
            }
            try {
                const frag = document.createRange().createContextualFragment(htmlString);
                traverseAndReport(frag, `xss-via-${prop}`);
            } catch {
                const m = matchesTaint(htmlString);
                if (m) {
                    maybeReportTaintedValue(htmlString, {
                        type: `xss-via-${prop}`,
                        sink: prop,
                        sinkId: prop === 'innerHTML' ? 'dom.innerHTML' : 'dom.outerHTML',
                        ruleId: prop === 'innerHTML' ? 'dom_innerhtml_xss' : 'dom_outerhtml_xss'
                    }, { value: htmlString, element: this, domPath: getDomPath(this) }, m);
                    scanInlineEvents(htmlString);
                }
            }
            return desc.set.call(this, htmlString);
        },
        configurable: true,
        enumerable: desc.enumerable
    });
});


// insertAdjacentHTML
; (function () {
    const origInsert = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (pos, htmlString) {
        if (__IAST_DISABLE_HOOKS__ || !isHookGroupEnabled('hook.dom.htmlStrings')) {
            return origInsert.call(this, pos, htmlString);
        }
        if (!allowHeavyHook()) {
            const m = matchesTaint(htmlString);
            if (m) {
                maybeReportTaintedValue(htmlString, {
                    type: 'xss-via-insertAdjacentHTML',
                    sink: 'insertAdjacentHTML',
                    sinkId: 'dom.insertAdjacentHTML',
                    ruleId: 'dom_insertadjacenthtml_xss'
                }, { value: htmlString, element: this, position: pos }, m);
            }
            return origInsert.call(this, pos, htmlString);
        }
        try {
            // parse HTML to a fragment for precise matching
            const frag = document.createRange().createContextualFragment(htmlString);
            traverseAndReport(frag, `insertAdjacentHTML(${pos})`);
        } catch {
            // fallback to simple match
            const m = matchesTaint(htmlString);
            if (m) {
                maybeReportTaintedValue(htmlString, {
                    type: 'xss-via-insertAdjacentHTML',
                    sink: 'insertAdjacentHTML',
                    sinkId: 'dom.insertAdjacentHTML',
                    ruleId: 'dom_insertadjacenthtml_xss'
                }, { value: htmlString, element: this, position: pos }, m);
                scanInlineEvents(htmlString);
            }
        }
        return origInsert.call(this, pos, htmlString);
    };
})();

// Attribute/property sinks (href/src/action/formaction + inline events)
; (function () {
    const resolveAttrSinkId = (el, attrName) => {
        const name = (attrName || '').toLowerCase();
        const tag = el?.tagName ? el.tagName.toLowerCase() : '';
        if (name.startsWith('on')) return 'dom.inline_event';
        if (name === 'srcdoc') return 'nav.iframe.srcdoc';
        if (name === 'href') return 'dom.attr.href';
        if (name === 'action') return 'dom.attr.action';
        if (name === 'formaction') return 'dom.attr.formaction';
        if (name === 'src') {
            if (tag === 'img') return 'http.image.src';
            if (tag === 'script') return 'script.element.src';
            if (tag === 'iframe') return 'nav.iframe.src';
            return 'dom.attr.src';
        }
        return null;
    };

    const reportAttrSink = (el, attrName, value) => {
        if (__IAST_DISABLE_HOOKS__ || !isHookGroupEnabled('hook.dom.attributes')) return;
        if (!hasRecentTaintActivity()) return;
        if (!allowHeavyHook()) return;
        const sinkId = resolveAttrSinkId(el, attrName);
        if (!sinkId) return;
        const m = matchesTaint(value);
        if (!m) return;
        const binding = buildRuleBinding({ sinkId, fallbackType: 'dom-attr' });
        maybeReportTaintedValue(value, binding, {
            value,
            attribute: attrName,
            element: el,
            domPath: getDomPath(el)
        }, m);
    };

    const wrapPropertySetter = (proto, prop) => {
        if (!proto) return;
        const desc = Object.getOwnPropertyDescriptor(proto, prop);
        if (!desc || !desc.set) return;
        Object.defineProperty(proto, prop, {
            configurable: true,
            enumerable: desc.enumerable,
            get: desc.get,
            set(value) {
                reportAttrSink(this, prop, value);
                return desc.set.call(this, value);
            }
        });
    };

    const origSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
        const res = origSetAttribute.apply(this, arguments);
        try {
            reportAttrSink(this, name, value);
        } catch (_) { }
        return res;
    };

    wrapPropertySetter(HTMLAnchorElement?.prototype, 'href');
    wrapPropertySetter(HTMLAreaElement?.prototype, 'href');
    wrapPropertySetter(HTMLLinkElement?.prototype, 'href');
    wrapPropertySetter(HTMLImageElement?.prototype, 'src');
    wrapPropertySetter(HTMLScriptElement?.prototype, 'src');
    wrapPropertySetter(HTMLIFrameElement?.prototype, 'src');
    wrapPropertySetter(HTMLIFrameElement?.prototype, 'srcdoc');
    wrapPropertySetter(HTMLFormElement?.prototype, 'action');
    wrapPropertySetter(HTMLButtonElement?.prototype, 'formAction');
    wrapPropertySetter(HTMLInputElement?.prototype, 'formAction');
})();

// createContextualFragment & appendChild/insertBefore
; (function () {
    // 1) Walk a subtree in post-order, checking text nodes and element attributes
    function traverseAndReport(root, trigger) {
        if (__IAST_DISABLE_HOOKS__) return;
        if (!window.__IAST_TAINTED__ || !Object.keys(window.__IAST_TAINTED__).length) return;
        if (!hasRecentTaintActivity()) return;
        if (!allowHeavyHook()) return;
        const seen = new Set();
        const maxNodes = 100;
        let visited = 0;
        const maxMs = 3;
        const start = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
        function scanNode(n) {
            if (seen.has(n)) return;
            if (visited >= maxNodes) return;
            visited += 1;
            const now = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
            if (now - start > maxMs) return;

            // TEXT NODE: look for taint in its textContent
            if (n.nodeType === Node.TEXT_NODE) {
                const txt = n.textContent || '';
                const m = matchesTaint(txt);
                if (m) {
                    seen.add(n);
                    maybeReportTaintedValue(txt, {
                        type: 'xss-via-mutation',
                        sink: trigger,
                        sinkId: 'dom.mutation',
                        ruleId: 'dom_mutation_xss'
                    }, {
                        element: document?.activeElement || null,
                        value: txt,
                        nodeType: 'TEXT_NODE',
                        snippet: txt.trim().slice(0, 200)
                    }, m);
                }
                return;
            }

            // ELEMENT NODE: check each attribute for taint
            if (n.nodeType === Node.ELEMENT_NODE) {
                for (const attr of n.attributes) {
                    const m = matchesTaint(attr.value);
                    if (m) {
                        seen.add(n);
                        maybeReportTaintedValue(attr.value, {
                            type: 'xss-via-mutation',
                            sink: trigger,
                            sinkId: 'dom.mutation',
                            ruleId: 'dom_mutation_xss'
                        }, {
                            element: n,
                            nodeType: 'ELEMENT_NODE',
                            tag: n.tagName,
                            attribute: attr.name,
                            value: attr.value,
                            domPath: getDomPath(n)
                        }, m);
                        return;  // one finding per element
                    }
                }
            }
        }

        // post-order traverse everything under root (including root itself if text or element)
        (function walk(n) {
            n.childNodes.forEach(walk);
            scanNode(n);
        })(root);
    }

    // 2) List of prototypes & methods to hook
    const hooks = [
        [Node.prototype, ['appendChild', 'insertBefore', 'replaceChild']],
        [Element.prototype, ['append', 'prepend', 'before', 'after', 'replaceWith']],
        [Document.prototype, ['adoptNode']]
    ];

    for (const [proto, methods] of hooks) {
        for (const name of methods) {
            const orig = proto[name];
            if (typeof orig !== 'function') continue;

            Object.defineProperty(proto, name, {
                configurable: true,
                writable: true,
                value: function (...args) {
                    if (__IAST_DISABLE_HOOKS__ || !isHookGroupEnabled('hook.dom.mutations')) {
                        return orig.apply(this, args);
                    }
                    if (!hasRecentTaintActivity()) {
                        return orig.apply(this, args);
                    }
                    if (!allowHeavyHook()) {
                        return orig.apply(this, args);
                    }
                    //console.debug(`[IAST] mutation hook: ${name}`, this, args);

                    // figure out which Nodes are being inserted/adopted
                    const nodes = [];
                    switch (name) {
                        case 'insertBefore':
                        case 'replaceChild':
                            nodes.push(args[0]);
                            break;
                        case 'appendChild':
                        case 'adoptNode':
                            nodes.push(args[0]);
                            break;
                        default:
                            // append/prepend/before/after/replaceWith take Node or strings
                            args.forEach(a => {
                                if (typeof a === 'string') {
                                    // strings become TextNodes at runtime; scan them too
                                    const txtNode = document.createTextNode(a);
                                    nodes.push(txtNode);
                                } else if (a instanceof Node) {
                                    nodes.push(a);
                                }
                            });
                    }

                    // run taint scan asynchronously (budgeted)
                    for (const n of nodes) {
                        if (IAST_MUTATION_QUEUE.length < IAST_MUTATION_QUEUE_MAX) {
                            IAST_MUTATION_QUEUE.push({ node: n, trigger: name });
                        }
                    }
                    scheduleMutationFlush();

                    // and finally perform the real mutation
                    return orig.apply(this, args);
                }
            });
        }
    }
})();

// DOM URL navigation sinks
; (function () {
    const NAV_SUPPRESS = { meta: null, time: 0 };
    const NAV_REPLAY_STATE = { active: false };
    function markLocationNavTrigger(meta) {
        NAV_SUPPRESS.meta = meta || null;
        NAV_SUPPRESS.time = Date.now();
    }
    function consumeLocationNavTrigger() {
        if (!NAV_SUPPRESS.meta) return null;
        if (Date.now() - NAV_SUPPRESS.time > 1500) {
            NAV_SUPPRESS.meta = null;
            return null;
        }
        const meta = NAV_SUPPRESS.meta;
        NAV_SUPPRESS.meta = null;
        return meta;
    }
    window.__IAST_CONSUME_NAV_TRIGGER__ = consumeLocationNavTrigger;
    function scheduleNavigationReplay(fn) {
        if (typeof fn !== 'function') return;
        setTimeout(() => {
            NAV_REPLAY_STATE.active = true;
            try {
                fn();
            } catch (e) {
                __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: navigation replay failed', e);
            } finally {
                NAV_REPLAY_STATE.active = false;
            }
        }, 0);
    }

    const LocationProto = typeof Location !== 'undefined' ? Location.prototype : null;

    function wrapLocationSetter(prop, ruleId, sinkId, label) {
        const targets = [];
        if (LocationProto) targets.push(LocationProto);
        try {
            if (window.location) targets.push(window.location);
        } catch (_) { }
        targets.forEach(target => {
            try {
                const desc = Object.getOwnPropertyDescriptor(target, prop);
                if (!desc || typeof desc.set !== 'function' || desc.configurable === false) return;
                Object.defineProperty(target, prop, {
                    configurable: true,
                    enumerable: desc.enumerable,
                    get: desc.get ? function () { return desc.get.call(this); } : undefined,
                    set(value) {
                        const ctx = this;
                        const runNative = () => desc.set.call(ctx, value);
                        if (NAV_REPLAY_STATE.active) {
                            return runNative();
                        }
                        if (!isHookGroupEnabled('hook.nav.redirects')) {
                            return runNative();
                        }
                        if (!shouldReportNavigationSink(value)) {
                            return runNative();
                        }
                        const elMeta = captureElementMeta(document?.activeElement || null);
                        const reported = maybeReportTaintedValue(value, {
                            type: 'dom-url-navigation',
                            sink: label,
                            sinkId,
                            ruleId
                        }, Object.assign({ property: prop, value }, elMeta));
                        if (reported) markLocationNavTrigger({ sinkId, ruleId, sinkLabel: label });
                        if (reported) {
                            scheduleNavigationReplay(runNative);
                            return;
                        }
                        return runNative();
                    }
                });
            } catch (e) {
                __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: unable to wrap location property', prop);
            }
        });
    }

    function wrapLocationMethod(method, ruleId, sinkId, label) {
        const targets = [];
        try {
            if (window.location && typeof window.location[method] === 'function') {
                targets.push({ target: window.location, useBound: true });
            }
        } catch (_) { }
        if (LocationProto && typeof LocationProto[method] === 'function') {
            targets.push({ target: LocationProto, useBound: false });
        }
        let wrapped = false;
        targets.forEach(({ target, useBound }) => {
            try {
                const orig = target[method];
                if (typeof orig !== 'function') return;
                if (useBound) {
                    const bound = orig.bind(window.location);
                    target[method] = function (...args) {
                        const callArgs = args.slice(0);
                        const invokeNative = () => bound(...callArgs);
                        if (NAV_REPLAY_STATE.active) {
                            return invokeNative();
                        }
                        if (!isHookGroupEnabled('hook.nav.redirects')) {
                            return invokeNative();
                        }
                        const url = args[0];
                        if (typeof url === 'string' && shouldReportNavigationSink(url)) {
                            const elMeta = captureElementMeta(document?.activeElement || null);
                            const reported = maybeReportTaintedValue(url, {
                                type: 'dom-url-navigation',
                                sink: label,
                                sinkId,
                                ruleId
                            }, Object.assign({ method: label, value: url }, elMeta, buildNetworkContext(url) || {}));
                            if (reported) {
                                markLocationNavTrigger({ sinkId, ruleId, sinkLabel: label });
                                scheduleNavigationReplay(invokeNative);
                                return;
                            }
                        }
                        return invokeNative();
                    };
                } else {
                    target[method] = function (...args) {
                        const ctx = this;
                        const callArgs = args.slice(0);
                        const invokeNative = () => orig.apply(ctx, callArgs);
                        if (NAV_REPLAY_STATE.active) {
                            return invokeNative();
                        }
                        if (!isHookGroupEnabled('hook.nav.redirects')) {
                            return invokeNative();
                        }
                        const url = args[0];
                        if (typeof url === 'string' && shouldReportNavigationSink(url)) {
                            const elMeta = captureElementMeta(document?.activeElement || null);
                            const reported = maybeReportTaintedValue(url, {
                                type: 'dom-url-navigation',
                                sink: label,
                                sinkId,
                                ruleId
                            }, Object.assign({ method: label, value: url }, elMeta, buildNetworkContext(url) || {}));
                            if (reported) {
                                markLocationNavTrigger({ sinkId, ruleId, sinkLabel: label });
                                scheduleNavigationReplay(invokeNative);
                                return;
                            }
                        }
                        return invokeNative();
                    };
                }
                wrapped = true;
            } catch (e) {
                __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: failed to wrap location method', method, e);
            }
        });
        if (!wrapped) {
            __PTK_IAST_DBG__ && __PTK_IAST_DBG__('IAST: unable to patch location method', method);
        }
    }

    wrapLocationSetter('href', 'location_href_redirect', 'nav.location.href', 'location.href');
    wrapLocationMethod('assign', 'location_assign_redirect', 'nav.location.assign', 'location.assign');
    wrapLocationMethod('replace', 'location_replace_redirect', 'nav.location.replace', 'location.replace');

    const HistoryProto = typeof History !== 'undefined' ? History.prototype : null;
    if (HistoryProto && typeof HistoryProto.pushState === 'function') {
        const origPushState = HistoryProto.pushState;
        HistoryProto.pushState = function (state, title, url) {
            if (!isHookGroupEnabled('hook.nav.redirects')) {
                return origPushState.apply(this, arguments);
            }
            if (typeof url === 'string' && url && shouldReportNavigationSink(url)) {
                maybeReportTaintedValue(url, {
                    type: 'dom-url-navigation',
                    sink: 'history.pushState',
                    sinkId: 'nav.history.pushState',
                    ruleId: 'history_pushstate_open_redirect'
                }, Object.assign({ value: url, method: 'history.pushState' }, buildNetworkContext(url) || {}));
            }
            return origPushState.apply(this, arguments);
        };
    }
})();

// Open-Redirect Detection

; (function () {
    function isExternalRedirect(url) {
        try {
            // resolve relative URLs against current location
            const resolved = new URL(url, window.location.href);
            // only consider http(s) URLs…
            if (!/^https?:$/i.test(resolved.protocol)) return false;
            // …and only if the origin really differs
            return resolved.origin !== window.location.origin;
        } catch (e) {
            // not a valid URL at all
            return false;
        }
    }

    function recordRedirect(url, method) {
        if (!isHookGroupEnabled('hook.nav.redirects')) return;
        // 1) skip anything that isn’t an external http(s) redirect
        if (!isExternalRedirect(url)) return;

        let resolvedSinkId = method === 'navigation.navigate' ? 'nav.navigation.navigate' : 'nav.window.open';
        let resolvedRuleId = method === 'navigation.navigate' ? 'navigation_api_redirect' : 'window_open_redirect';
        let resolvedSinkLabel = method === 'navigation.navigate' ? 'navigation.navigate' : method;
        if (method === 'navigation.navigate') {
            if (typeof window.__IAST_CONSUME_NAV_TRIGGER__ === 'function') {
                const recent = window.__IAST_CONSUME_NAV_TRIGGER__();
                if (recent && recent.sinkId) {
                    resolvedSinkId = recent.sinkId;
                    resolvedRuleId = recent.ruleId || resolvedRuleId;
                    resolvedSinkLabel = recent.sinkLabel || resolvedSinkLabel;
                } else {
                    resolvedSinkId = 'nav.location.href';
                    resolvedRuleId = 'location_href_redirect';
                    resolvedSinkLabel = 'location.href';
                }
            } else {
                resolvedSinkId = 'nav.location.href';
                resolvedRuleId = 'location_href_redirect';
                resolvedSinkLabel = 'location.href';
            }
        }

        const m = matchesTaint(url);
        const binding = buildRuleBinding({
            sinkId: resolvedSinkId,
            ruleId: resolvedRuleId,
            fallbackType: 'open-redirect'
        });
        if (m) {
            const meta = captureElementMeta(document?.activeElement || null);
            maybeReportTaintedValue(url, binding, Object.assign({ value: url }, meta, buildNetworkContext(url) || {}), m);
        }
    }

    //Wrap window.open()
    const origOpen = window.open;
    window.open = function (url, ...rest) {
        if (!isHookGroupEnabled('hook.nav.redirects')) {
            return origOpen.call(this, url, ...rest);
        }
        if (typeof url === 'string') {
            recordRedirect(url, 'window.open');
        }
        return origOpen.call(this, url, ...rest);
    };

    if ('navigation' in window && typeof navigation.addEventListener === 'function') {
        navigation.addEventListener('navigate', event => {
            if (!isHookGroupEnabled('hook.nav.redirects')) return;
            // event.destination.url is the URL we’re about to go to
            const url = event.destination.url;
            // reuse your open-redirect checker
            recordRedirect(url, 'navigation.navigate');
        });
    }

})();

// HTTP exfiltration sinks
; (function () {
    function coerceRequestUrl(input) {
        if (!input) return '';
        if (typeof input === 'string') return input;
        if (typeof URL !== 'undefined' && input instanceof URL) return input.href;
        if (typeof Request !== 'undefined' && input instanceof Request) return input.url;
        try {
            return String(input);
        } catch {
            return '';
        }
    }

    function coerceBodyString(body) {
        if (body == null) return '';
        if (typeof body === 'string') return body;
        if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
            return body.toString();
        }
        if (typeof FormData !== 'undefined' && body instanceof FormData) {
            const parts = [];
            body.forEach((val, key) => parts.push(`${key}=${val}`));
            return parts.join('&');
        }
        if (typeof Blob !== 'undefined' && body instanceof Blob) {
            // synchronous access not possible; fall back to placeholder
            return '[blob]';
        }
        return safeSerializeValue(body);
    }

    function scanHeaders(headers, cb) {
        if (!headers) return;
        if (typeof Headers !== 'undefined' && headers instanceof Headers) {
            headers.forEach((value, name) => cb(name, value));
            return;
        }
        if (Array.isArray(headers)) {
            headers.forEach(entry => {
                if (!entry) return;
                const [name, value] = entry;
                cb(name, value);
            });
            return;
        }
        if (typeof headers === 'object') {
            Object.entries(headers).forEach(([name, value]) => {
                if (Array.isArray(value)) {
                    value.forEach(v => cb(name, v));
                } else {
                    cb(name, value);
                }
            });
        }
    }

    const SAFE_HTTP_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

    function isCrossOriginUrl(url) {
        const target = buildNetworkTarget(url);
        if (!target) return false;
        return target.isCrossOrigin;
    }

    function requestIsInstance(resource) {
        return typeof Request !== 'undefined' && resource instanceof Request;
    }

    function resolveRequestMethod(resource, init) {
        if (init && init.method) return String(init.method).toUpperCase();
        if (requestIsInstance(resource) && resource.method) {
            return String(resource.method).toUpperCase();
        }
        return 'GET';
    }

    function resolveRequestCredentials(resource, init) {
        if (init && init.credentials) return String(init.credentials);
        if (requestIsInstance(resource) && resource.credentials) {
            return String(resource.credentials);
        }
        return 'same-origin';
    }

    function headersIndicateProtection(headerSet) {
        let protectedSignal = false;
        scanHeaders(headerSet, (name) => {
            if (protectedSignal || !name) return;
            const lower = String(name).toLowerCase();
            if (!lower) return;
            if (lower.includes('csrf') || lower.includes('xsrf') || lower.includes('token') || lower === 'x-requested-with'
                || lower === 'authorization' || lower === 'proxy-authorization' || lower.includes('api-key')) {
                protectedSignal = true;
            }
        });
        return protectedSignal;
    }

    function summarizeHeaders(headerSets, cap = 6) {
        const summary = [];
        headerSets.forEach(set => {
            scanHeaders(set, (name, value) => {
                if (summary.length >= cap) return;
                const serialized = safeSerializeValue(value || '');
                summary.push({
                    name,
                    value: serialized.length > 200 ? serialized.slice(0, 200) : serialized
                });
            });
        });
        return summary;
    }

    function documentHasAntiCsrfCookie() {
        if (typeof document === 'undefined' || !document.cookie) return false;
        try {
            return document.cookie.split(';').some(part => {
                const key = part.split('=')[0]?.trim().toLowerCase();
                if (!key) return false;
                return key.includes('csrf') || key.includes('xsrf');
            });
        } catch (_) {
            return false;
        }
    }

    if (typeof window.fetch === 'function') {
        const origFetch = window.fetch;
        window.fetch = function (...args) {
            if (!isHookGroupEnabled('hook.net.exfil')) {
                return origFetch.apply(this, args);
            }
            try {
                const resource = args[0];
                const init = args[1];
                const url = coerceRequestUrl(resource);
                const networkContext = buildNetworkContext(url);
                const suspiciousUrl = url && isSuspiciousExfilUrl(url);
                if (url && suspiciousUrl) {
                    maybeReportTaintedValue(url, {
                        type: 'http-exfiltration',
                        sink: 'fetch(url)',
                        sinkId: 'http.fetch.url',
                        ruleId: 'fetch_url_exfiltration'
                    }, Object.assign({ value: url, method: 'fetch', requestUrl: url }, networkContext || {}));
                }
                const headerCandidates = [];
                if (requestIsInstance(resource)) {
                    headerCandidates.push(resource.headers);
                }
                if (init && init.headers) {
                    headerCandidates.push(init.headers);
                }
                let hasProtectiveHeader = false;
                if (suspiciousUrl) {
                    headerCandidates.forEach(candidate => {
                        if (!hasProtectiveHeader && headersIndicateProtection(candidate)) {
                            hasProtectiveHeader = true;
                        }
                        scanHeaders(candidate, (name, value) => {
                            maybeReportTaintedValue(value, {
                                type: 'http-exfiltration',
                                sink: 'fetch headers',
                                sinkId: 'http.fetch.headers',
                                ruleId: 'fetch_headers_exfiltration'
                            }, Object.assign({ headerName: name, value, requestUrl: url, method: 'fetch' }, networkContext || {}));
                        });
                    });
                }

                const method = resolveRequestMethod(resource, init);
                const credentialsMode = resolveRequestCredentials(resource, init);
                const sendsCredentials = String(credentialsMode || '').toLowerCase() === 'include';
                const hasCsrfCookie = documentHasAntiCsrfCookie();
                if (url && isCrossOriginUrl(url) && sendsCredentials && !SAFE_HTTP_METHODS.has(method)
                    && !hasProtectiveHeader && !hasCsrfCookie) {
                    reportFinding({
                        type: 'csrf-cross-site-fetch',
                        sink: 'fetch',
                        sinkId: 'csrf.fetch',
                        ruleId: 'fetch_cross_site_no_csrf',
                        matched: null,
                        source: null,
                        sources: [],
                        context: {
                            method,
                            url,
                            credentials: credentialsMode,
                            headers: summarizeHeaders(headerCandidates),
                            value: url,
                            requestUrl: url,
                            ...(networkContext || {})
                        }
                    });
                }
            } catch (err) {
                __PTK_IAST_DBG__('fetch wrapper error', err);
            }
            return origFetch.apply(this, args);
        };
    }

    if (typeof XMLHttpRequest !== 'undefined') {
        const origOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function (method, url, ...rest) {
            if (!isHookGroupEnabled('hook.net.exfil')) {
                return origOpen.call(this, method, url, ...rest);
            }
            this.__ptk_iast_method = method;
            this.__ptk_iast_url = url;
            const networkTarget = buildNetworkTarget(url);
            this.__ptk_iast_networkTarget = networkTarget;
            this.__ptk_iast_url_resolved = networkTarget?.url || null;
            const suspicious = isSuspiciousExfilUrl(url);
            this.__ptk_iast_exfil_suspicious = suspicious;
            if (suspicious) {
                const networkContext = networkTarget ? {
                    networkTarget,
                    destUrl: networkTarget.url,
                    destHost: networkTarget.host,
                    destOrigin: networkTarget.origin,
                    isCrossOrigin: networkTarget.isCrossOrigin,
                    scheme: networkTarget.scheme
                } : null;
                maybeReportTaintedValue(url, {
                    type: 'http-exfiltration',
                    sink: 'XMLHttpRequest.open',
                    sinkId: 'http.xhr.open',
                    ruleId: 'xhr_url_exfiltration'
                }, Object.assign({ method, value: url, requestUrl: url }, networkContext || {}));
            }
            return origOpen.call(this, method, url, ...rest);
        };

        const origSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
        if (origSetRequestHeader) {
            XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
                if (!isHookGroupEnabled('hook.net.exfil')) {
                    return origSetRequestHeader.call(this, name, value);
                }
                const m = matchesTaint(value);
                if (m) {
                    const networkTarget = this.__ptk_iast_networkTarget || buildNetworkTarget(this.__ptk_iast_url || null);
                    const networkContext = networkTarget ? {
                        networkTarget,
                        destUrl: networkTarget.url,
                        destHost: networkTarget.host,
                        destOrigin: networkTarget.origin,
                        isCrossOrigin: networkTarget.isCrossOrigin,
                        scheme: networkTarget.scheme
                    } : null;
                    const binding = buildRuleBinding({ sinkId: 'http.xhr.setRequestHeader', fallbackType: 'xhr-header' });
                    maybeReportTaintedValue(value, binding, {
                        headerName: name,
                        value,
                        requestUrl: this.__ptk_iast_url || null,
                        method: this.__ptk_iast_method || null,
                        ...(networkContext || {})
                    }, m);
                }
                return origSetRequestHeader.call(this, name, value);
            };
        }

        const origSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function (body) {
            if (!isHookGroupEnabled('hook.net.exfil')) {
                return origSend.call(this, body);
            }
            if (body !== undefined) {
                const serialized = coerceBodyString(body);
                if (serialized && this.__ptk_iast_exfil_suspicious) {
                    const networkTarget = this.__ptk_iast_networkTarget || buildNetworkTarget(this.__ptk_iast_url || null);
                    const networkContext = networkTarget ? {
                        networkTarget,
                        destUrl: networkTarget.url,
                        destHost: networkTarget.host,
                        destOrigin: networkTarget.origin,
                        isCrossOrigin: networkTarget.isCrossOrigin,
                        scheme: networkTarget.scheme
                    } : null;
                    maybeReportTaintedValue(serialized, {
                        type: 'http-exfiltration',
                        sink: 'XMLHttpRequest.send',
                        sinkId: 'http.xhr.send',
                        ruleId: 'xhr_body_exfiltration'
                    }, {
                        method: this.__ptk_iast_method || null,
                        requestUrl: this.__ptk_iast_url || null,
                        value: serialized,
                        ...(networkContext || {})
                    });
                }
            }
            return origSend.call(this, body);
        };
    }

    if (typeof navigator !== 'undefined' && navigator && typeof navigator.sendBeacon === 'function') {
        const origSendBeacon = navigator.sendBeacon;
        navigator.sendBeacon = function (url, data) {
            if (!isHookGroupEnabled('hook.net.exfil')) {
                return origSendBeacon.call(this, url, data);
            }
            if (isSuspiciousExfilUrl(url)) {
                const networkContext = buildNetworkContext(url);
                maybeReportTaintedValue(data, {
                    type: 'http-exfiltration',
                    sink: 'navigator.sendBeacon',
                    sinkId: 'http.navigator.sendBeacon',
                    ruleId: 'sendbeacon_exfiltration'
                }, Object.assign({ value: coerceBodyString(data), url, requestUrl: url }, networkContext || {}));
            }
            return origSendBeacon.call(this, url, data);
        };
    }

    if (typeof HTMLImageElement !== 'undefined') {
        const desc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
        if (desc && desc.set) {
            Object.defineProperty(HTMLImageElement.prototype, 'src', {
                configurable: true,
                enumerable: desc.enumerable,
                get: desc.get,
                set(value) {
                    if (!isHookGroupEnabled('hook.net.exfil')) {
                        return desc.set.call(this, value);
                    }
                    if (isSuspiciousExfilUrl(value)) {
                        const networkContext = buildNetworkContext(value);
                        maybeReportTaintedValue(value, {
                            type: 'http-exfiltration',
                            sink: 'image.src',
                            sinkId: 'http.image.src',
                            ruleId: 'image_src_exfiltration'
                        }, Object.assign({ value, element: this, requestUrl: value }, networkContext || {}));
                    }
                    return desc.set.call(this, value);
                }
            });
        }
    }

    if (typeof WebSocket !== 'undefined' && WebSocket.prototype && typeof WebSocket.prototype.send === 'function') {
        const origSocketSend = WebSocket.prototype.send;
        WebSocket.prototype.send = function (data) {
            if (!isHookGroupEnabled('hook.net.exfil')) {
                return origSocketSend.apply(this, arguments);
            }
            const payload = safeSerializeValue(data);
            if (payload) {
                const networkContext = buildNetworkContext(this?.url || null);
                maybeReportTaintedValue(payload, {
                    type: 'realtime-exfiltration',
                    sink: 'WebSocket.send',
                    sinkId: 'realtime.websocket.send',
                    ruleId: 'websocket_send_exfiltration'
                }, {
                    value: payload,
                    url: this?.url || null,
                    protocol: this?.protocol || null,
                    ...(networkContext || {})
                });
            }
            return origSocketSend.apply(this, arguments);
        };
    }

    if (typeof RTCDataChannel !== 'undefined' && RTCDataChannel.prototype && typeof RTCDataChannel.prototype.send === 'function') {
        const origRtcSend = RTCDataChannel.prototype.send;
        RTCDataChannel.prototype.send = function (data) {
            if (!isHookGroupEnabled('hook.net.exfil')) {
                return origRtcSend.apply(this, arguments);
            }
            const payload = safeSerializeValue(data);
            if (payload) {
                maybeReportTaintedValue(payload, {
                    type: 'realtime-exfiltration',
                    sink: 'RTCDataChannel.send',
                    sinkId: 'realtime.webrtc.send',
                    ruleId: 'webrtc_datachannel_send_exfiltration'
                }, {
                    value: payload,
                    label: this?.label || null
                });
            }
            return origRtcSend.apply(this, arguments);
        };
    }
})();

// Dynamic script loading sinks
; (function () {
    if (typeof HTMLScriptElement === 'undefined') return;
    const desc = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
    if (!desc || !desc.set) return;
    Object.defineProperty(HTMLScriptElement.prototype, 'src', {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get,
        set(value) {
            if (!isHookGroupEnabled('hook.script.loading')) {
                return desc.set.call(this, value);
            }
            const networkContext = buildNetworkContext(value);
            maybeReportTaintedValue(value, {
                type: 'dynamic-script-loading',
                sink: 'script.src',
                sinkId: 'script.element.src',
                ruleId: 'script_src_injection'
            }, Object.assign({ value, element: this, requestUrl: value }, networkContext || {}));
            return desc.set.call(this, value);
        }
    });
})();

// Debug logging sinks
; (function () {
    if (typeof console === 'undefined') return;
    const sinks = [
        { method: 'log', ruleId: 'console_log_leak', sinkId: 'log.console.log' },
        { method: 'error', ruleId: 'console_error_leak', sinkId: 'log.console.error' }
    ];
    sinks.forEach(({ method, ruleId, sinkId }) => {
        const orig = console[method];
        if (typeof orig !== 'function') return;
        console[method] = function (...args) {
            if (!isHookGroupEnabled('hook.console.leaks')) {
                return orig.apply(this, args);
            }
            args.forEach(arg => {
                const payload = safeSerializeValue(arg);
                if (!payload) return;
                maybeReportTaintedValue(payload, {
                    type: 'debug-logging',
                    sink: `console.${method}`,
                    sinkId,
                    ruleId
                }, { value: payload, method: `console.${method}` });
            });
            return orig.apply(this, args);
        };
    });
})();

// Clipboard exfiltration sink
; (function () {
    if (typeof navigator === 'undefined') return;
    const clip = navigator.clipboard;
    if (!clip || typeof clip.writeText !== 'function') return;
    const origWriteText = clip.writeText;
    clip.writeText = function (...args) {
        if (!isHookGroupEnabled('hook.net.exfil')) {
            return origWriteText.apply(this, args);
        }
        const payload = safeSerializeValue(args[0]);
        if (payload) {
            maybeReportTaintedValue(payload, {
                type: 'clipboard-exfiltration',
                sink: 'navigator.clipboard.writeText',
                sinkId: 'clipboard.writeText',
                ruleId: 'clipboard_write_text_leak'
            }, { value: payload });
        }
        return origWriteText.apply(this, args);
    };
})();

// BroadcastChannel & MessagePort sinks
; (function () {
    if (typeof BroadcastChannel !== 'undefined' && BroadcastChannel.prototype) {
        const orig = BroadcastChannel.prototype.postMessage;
        if (typeof orig === 'function') {
            BroadcastChannel.prototype.postMessage = function (message) {
                if (!isHookGroupEnabled('hook.postMessage')) {
                    return orig.apply(this, arguments);
                }
                const payload = safeSerializeValue(message);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'web-messaging-channel',
                        sink: 'BroadcastChannel.postMessage',
                        sinkId: 'channel.broadcast.postMessage',
                        ruleId: 'broadcastchannel_postmessage_leak'
                    }, { value: payload, channelName: this?.name || null });
                }
                return orig.apply(this, arguments);
            };
        }
    }

    if (typeof MessagePort !== 'undefined' && MessagePort.prototype) {
        const origPortPost = MessagePort.prototype.postMessage;
        if (typeof origPortPost === 'function') {
            MessagePort.prototype.postMessage = function (message, transfer) {
                if (!isHookGroupEnabled('hook.postMessage')) {
                    return origPortPost.apply(this, arguments);
                }
                const payload = safeSerializeValue(message);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'web-messaging-channel',
                        sink: 'MessagePort.postMessage',
                        sinkId: 'channel.messageport.postMessage',
                        ruleId: 'messageport_postmessage_leak'
                    }, { value: payload });
                }
                return origPortPost.apply(this, arguments);
            };
        }
    }
})();

// Worker & ServiceWorker script loading sinks
; (function () {
    if (typeof navigator !== 'undefined' && navigator.serviceWorker && typeof navigator.serviceWorker.register === 'function') {
        const origRegister = navigator.serviceWorker.register;
        navigator.serviceWorker.register = function (...args) {
            if (!isHookGroupEnabled('hook.script.loading')) {
                return origRegister.apply(this, args);
            }
            const payload = safeSerializeValue(args[0]);
            if (payload) {
                maybeReportTaintedValue(payload, {
                    type: 'worker-script-loading',
                    sink: 'navigator.serviceWorker.register',
                    sinkId: 'worker.serviceWorker.register',
                    ruleId: 'serviceworker_register_injection'
                }, { value: payload });
            }
            return origRegister.apply(this, args);
        };
    }

    if (typeof window.Worker === 'function') {
        const OriginalWorker = window.Worker;
        window.Worker = new Proxy(OriginalWorker, {
            construct(target, args, newTarget) {
                if (!isHookGroupEnabled('hook.script.loading')) {
                    return Reflect.construct(target, args, newTarget);
                }
                const payload = safeSerializeValue(args[0]);
                if (payload) {
                    maybeReportTaintedValue(payload, {
                        type: 'worker-script-loading',
                        sink: 'Worker',
                        sinkId: 'worker.webworker.constructor',
                        ruleId: 'webworker_constructor_injection'
                    }, { value: payload });
                }
                return Reflect.construct(target, args, newTarget);
            }
        });
    }
})();

// window.postMessage misuse
; (function () {
    if (typeof window.postMessage !== 'function') return;
    const origPostMessage = window.postMessage;
    window.postMessage = function (message, targetOrigin, transfer) {
        if (!isHookGroupEnabled('hook.postMessage')) {
            return origPostMessage.apply(this, arguments);
        }
        const payload = safeSerializeValue(message);
        const originValue = targetOrigin == null ? '*' : targetOrigin;
        const defaultContext = { value: payload, targetOrigin: originValue };
        if (originValue === '*' || originValue === '') {
            maybeReportTaintedValue(payload, {
                type: 'postMessage-leak',
                sink: 'window.postMessage',
                sinkId: 'postmessage.anyOrigin',
                ruleId: 'postmessage_star_origin_leak'
            }, defaultContext);
        } else if (typeof originValue === 'string') {
            let destOrigin = null;
            try {
                destOrigin = new URL(originValue, window.location.href).origin;
            } catch (_) {
                destOrigin = null;
            }
            if (destOrigin && destOrigin !== window.location.origin) {
                maybeReportTaintedValue(payload, {
                    type: 'postMessage-leak',
                    sink: 'window.postMessage',
                    sinkId: 'postmessage.crossOrigin',
                    ruleId: 'postmessage_cross_origin_leak'
                }, Object.assign({}, defaultContext, { destination: destOrigin }));
            }
        }
        return origPostMessage.apply(this, arguments);
    };
})();

// IFrame navigation/content sinks
; (function () {
    if (typeof HTMLIFrameElement === 'undefined') return;
    const srcDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');
    if (srcDesc && srcDesc.set) {
        Object.defineProperty(HTMLIFrameElement.prototype, 'src', {
            configurable: true,
            enumerable: srcDesc.enumerable,
            get: srcDesc.get,
            set(value) {
                if (!isHookGroupEnabled('hook.dom.attributes')) {
                    return srcDesc.set.call(this, value);
                }
                if (shouldReportNavigationSink(value)) {
                    maybeReportTaintedValue(value, {
                        type: 'iframe-navigation',
                        sink: 'iframe.src',
                        sinkId: 'nav.iframe.src',
                        ruleId: 'iframe_src_redirect'
                    }, { value, element: this });
                }
                return srcDesc.set.call(this, value);
            }
        });
    }
    const srcdocDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'srcdoc');
    if (srcdocDesc && srcdocDesc.set) {
        Object.defineProperty(HTMLIFrameElement.prototype, 'srcdoc', {
            configurable: true,
            enumerable: srcdocDesc.enumerable,
            get: srcdocDesc.get,
            set(value) {
                if (!isHookGroupEnabled('hook.dom.attributes')) {
                    return srcdocDesc.set.call(this, value);
                }
                maybeReportTaintedValue(value, {
                    type: 'iframe-srcdoc',
                    sink: 'iframe.srcdoc',
                    sinkId: 'nav.iframe.srcdoc',
                    ruleId: 'iframe_srcdoc_xss'
                }, { value, element: this });
                return srcdocDesc.set.call(this, value);
            }
        });
    }
})();

// Timer-based execution sinks
; (function () {
    function wrapTimer(fnName, ruleId, sinkId) {
        if (typeof window[fnName] !== 'function') return;
        const orig = window[fnName];
        window[fnName] = function (handler, ...rest) {
            if (!isHookGroupEnabled('hook.code.exec')) {
                return orig.call(this, handler, ...rest);
            }
            if (typeof handler === 'string' && handler) {
                maybeReportTaintedValue(handler, {
                    type: 'timer-execution',
                    sink: fnName,
                    sinkId,
                    ruleId
                }, { value: handler, method: fnName });
            }
            return orig.call(this, handler, ...rest);
        };
    }
    wrapTimer('setTimeout', 'settimeout_string_execution', 'code.setTimeout');
    wrapTimer('setInterval', 'setinterval_string_execution', 'code.setInterval');
})();
