/* Author: Denis Podgurskii */
import { ptk_utils } from "../../utils.js"
import { jsonLogic } from '../../lib/json-logic-js.js'

export class ptk_module {
    constructor(module) {
        Object.assign(this, module)

        // You can keep strings and/or RegExp here
        this.nonAttackParams = ['csrf', '_csrf', /^x-.*-token$/i, /^ptk_/i]

        jsonLogic.add_operation("regex", this.op_regex)
        jsonLogic.add_operation("proof", this.op_proof)
    }

    /* ---------------- json-logic helpers ---------------- */

    op_regex(obj, pattern) {
        let success = false
        pattern = new RegExp(pattern, "gmi")
        if (Array.isArray(obj)) {
            Object.entries(obj).forEach(([_key, _value]) => {
                if (pattern.test(JSON.stringify(_value))) {
                    success = true
                }
            })
        } else {
            success = pattern.test(obj)
        }
        return success
    }

    op_proof(obj, pattern) {
        let proof = ""
        pattern = new RegExp(pattern, "gmi")
        if (Array.isArray(obj)) {
            Object.entries(obj).forEach(([_key, _value]) => {
                if (pattern.test(JSON.stringify(_value))) {
                    proof = JSON.stringify(_value).match(pattern)[0]
                }
            })
        } else {
            if (pattern.test(obj))
                proof = obj.match(pattern)[0]
        }
        return proof
    }

    /* ---------------- internal helpers ---------------- */

    // case-insensitive + regex-aware denylist
    isAttackableName(name) {
        const deny = this.nonAttackParams || []
        const n = String(name ?? '').toLowerCase()
        return !deny.some(d => {
            if (d instanceof RegExp) return d.test(name)
            return String(d).toLowerCase() === n
        })
    }

    // robust URL constructor (supports relative URLs)
    _toURL(u, baseFallback) {
        try {
            return new URL(u)
        } catch {
            const base = baseFallback || (typeof location !== 'undefined' ? location.origin : 'http://localhost')
            return new URL(u, base)
        }
    }

    // Deep clone
    _clone(obj) {
        return JSON.parse(JSON.stringify(obj))
    }

    // Header helpers
    _headersArray(schema) {
        return schema?.request?.headers || (schema.request.headers = [])
    }

    _findHeaderIndex(schema, name) {
        const headers = this._headersArray(schema)
        const lname = name.toLowerCase()
        return headers.findIndex(h => (h.name || '').toLowerCase() === lname)
    }

    _getHeader(schema, name) {
        const i = this._findHeaderIndex(schema, name)
        return i >= 0 ? this._headersArray(schema)[i].value : undefined
    }

    _setHeader(schema, name, value) {
        const headers = this._headersArray(schema)
        const i = this._findHeaderIndex(schema, name)
        if (i >= 0) headers[i].value = value
        else headers.push({ name, value })
    }

    _contentType(schema) {
        return (this._getHeader(schema, 'Content-Type') || schema?.request?.body?.mimeType || '').toLowerCase()
    }

    _getHeaderFromRaw(raw, name) {
        if (!raw) return null
        const target = String(name || '').toLowerCase()
        const lines = String(raw).split(/\r?\n/)
        for (const line of lines) {
            const idx = line.indexOf(':')
            if (idx === -1) continue
            const hname = line.slice(0, idx).trim().toLowerCase()
            if (hname === target) {
                return line.slice(idx + 1).trim()
            }
        }
        return null
    }

    _extractJwtFromString(value) {
        if (!value) return null
        const match = String(value).match(/ey[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_-]*/)
        return match ? match[0] : null
    }

    _decodeJwtPayload(token) {
        if (!token) return null
        const parts = String(token).split('.')
        if (parts.length < 2) return null
        let b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
        while (b64.length % 4) b64 += '='
        try {
            if (typeof atob === 'function') {
                return atob(b64)
            }
            if (typeof Buffer !== 'undefined') {
                return Buffer.from(b64, 'base64').toString('utf8')
            }
        } catch (_) {
            return null
        }
        return null
    }

    _looksJsonCt(ct) {
        return ct.includes('application/json') || ct.includes('text/json') || ct.includes('+json')
    }

    // Ensure body exists; return a mutable reference
    _ensureBody(schema) {
        if (!schema.request.body) schema.request.body = {}
        return schema.request.body
    }

    // Try to obtain JSON object for body; also indicate source
    _getJsonBody(schema) {
        const body = this._ensureBody(schema)
        const ct = this._contentType(schema)

        // Prefer explicit json field
        if (body.json && typeof body.json === 'object') {
            return { obj: body.json, source: 'json' }
        }

        // If content type suggests JSON, try to parse text/raw
        if (this._looksJsonCt(ct) && typeof body.text === 'string') {
            try {
                const obj = JSON.parse(body.text)
                body.json = obj
                return { obj, source: 'text' }
            } catch (_) { /* ignore */ }
        }

        // If no CT but text is parseable JSON, treat as JSON
        if (!this._looksJsonCt(ct) && typeof body.text === 'string') {
            try {
                const obj = JSON.parse(body.text)
                body.json = obj
                // also set header to json for clarity
                this._setHeader(schema, 'Content-Type', 'application/json')
                return { obj, source: 'text' }
            } catch (_) { /* ignore */ }
        }

        // If body has no text and no json but CT is JSON, initialize empty object
        if (this._looksJsonCt(ct) && !body.text && !body.json) {
            body.json = {}
            return { obj: body.json, source: 'json' }
        }

        return { obj: null, source: null }
    }

    // Sync json -> text (and ensure CT)
    _persistJsonBody(schema, obj) {
        const body = this._ensureBody(schema)
        body.json = obj
        try {
            body.text = JSON.stringify(obj)
        } catch {
            // Fallback, but shouldn't happen
            body.text = '' + obj
        }
        // Ensure Content-Type
        if (!this._looksJsonCt(this._contentType(schema))) {
            this._setHeader(schema, 'Content-Type', 'application/json')
        }
    }

    // JSON path parsing: supports dot and [index] notation
    _parseJsonPath(path) {
        const segs = []
        const re = /([^.\[\]]+)|\[(\d+)\]/g
        let m
        while ((m = re.exec(path)) !== null) {
            if (m[1] !== undefined) segs.push(m[1])
            else segs.push(Number(m[2]))
        }
        return segs
    }

    _getByJsonPath(obj, path) {
        const segs = Array.isArray(path) ? path : this._parseJsonPath(path)
        let cur = obj
        for (let i = 0; i < segs.length; i++) {
            if (cur == null) return { exists: false, parent: null, key: null, value: undefined }
            const k = segs[i]
            if (i === segs.length - 1) {
                return { exists: Object.prototype.hasOwnProperty.call(cur, k), parent: cur, key: k, value: cur?.[k] }
            } else {
                cur = cur?.[k]
            }
        }
        return { exists: false, parent: null, key: null, value: undefined }
    }

    _setByJsonPath(obj, path, value) {
        const segs = Array.isArray(path) ? path : this._parseJsonPath(path)
        let cur = obj
        for (let i = 0; i < segs.length - 1; i++) {
            const k = segs[i]
            const next = segs[i + 1]
            if (cur[k] == null || typeof cur[k] !== 'object') {
                // create object or array segment depending on next segment
                cur[k] = (typeof next === 'number') ? [] : {}
            }
            cur = cur[k]
        }
        const last = segs[segs.length - 1]
        cur[last] = value
    }

    _isPrimitive(v) {
        const t = typeof v
        return v == null || t === 'string' || t === 'number' || t === 'boolean'
    }

    // Enumerate JSON leaf paths (primitives only)
    _enumerateJsonLeaves(obj, basePath = '') {
        const out = []
        const addPath = (p) => (basePath ? `${basePath}.${p}` : p)

        if (Array.isArray(obj)) {
            for (let i = 0; i < obj.length; i++) {
                const val = obj[i]
                const path = `${basePath}[${i}]`
                if (this._isPrimitive(val)) {
                    out.push({ path, value: val })
                } else if (val && typeof val === 'object') {
                    out.push(...this._enumerateJsonLeaves(val, `${basePath}[${i}]`))
                }
            }
        } else if (obj && typeof obj === 'object') {
            for (const k of Object.keys(obj)) {
                const val = obj[k]
                const path = addPath(k)
                if (this._isPrimitive(val)) {
                    out.push({ path, value: val })
                } else if (val && typeof val === 'object') {
                    out.push(...this._enumerateJsonLeaves(val, path))
                }
            }
        }
        return out
    }

    /* ---------------- cookie helpers ---------------- */

    _parseCookieHeader(cookieStr) {
        const list = []
        if (!cookieStr) return list
        cookieStr.split(';').forEach(part => {
            const eq = part.indexOf('=')
            if (eq === -1) return
            const name = part.slice(0, eq).trim()
            const value = part.slice(eq + 1).trim()
            if (name) list.push({ name, value })
        })
        return list
    }

    _stringifyCookies(arr) {
        return (arr || []).map(c => `${c.name}=${c.value}`).join('; ')
    }

    _getCookiesArray(schema) {
        // Prefer structured cookies array if present; else parse header
        if (Array.isArray(schema?.request?.cookies)) {
            return schema.request.cookies
        }
        const cookieHeader = this._getHeader(schema, 'Cookie') || ''
        const parsed = this._parseCookieHeader(cookieHeader)
        schema.request.cookies = parsed // keep in schema for later
        return schema.request.cookies
    }

    _ensureCookiesArray(schema) {
        if (!Array.isArray(schema?.request?.cookies)) {
            schema.request.cookies = []
        }
        return schema.request.cookies
    }

    /* ---------------- target enumeration ---------------- */

    // Enumerate attack targets according to action filters (query, form-body, headers, json-body, cookies)
    _getParamTargets(schema, action) {
        const targets = []

        const qp = schema?.request?.queryParams || []
        const bp = schema?.request?.body?.params || []
        const hh = schema?.request?.headers || []

        const actionHasWildcardParam = (action.params || []).some(a => !a.name)
        const actionHasWildcardHeader = (action.headers || []).some(a => !a.name)

        // Query params
        for (const p of qp) {
            if (!this.isAttackableName(p.name)) continue
            const explicit = (action.params || []).some(a => a.name && a.name.toLowerCase() === p.name.toLowerCase())
            if (explicit || actionHasWildcardParam) {
                targets.push({ location: 'query', name: p.name })
            }
        }

        // Body params (form-encoded style)
        for (const p of bp) {
            if (!this.isAttackableName(p.name)) continue
            const explicit = (action.params || []).some(a => a.name && a.name.toLowerCase() === p.name.toLowerCase())
            if (explicit || actionHasWildcardParam) {
                targets.push({ location: 'body', name: p.name })
            }
        }

        // Headers (exclude Cookie; handled as cookie-level targets below)
        for (const h of hh) {
            if (!this.isAttackableName(h.name)) continue
            if ((h.name || '').toLowerCase() === 'cookie') continue
            const explicit = (action.headers || []).some(a => a.name && a.name.toLowerCase() === h.name.toLowerCase())
            if (explicit || actionHasWildcardHeader) {
                targets.push({ location: 'header', name: h.name })
            }
        }

        // Cookies (only if the action intends to touch cookies)
        const hasCookieIntent =
            (action.cookies && action.cookies.length > 0) ||
            (action.headers || []).some(h => (h.name || '').toLowerCase() === 'cookie')

        if (hasCookieIntent) {
            const cookies = this._getCookiesArray(schema)
            for (const c of cookies) {
                if (!this.isAttackableName(c.name)) continue
                targets.push({ location: 'cookie', name: c.name })
            }
        }

        // JSON body
        const { obj: jsonObj } = this._getJsonBody(schema)
        if (jsonObj && (action.params?.length || 0) >= 0) {
            const explicitJsonNames = (action.params || [])
                .filter(a => a.name && typeof a.name === 'string')
                .map(a => a.name)

            if (explicitJsonNames.length) {
                for (const path of explicitJsonNames) {
                    targets.push({ location: 'json', name: path })
                }
            } else if (actionHasWildcardParam) {
                const leaves = this._enumerateJsonLeaves(jsonObj)
                for (const leaf of leaves) {
                    targets.push({ location: 'json', name: leaf.path })
                }
            }
        }

        return targets
    }

    _recordMutation(list, location, name, before, after) {
        if (!list) return
        // Only record if an actual change occurred (prevents noisy entries)
        if (before !== after) list.push({ location, name, before, after })
    }

    /* ---------------- mutation primitives ---------------- */

    modifyProps(schema, action) {
        for (let i = 0; i < (action.props?.length || 0); i++) {
            ptk_utils.jsonSetValueByPath(schema, action.props[i].name, action.props[i].value, true)
        }
        return schema
    }

    modifyParam(name, param, action) {
        if (!this.isAttackableName(name) && name !== undefined && name !== null) return param

        if (action.regex) {
            let r = new RegExp(action.regex)
            return String(param ?? '').replace(r, action.value)
        } else if (action.operation === 'remove') {
            return ''
        } else if (action.operation === 'add') {
            return (action.position === 'after') ? (String(param ?? '') + action.value) : (action.value + String(param ?? ''))
        } else if (action.operation === 'replace') {
            return action.value
        }
        return param
    }

    // onlyName: mutate only this param name (atomic mode)
    // mutations: array to collect {location,name,before,after}
    modifyPostParams(schema, action, onlyName = null, mutations = null) {
        const params = schema?.request?.body?.params
        if (!params) return schema

        for (const a of (action.params || [])) {
            if (a.name) {
                if (onlyName && a.name.toLowerCase() !== onlyName.toLowerCase()) continue

                const ind = params.findIndex(obj => obj.name?.toLowerCase() === a.name.toLowerCase())
                if (ind < 0) {
                    this._recordMutation(mutations, 'body', a.name, undefined, a.value)
                    params.push({ name: a.name, value: a.value })
                } else {
                    const before = params[ind].value
                    const after = this.modifyParam(params[ind].name, params[ind].value, a)
                    params[ind].value = after
                    this._recordMutation(mutations, 'body', params[ind].name, before, after)
                }
            } else {
                for (const p of params) {
                    if (onlyName && p.name?.toLowerCase() !== onlyName.toLowerCase()) continue
                    const before = p.value
                    const after = this.modifyParam(p.name, p.value, a)
                    p.value = after
                    this._recordMutation(mutations, 'body', p.name, before, after)
                }
            }
        }

        // ensure uniqueness marker to defeat caching
        params.push({ name: 'ptk_rnd', value: ptk_utils.attackParamId() })
        return schema
    }

    modifyGetParams(schema, action, onlyName = null, mutations = null) {
        const urlObj = this._toURL(schema.request.url, schema.request.baseUrl)
        const params = schema.request.queryParams || (schema.request.queryParams = [])

        for (const a of (action.params || [])) {
            if (a.name) {
                if (onlyName && a.name.toLowerCase() !== onlyName.toLowerCase()) continue

                const ind = params.findIndex(obj => obj.name?.toLowerCase() === a.name.toLowerCase())
                if (ind < 0) {
                    this._recordMutation(mutations, 'query', a.name, undefined, a.value)
                    params.push({ name: a.name, value: a.value })
                    urlObj.searchParams.set(a.name, a.value)
                } else {
                    const before = params[ind].value
                    const after = this.modifyParam(params[ind].name, params[ind].value, a)
                    params[ind].value = after
                    urlObj.searchParams.set(a.name, after)
                    this._recordMutation(mutations, 'query', params[ind].name, before, after)
                }
            } else {
                for (const p of params) {
                    if (onlyName && p.name?.toLowerCase() !== onlyName.toLowerCase()) continue
                    const before = p.value
                    const after = this.modifyParam(p.name, p.value, a)
                    p.value = after
                    urlObj.searchParams.set(p.name, after)
                    this._recordMutation(mutations, 'query', p.name, before, after)
                }
            }
        }

        schema.request.url = urlObj.toString()
        return schema
    }

    // JSON body mutation
    // onlyPath: mutate only this JSON path (atomic mode)
    modifyJsonParams(schema, action, onlyPath = null, mutations = null) {
        const { obj: jsonObj } = this._getJsonBody(schema)
        if (!jsonObj) return schema

        const applyToPath = (path, act) => {
            const { exists, value } = this._getByJsonPath(jsonObj, path)
            const before = exists ? value : undefined
            const after = this.modifyParam(path, before, act) // use path as the "name"
            this._setByJsonPath(jsonObj, path, after)
            this._recordMutation(mutations, 'json', path, before, after)
        }

        const hasExplicit = (action.params || []).some(a => a.name)

        if (hasExplicit) {
            for (const a of (action.params || [])) {
                if (!a.name) continue
                if (onlyPath && a.name !== onlyPath) continue
                applyToPath(a.name, a)
            }
        } else {
            const leaves = this._enumerateJsonLeaves(jsonObj)
            for (const leaf of leaves) {
                if (onlyPath && leaf.path !== onlyPath) continue
                for (const a of (action.params || [])) {
                    applyToPath(leaf.path, a)
                }
            }
        }

        if (jsonObj && typeof jsonObj === 'object' && !Array.isArray(jsonObj)) {
            if (!Object.prototype.hasOwnProperty.call(jsonObj, 'ptk_rnd')) {
                jsonObj['ptk_rnd'] = ptk_utils.attackParamId()
            }
        }

        this._persistJsonBody(schema, jsonObj)
        return schema
    }

    // Cookie mutation (atomic or bulk)
    // onlyName: mutate only this cookie (atomic mode)
    modifyCookies(schema, action, onlyName = null, mutations = null) {
        const cookies = this._getCookiesArray(schema)
        const beforeSnapshot = cookies.map(c => ({ name: c.name, value: c.value }))

        // Determine cookie actions
        let cookieActs = []
        const cookieHeaderActs = (action.headers || []).filter(h => (h.name || '').toLowerCase() === 'cookie')
        const cookieHeaderAct = cookieHeaderActs.length ? cookieHeaderActs[0] : null

        if (Array.isArray(action.cookies) && action.cookies.length) {
            cookieActs = action.cookies
        } else if (cookieHeaderAct) {
            // Use header act as a template
            cookieActs = [{ name: onlyName || null, operation: cookieHeaderAct.operation, regex: cookieHeaderAct.regex, position: cookieHeaderAct.position, value: cookieHeaderAct.value }]
        }
        if (!cookieActs.length && !cookieHeaderAct) return schema

        const removeCookie = (cname, reason, beforeValue) => {
            const idx = cookies.findIndex(c => (c.name || '').toLowerCase() === (cname || '').toLowerCase())
            if (idx !== -1) {
                const before = typeof beforeValue !== 'undefined' ? beforeValue : cookies[idx].value
                cookies.splice(idx, 1)
                this._recordMutation(mutations, 'cookie', cname, before, undefined)
            }
        }

        // Apply per-cookie actions
        const apply = (cname, act) => {
            const idx = cookies.findIndex(c => (c.name || '').toLowerCase() === (cname || '').toLowerCase())
            if (idx === -1) {
                if (act.name) {
                    const before = undefined
                    if (act.operation === 'remove') {
                        return
                    }
                    const after = this.modifyParam(act.name, '', act)
                    cookies.push({ name: act.name, value: after })
                    this._recordMutation(mutations, 'cookie', act.name, before, after)
                }
            } else {
                const before = cookies[idx].value
                if (act.operation === 'remove') {
                    const name = cookies[idx].name
                    cookies.splice(idx, 1)
                    this._recordMutation(mutations, 'cookie', name || cname, before, undefined)
                    return
                }
                const after = this.modifyParam(cookies[idx].name, cookies[idx].value, act)
                cookies[idx].value = after
                this._recordMutation(mutations, 'cookie', cookies[idx].name, before, after)
            }
        }

        for (const act of cookieActs) {
            if (act.operation === 'remove' && act.regex && !act.name) {
                const r = new RegExp(act.regex)
                const toRemove = cookies.filter(c => r.test(String(c.value ?? ''))).map(c => c.name)
                for (const cname of toRemove) removeCookie(cname, 'regex')
                continue
            }
            if (act.name) {
                if (onlyName && act.name.toLowerCase() !== onlyName.toLowerCase()) continue
                apply(act.name, act)
            } else if (onlyName) {
                apply(onlyName, act)
            } else {
                for (const c of cookies) apply(c.name, act)
            }
        }

        // Rebuild Cookie header from array
        let headerAfter = this._stringifyCookies(cookies)
        this._setHeader(schema, 'Cookie', headerAfter)

        // ---- Fallback diff for header-level regex attacks ----
        // If no cookie-level mutation recorded BUT there's a Cookie header act,
        // apply the header regex to the whole header and diff to identify cookie name(s).
        const hasCookieMutations = (mutations || []).some(m => m.location === 'cookie')
        if (!hasCookieMutations && cookieHeaderAct) {
            const headerBefore = this._stringifyCookies(beforeSnapshot)
            const headerModified = this.modifyParam('Cookie', headerBefore, cookieHeaderAct)
            if (headerModified !== headerBefore) {
                const afterArr = this._parseCookieHeader(headerModified)
                const mapBefore = new Map(beforeSnapshot.map(c => [c.name, c.value]))
                const mapAfter = new Map(afterArr.map(c => [c.name, c.value]))

                for (const [k, vAfter] of mapAfter.entries()) {
                    const vBefore = mapBefore.get(k)
                    if (vBefore !== vAfter) {
                        this._recordMutation(mutations, 'cookie', k, vBefore, vAfter)
                    }
                }
                // Optionally detect removals (not typical for JWT-none), uncomment if needed:
                // for (const [k, vBefore] of mapBefore.entries()) {
                //     if (!mapAfter.has(k)) this._recordMutation(mutations, 'cookie', k, vBefore, undefined)
                // }

                // Persist parsed cookies + header
                schema.request.cookies = afterArr
                this._setHeader(schema, 'Cookie', headerModified)
            }
        }

        return schema
    }

    modifyHeaders(schema, action, onlyName = null, mutations = null) {
        const headers = this._headersArray(schema)

        for (const a of (action.headers || [])) {
            // Skip 'Cookie' here; handled by modifyCookies to track per-cookie names
            if ((a.name || '').toLowerCase() === 'cookie') continue

            if (a.operation === 'remove') {
                if (a.name) {
                    for (let i = headers.length - 1; i >= 0; i--) {
                        if ((headers[i].name || '').toLowerCase() === a.name.toLowerCase()) {
                            const before = headers[i].value
                            const name = headers[i].name
                            headers.splice(i, 1)
                            this._recordMutation(mutations, 'header', name, before, undefined)
                        }
                    }
                    continue
                }
                if (a.regex) {
                    const r = new RegExp(a.regex)
                    for (let i = headers.length - 1; i >= 0; i--) {
                        if (r.test(String(headers[i].value ?? ''))) {
                            const before = headers[i].value
                            const name = headers[i].name
                            headers.splice(i, 1)
                            this._recordMutation(mutations, 'header', name, before, undefined)
                        }
                    }
                    continue
                }
            }

            if (a.name) {
                if (onlyName && a.name.toLowerCase() !== onlyName.toLowerCase()) continue

                const ind = headers.findIndex(obj => obj.name?.toLowerCase() === a.name.toLowerCase())
                if (ind < 0) {
                    this._recordMutation(mutations, 'header', a.name, undefined, a.value)
                    headers.push({ name: a.name, value: a.value })
                } else {
                    const before = headers[ind].value
                    const after = this.modifyParam(headers[ind].name, headers[ind].value, a)
                    headers[ind].value = after
                    this._recordMutation(mutations, 'header', headers[ind].name, before, after)
                }
            } else {
                for (const h of headers) {
                    if (onlyName && h.name?.toLowerCase() !== onlyName.toLowerCase()) continue
                    const before = h.value
                    const after = this.modifyParam(h.name, h.value, a)
                    h.value = after
                    this._recordMutation(mutations, 'header', h.name, before, after)
                }
            }
        }
        return schema
    }

    modifyUrl(schema, action) {
        const url = this._toURL(schema.request.url, schema.request.baseUrl)
        schema.request.url = url.origin + action.url.value
        return schema
    }

    /* ---------------- attack preparation ---------------- */

    prepareAttack(a) {
        const attack = this._clone(a)
        const rnd = ptk_utils.attackParamId()

        if (attack.action?.random)
            attack.action.random = rnd

        const rep = (s) => (typeof s === 'string' ? s.replaceAll('%%random%%', rnd) : s)

        for (const arr of ['props', 'params', 'headers', 'cookies']) {
            for (const item of (attack.action?.[arr] || [])) {
                if (typeof item.value === 'string') item.value = rep(item.value)
            }
        }

        if (attack?.regex) {
            const asString = JSON.stringify(attack.regex)
            attack.regex = JSON.parse(asString.replaceAll('%%random%%', rnd))
        }

        if (attack?.spa) {
            const asString = JSON.stringify(attack.spa)
            attack.spa = JSON.parse(asString.replaceAll('%%random%%', rnd))
        }

        return attack
    }

    /* ---------------- build attacks ---------------- */

    // Build N per-param attacks (default) or 1 bulk attack; can be overridden via options.mode
    buildAttacks(schema, attack, options = {}) {
        const prepared = this.prepareAttack(attack)
        if (!prepared?.action) {
            console.warn('[PTK DAST] Skipping attack without action definition', {
                module: this.id || this.name || 'unknown-module',
                attack: attack?.id || attack?.name || 'unknown-attack'
            })
            return []
        }
        const forcedMode = options?.mode
        const forcedAtomic = (typeof options?.atomic === 'boolean') ? options.atomic : null
        let atomic = prepared.atomic !== false   // <-- keep exactly as you asked

        if (forcedMode === 'bulk') {
            atomic = false
        } else if (forcedMode === 'per-param') {
            atomic = true
        } else if (forcedAtomic !== null) {
            atomic = forcedAtomic
        }
        const attacks = []

        if (!atomic) {
            attacks.push(this.buildAttack(schema, prepared)) // bulk mode
            return attacks
        }

        // Atomic: one attack per target (query/body/header/json/cookie)
        const targets = this._getParamTargets(schema, prepared.action)

        // If no param/header/json targets (e.g., only props/url), fall back to single
        if (!targets.length && !prepared.action.params && !prepared.action.headers && !prepared.action.cookies) {
            attacks.push(this.buildAttack(schema, prepared))
            return attacks
        }

        for (const tgt of targets) {
            const _schema = this._clone(schema)
            const mutations = []

            // Apply URL and props first (shared per atomic attack)
            if (prepared.action.url) this.modifyUrl(_schema, prepared.action)
            if (prepared.action.props) this.modifyProps(_schema, prepared.action)

            // Apply only the selected target, while tracking before/after
            if (tgt.location === 'query') {
                if (prepared.action.params?.length) {
                    this.modifyGetParams(_schema, prepared.action, tgt.name, mutations)
                }
            } else if (tgt.location === 'body') {
                if (prepared.action.params?.length) {
                    this.modifyPostParams(_schema, prepared.action, tgt.name, mutations)
                }
            } else if (tgt.location === 'json') {
                if (prepared.action.params?.length) {
                    this.modifyJsonParams(_schema, prepared.action, tgt.name, mutations)
                }
            } else if (tgt.location === 'cookie') {
                if ((prepared.action.cookies && prepared.action.cookies.length) ||
                    (prepared.action.headers || []).some(h => (h.name || '').toLowerCase() === 'cookie')) {
                    this.modifyCookies(_schema, prepared.action, tgt.name, mutations)
                }
            } else if (tgt.location === 'header') {
                if (prepared.action.headers?.length) {
                    this.modifyHeaders(_schema, prepared.action, tgt.name, mutations)
                }
            }

            // Cookie sync (ensure schema.request.cookies aligned with header)
            const cookieIndex = (_schema.request.headers || []).findIndex(i => (i.name || '').toLowerCase() === 'cookie')
            if (cookieIndex > -1) {
                const cookieStr = _schema.request.headers[cookieIndex].value || ''
                const parsed = this._parseCookieHeader(cookieStr)
                _schema.request.cookies = parsed
            }

            // Attach metadata for reporting
            _schema.metadata = _schema.metadata || {}
            _schema.metadata.mutations = mutations
            if (!mutations.length) {
                continue
            }
            _schema.metadata.attacked = mutations[0]

            attacks.push(_schema)
        }

        return attacks
    }

    // Legacy single attack builder; used for bulk mode and for non-param/url/props-only cases
    buildAttack(schema, attack) {
        let _schema = this._clone(schema)
        const mutations = []

        // modify url
        if (attack.action.url) {
            _schema = this.modifyUrl(_schema, attack.action)
        }

        // modify properties, eg method or scheme
        if (attack.action.props) {
            _schema = this.modifyProps(_schema, attack.action)
        }

        // modify params (JSON or form or query)
        if (attack.action.params) {
            const method = (_schema.request.method || 'GET').toUpperCase()
            const hasBodyMethod = ["POST", "PUT", "DELETE", "PATCH"].includes(method)
            const { obj: jsonObj } = this._getJsonBody(_schema)

            if (hasBodyMethod && jsonObj) {
                _schema = this.modifyJsonParams(_schema, attack.action, null, mutations)
            } else if (hasBodyMethod) {
                _schema = this.modifyPostParams(_schema, attack.action, null, mutations)
            } else {
                _schema = this.modifyGetParams(_schema, attack.action, null, mutations)
            }
        }

        // modify cookies first (from action.cookies or headers['Cookie'])
        if ((attack.action.cookies && attack.action.cookies.length) ||
            (attack.action.headers || []).some(h => (h.name || '').toLowerCase() === 'cookie')) {
            _schema = this.modifyCookies(_schema, attack.action, null, mutations)
        }

        // modify other headers (Cookie excluded inside)
        if (attack.action.headers) {
            _schema = this.modifyHeaders(_schema, attack.action, null, mutations)
        }

        // Cookie sync (ensure schema.request.cookies matches header)
        const cookieIndex = (_schema.request.headers || []).findIndex((item) => (item.name || '').toLowerCase() === 'cookie')
        if (cookieIndex > -1) {
            const cookieStr = _schema.request.headers[cookieIndex].value || ''
            _schema.request.cookies = this._parseCookieHeader(cookieStr)
        }

        _schema.metadata = _schema.metadata || {}
        _schema.metadata.mutations = mutations
        if (mutations.length) {
            _schema.metadata.attacked = mutations[0]
        }


        // If exactly one cookie changed in bulk mode, set attacked to that cookie to aid reporting.
        const cookieMuts = mutations.filter(m => m.location === 'cookie' && m.before !== m.after)
        if (cookieMuts.length === 1) {
            _schema.metadata.attacked = cookieMuts[0]
        }
        // If no mutation was recorded (e.g., regex didn’t match), fall back to a generic target reference.
        if (!_schema.metadata.attacked) {
            _schema.metadata.attacked = {
                location: 'unknown',
                name: ''
            }
        }

        return _schema
    }

    /* ---------------- validation ---------------- */

    validateAttackConditions(attack, original) {
        return jsonLogic.apply(attack.metadata?.condition, { "original": original, "attack": attack, "module": this })
    }

    validateAttack(executed, original) {
        if (executed) {
            const success = jsonLogic.apply(executed.metadata?.validation?.rule, { "attack": executed, "original": original, "module": this })
            let proof = ""
            if (executed.metadata?.validation?.proof && success) {
                proof = jsonLogic.apply(executed.metadata.validation.proof, { "attack": executed, "original": original, "module": this })
            }
            if (success && !proof) {
                proof = this._buildBaselineProof(executed, original)
            }
            return {
                "success": !!success,
                "proof": proof,
                "detector": executed.metadata?.validation?.type || executed.metadata?.validation?.detector || null,
                "match": proof || null
            }
        }
        return { "success": false, "proof": "" }
    }

    _buildBaselineProof(attack, original) {
        const attackRes = attack?.response || {}
        const origRes = original?.response || {}
        const statusMatch = attackRes?.statusCode != null && origRes?.statusCode != null
            && Number(attackRes.statusCode) === Number(origRes.statusCode)
        const bodyMatch = typeof attackRes?.body === "string" && typeof origRes?.body === "string"
            && attackRes.body === origRes.body
        if (statusMatch && bodyMatch) {
            return "Attack response matches baseline (status and body)."
        }
        if (statusMatch) {
            return "Attack response status matches baseline."
        }
        if (bodyMatch) {
            return "Attack response body matches baseline."
        }
        return ""
    }
}
