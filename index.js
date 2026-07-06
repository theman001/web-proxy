const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const dns = require('dns').promises;
const net = require('net');
const path = require('path');

const app = express();

// ---------------------------------------------------------------------------
// Target URL parsing: /example.com/page -> URL('https://example.com/page')
// ---------------------------------------------------------------------------

// Explicit scheme in the path (tolerating a missing/collapsed slash, e.g.
// "/https:/example.com" - browsers' address bars sometimes produce that when
// pasting/typing these URLs). Unambiguous, so this always wins when present.
function parseExplicitTarget(rawUrl) {
    const path = rawUrl.replace(/^\/+/, '');
    if (!path) return null;
    const withScheme = path.match(/^(https?):\/*(.+)$/i);
    if (!withScheme) return null;
    try {
        return new URL(`${withScheme[1]}://${withScheme[2]}`);
    } catch {
        return null;
    }
}

// No scheme at all (e.g. "/claude.ai" or "/www.google.com") - default to https.
// Only meaningful for a fresh, top-level navigation (see isSameOriginReferer).
function parseBareTarget(rawUrl) {
    const path = rawUrl.replace(/^\/+/, '');
    if (!path || /^https?:\/*/i.test(path)) return null;
    try {
        return new URL(`https://${path}`);
    } catch {
        return null;
    }
}

function isSameOriginReferer(refererHeader, req) {
    if (!refererHeader) return false;
    try {
        return new URL(refererHeader).host === req.headers.host;
    } catch {
        return false;
    }
}

// A proxied page's own JS makes absolute-path requests at runtime (fetch('/api/x'),
// or a static resource the page never had rewritten) that carry no embedded target.
// Recover it from the Referer, since the browser still sends a same-origin Referer
// (the page and the follow-up request both live on this proxy's origin).
//
// Only trust an EXPLICIT scheme in the referer's path here. SPA client-side
// routing (history.pushState) can rewrite the iframe's own address bar to a
// bare absolute path (e.g. "/logout") with no request to us ever happening -
// if we treated that bare path as an established target, the first path
// segment ("logout") would get taken as a hostname. An explicit-scheme
// referer path, by contrast, can only exist because we ourselves put it
// there (direct entry or one of our own redirects), so it's safe to trust.
function parseTargetFromReferer(refererHeader, currentPath) {
    if (!refererHeader) return null;
    try {
        const refererUrl = new URL(refererHeader);
        const embedded = parseExplicitTarget(refererUrl.pathname + refererUrl.search);
        if (!embedded) return null;
        return new URL(embedded.origin + currentPath);
    } catch {
        return null;
    }
}

// Referer is not a reliable fallback on its own - a proxied page can send
// Referrer-Policy: origin (or no-referrer), which strips the path (or the
// whole header) we rely on to recover the embedded target. This cookie is a
// second, self-controlled memory of "what site is this session currently on"
// that doesn't depend on the proxied page's own policy.
const LAST_TARGET_COOKIE = '__px_target';

function getCookie(req, name) {
    const header = req.headers.cookie;
    if (!header) return null;
    for (const part of header.split(';')) {
        const idx = part.indexOf('=');
        if (idx === -1) continue;
        if (part.slice(0, idx).trim() === name) {
            try {
                return decodeURIComponent(part.slice(idx + 1).trim());
            } catch {
                return null;
            }
        }
    }
    return null;
}

function rememberTarget(res, target) {
    res.cookie(LAST_TARGET_COOKIE, target.origin, { httpOnly: true, sameSite: 'lax', path: '/' });
}

// Raw Set-Cookie string, for use inside onProxyRes: node-http-proxy calls
// res.writeHead(status, proxyRes.headers) after that hook runs, which
// replaces (not merges) any 'set-cookie' header we'd set earlier via
// res.cookie() whenever the upstream response also sets cookies. So for
// proxied responses this has to be folded into proxyRes.headers itself.
function trackingCookieHeader(target) {
    return `${LAST_TARGET_COOKIE}=${encodeURIComponent(target.origin)}; Path=/; HttpOnly; SameSite=Lax`;
}

function parseTargetFromCookie(req) {
    const origin = getCookie(req, LAST_TARGET_COOKIE);
    if (!origin) return null;
    try {
        return new URL(origin + req.url);
    } catch {
        return null;
    }
}

// ---------------------------------------------------------------------------
// SSRF guard: block requests aimed at private/loopback/link-local addresses.
// Best-effort only (DNS is re-resolved at request time, not pinned to the
// connection), so this does not fully close DNS-rebinding style attacks.
// ---------------------------------------------------------------------------

function isPrivateIpv4(ip) {
    const [a, b] = ip.split('.').map(Number);
    return (
        a === 10 ||
        a === 127 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 169 && b === 254) // link-local, includes cloud metadata 169.254.169.254
    );
}

function isPrivateIp(ip) {
    if (net.isIPv4(ip)) return isPrivateIpv4(ip);
    if (net.isIPv6(ip)) {
        const lower = ip.toLowerCase();
        if (lower === '::1') return true;
        if (lower.startsWith('fe80:')) return true;
        if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
        const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
        if (mapped) return isPrivateIpv4(mapped[1]);
    }
    return false;
}

async function assertPublicTarget(targetUrl) {
    const hostname = targetUrl.hostname.toLowerCase();
    if (hostname === 'localhost' || hostname === '0.0.0.0') {
        throw new Error('blocked hostname');
    }
    if (net.isIP(hostname)) {
        if (isPrivateIp(hostname)) throw new Error('blocked ip');
        return;
    }
    const records = await dns.lookup(hostname, { all: true }).catch(() => []);
    for (const { address } of records) {
        if (isPrivateIp(address)) throw new Error('blocked resolved ip');
    }
}

function resolveAndEmbed(raw, base) {
    if (!raw) return raw;
    const trimmed = raw.trim();
    if (/^(#|mailto:|tel:|javascript:|data:|blob:)/i.test(trimmed)) return raw;
    try {
        return `/${new URL(trimmed, base).toString()}`;
    } catch {
        return raw;
    }
}

// ---------------------------------------------------------------------------
// Cookies: keep forwarding them (auth/session flows), but strip Domain so
// they become host-only, and scope Path per target so cookies from different
// proxied sites (which all share this one proxy host) don't collide.
// ---------------------------------------------------------------------------

function rewriteCookie(cookieStr, target) {
    const [nameValue, ...attrs] = cookieStr.split(';').map((p) => p.trim());
    const kept = attrs.filter((a) => !/^domain=/i.test(a) && !/^path=/i.test(a));
    kept.push(`Path=/${target.origin}`);
    return [nameValue, ...kept].join('; ');
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Simple mode: a toggle back to the original single-target behavior (fixed
// destination, redirects followed server-side, no path/cookie rewriting).
// There's exactly one shared target at a time - fine for local single-user
// use, but note it's not per-tab/session.
//
// Critically, this must be mounted at the true root with NO path prefix.
// Sites with client-side routing (React Router etc.) match their own routes
// against window.location.pathname - a prefix like "/__simple/login" doesn't
// match a route registered for "/login", so the app's own router renders
// its "not found" fallback even though every request behind the scenes
// succeeded. The original single-target proxy never had this problem
// because it was mounted at "/" with zero rewriting, so this needs to
// behave identically once engaged: the browser's own address bar must show
// the exact same path the target site would show, with nothing extra.
// ---------------------------------------------------------------------------

let simpleModeTarget = null;

app.get('/__mode', async (req, res) => {
    const { mode, target } = req.query;
    if (mode === 'smart') {
        simpleModeTarget = null;
        return res.status(200).send('smart mode');
    }
    if (mode === 'simple') {
        if (!target) return res.status(400).send('target query param required');
        let parsed;
        try {
            parsed = new URL(/^https?:\/\//i.test(target) ? target : `https://${target}`);
        } catch {
            return res.status(400).send('Invalid target URL');
        }
        try {
            await assertPublicTarget(parsed);
        } catch {
            return res.status(403).send('Target host is not allowed.');
        }
        simpleModeTarget = parsed.origin;
        return res.status(200).send(`simple mode -> ${simpleModeTarget}`);
    }
    return res.status(400).send('mode must be "simple" or "smart"');
});

const simpleModeProxy = createProxyMiddleware({
    router: () => simpleModeTarget,
    changeOrigin: true,
    autoRewrite: true,
    followRedirects: true,
    cookieDomainRewrite: '',
    // Deliberately no `ws: true` here - that makes http-proxy-middleware
    // auto-subscribe to the server's 'upgrade' event on its own, which with
    // two proxy instances (this one and smartModeProxy) both racing to
    // handle every upgrade would crash. We call .upgrade() ourselves below
    // (see server.on('upgrade', ...)), which only works when it hasn't
    // auto-subscribed.
    onProxyRes: (proxyRes) => {
        if (proxyRes.headers['location']) {
            console.log('Redirect detected:', proxyRes.headers['location']);
        }
        proxyRes.headers['access-control-allow-origin'] = '*';
    },
    onError: (err, _req, res) => {
        res.status(502).send(`Bad gateway: ${err.message}`);
    },
});

// While simple mode is engaged, it owns every path at the root - exactly
// like the original proxy, which had nothing else registered at all.
app.use((req, res, next) => {
    if (!simpleModeTarget) return next();
    if (req.url === '/__mode' || req.url.startsWith('/__mode?')) return next();
    return simpleModeProxy(req, res, next);
});

app.get('/', (_req, res) => {
    res.sendFile(path.join(__dirname, 'shell.html'));
});

// Avoid the browser's automatic favicon request being misread as a proxy
// target (e.g. bare-domain fallback treating "favicon.ico" as a hostname).
// Only reachable in smart mode - simple mode claims every path above.
app.get('/favicon.ico', (_req, res) => res.status(204).end());

app.use((req, res, next) => {
    // 1) Explicit scheme in the path is unambiguous - always wins.
    const explicitTarget = parseExplicitTarget(req.url);
    if (explicitTarget) {
        if (!['http:', 'https:'].includes(explicitTarget.protocol)) {
            return res.status(400).send('Invalid target URL. Usage: /<target-url>, e.g. /https://example.com/page');
        }
        req.proxyTarget = explicitTarget;
        return next();
    }

    // 2) Bare/ambiguous path (e.g. "/api/x", "/logout") while already browsing
    // a proxied page - it's almost certainly that page's own link click,
    // asset, fetch call or redirect target, not the user typing a new bare
    // domain. Resolve against whatever site this session is currently on
    // instead of treating "api"/"logout" as a hostname. Prefer the Referer
    // (works even across concurrent tabs/sessions), but fall back to our own
    // "last known target" cookie since a page can send Referrer-Policy:
    // origin/no-referrer and strip exactly the info we need from it.
    const inSessionTarget =
        (isSameOriginReferer(req.headers.referer, req) && parseTargetFromReferer(req.headers.referer, req.url)) ||
        parseTargetFromCookie(req);
    if (inSessionTarget) {
        rememberTarget(res, inSessionTarget);
        // 307/308 preserve method and body, unlike 302/303 - important for API calls.
        return res.redirect(307, `/${inSessionTarget.toString()}`);
    }

    // 3) Fresh navigation with a bare domain (e.g. typed "/claude.ai" directly).
    const bareTarget = parseBareTarget(req.url);
    if (!bareTarget) {
        return res.status(400).send('Invalid target URL. Usage: /<target-url>, e.g. /https://example.com/page');
    }
    req.proxyTarget = bareTarget;
    next();
});

app.use(async (req, res, next) => {
    try {
        await assertPublicTarget(req.proxyTarget);
        next();
    } catch {
        res.status(403).send('Target host is not allowed.');
    }
});

const smartModeProxy = createProxyMiddleware({
    changeOrigin: true,
    followRedirects: false,
    // See the comment on simpleModeProxy - no `ws: true` here either, for
    // the same reason.
    router: (req) => req.proxyTarget.origin,
    pathRewrite: (_path, req) => req.proxyTarget.pathname + req.proxyTarget.search,
    onProxyRes: (proxyRes, req) => {
        const target = req.proxyTarget;

        const siteCookies = (proxyRes.headers['set-cookie'] || []).map((c) => rewriteCookie(c, target));
        proxyRes.headers['set-cookie'] = [...siteCookies, trackingCookieHeader(target)];
        if (proxyRes.headers['location']) {
            proxyRes.headers['location'] = resolveAndEmbed(proxyRes.headers['location'], target);
        }
        proxyRes.headers['access-control-allow-origin'] = '*';
        delete proxyRes.headers['content-security-policy'];
        delete proxyRes.headers['content-security-policy-report-only'];
        delete proxyRes.headers['x-frame-options'];
        // This origin is shared by every site proxied through here - honoring
        // Clear-Site-Data would wipe storage for all of them, not just the
        // target that asked for it.
        delete proxyRes.headers['clear-site-data'];
    },
    onError: (err, req, res) => {
        res.status(502).send(`Bad gateway: ${err.message}`);
    },
});
app.use(smartModeProxy);

const server = app.listen(3000, () => {
    console.log('Proxy server is running on http://localhost:3000');
});

// WebSocket upgrade requests hit the raw http.Server directly, bypassing
// Express's middleware stack entirely - so the routing logic (and the SSRF
// guard) above never runs for them. Re-derive the target here using the
// same rules, re-check it, before handing off to the owning proxy instance.
server.on('upgrade', async (req, socket, head) => {
    // simpleModeTarget was already vetted when it was set via /__mode. It
    // owns every path (mirroring the regular-request middleware above), so
    // check it first.
    if (simpleModeTarget && req.url !== '/__mode' && !req.url.startsWith('/__mode?')) {
        return simpleModeProxy.upgrade(req, socket, head);
    }

    const target =
        parseExplicitTarget(req.url) ||
        (isSameOriginReferer(req.headers.referer, req) && parseTargetFromReferer(req.headers.referer, req.url)) ||
        parseTargetFromCookie(req);
    if (!target) return socket.destroy();
    try {
        await assertPublicTarget(target);
    } catch {
        return socket.destroy();
    }
    req.proxyTarget = target;
    smartModeProxy.upgrade(req, socket, head);
});
