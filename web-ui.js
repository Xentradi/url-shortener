import express from 'express';
import crypto from 'crypto';
import {rateLimit} from 'express-rate-limit';

export function registerWebUi({
  app,
  logger,
  Url,
  ApiKey,
  spamLimiter,
  authenticateKeyByValue,
  hasScope,
  parseExpirationDate,
  sanitizeUrl,
  validateUrl,
  isExpired,
  getExpirationPurgeAt,
  generateUniqueShortId,
  maxTtlDays,
  maxActiveLinksPerKey,
  shortIdLength,
  uiAssetVersion,
  apiHost,
  isWebHost,
  isLocalHost,
  requireWebHost,
  isValidObjectId,
  uiSessionCookie,
  uiSessionRememberSeconds,
  uiSessionShortSeconds,
  uiSessionRememberMaxSeconds,
  uiSessionShortMaxSeconds,
  uiSessionSecret,
}) {
  const MAX_TTL_DAYS = Number(maxTtlDays);
  const MAX_ACTIVE_LINKS_PER_KEY = Number(maxActiveLinksPerKey);
  const SHORT_ID_LENGTH = Number(shortIdLength);
  const UI_ASSET_VERSION = String(uiAssetVersion || process.env.UI_ASSET_VERSION || '20260206');
  const API_HOST = String(apiHost || 'api.x3n.us').toLowerCase();
  const UI_SESSION_COOKIE = String(uiSessionCookie || process.env.UI_SESSION_COOKIE || 'ui_session');
  const UI_SESSION_REMEMBER_SECONDS = Number(
    uiSessionRememberSeconds || process.env.UI_SESSION_REMEMBER_SECONDS || 60 * 60 * 24 * 31
  );
  const UI_SESSION_SHORT_SECONDS = Number(
    uiSessionShortSeconds || process.env.UI_SESSION_SHORT_SECONDS || 60 * 60 * 12
  );
  const UI_SESSION_REMEMBER_MAX_SECONDS = Number(
    uiSessionRememberMaxSeconds || process.env.UI_SESSION_REMEMBER_MAX_SECONDS || 60 * 60 * 24 * 90
  );
  const UI_SESSION_SHORT_MAX_SECONDS = Number(
    uiSessionShortMaxSeconds || process.env.UI_SESSION_SHORT_MAX_SECONDS || 60 * 60 * 24 * 7
  );
  const UI_SESSION_SECRET = String(
    uiSessionSecret
    || process.env.UI_SESSION_SECRET
    || process.env.DOCS_SESSION_SECRET
    || process.env.API_KEY_PEPPER
    || process.env.ADMIN_NUKE_KEY
    || crypto.randomBytes(32).toString('hex')
  );

  const uiLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 25,
    handler: (req, res) => {
      return redirectUiWithMessage(res, 'error', 'Too many login attempts. Please try again later.');
    },
  });
  app.use('/ui-assets', requireWebHost, express.static('public', {
    maxAge: 0,
    etag: true,
    setHeaders: (res) => {
      res.setHeader('Cache-Control', 'no-store, max-age=0');
    },
  }));
  
  app.get('/', uiSessionOptionalAuth, async (req, res, next) => {
    if (!isWebHost(req)) {
      return next();
    }
  
    const errorMessage = readQueryValue(req.query.error);
    const successMessage = readQueryValue(req.query.success);
    const createdShortId = readQueryValue(req.query.created);
  
    if (!req.uiAuth) {
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).send(renderUiLoginPage({
        errorMessage,
        successMessage,
      }));
    }
  
    const apiKeyId = req.uiAuth.apiKey?._id || null;
    if (!apiKeyId) {
      clearUiSessionCookie(res);
      return redirectUiWithMessage(res, 'error', 'Session is invalid. Please log in again.');
    }
  
    try {
      const [myUrls, adminData] = await Promise.all([
        Url.find({apiKeyId, deletedAt: null})
          .sort({createdAt: -1})
          .limit(200)
          .lean(),
        req.uiAuth.isAdmin ? fetchUiAdminData() : Promise.resolve(null),
      ]);
  
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).send(renderUiDashboardPage({
        request: req,
        session: req.uiAuth,
        myUrls,
        adminData,
        errorMessage,
        successMessage,
        createdShortId,
      }));
    } catch (error) {
      logger.error('Failed to render shortener UI', {error: String(error)});
      return res.status(500).send(renderUiLoginPage({
        errorMessage: 'Failed to load dashboard',
        successMessage: '',
      }));
    }
  });
  
  app.get('/shorten', (req, res) => {
    if (isWebHost(req)) {
      return res.redirect('/');
    }
    return res.status(404).json({error: 'Not found'});
  });
  
  app.post('/login', requireWebHost, uiLoginLimiter, async (req, res) => {
    const accessKey = String(req.body?.accessKey || '').trim();
    const rememberMe = req.body?.rememberMe === 'on';
  
    if (!accessKey) {
      return redirectUiWithMessage(res, 'error', 'Missing key');
    }
  
    try {
      const keyRecord = await authenticateKeyByValue(accessKey, req);
      if (!keyRecord) {
        return redirectUiWithMessage(res, 'error', 'Invalid key');
      }
  
      const sessionBundle = createUiSession({
        apiKeyId: keyRecord._id?.toString() || '',
        rememberMe,
      });
      setUiSessionCookie(res, sessionBundle.token, sessionBundle.maxAgeSeconds);
      return redirectUiWithMessage(res, 'success', 'Login successful');
    } catch (error) {
      logger.error('Failed to create UI session', {error: String(error)});
      return redirectUiWithMessage(res, 'error', 'Failed to log in');
    }
  });
  
  app.post('/logout', requireWebHost, uiSessionOptionalAuth, uiSessionRequiredAuth, requireUiCsrf, (req, res) => {
    clearUiSessionCookie(res);
    return redirectUiWithMessage(res, 'success', 'Logged out');
  });
  
  app.post('/create', requireWebHost, spamLimiter, uiSessionOptionalAuth, uiSessionRequiredAuth, requireUiCsrf, async (req, res) => {
    if (!hasScope(req.uiAuth.apiKey, 'shorten:write') && !req.uiAuth.isAdmin) {
      return redirectUiWithMessage(res, 'error', 'This key is missing shorten:write scope');
    }
  
    let originalUrl = req.body?.originalUrl;
    if (!originalUrl) {
      return redirectUiWithMessage(res, 'error', 'Missing original URL');
    }
  
    originalUrl = sanitizeUrl(String(originalUrl));
    const validation = validateUrl(originalUrl, {blockHost: req.hostname});
    if (!validation.ok) {
      return redirectUiWithMessage(res, 'error', validation.error);
    }
  
    const rawExpirationInput = readFormValue(req.body?.expirationDate);
    const hasExpiration = rawExpirationInput !== undefined;
    const canUseExtendedTtl = req.uiAuth.isAdmin
      || hasScope(req.uiAuth.apiKey, 'ttl:extended')
      || hasScope(req.uiAuth.apiKey, 'ttl:*');
    const expirationResult = parseExpirationDate(rawExpirationInput, {
      allowIndefinite: true,
      applyDefault: !hasExpiration,
      maxDays: canUseExtendedTtl ? null : MAX_TTL_DAYS,
    });
    if (!expirationResult.ok) {
      return redirectUiWithMessage(res, 'error', expirationResult.error);
    }
    const expirationDate = expirationResult.value;
  
    try {
      const existing = await Url.findOne({
        originalUrl,
        apiKeyId: req.uiAuth.apiKey._id,
        deletedAt: null,
      });
      if (existing) {
        if (isExpired(existing.expirationDate)) {
          existing.expirationDate = expirationDate;
          existing.purgeAt = getExpirationPurgeAt(expirationDate);
          await existing.save();
        }
        return redirectUiAfterCreate(res, existing.shortId, 'Reused existing short URL');
      }
  
      const now = new Date();
      const activeLinkCount = await Url.countDocuments({
        apiKeyId: req.uiAuth.apiKey._id,
        deletedAt: null,
        $or: [{expirationDate: null}, {expirationDate: {$gt: now}}],
      });
      if (activeLinkCount >= MAX_ACTIVE_LINKS_PER_KEY) {
        return redirectUiWithMessage(res, 'error', 'Active link limit reached for this API key');
      }
  
      const shortId = await generateUniqueShortId(SHORT_ID_LENGTH);
      const newUrl = await Url.create({
        shortId,
        originalUrl,
        expirationDate,
        purgeAt: getExpirationPurgeAt(expirationDate),
        apiKeyId: req.uiAuth.apiKey._id,
      });
      return redirectUiAfterCreate(res, newUrl.shortId, 'Short URL created');
    } catch (error) {
      logger.error('Failed to create URL from UI', {error: String(error)});
      return redirectUiWithMessage(res, 'error', 'Failed to create short URL');
    }
  });
  app.get(`/:shortId([A-Za-z0-9_-]{${SHORT_ID_LENGTH}})`, async (req, res) => {
    if (!isWebHost(req)) {
      return res.status(404).json({error: 'Not found'});
    }
    const {shortId} = req.params;
    try {
      const urlRecord = await Url.findOne({shortId, deletedAt: null});
  
      if (!urlRecord) {
        return res.status(404).json({error: 'URL not found'});
      }
  
      if (isExpired(urlRecord.expirationDate)) {
        return res.status(410).json({error: 'URL expired'});
      }
  
      await Url.updateOne(
        {_id: urlRecord._id},
        {$inc: {clicks: 1}, $set: {lastClickAt: new Date()}}
      );
      return res.redirect(urlRecord.originalUrl);
  
    } catch (error) {
      logger.error('Error retrieving URL', {error: String(error)});
      res.status(500).json({error: 'Error redirecting URL'});
    }
  })
  function timingSafeEqual(a, b) {
    const aBuf = Buffer.from(String(a));
    const bBuf = Buffer.from(String(b));
    if (aBuf.length !== bBuf.length) {
      return false;
    }
    return crypto.timingSafeEqual(aBuf, bBuf);
  }
  
  function base64urlEncode(value) {
    return Buffer.from(String(value), 'utf8').toString('base64url');
  }
  
  function parseCookies(header) {
    const result = {};
    if (!header) return result;
    const parts = String(header).split(';');
    for (const part of parts) {
      const index = part.indexOf('=');
      if (index <= 0) continue;
      const key = part.slice(0, index).trim();
      let value = part.slice(index + 1).trim();
      try {
        value = decodeURIComponent(value);
      } catch {
        continue;
      }
      if (key) result[key] = value;
    }
    return result;
  }
  async function fetchUiAdminData() {
    const now = new Date();
    const twoYears = new Date();
    twoYears.setFullYear(twoYears.getFullYear() + 2);
  
    const [statsCounts, apiKeys, recentUrls] = await Promise.all([
      Promise.all([
        Url.countDocuments({}),
        Url.countDocuments({deletedAt: {$ne: null}}),
        Url.countDocuments({deletedAt: null, expirationDate: {$lte: now}}),
        Url.countDocuments({
          deletedAt: null,
          $or: [{expirationDate: null}, {expirationDate: {$gt: now}}],
        }),
        Url.countDocuments({
          deletedAt: null,
          $or: [{expirationDate: null}, {expirationDate: {$gt: twoYears}}],
        }),
        Url.countDocuments({purgeAt: {$ne: null}}),
      ]),
      ApiKey.find({}, '-keyHash')
        .sort({createdAt: -1})
        .limit(50)
        .lean(),
      Url.find({deletedAt: null})
        .sort({createdAt: -1})
        .limit(100)
        .lean(),
    ]);
  
    return {
      stats: {
        total: statsCounts[0],
        deleted: statsCounts[1],
        expired: statsCounts[2],
        active: statsCounts[3],
        longTtl: statsCounts[4],
        purgeScheduled: statsCounts[5],
      },
      apiKeys,
      recentUrls,
    };
  }
  
  async function uiSessionOptionalAuth(req, res, next) {
    const session = getUiSession(req);
    if (!session) {
      return next();
    }
  
    if (!session.apiKeyId || !isValidObjectId(session.apiKeyId) || !session.csrfToken) {
      clearUiSessionCookie(res);
      return next();
    }
  
    try {
      const keyRecord = await ApiKey.findOne({_id: session.apiKeyId, active: true});
      if (!keyRecord) {
        clearUiSessionCookie(res);
        return next();
      }
  
      const refreshed = refreshUiSession(session);
      if (refreshed) {
        setUiSessionCookie(res, refreshed.token, refreshed.maxAgeSeconds);
      }
  
      req.uiAuth = {
        apiKey: keyRecord,
        isAdmin: hasScope(keyRecord, 'admin:*'),
        csrfToken: session.csrfToken,
        rememberMe: session.rememberMe,
      };
      req.apiKey = keyRecord;
      res.locals.apiKeyId = keyRecord._id?.toString() || null;
      return next();
    } catch (error) {
      logger.error('Failed to authenticate UI session', {error: String(error)});
      return res.status(500).send(renderUiLoginPage({
        errorMessage: 'Failed to authenticate session',
        successMessage: '',
      }));
    }
  }
  
  function uiSessionRequiredAuth(req, res, next) {
    if (!req.uiAuth) {
      return redirectUiWithMessage(res, 'error', 'Please log in');
    }
    return next();
  }
  
  function requireUiCsrf(req, res, next) {
    const expected = req.uiAuth?.csrfToken;
    const provided = String(req.body?.csrfToken || '').trim();
    if (!expected || !provided) {
      return redirectUiWithMessage(res, 'error', 'Session verification failed');
    }
    if (!timingSafeEqual(provided, expected)) {
      return redirectUiWithMessage(res, 'error', 'Session verification failed');
    }
    return next();
  }
  
  function createUiSession({apiKeyId, rememberMe}) {
    const now = Math.floor(Date.now() / 1000);
    const ttlSeconds = rememberMe ? UI_SESSION_REMEMBER_SECONDS : UI_SESSION_SHORT_SECONDS;
    const maxWindowSeconds = rememberMe ? UI_SESSION_REMEMBER_MAX_SECONDS : UI_SESSION_SHORT_MAX_SECONDS;
    const maxExp = now + maxWindowSeconds;
    const payload = {
      apiKeyId,
      rememberMe: Boolean(rememberMe),
      csrfToken: crypto.randomBytes(16).toString('hex'),
      iat: now,
      exp: Math.min(now + ttlSeconds, maxExp),
      maxExp,
    };
  
    return {
      token: encodeUiSession(payload),
      maxAgeSeconds: ttlSeconds,
    };
  }
  
  function refreshUiSession(session) {
    const now = Math.floor(Date.now() / 1000);
    const ttlSeconds = session.rememberMe ? UI_SESSION_REMEMBER_SECONDS : UI_SESSION_SHORT_SECONDS;
    const nextExp = Math.min(now + ttlSeconds, session.maxExp);
    if (nextExp <= session.exp) {
      return null;
    }
  
    const payload = {
      ...session,
      exp: nextExp,
    };
  
    return {
      token: encodeUiSession(payload),
      maxAgeSeconds: Math.max(nextExp - now, 0),
    };
  }
  
  function encodeUiSession(payload) {
    const encodedPayload = base64urlEncode(JSON.stringify(payload));
    const signature = signUiSession(encodedPayload);
    return `${encodedPayload}.${signature}`;
  }
  
  function getUiSession(req) {
    const cookieHeader = req.headers.cookie || '';
    const cookies = parseCookies(cookieHeader);
    const token = cookies[UI_SESSION_COOKIE];
    if (!token) return null;
  
    const [encodedPayload, signature] = token.split('.');
    if (!encodedPayload || !signature) return null;
  
    const expectedSignature = signUiSession(encodedPayload);
    if (!timingSafeEqual(signature, expectedSignature)) {
      return null;
    }
  
    try {
      const json = Buffer.from(encodedPayload, 'base64url').toString('utf8');
      const payload = JSON.parse(json);
      const now = Math.floor(Date.now() / 1000);
      if (!payload?.exp || !payload?.maxExp || now >= Number(payload.exp) || now >= Number(payload.maxExp)) {
        return null;
      }
      return payload;
    } catch {
      return null;
    }
  }
  
  function signUiSession(value) {
    return crypto.createHmac('sha256', UI_SESSION_SECRET).update(value).digest('hex');
  }
  
  function setUiSessionCookie(res, token, maxAgeSeconds) {
    const cookieParts = [
      `${UI_SESSION_COOKIE}=${token}`,
      'Path=/',
      `Max-Age=${Math.max(Number(maxAgeSeconds) || 0, 0)}`,
      'HttpOnly',
      'SameSite=Lax',
    ];
    if (process.env.NODE_ENV === 'production') {
      cookieParts.push('Secure');
    }
    res.setHeader('Set-Cookie', cookieParts.join('; '));
  }
  
  function clearUiSessionCookie(res) {
    const cookieParts = [
      `${UI_SESSION_COOKIE}=`,
      'Path=/',
      'Max-Age=0',
      'HttpOnly',
      'SameSite=Lax',
    ];
    if (process.env.NODE_ENV === 'production') {
      cookieParts.push('Secure');
    }
    res.setHeader('Set-Cookie', cookieParts.join('; '));
  }
  
  function redirectUiWithMessage(res, type, message) {
    const safeType = type === 'success' ? 'success' : 'error';
    const safeMessage = encodeURIComponent(String(message || '').slice(0, 180));
    return res.redirect(`/?${safeType}=${safeMessage}`);
  }
  
  function redirectUiAfterCreate(res, shortId, successMessage) {
    const params = new URLSearchParams();
    params.set('created', shortId);
    params.set('success', successMessage);
    return res.redirect(`/?${params.toString()}`);
  }
  
  function readQueryValue(value) {
    if (Array.isArray(value)) return String(value[0] || '').trim();
    if (value === undefined || value === null) return '';
    return String(value).trim();
  }
  
  function readFormValue(value) {
    if (value === undefined || value === null) return undefined;
    const normalized = String(value).trim();
    return normalized ? normalized : undefined;
  }
  
  function getRequestBaseUrl(req) {
    const forwardedProto = req.headers['x-forwarded-proto'];
    const protocol = forwardedProto
      ? String(forwardedProto).split(',')[0].trim()
      : req.protocol;
    const host = req.get('host');
    return `${protocol}://${host}`;
  }
  
  function getApiDocsUrl(req) {
    if (isLocalHost(req)) {
      return '/docs';
    }
    const forwardedProto = req.headers['x-forwarded-proto'];
    const protocol = forwardedProto
      ? String(forwardedProto).split(',')[0].trim()
      : req.protocol;
    return `${protocol}://${API_HOST}/docs`;
  }
  
  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
  
  function formatDateTime(value) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toISOString().replace('T', ' ').replace('.000Z', ' UTC');
  }
  
  function renderUiLoginPage({errorMessage, successMessage}) {
    const error = errorMessage ? `<div class="ui-alert ui-alert-error">${escapeHtml(errorMessage)}</div>` : '';
    const success = successMessage ? `<div class="ui-alert ui-alert-success">${escapeHtml(successMessage)}</div>` : '';
  
    return `<!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>X3N LinkHub Login</title>
    <link rel="stylesheet" href="/ui-assets/ui.css?v=${encodeURIComponent(UI_ASSET_VERSION)}">
  </head>
  <body class="ui-body">
    <main class="ui-shell ui-shell-login">
      <section class="ui-card">
        <h1>X3N LinkHub</h1>
        <p class="ui-muted">Authenticate with an API key or admin key. The raw key is not stored in browser storage.</p>
        ${error}
        ${success}
        <form method="post" action="/login" class="ui-form">
          <label for="accessKey">Access key</label>
          <input id="accessKey" name="accessKey" type="password" autocomplete="current-password" required>
          <label class="ui-check"><input type="checkbox" name="rememberMe"> Remember me for 31 days</label>
          <button type="submit">Authenticate</button>
        </form>
      </section>
    </main>
  </body>
  </html>`;
  }
  
  function renderUiDashboardPage({
    request,
    session,
    myUrls,
    adminData,
    errorMessage,
    successMessage,
    createdShortId,
  }) {
    const shortenerBase = getRequestBaseUrl(request);
    const apiDocsUrl = getApiDocsUrl(request);
    const roleLabel = session.isAdmin ? 'Admin Session' : 'User Session';
    const roleClass = session.isAdmin ? 'ui-pill-admin' : 'ui-pill-user';
  
    const createdBlock = createdShortId
      ? `<div class="ui-alert ui-alert-success">Latest short URL:
          <a href="/${escapeHtml(encodeURIComponent(createdShortId))}" target="_blank" rel="noopener">
            ${escapeHtml(`${shortenerBase}/${createdShortId}`)}
          </a>
        </div>`
      : '';
    const error = errorMessage ? `<div class="ui-alert ui-alert-error">${escapeHtml(errorMessage)}</div>` : '';
    const success = successMessage ? `<div class="ui-alert ui-alert-success">${escapeHtml(successMessage)}</div>` : '';
  
    const myRows = myUrls.length
      ? myUrls.map((item) => {
        const shortUrl = `${shortenerBase}/${item.shortId}`;
        const expires = item.expirationDate ? formatDateTime(item.expirationDate) : 'Indefinite';
        return `<tr>
          <td><a href="/${escapeHtml(encodeURIComponent(item.shortId))}" target="_blank" rel="noopener">${escapeHtml(shortUrl)}</a></td>
          <td class="ui-break">${escapeHtml(item.originalUrl || '')}</td>
          <td>${escapeHtml(formatDateTime(item.createdAt))}</td>
          <td>${escapeHtml(expires)}</td>
          <td>${escapeHtml(String(item.clicks || 0))}</td>
        </tr>`;
      }).join('')
      : '<tr><td colspan="5" class="ui-muted">No links yet.</td></tr>';
  
    const adminPanels = adminData
      ? renderUiAdminPanels({
        adminData,
        shortenerBase,
        apiDocsUrl,
        csrfToken: session.csrfToken,
      })
      : '';
    const adminScript = session.isAdmin
      ? `<script defer src="/ui-assets/admin-ui.js?v=${encodeURIComponent(UI_ASSET_VERSION)}"></script>`
      : '';
  
    return `<!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>X3N LinkHub Dashboard</title>
    <link rel="stylesheet" href="/ui-assets/ui.css?v=${encodeURIComponent(UI_ASSET_VERSION)}">
  </head>
  <body class="ui-body">
    <main class="ui-shell">
      <header class="ui-topbar">
        <div>
          <h1>X3N LinkHub</h1>
          <p class="ui-muted">Signed in as <strong>${escapeHtml(session.apiKey.name || 'Unnamed key')}</strong></p>
        </div>
        <div class="ui-topbar-actions">
          <span class="ui-pill ${roleClass}">${escapeHtml(roleLabel)}</span>
          <form method="post" action="/logout">
            <input type="hidden" name="csrfToken" value="${escapeHtml(session.csrfToken)}">
            <button type="submit" class="ui-btn-secondary">Log out</button>
          </form>
        </div>
      </header>
  
      ${error}
      ${success}
      ${createdBlock}
  
      <section class="ui-card">
        <h2>Create short URL</h2>
        <form method="post" action="/create" class="ui-form">
          <input type="hidden" name="csrfToken" value="${escapeHtml(session.csrfToken)}">
          <label for="originalUrl">Original URL</label>
          <input id="originalUrl" name="originalUrl" type="url" placeholder="https://example.com/path" required>
          <label for="expirationDate">Expiration (optional)</label>
          <input id="expirationDate" name="expirationDate" type="text" placeholder="ISO datetime, or indefinite">
          <button type="submit">Shorten</button>
        </form>
      </section>
  
      <section class="ui-card">
        <h2>My links</h2>
        <div class="ui-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Short URL</th>
                <th>Original URL</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Clicks</th>
              </tr>
            </thead>
            <tbody>${myRows}</tbody>
          </table>
        </div>
      </section>
  
      ${adminPanels}
    </main>
    ${adminScript}
  </body>
  </html>`;
  }
  
  function renderUiAdminPanels({adminData, shortenerBase, apiDocsUrl, csrfToken}) {
    const stats = adminData.stats;
    const recentRows = adminData.recentUrls.length
      ? adminData.recentUrls.map((item) => {
        const shortId = String(item.shortId || '');
        const shortUrl = `${shortenerBase}/${shortId}`;
        const expires = item.expirationDate ? formatDateTime(item.expirationDate) : 'Indefinite';
        const deleted = item.deletedAt ? formatDateTime(item.deletedAt) : '—';
        const encodedId = escapeHtml(String(item._id || ''));
        const encodedShortId = escapeHtml(shortId);
        return `<tr>
          <td class="ui-break">${encodedId}</td>
          <td><a href="/${escapeHtml(encodeURIComponent(shortId))}" target="_blank" rel="noopener">${escapeHtml(shortUrl)}</a></td>
          <td class="ui-break">${escapeHtml(item.originalUrl || '')}</td>
          <td>${escapeHtml(expires)}</td>
          <td>${escapeHtml(deleted)}</td>
          <td>${escapeHtml(String(item.clicks || 0))}</td>
          <td>${escapeHtml(item.apiKeyId ? String(item.apiKeyId) : '—')}</td>
          <td class="ui-row-actions">
            <button type="button" class="ui-btn-small ui-btn-secondary" data-url-action="inspect" data-url-id="${encodedId}">Inspect</button>
            <button type="button" class="ui-btn-small ui-btn-secondary" data-url-action="fill" data-url-id="${encodedId}" data-url-short-id="${encodedShortId}">Edit</button>
            <button type="button" class="ui-btn-small ui-btn-danger" data-url-action="delete" data-url-id="${encodedId}">Delete</button>
          </td>
        </tr>`;
      }).join('')
      : '<tr><td colspan="8" class="ui-muted">No URL records found.</td></tr>';
  
    const keyRows = adminData.apiKeys.length
      ? adminData.apiKeys.map((key) => {
        const id = escapeHtml(String(key._id));
        const name = escapeHtml(key.name || '');
        const scopes = escapeHtml((key.scopes || []).join(', '));
        const active = key.active ? 'yes' : 'no';
        const activeValue = key.active ? 'true' : 'false';
        return `<tr>
          <td class="ui-break">${id}</td>
          <td>${name}</td>
          <td class="ui-break">${scopes}</td>
          <td>${escapeHtml(active)}</td>
          <td>${escapeHtml(formatDateTime(key.lastUsedAt))}</td>
          <td>${escapeHtml(String(key.usageCount || 0))}</td>
          <td class="ui-row-actions">
            <button type="button" class="ui-btn-small ui-btn-secondary" data-key-action="fill" data-key-id="${id}" data-key-name="${name}" data-key-scopes="${scopes}" data-key-active="${activeValue}">Edit</button>
            <button type="button" class="ui-btn-small ui-btn-secondary" data-key-action="rotate" data-key-id="${id}">Rotate</button>
            <button type="button" class="ui-btn-small ui-btn-danger" data-key-action="delete" data-key-id="${id}">Delete</button>
          </td>
        </tr>`;
      }).join('')
      : '<tr><td colspan="7" class="ui-muted">No API keys found.</td></tr>';
  
    return `<section class="ui-card ui-admin-console" id="adminConsole" data-csrf-token="${escapeHtml(csrfToken || '')}">
      <div class="ui-admin-header">
        <h2>Admin Console</h2>
        <div class="ui-inline-actions">
          <button type="button" id="adminRefreshStatsBtn" class="ui-btn-secondary">Refresh stats</button>
          <a href="${escapeHtml(apiDocsUrl)}" target="_blank" rel="noopener" class="ui-admin-link">Open API docs</a>
        </div>
      </div>
      <p class="ui-muted">Manage API keys, URL lifecycle, maintenance jobs, and audit logs from one place.</p>
      <div id="adminGlobalStatus" class="ui-inline-output" role="status" aria-live="polite"></div>
      <div class="ui-admin-tabs" role="tablist" aria-label="Admin sections">
        <button type="button" class="ui-admin-tab is-active" data-admin-tab="overview">Overview</button>
        <button type="button" class="ui-admin-tab" data-admin-tab="keys">API Keys</button>
        <button type="button" class="ui-admin-tab" data-admin-tab="urls">URLs</button>
        <button type="button" class="ui-admin-tab" data-admin-tab="maintenance">Maintenance</button>
        <button type="button" class="ui-admin-tab" data-admin-tab="audit">Audit</button>
      </div>
    </section>
  
    <section class="ui-card ui-admin-panel is-active" data-admin-panel="overview">
      <div class="ui-admin-header">
        <h2>Service Overview</h2>
        <button type="button" id="adminOverviewRefreshUrlsBtn" class="ui-btn-secondary">Refresh recent URLs</button>
      </div>
      <div id="adminOverviewStatus" class="ui-inline-output"></div>
      <div class="ui-metric-grid">
        <article><h3>Total</h3><p id="adminStatTotal">${escapeHtml(String(stats.total))}</p></article>
        <article><h3>Active</h3><p id="adminStatActive">${escapeHtml(String(stats.active))}</p></article>
        <article><h3>Expired</h3><p id="adminStatExpired">${escapeHtml(String(stats.expired))}</p></article>
        <article><h3>Deleted</h3><p id="adminStatDeleted">${escapeHtml(String(stats.deleted))}</p></article>
        <article><h3>Long TTL</h3><p id="adminStatLongTtl">${escapeHtml(String(stats.longTtl))}</p></article>
        <article><h3>Purge queued</h3><p id="adminStatPurgeScheduled">${escapeHtml(String(stats.purgeScheduled))}</p></article>
      </div>
      <div class="ui-table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Short URL</th>
              <th>Original URL</th>
              <th>Expires</th>
              <th>Deleted</th>
              <th>Clicks</th>
              <th>API key ID</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="adminRecentUrlsBody">${recentRows}</tbody>
        </table>
      </div>
    </section>
  
    <section class="ui-card ui-admin-panel" data-admin-panel="keys">
      <div class="ui-admin-header">
        <h2>API Keys</h2>
        <button type="button" id="adminApiKeysRefreshBtn" class="ui-btn-secondary">Refresh keys</button>
      </div>
      <div id="adminApiKeyStatus" class="ui-inline-output"></div>
      <div class="ui-split-grid">
        <article class="ui-subcard">
          <h3>Create key</h3>
          <form id="adminApiKeyCreateForm" class="ui-form">
            <label for="adminApiKeyName">Name</label>
            <input id="adminApiKeyName" name="name" type="text" maxlength="120" required>
            <label for="adminApiKeyScopes">Scopes (comma-separated, optional)</label>
            <input id="adminApiKeyScopes" name="scopes" type="text" placeholder="shorten:write, admin:*">
            <button type="submit">Create key</button>
          </form>
        </article>
        <article class="ui-subcard">
          <h3>Edit key</h3>
          <form id="adminApiKeyUpdateForm" class="ui-form">
            <label for="adminApiKeyUpdateId">API key ID</label>
            <input id="adminApiKeyUpdateId" name="id" type="text" required>
            <label for="adminApiKeyUpdateName">Name (optional)</label>
            <input id="adminApiKeyUpdateName" name="name" type="text" maxlength="120" placeholder="Leave blank to keep unchanged">
            <label for="adminApiKeyUpdateScopes">Scopes (optional)</label>
            <input id="adminApiKeyUpdateScopes" name="scopes" type="text" placeholder="Leave blank to keep unchanged">
            <label for="adminApiKeyUpdateActive">Active state</label>
            <select id="adminApiKeyUpdateActive" name="active">
              <option value="">No change</option>
              <option value="true">Active</option>
              <option value="false">Disabled</option>
            </select>
            <button type="submit">Update key</button>
          </form>
          <div class="ui-inline-actions">
            <button type="button" id="adminApiKeyRotateSelectedBtn" class="ui-btn-secondary">Rotate selected</button>
            <button type="button" id="adminApiKeyDeleteSelectedBtn" class="ui-btn-danger">Delete selected</button>
          </div>
        </article>
      </div>
      <div class="ui-table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Scopes</th>
              <th>Active</th>
              <th>Last used</th>
              <th>Usage count</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="adminApiKeysBody">${keyRows}</tbody>
        </table>
      </div>
    </section>
  
    <section class="ui-card ui-admin-panel" data-admin-panel="urls">
      <div class="ui-admin-header">
        <h2>URL Management</h2>
        <button type="button" id="adminUrlsRefreshBtn" class="ui-btn-secondary">Refresh search</button>
      </div>
      <div id="adminUrlStatus" class="ui-inline-output"></div>
      <div class="ui-split-grid">
        <article class="ui-subcard">
          <h3>Search URLs</h3>
          <form id="adminUrlSearchForm" class="ui-form ui-form-grid">
            <label for="adminUrlQ">Query</label>
            <input id="adminUrlQ" name="q" type="text" placeholder="Matches shortId + original URL">
            <label for="adminUrlShortId">Short ID</label>
            <input id="adminUrlShortId" name="shortId" type="text">
            <label for="adminUrlOriginalUrl">Original URL contains</label>
            <input id="adminUrlOriginalUrl" name="originalUrl" type="text">
            <label for="adminUrlApiKeyId">API key ID</label>
            <input id="adminUrlApiKeyId" name="apiKeyId" type="text">
            <label for="adminUrlCreatedFrom">Created from (ISO)</label>
            <input id="adminUrlCreatedFrom" name="createdFrom" type="text" placeholder="2026-01-01T00:00:00Z">
            <label for="adminUrlCreatedTo">Created to (ISO)</label>
            <input id="adminUrlCreatedTo" name="createdTo" type="text" placeholder="2026-12-31T23:59:59Z">
            <label for="adminUrlExpiresFrom">Expires from (ISO)</label>
            <input id="adminUrlExpiresFrom" name="expiresFrom" type="text" placeholder="2026-01-01T00:00:00Z">
            <label for="adminUrlExpiresTo">Expires to (ISO)</label>
            <input id="adminUrlExpiresTo" name="expiresTo" type="text" placeholder="2026-12-31T23:59:59Z">
            <label for="adminUrlExpired">Expired filter</label>
            <select id="adminUrlExpired" name="expired">
              <option value="">Any</option>
              <option value="true">Expired only</option>
              <option value="false">Not expired only</option>
            </select>
            <label for="adminUrlSortBy">Sort by</label>
            <select id="adminUrlSortBy" name="sortBy">
              <option value="createdAt">createdAt</option>
              <option value="lastClickAt">lastClickAt</option>
              <option value="clicks">clicks</option>
              <option value="expirationDate">expirationDate</option>
              <option value="shortId">shortId</option>
              <option value="originalUrl">originalUrl</option>
            </select>
            <label for="adminUrlSortDir">Sort direction</label>
            <select id="adminUrlSortDir" name="sortDir">
              <option value="desc">desc</option>
              <option value="asc">asc</option>
            </select>
            <label for="adminUrlLimit">Limit</label>
            <input id="adminUrlLimit" name="limit" type="number" min="1" max="200" value="50">
            <label for="adminUrlOffset">Offset</label>
            <input id="adminUrlOffset" name="offset" type="number" min="0" value="0">
            <label class="ui-check ui-span-2"><input id="adminUrlIncludeDeleted" name="includeDeleted" type="checkbox"> Include soft-deleted URLs</label>
            <button type="submit" class="ui-span-2">Search</button>
          </form>
        </article>
        <article class="ui-subcard">
          <h3>Lookup and edit</h3>
          <form id="adminUrlLookupIdForm" class="ui-form">
            <label for="adminUrlLookupId">Fetch by URL ID</label>
            <div class="ui-inline-fields">
              <input id="adminUrlLookupId" name="id" type="text" placeholder="ObjectId">
              <button type="submit" class="ui-btn-secondary">Fetch</button>
            </div>
            <label class="ui-check"><input name="includeDeleted" type="checkbox"> Include soft-deleted</label>
          </form>
          <form id="adminUrlLookupShortForm" class="ui-form">
            <label for="adminUrlLookupShortId">Fetch by short ID</label>
            <div class="ui-inline-fields">
              <input id="adminUrlLookupShortId" name="shortId" type="text" placeholder="shortId">
              <button type="submit" class="ui-btn-secondary">Fetch</button>
            </div>
            <label class="ui-check"><input name="includeDeleted" type="checkbox"> Include soft-deleted</label>
          </form>
          <form id="adminUrlUpdateForm" class="ui-form">
            <label for="adminUrlUpdateId">URL ID</label>
            <input id="adminUrlUpdateId" name="id" type="text" required>
            <label for="adminUrlUpdateOriginalUrl">Original URL (optional)</label>
            <input id="adminUrlUpdateOriginalUrl" name="originalUrl" type="text" placeholder="Leave blank to keep unchanged">
            <label for="adminUrlUpdateExpirationDate">Expiration (optional)</label>
            <input id="adminUrlUpdateExpirationDate" name="expirationDate" type="text" placeholder="ISO datetime or none">
            <label class="ui-check"><input id="adminUrlUpdateClearExpiration" name="clearExpiration" type="checkbox"> Clear expiration (set indefinite)</label>
            <label for="adminUrlUpdateClicks">Clicks (optional)</label>
            <input id="adminUrlUpdateClicks" name="clicks" type="number" min="0" placeholder="Leave blank to keep unchanged">
            <label for="adminUrlUpdateLastClickAt">Last click timestamp (optional)</label>
            <input id="adminUrlUpdateLastClickAt" name="lastClickAt" type="text" placeholder="ISO datetime">
            <label class="ui-check"><input id="adminUrlUpdateClearLastClickAt" name="clearLastClickAt" type="checkbox"> Clear last click timestamp</label>
            <label for="adminUrlUpdateApiKeyId">API key ID (optional)</label>
            <input id="adminUrlUpdateApiKeyId" name="apiKeyId" type="text" placeholder="Leave blank to keep unchanged">
            <label class="ui-check"><input id="adminUrlUpdateClearApiKeyId" name="clearApiKeyId" type="checkbox"> Clear API key link</label>
            <div class="ui-inline-actions">
              <button type="submit">Update URL</button>
              <button type="button" id="adminUrlDeleteSelectedBtn" class="ui-btn-danger">Soft delete URL</button>
            </div>
          </form>
        </article>
      </div>
      <div class="ui-table-wrap">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Short URL</th>
              <th>Original URL</th>
              <th>Expires</th>
              <th>Deleted</th>
              <th>Clicks</th>
              <th>API key ID</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="adminUrlsBody">${recentRows}</tbody>
        </table>
      </div>
      <div class="ui-pagination">
        <button type="button" id="adminUrlsPrevBtn" class="ui-btn-secondary">Previous</button>
        <p id="adminUrlsPageInfo" class="ui-muted">Showing initial recent results.</p>
        <button type="button" id="adminUrlsNextBtn" class="ui-btn-secondary">Next</button>
      </div>
    </section>
  
    <section class="ui-card ui-admin-panel" data-admin-panel="maintenance">
      <div class="ui-admin-header">
        <h2>Maintenance</h2>
        <button type="button" id="adminMaintenanceRefreshStatsBtn" class="ui-btn-secondary">Refresh stats</button>
      </div>
      <div id="adminMaintenanceStatus" class="ui-inline-output"></div>
      <div class="ui-maintenance-grid">
        <article class="ui-subcard">
          <h3>Cleanup expired URLs</h3>
          <p class="ui-muted">Endpoint: <code>/admin/maintenance/cleanup/expired</code></p>
          <form class="ui-form ui-maint-form" data-endpoint="/admin/maintenance/cleanup/expired">
            <label class="ui-check"><input name="dryRun" type="checkbox" checked> Dry run</label>
            <label class="ui-check"><input name="hardDelete" type="checkbox"> Hard delete matches</label>
            <label>Limit</label>
            <input name="limit" type="number" min="1" max="5000" value="1000">
            <button type="submit">Run</button>
          </form>
        </article>
        <article class="ui-subcard">
          <h3>Hard-delete old soft deletes</h3>
          <p class="ui-muted">Endpoint: <code>/admin/maintenance/cleanup/deleted</code></p>
          <form class="ui-form ui-maint-form" data-endpoint="/admin/maintenance/cleanup/deleted">
            <label class="ui-check"><input name="dryRun" type="checkbox" checked> Dry run</label>
            <label>Older than days</label>
            <input name="olderThanDays" type="number" min="1" value="90">
            <label>Limit</label>
            <input name="limit" type="number" min="1" max="5000" value="1000">
            <button type="submit">Run</button>
          </form>
        </article>
        <article class="ui-subcard">
          <h3>Cleanup inactive long-lived URLs</h3>
          <p class="ui-muted">Endpoint: <code>/admin/maintenance/cleanup/inactive</code></p>
          <form class="ui-form ui-maint-form" data-endpoint="/admin/maintenance/cleanup/inactive">
            <label class="ui-check"><input name="dryRun" type="checkbox" checked> Dry run</label>
            <label>Inactive days</label>
            <input name="inactiveDays" type="number" min="1" value="365">
            <label>Limit</label>
            <input name="limit" type="number" min="1" max="5000" value="1000">
            <button type="submit">Run</button>
          </form>
        </article>
        <article class="ui-subcard">
          <h3>Cleanup orphaned API key URLs</h3>
          <p class="ui-muted">Endpoint: <code>/admin/maintenance/cleanup/orphaned-keys</code></p>
          <form class="ui-form ui-maint-form" data-endpoint="/admin/maintenance/cleanup/orphaned-keys">
            <label class="ui-check"><input name="dryRun" type="checkbox" checked> Dry run</label>
            <label>Limit</label>
            <input name="limit" type="number" min="1" max="5000" value="1000">
            <button type="submit">Run</button>
          </form>
        </article>
        <article class="ui-subcard">
          <h3>Backfill purgeAt values</h3>
          <p class="ui-muted">Endpoint: <code>/admin/maintenance/backfill/purge-at</code></p>
          <form class="ui-form ui-maint-form" data-endpoint="/admin/maintenance/backfill/purge-at">
            <label class="ui-check"><input name="dryRun" type="checkbox" checked> Dry run</label>
            <label>Limit</label>
            <input name="limit" type="number" min="1" max="10000" value="5000">
            <button type="submit">Run</button>
          </form>
        </article>
        <article class="ui-subcard">
          <h3>Rebuild indexes</h3>
          <p class="ui-muted">Endpoint: <code>/admin/maintenance/indexes/rebuild</code></p>
          <form class="ui-form ui-maint-form" data-endpoint="/admin/maintenance/indexes/rebuild">
            <label class="ui-check"><input name="dryRun" type="checkbox" checked> Dry run</label>
            <button type="submit">Run</button>
          </form>
        </article>
        <article class="ui-subcard">
          <h3>Danger zone: nuke database</h3>
          <p class="ui-muted">Endpoint: <code>/admin/maintenance/nuke</code></p>
          <form id="adminNukeForm" class="ui-form">
            <label for="adminNukeKey">Admin nuke key</label>
            <input id="adminNukeKey" name="nukeKey" type="password" autocomplete="off" placeholder="X-Admin-Nuke-Key">
            <label for="adminNukeConfirm">Confirm token</label>
            <input id="adminNukeConfirm" name="confirm" type="text" placeholder="Type WIPE-ALL">
            <label class="ui-check"><input name="alsoApiKeys" type="checkbox"> Also delete API keys</label>
            <button type="submit" class="ui-btn-danger">Run nuke</button>
          </form>
        </article>
      </div>
    </section>
  
    <section class="ui-card ui-admin-panel" data-admin-panel="audit">
      <div class="ui-admin-header">
        <h2>Admin Audit Logs</h2>
        <button type="button" id="adminAuditRefreshBtn" class="ui-btn-secondary">Refresh logs</button>
      </div>
      <div id="adminAuditStatus" class="ui-inline-output"></div>
      <form id="adminAuditForm" class="ui-form ui-form-grid">
        <label for="adminAuditAction">Action</label>
        <select id="adminAuditAction" name="action">
          <option value="">Any</option>
          <option value="admin">admin</option>
          <option value="maintenance">maintenance</option>
        </select>
        <label for="adminAuditMethod">Method</label>
        <select id="adminAuditMethod" name="method">
          <option value="">Any</option>
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PATCH">PATCH</option>
          <option value="DELETE">DELETE</option>
        </select>
        <label for="adminAuditPath">Path contains</label>
        <input id="adminAuditPath" name="path" type="text">
        <label for="adminAuditStatusCode">Status code</label>
        <input id="adminAuditStatusCode" name="status" type="number" min="100" max="599">
        <label for="adminAuditRequestId">Request ID</label>
        <input id="adminAuditRequestId" name="requestId" type="text">
        <label for="adminAuditIp">IP</label>
        <input id="adminAuditIp" name="ip" type="text">
        <label for="adminAuditFrom">From (ISO)</label>
        <input id="adminAuditFrom" name="from" type="text" placeholder="2026-01-01T00:00:00Z">
        <label for="adminAuditTo">To (ISO)</label>
        <input id="adminAuditTo" name="to" type="text" placeholder="2026-12-31T23:59:59Z">
        <label for="adminAuditSortDir">Sort direction</label>
        <select id="adminAuditSortDir" name="sortDir">
          <option value="desc">desc</option>
          <option value="asc">asc</option>
        </select>
        <label for="adminAuditLimit">Limit</label>
        <input id="adminAuditLimit" name="limit" type="number" min="1" max="500" value="100">
        <button type="submit" class="ui-span-2">Load logs</button>
      </form>
      <div class="ui-table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>Method</th>
              <th>Path</th>
              <th>Status</th>
              <th>IP</th>
              <th>Request ID</th>
            </tr>
          </thead>
          <tbody id="adminAuditBody">
            <tr><td colspan="7" class="ui-muted">Use "Load logs" to fetch audit records.</td></tr>
          </tbody>
        </table>
      </div>
      <div class="ui-pagination">
        <button type="button" id="adminAuditPrevBtn" class="ui-btn-secondary">Previous</button>
        <p id="adminAuditPageInfo" class="ui-muted">No audit data loaded.</p>
        <button type="button" id="adminAuditNextBtn" class="ui-btn-secondary">Next</button>
      </div>
    </section>
  
    <section class="ui-card">
      <h2>Last API response</h2>
      <pre id="adminJsonOutput" class="ui-json-output">Run an admin action to view the latest JSON response.</pre>
    </section>`;
  }

  function isUnsafeHttpMethod(method) {
    const value = String(method || '').toUpperCase();
    return value !== 'GET' && value !== 'HEAD' && value !== 'OPTIONS';
  }

  async function adminSessionAuth(req, res, next) {
    const session = getUiSession(req);
    if (!session) {
      return res.status(401).json({error: 'Missing admin session'});
    }

    if (!session.apiKeyId || !isValidObjectId(session.apiKeyId) || !session.csrfToken) {
      clearUiSessionCookie(res);
      return res.status(401).json({error: 'Invalid admin session'});
    }

    try {
      const keyRecord = await ApiKey.findOne({_id: session.apiKeyId, active: true});
      if (!keyRecord) {
        clearUiSessionCookie(res);
        return res.status(403).json({error: 'Invalid admin session'});
      }

      if (!hasScope(keyRecord, 'admin:*')) {
        return res.status(403).json({error: 'Insufficient scope'});
      }

      if (isUnsafeHttpMethod(req.method)) {
        const providedToken = String(req.get('x-ui-csrf-token') || '').trim();
        if (!providedToken || !timingSafeEqual(providedToken, session.csrfToken)) {
          return res.status(403).json({error: 'Session verification failed'});
        }
      }

      const refreshed = refreshUiSession(session);
      if (refreshed) {
        setUiSessionCookie(res, refreshed.token, refreshed.maxAgeSeconds);
      }

      req.uiAuth = {
        apiKey: keyRecord,
        isAdmin: true,
        csrfToken: session.csrfToken,
        rememberMe: session.rememberMe,
      };
      req.apiKey = keyRecord;
      res.locals.apiKeyId = keyRecord._id?.toString() || null;
      return next();
    } catch (error) {
      logger.error('Failed to authenticate admin session', {error: String(error)});
      return res.status(500).json({error: 'Failed to authenticate admin session'});
    }
  }

  return {
    adminSessionAuth,
  };
}
