// index.js
import express from 'express';
import {nanoid} from 'nanoid';
import mongoose from 'mongoose';
import validator from 'validator';
import {rateLimit} from 'express-rate-limit';
import crypto from 'crypto';
import net from 'net';
import fs from 'fs';
import path from 'path';
import {fileURLToPath} from 'url';
import yaml from 'js-yaml';
import swaggerUi from 'swagger-ui-express';
import 'dotenv/config'

import Url from './models/urlModel.js'
import ApiKey from './models/apiKeyModel.js'
import AdminAudit from './models/adminAuditModel.js'
import blocklist from './blocklist.json' with {type: 'json'};
import logger from './logger.js';

const port = process.env.PORT || 3000;
const dbUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/urlShortener';
const redirectUrl = process.env.REDIRECT_URL || 'https://example.com';
const SHORT_ID_LENGTH = Number(process.env.SHORT_ID_LENGTH || 6);
const ADMIN_NUKE_KEY = process.env.ADMIN_NUKE_KEY;
const API_KEY_PEPPER = process.env.API_KEY_PEPPER || '';
const API_HOST = String(process.env.API_HOST || 'api.x3n.us').toLowerCase();
const WEB_HOSTS = new Set(
  String(process.env.WEB_HOSTS || 'x3n.us,www.x3n.us')
    .split(',')
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean)
);
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1']);
const DEFAULT_TTL_DAYS = 180;
const MAX_TTL_DAYS = 365 * 2;
const SOFT_DELETE_RETENTION_DAYS = 90;
const MAX_ACTIVE_LINKS_PER_KEY = 50000;
const DEFAULT_JSON_LIMIT = '100kb';
const DOCS_SESSION_COOKIE = 'docs_auth';
const DOCS_SESSION_TTL_SECONDS = 60 * 10;
const UI_SESSION_COOKIE = 'ui_session';
const UI_SESSION_REMEMBER_SECONDS = 60 * 60 * 24 * 31;
const UI_SESSION_SHORT_SECONDS = 60 * 60 * 12;
const UI_SESSION_REMEMBER_MAX_SECONDS = 60 * 60 * 24 * 90;
const UI_SESSION_SHORT_MAX_SECONDS = 60 * 60 * 24 * 7;
const DOCS_SESSION_SECRET = process.env.DOCS_SESSION_SECRET
  || API_KEY_PEPPER
  || ADMIN_NUKE_KEY
  || crypto.randomBytes(32).toString('hex');
const UI_SESSION_SECRET = process.env.UI_SESSION_SECRET
  || DOCS_SESSION_SECRET;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const openApiFilePath = path.join(__dirname, 'openapi.yaml');

let openApiRaw = null;
let openApiDocument = null;
try {
  openApiRaw = fs.readFileSync(openApiFilePath, 'utf8');
  openApiDocument = yaml.load(openApiRaw);
} catch (error) {
  logger.error('Failed to load openapi.yaml', {error: String(error)});
}

const swaggerUiOptions = {
  explorer: true,
  customSiteTitle: 'X3N LinkHub API Docs',
  swaggerOptions: {
    url: '/docs/openapi.yaml',
  },
};
const swaggerUiFiles = swaggerUi.serveFiles(null, swaggerUiOptions);
const swaggerUiHandler = swaggerUi.setup(null, swaggerUiOptions);

const spamLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

const apiKeyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  keyGenerator: (req) => req.apiKey?._id?.toString() || req.ip,
  message: 'Too many requests for this API key, please try again later.'
});

const uiLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  handler: (req, res) => {
    return redirectUiWithMessage(res, 'error', 'Too many login attempts. Please try again later.');
  },
});

const app = express();

app.set('trust proxy', 1);
if (!API_KEY_PEPPER) {
  logger.warn('API_KEY_PEPPER is not set; API key hashes are less resistant to offline cracking');
}

app.use((req, res, next) => {
  const requestId = crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex');
  req.requestId = requestId;
  const start = Date.now();
  res.on('finish', () => {
    const payload = {
      requestId,
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      durationMs: Date.now() - start,
      apiKeyId: res.locals.apiKeyId || req.apiKey?._id || null,
    };
    logger.info('request', payload);
  });
  return next();
});

app.use('/admin', requireApiHost, adminKeyAuth, requireScope('admin:*'));
app.use('/admin', adminAudit);

mongoose.connect(dbUri, {});

app.use(express.json({limit: DEFAULT_JSON_LIMIT}));
app.use(express.urlencoded({extended: false, limit: '20kb'}));
app.use('/ui-assets', requireWebHost, express.static('public'));

app.get('/', uiSessionOptionalAuth, async (req, res) => {
  if (isApiHost(req) && !isWebHost(req)) {
    return res.status(200).json({
      ok: true,
      service: 'x3n-linkhub-api',
      docs: '/docs',
    });
  }
  if (!isWebHost(req)) {
    return res.status(404).json({error: 'Not found'});
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

app.get('/docs', requireApiHost, docsAuth, (req, res, next) => {
  if (!openApiRaw || !openApiDocument) {
    return res.status(500).json({error: 'OpenAPI document is unavailable'});
  }
  res.setHeader('Cache-Control', 'no-store');
  return swaggerUiHandler(req, res, next);
});
app.get('/docs/openapi.yaml', requireApiHost, docsAuth, (req, res) => {
  if (!openApiRaw) {
    return res.status(500).json({error: 'OpenAPI document is unavailable'});
  }
  res.setHeader('Cache-Control', 'no-store');
  res.type('application/yaml');
  return res.send(openApiRaw);
});
app.use('/docs', requireApiHost, docsAuth, swaggerUiFiles);

app.get('/healthz', (req, res) => {
  return res.status(200).json({ok: true});
});

app.get('/readyz', (req, res) => {
  const isReady = mongoose.connection.readyState === 1;
  return res.status(isReady ? 200 : 503).json({ok: isReady});
});

app.post('/admin/api-keys', async (req, res) => {
  const {name, scopes} = req.body;
  if (!name) {
    return res.status(400).json({error: 'Missing name'});
  }
  if (scopes !== undefined && (!Array.isArray(scopes) || scopes.some((s) => typeof s !== 'string'))) {
    return res.status(400).json({error: 'Scopes must be an array of strings'});
  }

  try {
    const rawKey = crypto.randomBytes(24).toString('hex');
    const keyHash = hashApiKey(rawKey);
    const keyRecord = await ApiKey.create({
      name,
      keyHash,
      scopes: Array.isArray(scopes) && scopes.length ? scopes : ['shorten:write'],
    });
    return res.status(201).json({
      id: keyRecord._id,
      name: keyRecord.name,
      active: keyRecord.active,
      createdAt: keyRecord.createdAt,
      scopes: keyRecord.scopes,
      apiKey: rawKey,
    });
  } catch (error) {
    logger.error('Failed to create API key', {error: String(error)});
    return res.status(500).json({error: 'Failed to create API key'});
  }
});

app.get('/admin/api-keys', async (req, res) => {
  try {
    const keys = await ApiKey.find({}, '-keyHash').sort({createdAt: -1});
    return res.json(keys);
  } catch (error) {
    logger.error('Failed to list API keys', {error: String(error)});
    return res.status(500).json({error: 'Failed to list API keys'});
  }
});

app.patch('/admin/api-keys/:id', async (req, res) => {
  const {id} = req.params;
  const {name, active, scopes} = req.body;

  if (!isValidObjectId(id)) {
    return res.status(400).json({error: 'Invalid API key id'});
  }

  if (name === undefined && active === undefined && scopes === undefined) {
    return res.status(400).json({error: 'No fields to update'});
  }

  try {
    const updates = {};
    if (name !== undefined) updates.name = name;
    if (active !== undefined) updates.active = Boolean(active);
    if (scopes !== undefined) {
      if (!Array.isArray(scopes) || scopes.some((s) => typeof s !== 'string')) {
        return res.status(400).json({error: 'Scopes must be an array of strings'});
      }
      updates.scopes = Array.isArray(scopes) ? scopes : [];
    }

    const existingKey = await ApiKey.findById(id);
    if (!existingKey) {
      return res.status(404).json({error: 'API key not found'});
    }

    const keyRecord = await ApiKey.findByIdAndUpdate(id, updates, {new: true});
    if (!keyRecord) {
      return res.status(404).json({error: 'API key not found'});
    }

    if (active !== undefined && existingKey.active && !keyRecord.active) {
      const now = new Date();
      const purgeAt = getSoftDeletePurgeAt(now);
      await Url.updateMany(
        {apiKeyId: keyRecord._id, deletedAt: null},
        {$set: {expirationDate: now, purgeAt}}
      );
    }
    return res.json(keyRecord);
  } catch (error) {
    logger.error('Failed to update API key', {error: String(error)});
    return res.status(500).json({error: 'Failed to update API key'});
  }
});

app.post('/admin/api-keys/:id/rotate', async (req, res) => {
  const {id} = req.params;
  if (!isValidObjectId(id)) {
    return res.status(400).json({error: 'Invalid API key id'});
  }
  try {
    const keyRecord = await ApiKey.findById(id);
    if (!keyRecord) {
      return res.status(404).json({error: 'API key not found'});
    }

    const rawKey = crypto.randomBytes(24).toString('hex');
    keyRecord.keyHash = hashApiKey(rawKey);
    keyRecord.lastUsedAt = null;
    keyRecord.lastUsedIp = null;
    keyRecord.lastUsedUserAgent = null;
    keyRecord.usageCount = 0;
    await keyRecord.save();

    return res.json({
      id: keyRecord._id,
      name: keyRecord.name,
      active: keyRecord.active,
      scopes: keyRecord.scopes,
      apiKey: rawKey,
    });
  } catch (error) {
    logger.error('Failed to rotate API key', {error: String(error)});
    return res.status(500).json({error: 'Failed to rotate API key'});
  }
});

app.delete('/admin/api-keys/:id', async (req, res) => {
  const {id} = req.params;
  if (!isValidObjectId(id)) {
    return res.status(400).json({error: 'Invalid API key id'});
  }
  try {
    const keyRecord = await ApiKey.findByIdAndDelete(id);
    if (!keyRecord) {
      return res.status(404).json({error: 'API key not found'});
    }
    return res.status(204).send();
  } catch (error) {
    logger.error('Failed to delete API key', {error: String(error)});
    return res.status(500).json({error: 'Failed to delete API key'});
  }
});

app.get('/admin/urls', async (req, res) => {
  const {
    q,
    shortId,
    originalUrl,
    apiKeyId,
    createdFrom,
    createdTo,
    expiresFrom,
    expiresTo,
    expired,
    includeDeleted,
    sortBy = 'createdAt',
    sortDir = 'desc',
    limit = '50',
    offset = '0',
  } = req.query;

  const filter = {};
  const and = [];
  const or = [];

  if (q) {
    const re = new RegExp(escapeRegExp(String(q)), 'i');
    or.push({shortId: re});
    or.push({originalUrl: re});
  }

  if (shortId) filter.shortId = new RegExp(escapeRegExp(String(shortId)), 'i');
  if (originalUrl) filter.originalUrl = new RegExp(escapeRegExp(String(originalUrl)), 'i');
  if (apiKeyId) filter.apiKeyId = apiKeyId;

  if (createdFrom || createdTo) {
    filter.createdAt = {};
    if (createdFrom) filter.createdAt.$gte = new Date(createdFrom);
    if (createdTo) filter.createdAt.$lte = new Date(createdTo);
  }

  if (expiresFrom || expiresTo) {
    filter.expirationDate = {};
    if (expiresFrom) filter.expirationDate.$gte = new Date(expiresFrom);
    if (expiresTo) filter.expirationDate.$lte = new Date(expiresTo);
  }

  if (expired !== undefined) {
    const now = new Date();
    const isExpired = String(expired).toLowerCase() === 'true';
    if (isExpired) {
      and.push({expirationDate: {$lte: now}});
    } else {
      and.push({
        $or: [
          {expirationDate: null},
          {expirationDate: {$gt: now}},
        ],
      });
    }
  }

  if (or.length) and.push({$or: or});
  if (!includeDeleted || String(includeDeleted).toLowerCase() !== 'true') {
    filter.deletedAt = null;
  }
  if (and.length) filter.$and = and;

  const allowedSort = new Set([
    'createdAt',
    'lastClickAt',
    'clicks',
    'expirationDate',
    'shortId',
    'originalUrl',
  ]);
  const sortField = allowedSort.has(sortBy) ? sortBy : 'createdAt';
  const sortDirection = String(sortDir).toLowerCase() === 'asc' ? 1 : -1;

  const limitNum = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200);
  const offsetNum = Math.max(parseInt(offset, 10) || 0, 0);

  try {
    const [total, items] = await Promise.all([
      Url.countDocuments(filter),
      Url.find(filter)
        .sort({[sortField]: sortDirection})
        .skip(offsetNum)
        .limit(limitNum),
    ]);

    return res.json({
      total,
      limit: limitNum,
      offset: offsetNum,
      items,
    });
  } catch (error) {
    logger.error('Failed to list URLs', {error: String(error)});
    return res.status(500).json({error: 'Failed to list URLs'});
  }
});

app.get('/admin/urls/:id', async (req, res) => {
  const {id} = req.params;
  if (!isValidObjectId(id)) {
    return res.status(400).json({error: 'Invalid URL id'});
  }
  try {
    const includeDeleted = String(req.query.includeDeleted || '').toLowerCase() === 'true';
    const filter = includeDeleted ? {_id: id} : {_id: id, deletedAt: null};
    const urlRecord = await Url.findOne(filter);
    if (!urlRecord) {
      return res.status(404).json({error: 'URL not found'});
    }
    return res.json(urlRecord);
  } catch (error) {
    logger.error('Failed to fetch URL', {error: String(error)});
    return res.status(500).json({error: 'Failed to fetch URL'});
  }
});

app.get('/admin/urls/by-short-id/:shortId', async (req, res) => {
  const {shortId} = req.params;
  try {
    const includeDeleted = String(req.query.includeDeleted || '').toLowerCase() === 'true';
    const filter = includeDeleted ? {shortId} : {shortId, deletedAt: null};
    const urlRecord = await Url.findOne(filter);
    if (!urlRecord) {
      return res.status(404).json({error: 'URL not found'});
    }
    return res.json(urlRecord);
  } catch (error) {
    logger.error('Failed to fetch URL by shortId', {error: String(error)});
    return res.status(500).json({error: 'Failed to fetch URL'});
  }
});

app.patch('/admin/urls/:id', async (req, res) => {
  const {id} = req.params;
  const {originalUrl, expirationDate, clicks, lastClickAt, apiKeyId} = req.body;

  if (!isValidObjectId(id)) {
    return res.status(400).json({error: 'Invalid URL id'});
  }

  const updates = {};
  if (originalUrl !== undefined) {
    const sanitized = sanitizeUrl(String(originalUrl));
    const validation = validateUrl(sanitized);
    if (!validation.ok) return res.status(400).json({error: validation.error});
    updates.originalUrl = sanitized;
  }
  if (expirationDate !== undefined) {
    const expirationResult = parseExpirationDate(expirationDate, {
      allowIndefinite: true,
      applyDefault: false,
    });
    if (!expirationResult.ok) {
      return res.status(400).json({error: expirationResult.error});
    }
    updates.expirationDate = expirationResult.value;
    updates.purgeAt = updates.deletedAt
      ? getSoftDeletePurgeAt(updates.deletedAt)
      : getExpirationPurgeAt(expirationResult.value);
  }
  if (clicks !== undefined) {
    const parsedClicks = Number(clicks);
    if (!Number.isFinite(parsedClicks) || parsedClicks < 0) {
      return res.status(400).json({error: 'Clicks must be a non-negative number'});
    }
    updates.clicks = Math.floor(parsedClicks);
  }
  if (lastClickAt !== undefined) {
    if (!lastClickAt) {
      updates.lastClickAt = null;
    } else {
      const parsedLastClickAt = new Date(lastClickAt);
      if (Number.isNaN(parsedLastClickAt.getTime())) {
        return res.status(400).json({error: 'Invalid lastClickAt'});
      }
      updates.lastClickAt = parsedLastClickAt;
    }
  }
  if (apiKeyId !== undefined) {
    if (apiKeyId && !isValidObjectId(apiKeyId)) {
      return res.status(400).json({error: 'Invalid apiKeyId'});
    }
    updates.apiKeyId = apiKeyId || null;
  }

  if (!Object.keys(updates).length) {
    return res.status(400).json({error: 'No fields to update'});
  }

  try {
    const urlRecord = await Url.findByIdAndUpdate(id, updates, {new: true});
    if (!urlRecord) {
      return res.status(404).json({error: 'URL not found'});
    }
    return res.json(urlRecord);
  } catch (error) {
    logger.error('Failed to update URL', {error: String(error)});
    return res.status(500).json({error: 'Failed to update URL'});
  }
});

app.delete('/admin/urls/:id', async (req, res) => {
  const {id} = req.params;
  if (!isValidObjectId(id)) {
    return res.status(400).json({error: 'Invalid URL id'});
  }
  try {
    const deletedAt = new Date();
    const urlRecord = await Url.findByIdAndUpdate(
      id,
      {deletedAt, purgeAt: getSoftDeletePurgeAt(deletedAt)},
      {new: true}
    );
    if (!urlRecord) {
      return res.status(404).json({error: 'URL not found'});
    }
    return res.status(204).send();
  } catch (error) {
    logger.error('Failed to delete URL', {error: String(error)});
    return res.status(500).json({error: 'Failed to delete URL'});
  }
});

app.get('/admin/maintenance/stats', async (req, res) => {
  try {
    const now = new Date();
    const twoYears = new Date();
    twoYears.setFullYear(twoYears.getFullYear() + 2);

    const [total, deleted, expired, active, longTtl, purgeScheduled] = await Promise.all([
      Url.countDocuments({}),
      Url.countDocuments({deletedAt: {$ne: null}}),
      Url.countDocuments({deletedAt: null, expirationDate: {$lte: now}}),
      Url.countDocuments({deletedAt: null, $or: [{expirationDate: null}, {expirationDate: {$gt: now}}]}),
      Url.countDocuments({deletedAt: null, $or: [{expirationDate: null}, {expirationDate: {$gt: twoYears}}]}),
      Url.countDocuments({purgeAt: {$ne: null}}),
    ]);

    return res.json({
      total,
      deleted,
      expired,
      active,
      longTtl,
      purgeScheduled,
    });
  } catch (error) {
    logger.error('Failed to fetch maintenance stats', {error: String(error)});
    return res.status(500).json({error: 'Failed to fetch maintenance stats'});
  }
});

app.post('/admin/maintenance/cleanup/expired', async (req, res) => {
  const {dryRun = true, hardDelete = false, limit = 1000} = req.body || {};
  const now = new Date();
  const limitNum = Math.min(Math.max(parseInt(limit, 10) || 1000, 1), 5000);

  const filter = {deletedAt: null, expirationDate: {$lte: now}};

  try {
    const ids = await Url.find(filter).select('_id').limit(limitNum);
    if (dryRun) {
      return res.json({matched: ids.length, affected: 0});
    }

    if (hardDelete) {
      const result = await Url.deleteMany({_id: {$in: ids.map((d) => d._id)}});
      return res.json({matched: ids.length, affected: result.deletedCount || 0});
    }

    const result = await Url.updateMany(
      {_id: {$in: ids.map((d) => d._id)}},
      {$set: {deletedAt: now, purgeAt: getSoftDeletePurgeAt(now)}}
    );
    return res.json({matched: ids.length, affected: result.modifiedCount || 0});
  } catch (error) {
    logger.error('Failed to cleanup expired URLs', {error: String(error)});
    return res.status(500).json({error: 'Failed to cleanup expired URLs'});
  }
});

app.post('/admin/maintenance/cleanup/deleted', async (req, res) => {
  const {dryRun = true, olderThanDays = 90, limit = 1000} = req.body || {};
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - Number(olderThanDays || 90));
  const limitNum = Math.min(Math.max(parseInt(limit, 10) || 1000, 1), 5000);

  const filter = {deletedAt: {$ne: null, $lte: cutoff}};

  try {
    const ids = await Url.find(filter).select('_id').limit(limitNum);
    if (dryRun) {
      return res.json({matched: ids.length, affected: 0});
    }

    const result = await Url.deleteMany({_id: {$in: ids.map((d) => d._id)}});
    return res.json({matched: ids.length, affected: result.deletedCount || 0});
  } catch (error) {
    logger.error('Failed to cleanup deleted URLs', {error: String(error)});
    return res.status(500).json({error: 'Failed to cleanup deleted URLs'});
  }
});

app.post('/admin/maintenance/cleanup/inactive', async (req, res) => {
  const {dryRun = true, inactiveDays = 365, limit = 1000} = req.body || {};
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - Number(inactiveDays || 365));
  const twoYears = new Date();
  twoYears.setFullYear(twoYears.getFullYear() + 2);
  const limitNum = Math.min(Math.max(parseInt(limit, 10) || 1000, 1), 5000);

  const filter = {
    deletedAt: null,
    $and: [
      {$or: [{expirationDate: null}, {expirationDate: {$gt: twoYears}}]},
      {
        $or: [
          {lastClickAt: {$lte: cutoff}},
          {lastClickAt: null, createdAt: {$lte: cutoff}},
        ],
      },
    ],
  };

  try {
    const ids = await Url.find(filter).select('_id').limit(limitNum);
    if (dryRun) {
      return res.json({matched: ids.length, affected: 0});
    }

    const deletedAt = new Date();
    const result = await Url.updateMany(
      {_id: {$in: ids.map((d) => d._id)}},
      {$set: {deletedAt, purgeAt: getSoftDeletePurgeAt(deletedAt)}}
    );
    return res.json({matched: ids.length, affected: result.modifiedCount || 0});
  } catch (error) {
    logger.error('Failed to cleanup inactive URLs', {error: String(error)});
    return res.status(500).json({error: 'Failed to cleanup inactive URLs'});
  }
});

app.post('/admin/maintenance/cleanup/orphaned-keys', async (req, res) => {
  const {dryRun = true, limit = 1000} = req.body || {};
  const limitNum = Math.min(Math.max(parseInt(limit, 10) || 1000, 1), 5000);

  try {
    const keyIds = await ApiKey.distinct('_id');
    const filter = {
      deletedAt: null,
      apiKeyId: {$ne: null, $nin: keyIds},
    };

    const ids = await Url.find(filter).select('_id').limit(limitNum);
    if (dryRun) {
      return res.json({matched: ids.length, affected: 0});
    }

    const deletedAt = new Date();
    const result = await Url.updateMany(
      {_id: {$in: ids.map((d) => d._id)}},
      {$set: {deletedAt, purgeAt: getSoftDeletePurgeAt(deletedAt)}}
    );
    return res.json({matched: ids.length, affected: result.modifiedCount || 0});
  } catch (error) {
    logger.error('Failed to cleanup orphaned keys', {error: String(error)});
    return res.status(500).json({error: 'Failed to cleanup orphaned keys'});
  }
});

app.post('/admin/maintenance/backfill/purge-at', async (req, res) => {
  const {dryRun = true, limit = 5000} = req.body || {};
  const limitNum = Math.min(Math.max(parseInt(limit, 10) || 5000, 1), 10000);

  const filter = {
    purgeAt: null,
    $or: [
      {deletedAt: {$ne: null}},
      {deletedAt: null, expirationDate: {$ne: null}},
    ],
  };

  try {
    const docs = await Url.find(filter)
      .select('_id deletedAt expirationDate')
      .limit(limitNum);

    if (dryRun) {
      return res.json({matched: docs.length, affected: 0});
    }

    const ops = docs
      .map((doc) => {
        const purgeAt = doc.deletedAt
          ? getSoftDeletePurgeAt(doc.deletedAt)
          : getExpirationPurgeAt(doc.expirationDate);
        if (!purgeAt) return null;
        return {
          updateOne: {
            filter: {_id: doc._id},
            update: {$set: {purgeAt}},
          },
        };
      })
      .filter(Boolean);

    if (!ops.length) {
      return res.json({matched: docs.length, affected: 0});
    }

    const result = await Url.bulkWrite(ops, {ordered: false});
    return res.json({matched: docs.length, affected: result.modifiedCount || 0});
  } catch (error) {
    logger.error('Failed to backfill purgeAt', {error: String(error)});
    return res.status(500).json({error: 'Failed to backfill purgeAt'});
  }
});

app.post('/admin/maintenance/indexes/rebuild', async (req, res) => {
  const {dryRun = true} = req.body || {};
  if (dryRun) {
    return res.json({ok: true, dryRun: true});
  }

  try {
    await Url.syncIndexes();
    await ApiKey.syncIndexes();
    await AdminAudit.syncIndexes();
    return res.json({ok: true});
  } catch (error) {
    logger.error('Failed to rebuild indexes', {error: String(error)});
    return res.status(500).json({error: 'Failed to rebuild indexes'});
  }
});

app.post('/admin/maintenance/nuke', async (req, res) => {
  const {confirm, alsoApiKeys = false} = req.body || {};
  const nukeKey = req.get('x-admin-nuke-key');

  if (!ADMIN_NUKE_KEY) {
    return res.status(500).json({error: 'Admin nuke key not configured'});
  }
  if (!nukeKey || nukeKey !== ADMIN_NUKE_KEY) {
    return res.status(403).json({error: 'Invalid admin nuke key'});
  }
  if (confirm !== 'WIPE-ALL') {
    return res.status(400).json({error: 'Missing or invalid confirm token'});
  }

  try {
    const resultUrls = await Url.deleteMany({});
    let resultKeys = null;
    if (alsoApiKeys) {
      resultKeys = await ApiKey.deleteMany({});
    }
    return res.json({
      urlsDeleted: resultUrls.deletedCount || 0,
      apiKeysDeleted: resultKeys ? resultKeys.deletedCount || 0 : 0,
    });
  } catch (error) {
    logger.error('Failed to nuke database', {error: String(error)});
    return res.status(500).json({error: 'Failed to nuke database'});
  }
});

app.get('/admin/audit', async (req, res) => {
  const {
    action,
    method,
    path,
    status,
    requestId,
    ip,
    from,
    to,
    sortDir = 'desc',
    limit = '100',
    offset = '0',
  } = req.query;

  const filter = {};
  if (action) filter.action = action;
  if (method) filter.method = String(method).toUpperCase();
  if (path) filter.path = new RegExp(escapeRegExp(String(path)), 'i');
  if (status) filter.status = Number(status);
  if (requestId) filter.requestId = requestId;
  if (ip) filter.ip = ip;

  if (from || to) {
    filter.createdAt = {};
    if (from) filter.createdAt.$gte = new Date(from);
    if (to) filter.createdAt.$lte = new Date(to);
  }

  const sortDirection = String(sortDir).toLowerCase() === 'asc' ? 1 : -1;
  const limitNum = Math.min(Math.max(parseInt(limit, 10) || 100, 1), 500);
  const offsetNum = Math.max(parseInt(offset, 10) || 0, 0);

  try {
    const [total, items] = await Promise.all([
      AdminAudit.countDocuments(filter),
      AdminAudit.find(filter)
        .sort({createdAt: sortDirection})
        .skip(offsetNum)
        .limit(limitNum),
    ]);

    return res.json({
      total,
      limit: limitNum,
      offset: offsetNum,
      items,
    });
  } catch (error) {
    logger.error('Failed to list admin audit logs', {error: String(error)});
    return res.status(500).json({error: 'Failed to list admin audit logs'});
  }
});

app.post('/shorten', requireApiHost, spamLimiter, apiKeyAuth, requireScope('shorten:write'), apiKeyLimiter, async (req, res) => {
  let {originalUrl, expirationDate} = req.body;
  const hasExpiration = Object.prototype.hasOwnProperty.call(req.body, 'expirationDate');
  const canUseExtendedTtl = hasScope(req.apiKey, 'ttl:extended') || hasScope(req.apiKey, 'ttl:*');
  const expirationResult = parseExpirationDate(expirationDate, {
    allowIndefinite: true,
    applyDefault: !hasExpiration,
    maxDays: canUseExtendedTtl ? null : MAX_TTL_DAYS,
  });
  if (!expirationResult.ok) {
    return res.status(400).json({error: expirationResult.error});
  }
  expirationDate = expirationResult.value;

  if (!originalUrl) {
    return res.status(400).json({error: 'Missing original URL'});
  }

  // Sanitize URL
  originalUrl = sanitizeUrl(originalUrl);
  logger.info('shorten_request', {originalUrl});

  // Validate URL format
  const validation = validateUrl(originalUrl, {blockHost: req.hostname});
  if (!validation.ok) {
    return res.status(400).json({error: validation.error});
  }

  try {
    const existing = await Url.findOne({
      originalUrl,
      apiKeyId: req.apiKey?._id || null,
      deletedAt: null,
    });
    if (existing) {
      if (isExpired(existing.expirationDate)) {
        existing.expirationDate = expirationDate;
        existing.purgeAt = getExpirationPurgeAt(expirationDate);
        await existing.save();
      }
      return res.json(existing);
    }

    const now = new Date();
    const activeLinkCount = await Url.countDocuments({
      apiKeyId: req.apiKey?._id || null,
      deletedAt: null,
      $or: [{expirationDate: null}, {expirationDate: {$gt: now}}],
    });
    if (activeLinkCount >= MAX_ACTIVE_LINKS_PER_KEY) {
      return res.status(429).json({error: 'Active link limit reached for this API key'});
    }
  } catch (error) {
    logger.error('Failed to check existing URL', {error: String(error)});
    return res.status(500).json({error: 'Failed to check existing URL'});
  }

  const shortId = await generateUniqueShortId(SHORT_ID_LENGTH);

  try {
    const newUrl = await Url.create({
      shortId,
      originalUrl,
      expirationDate,
      purgeAt: getExpirationPurgeAt(expirationDate),
      apiKeyId: req.apiKey?._id || null,
    });

    res.json(newUrl)
  } catch (error) {
    logger.error('Failed to create URL', {error: String(error)});
    res.status(500).json({error: 'Failed to create URL'});
  }

})
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


mongoose.connection.on('connected', () => {
  logger.info('Connected to MongoDB');
  const server = app.listen(port, () => {
    logger.info(`Server running on port ${port}`);
  });
  // Basic slow-client protection defaults.
  server.requestTimeout = 30_000;
  server.headersTimeout = 35_000;
  server.keepAliveTimeout = 5_000;
})

mongoose.connection.on('error', (error) => {
  logger.error('Failed to connect to MongoDB', {error: String(error)});
  process.exit(1);
})

mongoose.connection.on('disconnected', () => {
  logger.error('MongoDB connection disconnected');
  process.exit(1);
})

process.on('SIGINT', () => {
  mongoose.connection.close();
  process.exit(0);
});

function sanitizeUrl(url) {
  url = url.trim() // Trim leading/trailing whitespace
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = `http://${url}`;
  }

  url = url.replace(/[<>\"'`]/g, ''); // Remove or encode dangerous characters

  return url;
}

function validateUrl(url, {blockHost} = {}) {
  if (url.length > 2048) {
    return {ok: false, error: 'URL is too long'};
  }
  const options = {
    require_protocol: true,
    require_valid_protocol: true,
    require_tld: true,
    require_host: true,
    require_valid_host: true,
    allow_protocol_relative_urls: false
  }
  // Validate URL format
  if (!validator.isURL(url, options)) {
    return {ok: false, error: 'Invalid URL format'};
  }

  try {
    const parsed = new URL(url);
    const protocol = parsed.protocol.toLowerCase();
    if (protocol !== 'http:' && protocol !== 'https:') {
      return {ok: false, error: 'Only http and https URLs are allowed'};
    }

    const host = parsed.hostname.toLowerCase();
    if (blockHost) {
      const blocked = String(blockHost).toLowerCase();
      if (host === blocked || host.endsWith(`.${blocked}`)) {
        return {ok: false, error: 'Shortening this domain is not allowed'};
      }
    }
    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
      return {ok: false, error: 'Localhost and .local domains are not allowed'};
    }
    if (host.endsWith('.onion')) {
      return {ok: false, error: '.onion domains are not allowed'};
    }
    if (isShortenerHost(host)) {
      return {ok: false, error: 'Shortener URLs are not allowed'};
    }

    if (isPrivateIp(host)) {
      return {ok: false, error: 'Private or local IPs are not allowed'};
    }
  } catch {
    return {ok: false, error: 'Invalid URL'};
  }

  return {ok: true};
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isShortenerHost(host) {
  const blocklistHosts = blocklist?.shortenerHosts || [];
  return blocklistHosts.some((d) => host === d || host.endsWith(`.${d}`));
}

function isPrivateIp(host) {
  const ipVersion = net.isIP(host);
  if (!ipVersion) return false;

  if (ipVersion === 4) {
    const parts = host.split('.').map(Number);
    const [a, b] = parts;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    return false;
  }

  if (ipVersion === 6) {
    const normalized = host.toLowerCase();
    if (normalized === '::1') return true;
    if (normalized.startsWith('fe80:')) return true; // link-local
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true; // unique local
    return false;
  }

  return false;
}

function addDays(date, days) {
  const next = new Date(date);
  next.setDate(next.getDate() + days);
  return next;
}

function getSoftDeletePurgeAt(deletedAt) {
  if (!deletedAt) return null;
  return addDays(deletedAt, SOFT_DELETE_RETENTION_DAYS);
}

function getExpirationPurgeAt(expirationDate) {
  if (!expirationDate) return null;
  return addDays(expirationDate, SOFT_DELETE_RETENTION_DAYS);
}

function parseExpirationDate(input, {allowIndefinite, applyDefault, maxDays = null}) {
  const now = new Date();

  if (input === undefined) {
    if (applyDefault) {
      const d = new Date();
      d.setDate(d.getDate() + DEFAULT_TTL_DAYS);
      return {ok: true, value: d};
    }
    return {ok: true, value: undefined};
  }

  if (input === null || input === '') {
    if (allowIndefinite) return {ok: true, value: null};
    return {ok: false, error: 'Expiration date required'};
  }

  const value = String(input).toLowerCase();
  if (allowIndefinite && (value === 'none' || value === 'indefinite' || value === 'never')) {
    return {ok: true, value: null};
  }

  const date = new Date(input);
  if (Number.isNaN(date.getTime())) {
    return {ok: false, error: 'Invalid expiration date'};
  }

  if (date <= now) {
    return {ok: false, error: 'Expiration date must be in the future'};
  }

  if (maxDays && maxDays > 0) {
    const maxAllowed = new Date(now);
    maxAllowed.setDate(maxAllowed.getDate() + maxDays);
    if (date > maxAllowed) {
      return {ok: false, error: `Expiration date exceeds max TTL (${maxDays} days)`};
    }
  }

  return {ok: true, value: date};
}

function isExpired(expirationDate) {
  if (!expirationDate) return false;
  return new Date() > expirationDate;
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = String(forwarded).split(',')[0].trim();
    if (first) return first;
  }
  return req.ip;
}

function hashApiKey(apiKey, {usePepper = true} = {}) {
  const suffix = usePepper ? API_KEY_PEPPER : '';
  return crypto.createHash('sha256').update(apiKey + suffix).digest('hex');
}

function hasScope(apiKey, scope) {
  const scopes = apiKey?.scopes || [];
  if (scopes.includes('*') || scopes.includes(scope)) return true;
  const [prefix] = String(scope).split(':');
  return scopes.includes(`${prefix}:*`);
}

function adminAudit(req, res, next) {
  const start = Date.now();
  res.on('finish', async () => {
    try {
      const durationMs = Date.now() - start;
      const action = req.originalUrl.startsWith('/admin/maintenance')
        ? 'maintenance'
        : 'admin';
      const meta = {
        durationMs,
        query: req.query || {},
        body: req.body || {},
      };
      await AdminAudit.create({
        action,
        method: req.method,
        path: req.originalUrl,
        status: res.statusCode,
        requestId: req.requestId || null,
        ip: getClientIp(req),
        meta,
      });
    } catch (error) {
      logger.error('Failed to write admin audit log', {error: String(error)});
    }
  });
  return next();
}

async function authenticateKeyByValue(rawKey, req) {
  const pepperedHash = hashApiKey(rawKey, {usePepper: true});
  let keyRecord = await ApiKey.findOne({keyHash: pepperedHash, active: true});

  if (!keyRecord && API_KEY_PEPPER) {
    const legacyHash = hashApiKey(rawKey, {usePepper: false});
    keyRecord = await ApiKey.findOne({keyHash: legacyHash, active: true});
    if (keyRecord) {
      keyRecord.keyHash = pepperedHash;
    }
  }

  if (!keyRecord) {
    return null;
  }

  keyRecord.usageCount += 1;
  keyRecord.lastUsedAt = new Date();
  keyRecord.lastUsedIp = getClientIp(req);
  keyRecord.lastUsedUserAgent = req.headers['user-agent'] || null;
  await keyRecord.save();

  req.apiKey = keyRecord;
  return keyRecord;
}

async function headerKeyAuth(req, res, next, {headerName, missingError, invalidError}) {
  const keyValue = req.get(headerName);
  if (!keyValue) {
    return res.status(401).json({error: missingError});
  }

  try {
    const keyRecord = await authenticateKeyByValue(keyValue, req);
    if (!keyRecord) {
      return res.status(403).json({error: invalidError});
    }
    res.locals.apiKeyId = keyRecord._id?.toString() || null;
    return next();
  } catch (error) {
    logger.error('API key auth error', {error: String(error)});
    return res.status(500).json({error: 'Failed to authenticate API key'});
  }
}

async function apiKeyAuth(req, res, next) {
  return headerKeyAuth(req, res, next, {
    headerName: 'x-api-key',
    missingError: 'Missing X-API-Key header',
    invalidError: 'Invalid API key',
  });
}

async function adminKeyAuth(req, res, next) {
  return headerKeyAuth(req, res, next, {
    headerName: 'x-admin-key',
    missingError: 'Missing X-Admin-Key header',
    invalidError: 'Invalid admin key',
  });
}

async function docsAuth(req, res, next) {
  const existingSession = getDocsSession(req);
  if (existingSession) {
    res.locals.apiKeyId = existingSession.apiKeyId || null;
    return next();
  }

  try {
    await adminKeyAuth(req, res, async () => {
      if (!hasScope(req.apiKey, 'admin:*')) {
        return res.status(403).json({error: 'Insufficient scope'});
      }

      const token = createDocsSession(req.apiKey?._id?.toString() || null);
      const cookieParts = [
        `${DOCS_SESSION_COOKIE}=${token}`,
        'Path=/docs',
        `Max-Age=${DOCS_SESSION_TTL_SECONDS}`,
        'HttpOnly',
        'SameSite=Lax',
      ];
      if (process.env.NODE_ENV === 'production') {
        cookieParts.push('Secure');
      }
      res.setHeader('Set-Cookie', cookieParts.join('; '));
      return next();
    });
  } catch (error) {
    logger.error('Docs auth error', {error: String(error)});
    return res.status(500).json({error: 'Failed to authenticate docs access'});
  }
}

function createDocsSession(apiKeyId) {
  const payload = {
    apiKeyId,
    exp: Math.floor(Date.now() / 1000) + DOCS_SESSION_TTL_SECONDS,
  };
  const encodedPayload = base64urlEncode(JSON.stringify(payload));
  const signature = signDocsSession(encodedPayload);
  return `${encodedPayload}.${signature}`;
}

function getDocsSession(req) {
  const cookieHeader = req.headers.cookie || '';
  const cookies = parseCookies(cookieHeader);
  const token = cookies[DOCS_SESSION_COOKIE];
  if (!token) return null;

  const [encodedPayload, signature] = token.split('.');
  if (!encodedPayload || !signature) return null;

  const expectedSignature = signDocsSession(encodedPayload);
  if (!timingSafeEqual(signature, expectedSignature)) {
    return null;
  }

  try {
    const json = Buffer.from(encodedPayload, 'base64url').toString('utf8');
    const payload = JSON.parse(json);
    if (!payload?.exp || Math.floor(Date.now() / 1000) >= Number(payload.exp)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

function signDocsSession(value) {
  return crypto.createHmac('sha256', DOCS_SESSION_SECRET).update(value).digest('hex');
}

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

function getRequestHost(req) {
  const hostHeader = String(req.get('host') || '').trim().toLowerCase();
  if (!hostHeader) return '';
  return hostHeader.split(':')[0];
}

function isLocalHost(req) {
  return LOCAL_HOSTS.has(getRequestHost(req));
}

function isApiHost(req) {
  const host = getRequestHost(req);
  return host === API_HOST || isLocalHost(req);
}

function isWebHost(req) {
  const host = getRequestHost(req);
  return WEB_HOSTS.has(host) || isLocalHost(req);
}

function requireApiHost(req, res, next) {
  if (isApiHost(req)) return next();
  return res.status(404).json({error: 'Not found'});
}

function requireWebHost(req, res, next) {
  if (isWebHost(req)) return next();
  return res.status(404).json({error: 'Not found'});
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
  <link rel="stylesheet" href="/ui-assets/ui.css">
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

  const adminPanels = adminData ? renderUiAdminPanels({adminData, shortenerBase, apiDocsUrl}) : '';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>X3N LinkHub Dashboard</title>
  <link rel="stylesheet" href="/ui-assets/ui.css">
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
</body>
</html>`;
}

function renderUiAdminPanels({adminData, shortenerBase, apiDocsUrl}) {
  const stats = adminData.stats;
  const recentRows = adminData.recentUrls.length
    ? adminData.recentUrls.map((item) => {
      const shortUrl = `${shortenerBase}/${item.shortId}`;
      return `<tr>
        <td><a href="/${escapeHtml(encodeURIComponent(item.shortId))}" target="_blank" rel="noopener">${escapeHtml(shortUrl)}</a></td>
        <td class="ui-break">${escapeHtml(item.originalUrl || '')}</td>
        <td>${escapeHtml(formatDateTime(item.createdAt))}</td>
        <td>${escapeHtml(item.apiKeyId ? String(item.apiKeyId) : '—')}</td>
      </tr>`;
    }).join('')
    : '<tr><td colspan="4" class="ui-muted">No records found.</td></tr>';

  const keyRows = adminData.apiKeys.length
    ? adminData.apiKeys.map((key) => `<tr>
      <td>${escapeHtml(String(key._id))}</td>
      <td>${escapeHtml(key.name || '')}</td>
      <td>${escapeHtml((key.scopes || []).join(', '))}</td>
      <td>${escapeHtml(key.active ? 'yes' : 'no')}</td>
      <td>${escapeHtml(formatDateTime(key.lastUsedAt))}</td>
      <td>${escapeHtml(String(key.usageCount || 0))}</td>
    </tr>`).join('')
    : '<tr><td colspan="6" class="ui-muted">No API keys found.</td></tr>';

  return `<section class="ui-card">
    <div class="ui-admin-header">
      <h2>Admin overview</h2>
      <a href="${escapeHtml(apiDocsUrl)}" target="_blank" rel="noopener" class="ui-admin-link">Open API docs</a>
    </div>
    <div class="ui-metric-grid">
      <article><h3>Total</h3><p>${escapeHtml(String(stats.total))}</p></article>
      <article><h3>Active</h3><p>${escapeHtml(String(stats.active))}</p></article>
      <article><h3>Expired</h3><p>${escapeHtml(String(stats.expired))}</p></article>
      <article><h3>Deleted</h3><p>${escapeHtml(String(stats.deleted))}</p></article>
      <article><h3>Long TTL</h3><p>${escapeHtml(String(stats.longTtl))}</p></article>
      <article><h3>Purge queued</h3><p>${escapeHtml(String(stats.purgeScheduled))}</p></article>
    </div>
  </section>
  <section class="ui-card">
    <h2>Recent global URLs</h2>
    <div class="ui-table-wrap">
      <table>
        <thead>
          <tr>
            <th>Short URL</th>
            <th>Original URL</th>
            <th>Created</th>
            <th>API key ID</th>
          </tr>
        </thead>
        <tbody>${recentRows}</tbody>
      </table>
    </div>
  </section>
  <section class="ui-card">
    <h2>API keys</h2>
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
          </tr>
        </thead>
        <tbody>${keyRows}</tbody>
      </table>
    </div>
  </section>`;
}

function requireScope(scope) {
  return (req, res, next) => {
    const scopes = req.apiKey?.scopes;
    if (!scopes || scopes.length === 0) {
      return res.status(403).json({error: 'Insufficient scope'});
    }
    if (hasScope(req.apiKey, scope)) {
      return next();
    }
    return res.status(403).json({error: 'Insufficient scope'});
  };
}

function isValidObjectId(value) {
  return mongoose.Types.ObjectId.isValid(value);
}

async function generateUniqueShortId(length = 6) {
  const maxAttempts = 10;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const shortId = nanoid(length);
      const existingUrl = await Url.exists({shortId});
      if (!existingUrl) return shortId;
    } catch (error) {
      logger.error('Error generating unique short ID', {error: String(error)});
      throw new Error('Failed to generate unique short ID');
    }
    const delayMs = Math.min(5 * attempt * attempt, 50);
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  throw new Error('Failed to generate unique short ID after retries');
}
