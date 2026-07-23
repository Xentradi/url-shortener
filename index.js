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
import {registerWebUi} from './web-ui.js';

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
const DOCS_SESSION_SECRET = process.env.DOCS_SESSION_SECRET
  || API_KEY_PEPPER
  || ADMIN_NUKE_KEY
  || crypto.randomBytes(32).toString('hex');
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


mongoose.connect(dbUri, {});

app.use(express.json({limit: DEFAULT_JSON_LIMIT}));
app.use(express.urlencoded({extended: false, limit: '20kb'}));

const webUi = registerWebUi({
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
  maxTtlDays: MAX_TTL_DAYS,
  maxActiveLinksPerKey: MAX_ACTIVE_LINKS_PER_KEY,
  shortIdLength: SHORT_ID_LENGTH,
  apiHost: API_HOST,
  isWebHost,
  isLocalHost,
  requireWebHost,
  isValidObjectId,
});

app.use('/admin', createAdminRouteAuth({
  uiAdminSessionAuth: webUi.adminSessionAuth,
}));
app.use('/admin', adminAudit);

app.get('/', requireApiHost, (req, res) => {
  return res.status(200).json({
    ok: true,
    service: 'x3n-linkhub-api',
    docs: '/docs',
  });
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

function createAdminRouteAuth({uiAdminSessionAuth}) {
  return (req, res, next) => {
    const isApi = isApiHost(req);
    const isWeb = isWebHost(req);
    if (!isApi && !isWeb) {
      return res.status(404).json({error: 'Not found'});
    }

    const hasAdminHeader = Boolean(req.get('x-admin-key'));
    if (isApi && (hasAdminHeader || !isWeb)) {
      return adminKeyAuth(req, res, () => {
        if (!hasScope(req.apiKey, 'admin:*')) {
          return res.status(403).json({error: 'Insufficient scope'});
        }
        return next();
      });
    }

    return uiAdminSessionAuth(req, res, next);
  };
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
