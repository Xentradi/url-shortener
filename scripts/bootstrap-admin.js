// scripts/bootstrap-admin.js
import crypto from 'crypto';
import path from 'path';
import {fileURLToPath} from 'url';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import ApiKey from '../models/apiKeyModel.js';
import logger from '../logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({path: path.resolve(__dirname, '../.env')});

const dbUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/urlShortener';
const name = process.env.ADMIN_BOOTSTRAP_NAME || 'admin';
const scopes = ['admin:*'];
const nukeKey = crypto.randomBytes(32).toString('hex');
const apiKeyPepper = process.env.API_KEY_PEPPER || '';

async function main() {
  await mongoose.connect(dbUri, {});

  const rawKey = crypto.randomBytes(24).toString('hex');
  const keyHash = crypto.createHash('sha256').update(rawKey + apiKeyPepper).digest('hex');

  const keyRecord = await ApiKey.create({
    name,
    keyHash,
    scopes,
  });

  logger.info('Admin API key created', {
    id: keyRecord._id.toString(),
    name: keyRecord.name,
    scopes: keyRecord.scopes.join(','),
  });
  // Also print to stdout for operator visibility
  process.stdout.write(`Admin API key created\n`);
  process.stdout.write(`id: ${keyRecord._id.toString()}\n`);
  process.stdout.write(`name: ${keyRecord.name}\n`);
  process.stdout.write(`scopes: ${keyRecord.scopes.join(',')}\n`);
  process.stdout.write(`adminKey (use as X-Admin-Key): ${rawKey}\n`);
  process.stdout.write(`nukeKey (set this in .env manually): ${nukeKey}\n`);
  process.stdout.write(`export ADMIN_NUKE_KEY=${nukeKey}\n`);
}

main()
  .catch((error) => {
    logger.error('Failed to bootstrap admin API key', {error: String(error)});
    process.exit(1);
  })
  .finally(async () => {
    await mongoose.disconnect();
  });
