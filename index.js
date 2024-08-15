// index.js
import express from 'express';
import {nanoid} from 'nanoid';
import mongoose from 'mongoose';
import validator from 'validator';
import {rateLimit} from 'express-rate-limit';
import 'dotenv/config'

import Url from './models/urlModel.js'

const port = process.env.PORT || 3000;
const dbUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/urlShortener';
const redirectUrl = process.env.REDIRECT_URL || 'https://example.com';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

const app = express();

mongoose.connect(dbUri, {});

app.use(express.json());
app.use('/shorten', limiter)
app.use('/shorten', express.static('public'));

app.get('/', async (req, res) => {
  return res.redirect(redirectUrl);
})

app.post('/shorten', async (req, res) => {
  let {originalUrl, creator, expirationDate} = req.body;
  expirationDate = expirationDate ? new Date(expirationDate) : null;

  if (!originalUrl) {
    return res.status(400).json({error: 'Missing original URL'});
  }

  // Sanitize URL
  originalUrl = sanitizeUrl(originalUrl);
  console.log(`Original URL: ${originalUrl}`);

  // Validate URL format
  if (!validateUrl(originalUrl)) {
    return res.status(400).json({error: 'Invalid URL format'});
  }

  const shortId = await generateUniqueShortId(6);

  try {
    const newUrl = await Url.create({
      shortId,
      originalUrl,
      creator: creator || 'anonymous',
      expirationDate,
    });

    res.json(newUrl)
  } catch (error) {
    res.status(500).json({error: 'Failed to create URL'});
  }

})
app.get('/:shortId', async (req, res) => {
  const {shortId} = req.params;
  try {
    const urlRecord = await Url.findOne({shortId});

    if (!urlRecord) {
      return res.status(404).json({error: 'URL not found'});
    }

    urlRecord.clicks++;
    urlRecord.lastClickAt = new Date();

    // Add base analytics data
    urlRecord.analytics = {
      timestamp: new Date(),
      referrer: req.headers.referer || null,
      ip: req.ip,
      userAgent: req.headers['user-agent'],

    }
    await urlRecord.save();
    return res.redirect(urlRecord.originalUrl);

  } catch (error) {
    console.error('Error retrieving URL', error);
    res.status(500).json({error: 'Error redirecting URL'});
  }
})


mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB');
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);

  });
})

mongoose.connection.on('error', (error) => {
  console.error('Failed to connect to MongoDB', error);
  process.exit(1);
})

mongoose.connection.on('disconnected', () => {
  console.error('MongoDB connection disconnected');
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

function validateUrl(url) {
  const options = {
    require_protocol: true,
    require_valid_protocol: true,
    require_tld: true,
    require_host: true,
    require_valid_host: true,
    allow_protocol_relative_urls: false
  }
  // Validate URL format
  return validator.isURL(url, options);
}

async function generateUniqueShortId(length = 6) {
  let shortId;
  let existingUrl;
  try {
    do {
      shortId = nanoid(6);
      existingUrl = await Url.exists({shortId});
    } while (existingUrl);
  } catch (error) {
    console.error('Error generating unique short ID', error);
    throw new Error('Failed to generate unique short ID');
  }

  return shortId;
}

