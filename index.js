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

/**
 * Handles the creation of a new shortened URL.
 *
 * @param {Object} req - The request object containing the original URL, creator, and expiration date.
 * @param {string} req.body.originalUrl - The original URL to be shortened.
 * @param {string} [req.body.creator] - The creator of the URL. Defaults to 'anonymous' if not provided.
 * @param {string} [req.body.expirationDate] - The expiration date of the shortened URL. Must be a valid date string.
 * @param {Object} res - The response object to send back the result.
 *
 * @returns {Object} - A JSON object containing the shortened URL details or an error message.
 */
app.post('/shorten', async (req, res) => {
  let {originalUrl, creator, expirationDate} = req.body;
  expirationDate = expirationDate ? new Date(expirationDate) : null;

  if (!originalUrl) {
    return res.status(400).json({error: 'Missing original URL'});
  }

  // Ensure URL has protocol (http or https)
  if (!originalUrl.startsWith('http://') && !originalUrl.startsWith('https://')) {
    originalUrl = `http://${originalUrl}`;
  }

  // Validate URL format
  if (!validator.isURL(originalUrl)) {
    return res.status(400).json({error: 'Invalid URL format'});
  }

  const shortId = nanoid(6);

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