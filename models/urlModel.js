// models/urlModel.js
import mongoose from "mongoose";

const urlSchema = new mongoose.Schema({
  shortId: {type: String, required: true, unique: true},
  originalUrl: {type: String, required: true},
  createdAt: {type: Date, default: Date.now},
  clicks: {type: Number, default: 0},
  lastClickAt: {type: Date, default: null},
  creator: {type: String, default: 'anonymous'},
  expirationDate: {type: Date, default: null},
  analytics: {
    timestamp: {type: Date, default: Date.now},
    referrer: {type: String, default: null},
    ip: {type: String, default: null},
    userAgent: {type: String, default: null},
  }
})

const Url = mongoose.model('Url', urlSchema);

export default Url;