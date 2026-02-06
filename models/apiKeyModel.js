// models/apiKeyModel.js
import mongoose from "mongoose";

const apiKeySchema = new mongoose.Schema({
  name: {type: String, required: true},
  keyHash: {type: String, required: true, unique: true},
  scopes: {type: [String], default: ['shorten:write']},
  createdAt: {type: Date, default: Date.now},
  lastUsedAt: {type: Date, default: null},
  lastUsedIp: {type: String, default: null},
  lastUsedUserAgent: {type: String, default: null},
  usageCount: {type: Number, default: 0},
  active: {type: Boolean, default: true},
});

const ApiKey = mongoose.model('ApiKey', apiKeySchema);

export default ApiKey;
