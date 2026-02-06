// models/urlModel.js
import mongoose from "mongoose";

const urlSchema = new mongoose.Schema({
  shortId: {type: String, required: true, unique: true},
  originalUrl: {type: String, required: true},
  createdAt: {type: Date, default: Date.now},
  clicks: {type: Number, default: 0},
  lastClickAt: {type: Date, default: null},
  expirationDate: {type: Date, default: null},
  deletedAt: {type: Date, default: null},
  purgeAt: {type: Date, default: null},
  apiKeyId: {type: mongoose.Schema.Types.ObjectId, ref: 'ApiKey', default: null},
})

urlSchema.index({shortId: 1}, {unique: true});
urlSchema.index(
  {apiKeyId: 1, originalUrl: 1},
  {unique: true, partialFilterExpression: {deletedAt: null}}
);
urlSchema.index({originalUrl: 1});
urlSchema.index({createdAt: -1});
urlSchema.index({expirationDate: 1});
urlSchema.index({deletedAt: 1});
urlSchema.index({purgeAt: 1}, {expireAfterSeconds: 0});

const Url = mongoose.model('Url', urlSchema);

export default Url;
