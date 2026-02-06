// models/adminAuditModel.js
import mongoose from "mongoose";

const adminAuditSchema = new mongoose.Schema({
  action: {type: String, required: true},
  method: {type: String, required: true},
  path: {type: String, required: true},
  status: {type: Number, required: true},
  requestId: {type: String, default: null},
  ip: {type: String, default: null},
  meta: {type: Object, default: {}},
  createdAt: {type: Date, default: Date.now},
});

adminAuditSchema.index(
  {createdAt: 1},
  {expireAfterSeconds: 60 * 60 * 24 * 365 * 5}
);
adminAuditSchema.index({createdAt: -1});
adminAuditSchema.index({action: 1, createdAt: -1});
adminAuditSchema.index({requestId: 1});
adminAuditSchema.index({ip: 1, createdAt: -1});

const AdminAudit = mongoose.model('AdminAudit', adminAuditSchema);

export default AdminAudit;
