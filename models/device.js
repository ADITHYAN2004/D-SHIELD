// models/device.js
const mongoose = require('mongoose');

const deviceSchema = new mongoose.Schema({
  deviceId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  ip: { type: String, required: true },
  mac: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const Device = mongoose.model('Device', deviceSchema);

module.exports = Device;