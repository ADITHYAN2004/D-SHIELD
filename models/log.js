const mongoose = require('mongoose');

const LogSchema = new mongoose.Schema({
  deviceId: {
    type: String,
    required: false
  },
  deviceName: {
    type: String,
    required: false
  },
  deviceIp: {
    type: String,
    required: false
  },
  logType: {
    type: String,
    required: true,
    enum: ['nmap', 'iot', 'unknown']
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  content: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  sourceFile: {
    type: String,
    required: true
  }
});

module.exports = mongoose.model('Log', LogSchema);