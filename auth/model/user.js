const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  full_name: { type: String, default: null },
  email: { type: String, unique: true },
  password: { type: String },
  role: { type: String },
  token: { type: String },
});

module.exports = mongoose.model('user', userSchema);
