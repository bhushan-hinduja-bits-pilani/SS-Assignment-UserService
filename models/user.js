const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, unique: true },
    password: String,
    receiveQuotes: Boolean,
    dailyReminders: Boolean,
    weatherUpdates: Boolean,
    city: String,
    dateRegistered: { type: Date, default: Date.now },
});

module.exports = mongoose.model('User', userSchema);
