const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); 

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    phone: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    tokens: [{
        token: {
            type: String,
            required: true
        },
        createdAt: {
            type: Date,
            default: Date.now
        }
    }]
}, { timestamps: true });

// Hash password before saving
UserSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

// Method to generate auth token
UserSchema.methods.generateAuthToken = function() {
    const token = jwt.sign({ _id: this._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    this.tokens.push({ token });
    return token;
};

// Method to remove all tokens (for logout all devices)
UserSchema.methods.removeAllTokens = function() {
    this.tokens = [];
};

// Method to remove specific token
UserSchema.methods.removeToken = function(token) {
    this.tokens = this.tokens.filter(t => t.token !== token);
};

const User = mongoose.model('User', UserSchema);
module.exports = User;