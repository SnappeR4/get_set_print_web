// middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Only use this for routes that REQUIRE authentication
const requireAuth = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({
                status: 'FAILED',
                message: 'Authentication required'
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded._id);

        if (!user) {
            return res.status(401).json({
                status: 'FAILED',
                message: 'User not found'
            });
        }

        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({
            status: 'FAILED',
            message: 'Invalid token',
            error: error.message
        });
    }
};

module.exports = { requireAuth };