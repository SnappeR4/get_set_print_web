const User = require('../models/User');
const Token = require('../models/Token');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
// Register new user
const register = async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ $or: [{ email }, { phone }] });
        if (existingUser) {
            return res.status(400).json({
                status: 'FAILED',
                message: 'User with this email or phone already exists'
            });
        }

        const user = new User({ name, email, phone, password });
        await user.save();
        
        // Generate token
        const token = user.generateAuthToken();
        await user.save();

        res.status(201).json({
            status: 'SUCCESS',
            message: 'User registered successfully',
            data: {
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    phone: user.phone
                },
                token
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            status: 'ERROR',
            message: 'Registration failed',
            error: error.message
        });
    }
};

// Login user
const login = async (req, res) => {
    try {
        const { login, password } = req.body;

        // Input validation
        if (!login || !password) {
            return res.status(400).json({
                status: 'FAILED',
                message: 'Both login and password are required'
            });
        }

        // Find user by email, phone, or username
        const user = await User.findOne({
            $or: [
                { email: login },
                { phone: login },
                { name: login }
            ]
        });

        if (!user) {
            return res.status(404).json({
                status: 'FAILED',
                message: 'User not found'
            });
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({
                status: 'FAILED',
                message: 'Invalid credentials'
            });
        }

        // Generate NEW token (regardless of previous tokens)
        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
        
        // Save token (optional - only if you want to track active tokens)
        user.tokens = user.tokens.concat({ token });
        await user.save();

        // Return success response with user data and new token
        res.status(200).json({
            status: 'SUCCESS',
            message: 'Login successful',
            data: {
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    phone: user.phone
                },
                token: token // Include the new token in response
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            status: 'ERROR',
            message: 'Login failed',
            error: error.message
        });
    }
};
// Logout user
const logout = async (req, res) => {
    try {
        const token = req.headers.authorization.split(' ')[1];
        const user = await User.findById(req.user._id);
        
        user.removeToken(token);
        await user.save();

        res.json({
            status: 'SUCCESS',
            message: 'Logged out successfully'
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            status: 'ERROR',
            message: 'Logout failed',
            error: error.message
        });
    }
};

// Validate token
const validate = async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password -tokens');
        
        res.json({
            status: 'SUCCESS',
            message: 'Token is valid',
            data: { user }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            status: 'ERROR',
            message: 'Validation failed',
            error: error.message
        });
    }
};

// Add to exports
module.exports = {
    register,
    login,
    logout,
    validate
};
