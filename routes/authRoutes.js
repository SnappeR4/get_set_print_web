const express = require('express');
const router = express.Router();
const AuthController = require('../controllers/AuthController');
const { requireAuth } = require('../middleware/auth');

// Make sure AuthController exports are correct
router.post('/register', AuthController.register);
router.post('/login', AuthController.login);
router.post('/logout', requireAuth, AuthController.logout);
router.post('/validate', requireAuth, AuthController.validate);

module.exports = router;