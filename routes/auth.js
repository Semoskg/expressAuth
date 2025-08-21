const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { users } = require('../data/users');

const router = express.Router();

// Helpers
const signAccess = (user) =>
    jwt.sign({ username: user.username }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES,
        subject: String(user.id)
    });

const signRefresh = (user) =>
    jwt.sign({ username: user.username }, process.env.REFRESH_JWT_SECRET, {
        expiresIn: process.env.REFRESH_JWT_EXPIRES,
        subject: String(user.id)
    });

// (Optional) track valid refresh tokens in memory (basic)
const validRefreshTokens = new Set();

// POST /api/auth/register
router.post(
    '/register', [
        body('username').trim().isLength({ min: 3 }).withMessage('Username ≥ 3 chars'),
        body('password').isLength({ min: 6 }).withMessage('Password ≥ 6 chars')
    ],
    async(req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { username, password } = req.body;
        const exists = users.find(u => u.username.toLowerCase() === username.toLowerCase());
        if (exists) return res.status(409).json({ message: 'Username already taken' });

        const passwordHash = await bcrypt.hash(password, 12);
        const user = { id: users.length + 1, username, passwordHash };
        users.push(user);

        return res.status(201).json({ message: 'Registered successfully' });
    }
);

// POST /api/auth/login
router.post(
    '/login', [
        body('username').notEmpty(),
        body('password').notEmpty()
    ],
    async(req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        const { username, password } = req.body;
        const user = users.find(u => u.username.toLowerCase() === username.toLowerCase());
        if (!user) return res.status(401).json({ message: 'Invalid credentials' });

        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

        const accessToken = signAccess(user);
        const refreshToken = signRefresh(user);
        validRefreshTokens.add(refreshToken);

        // Set refresh token as httpOnly cookie
        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        return res.json({ accessToken, user: { id: user.id, username: user.username } });
    }
);


router.post('/refresh', (req, res) => {
    const token = req.cookies && req.cookies.refresh_token;

    if (!token) return res.status(401).json({ message: 'No refresh token' });
    if (!validRefreshTokens.has(token)) return res.status(401).json({ message: 'Refresh token revoked' });

    try {
        const payload = jwt.verify(token, process.env.REFRESH_JWT_SECRET);
        const user = users.find(u => String(u.id) === payload.sub);
        if (!user) return res.status(401).json({ message: 'User not found' });

        const newAccess = signAccess(user);
        return res.json({ accessToken: newAccess });
    } catch (e) {
        return res.status(401).json({ message: 'Invalid or expired refresh token' });
    }
});


router.post('/logout', (req, res) => {
    const token = req.cookies && req.cookies.refresh_token;

    if (token) validRefreshTokens.delete(token);
    res.clearCookie('refresh_token', { httpOnly: true, sameSite: 'lax' });
    return res.json({ message: 'Logged out' });
});

// GET /api/auth/profile (protected)
const auth = require('../middleware/auth');
router.get('/profile', auth, (req, res) => {
    res.json({ id: req.user.id, username: req.user.username });
});

module.exports = router;