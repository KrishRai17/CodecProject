const jwt = require('jsonwebtoken');
const User = require('../models/User');

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';

const protect = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || '';
    const tokenFromHeader = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    const tokenFromCookie = req.cookies?.token || null;
    const token = tokenFromHeader || tokenFromCookie;

    if (!token) {
      return res.status(401).json({ ok: false, message: 'Authentication required.' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('-passwordHash');

    if (!user) {
      return res.status(401).json({ ok: false, message: 'User no longer exists.' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ ok: false, message: 'Invalid or expired token.' });
  }
};

module.exports = { protect };
