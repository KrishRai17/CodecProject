const { body, validationResult } = require('express-validator');

const registerValidation = [
  body('name').trim().isLength({ min: 2, max: 80 }).withMessage('Name must be 2 to 80 characters long.'),
  body('email').isEmail().normalizeEmail().withMessage('A valid email is required.'),
  body('password').isLength({ min: 8, max: 128 }).withMessage('Password must be between 8 and 128 characters.'),
];

const loginValidation = [
  body('email').isEmail().normalizeEmail().withMessage('A valid email is required.'),
  body('password').notEmpty().withMessage('Password is required.'),
];

const noteValidation = [
  body('title').trim().isLength({ min: 1, max: 120 }).withMessage('Title must be 1 to 120 characters.'),
  body('content').trim().isLength({ min: 1, max: 10000 }).withMessage('Content must be 1 to 10000 characters.'),
];

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ ok: false, errors: errors.array() });
  }
  next();
};

module.exports = { registerValidation, loginValidation, noteValidation, handleValidationErrors };
