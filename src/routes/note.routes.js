const express = require('express');
const Note = require('../models/Note');
const { protect } = require('../middleware/auth');
const { noteValidation, handleValidationErrors } = require('../middleware/validate');
const { encryptText, decryptText } = require('../utils/encryption');

const router = express.Router();

router.use(protect);

router.get('/', async (req, res, next) => {
  try {
    const notes = await Note.find({ userId: req.user._id }).sort({ createdAt: -1 });

    const decryptedNotes = notes.map((note) => ({
      id: note._id,
      title: decryptText(note.encryptedTitle, note.titleIv, note.titleTag),
      content: decryptText(note.encryptedContent, note.contentIv, note.contentTag),
      createdAt: note.createdAt,
      updatedAt: note.updatedAt,
    }));

    return res.json({ ok: true, notes: decryptedNotes });
  } catch (error) {
    next(error);
  }
});

router.post('/', noteValidation, handleValidationErrors, async (req, res, next) => {
  try {
    const { title, content } = req.body;
    const titleCipher = encryptText(title);
    const contentCipher = encryptText(content);

    const note = await Note.create({
      userId: req.user._id,
      encryptedTitle: titleCipher.encryptedText,
      encryptedContent: contentCipher.encryptedText,
      titleIv: titleCipher.iv,
      titleTag: titleCipher.tag,
      contentIv: contentCipher.iv,
      contentTag: contentCipher.tag,
    });

    return res.status(201).json({
      ok: true,
      message: 'Note created successfully.',
      note: {
        id: note._id,
        title,
        content,
        createdAt: note.createdAt,
      },
    });
  } catch (error) {
    next(error);
  }
});

router.delete('/:id', async (req, res, next) => {
  try {
    const note = await Note.findOne({ _id: req.params.id, userId: req.user._id });

    if (!note) {
      return res.status(404).json({ ok: false, message: 'Note not found.' });
    }

    await note.deleteOne();
    return res.json({ ok: true, message: 'Note deleted successfully.' });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
