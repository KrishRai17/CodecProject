const mongoose = require('mongoose');

const noteSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    encryptedTitle: {
      type: String,
      required: true,
    },
    encryptedContent: {
      type: String,
      required: true,
    },
    titleIv: {
      type: String,
      required: true,
    },
    titleTag: {
      type: String,
      required: true,
    },
    contentIv: {
      type: String,
      required: true,
    },
    contentTag: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model('Note', noteSchema);
