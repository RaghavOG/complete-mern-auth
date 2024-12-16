import mongoose from 'mongoose';

const passwordSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true, // Ensure only one Passwords document per user
  },
  passwordHash: {
    type: String,
  },
  resetToken: {
    type: String,
    required: false,
  },
  expiresAt: {
    type: Date, // Token expiry time.
    required: false,
  },
  used: {
    type: Boolean,
    default: false,
  },
  prevPasswords: [{
    passwordHash: String,
    changedAt: { type: Date, default: Date.now },
  }],
}, { timestamps: true });

export const Passwords = mongoose.model('Password', passwordSchema);
