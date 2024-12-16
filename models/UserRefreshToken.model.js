import mongoose from 'mongoose';

const userRefreshTokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  sessionId: { type: String, required: true }, // Link to specific session
  refreshToken: {
    type: String,
    required: true,
  },
  ip: { type: String },
  blacklisted: {
    type: Boolean,
    default: false,
  },
});

export const UserRefreshToken = mongoose.model("UserRefreshToken", userRefreshTokenSchema);
