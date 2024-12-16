import mongoose from "mongoose";

const tokenBlacklistSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
});

export const TokenBlacklist =   mongoose.model("TokenBlacklist", tokenBlacklistSchema);
 