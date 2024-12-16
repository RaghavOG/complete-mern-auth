import mongoose from "mongoose";

const passwordResetSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  resetToken: {
    type: String,
    required: true,
  },
  expiresAt: {
    type: Date, // Token expires in 15 minutes.
    required: true,
  },
  used: {
    type: Boolean,
    default: false, // Mark as true after successful password reset.
  },
});

export const PasswordReset =  mongoose.model("PasswordReset", passwordResetSchema);
