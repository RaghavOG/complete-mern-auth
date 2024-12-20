import mongoose from "mongoose";

const emailVerificationSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  otp: {
    type: String,
    required: true,
  },
  expiresAt: {
    type: Date, // OTP expires in 15 minutes.
    required: true,
  },
  used: {
    type: Boolean,
    default: false, // Mark as true after the OTP is successfully used.
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', // Reference to the User model
    required: true,
  },
});

export const EmailVerification = mongoose.model("EmailVerification", emailVerificationSchema);
