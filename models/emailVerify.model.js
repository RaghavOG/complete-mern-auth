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
});

export const EmailVerification =   mongoose.model("EmailVerification", emailVerificationSchema);
