import mongoose from "mongoose";

const otpSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
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
  invalidAttempts: {
    type: Number,
    default: 0, // Track invalid OTP attempts for security purposes.
  },
});

export const OTP =  mongoose.model("OTP", otpSchema);
