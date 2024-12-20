import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  phone: {
    type: String,
    required: true,
    // unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  passwordRecord: { type: mongoose.Schema.Types.ObjectId, ref: 'Password' },
  profilePic: {
    type: String,
    default: "https://img.freepik.com/free-vector/businessman-character-avatar-isolated_24877-60111.jpg?t=st=1734246128~exp=1734249728~hmac=929022529bceefc2aa41c6ff3620b5a3efa37489cab55d29e1a5d8846a937ac3&w=740", 
  },
  emailVerified: {
    type: Boolean,
    default: false,
  },
  
  emailVerificationToken: {
    type: String,
  },
  verificationExpires: {
    type: Date, // Expiry for email verification.
  },
  
  activeSessions: [
    {
      sessionId: String, // Unique ID for the session
      ip: String,
      userAgent: String,
      issuedAt: { type: Date, default: Date.now },
    },
  ],
  failedLoginAttempts: { type: Number, default: 0 },
  lockoutUntil: { type: Date, default: null },
}, { timestamps: true });

const  User =  mongoose.model("User", userSchema);
export default User;