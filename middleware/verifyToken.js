import jwt from 'jsonwebtoken';
import { ENV_VARS } from '../config/envVars.js';
import User from '../models/user.model.js';
import logger from "../utils/logger.js";
import { isTokenExpired } from '../utils/tokenUtils.js';
import mongoose from 'mongoose';

export const verifyAccessToken = async (req, res, next) => {
  const { accessToken } = req.cookies;

  // console.log("Entered verifyAccessToken");

  if (!accessToken) {
    logger.error('Access token not provided');
    return res.status(401).json({ message: "Access token not provided" });
  }

  // console.log("==============================================================")
  
  // console.log("Access Token: ", accessToken);
  
  // console.log("==============================================================")
  try {
    // Check if token is expired (helper function for checking expiration)
    if (isTokenExpired(accessToken, ENV_VARS.JWT_SECRET)) {
      logger.error('Access token expired');
      return res.status(401).json({ message: "Access token expired" });
    }

    // Verify the JWT
    const decoded = jwt.verify(accessToken, ENV_VARS.JWT_SECRET);

// console.log("decoded: ", decoded);

// console.log("==============================================================")


// Ensure that the userId is an ObjectId before using it
const userId = new mongoose.Types.ObjectId(decoded.userId.userId);
console.log("userId: ", userId);

// console.log("==============================================================")
    req.user = await User.findById(userId);

    if (!req.user) {
      logger.error('User not found');
      return res.status(401).json({ message: "User not found" });
    }

    // Proceed to the next middleware or route handler
    next();
  } catch (error) {
    logger.error('Access token verification failed:', error);
    return res.status(401).json({ message: "Invalid or expired access token" });
  }
};