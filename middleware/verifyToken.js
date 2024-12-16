import jwt from 'jsonwebtoken';
import { ENV_VARS } from '../config/envVars.js';
import User from '../models/user.model.js';
import { isTokenExpired } from '../utils/tokenUtils.js';
import logger from "../utils/logger.js";
import mongoose from 'mongoose';

export const verifyAccessToken = async (req, res, next) => {
  const { accessToken, refreshToken } = req.cookies;

  if (!accessToken) {
    logger.error('Access token not provided');
    return res.status(401).json({ message: "Access token not provided" });
  }
  
  try {
    if (isTokenExpired(accessToken, ENV_VARS.JWT_SECRET)) {
      logger.error('Access token is expired');
      if (!refreshToken) {
        logger.error('Refresh token not provided');
        return res.status(401).json({ message: "Refresh token not provided" });
      }
      
      if (isTokenExpired(refreshToken, ENV_VARS.JWT_REFRESH_SECRET)) {
        logger.error('Refresh token expired');
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');
        return res.status(401).json({ message: "Refresh token expired. Please log in again." });
      }
      
      const decodedRefreshToken = jwt.verify(refreshToken, ENV_VARS.JWT_REFRESH_SECRET);
      const { userId } = decodedRefreshToken;

      const user = await User.findById(userId.userId);
      if (!user) {
        logger.error('User not found');
        return res.status(404).json({ message: "User not found" });
      }

      const newAccessToken = jwt.sign({ userId: user._id }, ENV_VARS.JWT_SECRET, {
        expiresIn: '1h',
      });

      res.cookie('accessToken', newAccessToken, { httpOnly: true, secure: true });

      req.user = user;
      return next();
    }

    const decoded = jwt.verify(accessToken, ENV_VARS.JWT_SECRET);

    const userId = new mongoose.Types.ObjectId(decoded.userId.userId);
    req.user = await User.findById(userId);

    if (!req.user) {
      logger.error('User not found');
      return res.status(401).json({ message: "User not found" });
    }

    next();
  } catch (error) {
    logger.error('Access token verification failed:', error);
    return res.status(401).json({ message: "Invalid or expired access token" });
  }
};
