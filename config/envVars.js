import { config } from 'dotenv';
import { cleanEnv, port, str } from 'envalid';
config();

export default cleanEnv(process.env, {
    MONGO_URI: str(),
    PORT: port() ,
    JWT_SECRET: str() || 'secret',
    JWT_REFRESH_SECRET: str() ||   'refreshsecret',
	NODE_ENV: str() || 'development',
    FRONTEND_URL: str() || 'http://localhost:3000',
    CLOUDINARY_NAME: str(),
    CLOUDINARY_API_KEY: str(),
    CLOUDINARY_API_SECRET: str(),
    EMAIL_USER: str(),
    EMAIL_PASS: str(),
});

export const ENV_VARS = {
	MONGO_URI: process.env.MONGO_URI,
	PORT: process.env.PORT || 5000,
	JWT_SECRET: process.env.JWT_SECRET,
    JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET,
	NODE_ENV: process.env.NODE_ENV,
	FRONTEND_URL: process.env.FRONTEND_URL,
	CLOUDINARY_NAME: process.env.CLOUDINARY_NAME,
    CLOUDINARY_API_KEY: process.env.CLOUDINARY_API_KEY,
    CLOUDINARY_API_SECRET: process.env.CLOUDINARY_API_SECRET,
    EMAIL_PASS: process.env.EMAIL_PASS,
    EMAIL_USER: process.env.EMAIL_USER,
	
};
	