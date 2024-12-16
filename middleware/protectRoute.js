import jwt from "jsonwebtoken";

export const protectRoute = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Unauthorized, no token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Add user info to the request object
    next();
  } catch (error) {
    return res.status(401).json({ message: "Unauthorized, invalid token." });
  }
};
