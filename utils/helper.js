import jwt from 'jsonwebtoken';
import * as dotenv from 'dotenv';
dotenv.config();

export const verifyToken = (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({
      message: 'Authorization header not found',
      success: false,
    });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({
      message: 'You are not authenticated!',
      success: false,
    });
  }

  try {
    const decodedToken = jwt.verify(token, process.env.APP_SECRET);
    req.user = decodedToken;
  } catch (error) {
    return res.status(401).json({
      message: 'You are not authenticated!',
      success: false,
    });
  }
};

