const jwt = require("jsonwebtoken");
const blacklistTokenModel = require("../models/blacklistToken.model");

const authUserMiddleware = async (req, res, next) => {
  const token = req.cookies.token;

  if (!token) 
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  

  const isTokenBlacklisted = await blacklistTokenModel.findOne({ token });
  if (isTokenBlacklisted) 
    return res.status(401).json({ message: "Unauthorized: Invalid token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Unauthorized: Invalid token" });
  }
}

module.exports = {
  authUserMiddleware
}