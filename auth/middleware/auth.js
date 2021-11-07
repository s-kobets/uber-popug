const jwt = require('jsonwebtoken');

const config = process.env;

const verifyToken = (req, res, next) => {
  const token =
    req.body.token ||
    req.query.token ||
    req.cookies['token'] ||
    req.headers['x-access-token'];

  if (!token) {
    res.status(403).json({ err: 'A token is required for authentication' });
  }
  try {
    const decoded = jwt.verify(token, config.TOKEN_KEY);
    req.user = decoded;
  } catch (err) {
    res.status(401).json({ err: 'Invalid Token' });
  }
  next();
};

module.exports = verifyToken;
