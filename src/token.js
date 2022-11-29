const { sign } = require("jsonwebtoken");

const createAccessToken = (userId) => {
  return sign({ userId }, process.env.ACESS_TOKEN_SECRET, { expiresIn: "15m" });
};

const createRefreshToken = (userId) => {
  return sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "1d",
  });
};

const sendAccessToken = (res, req, acccessToken) => {
  res.send({
    acccessToken,
    email: req.body.email,
  });
};

const sendRefreshToken = (res, refreshToken) => {
  res.cookie("refreshToken", refreshToken, { httpOnly: true, path: "/refresh_token" });
};

module.exports = {
  createAccessToken,
  createRefreshToken,
  sendAccessToken,
  sendRefreshToken,
};
