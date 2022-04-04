const express = require("express");
const passport = require("passport");
const jwt = require("jsonwebtoken");

const router = express.Router();

router.post("/", async (req, res, next) => {
  auth(req, res, next);
});

router.post("/guest", async (req, res, next) => {
  req.body = {
    email: process.env.GUEST_USERNAME,
    password: process.env.GUEST_PASSWORD,
  };
  auth(req, res, next);
});


function auth(req, res, next) {
  passport.authenticate("login", async (err, user, info) => {
    try {
      if (err || !user) {
        return res.status(400).json({
          message: info.message,
        });
      }

      req.login(user, {session: false}, async (error) => {
        if (error) {
          return res.status(400).json({
            message: error.message,
          });
        }

        const body = {_id: user._id, email: user.email, isSuperAdmin: user.isSuperAdmin};
        const token = jwt.sign(
          {
            user: body,
          },
          process.env.ENCRYPTION_SECRET,
          {
            expiresIn: parseInt(process.env.TOKEN_EXPIRE_TIME),
          }
        );
        const refreshToken = jwt.sign(
          {
            token: token,
            user: body,
          },
          process.env.ENCRYPTION_SECRET,
          {
            expiresIn: parseInt(process.env.REFRESH_TOKEN_EXPIRE_TIME),
          }
        );

        return res.json({
          token: token,
          refreshToken: refreshToken,
          user: {
            username: user.username ?? null,
            email: user.email,
            isSuperAdmin: user.isSuperAdmin
          }
        });
      });
    } catch (error) {
      return next(error);
    }
  })(req, res, next);
}

module.exports = router;
