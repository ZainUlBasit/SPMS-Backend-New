const Joi = require("joi");
const bcrypt = require("bcrypt");
const User = require("../Models/User");
const jwt = require("jsonwebtoken");
const { createError, successMessage } = require("../utils/ResponseMessage");
const privateKey = process.env.ACCESS_SECRET_KEY;

function authControllers() {
  return {
    login: async (req, res) => {
      // validate the req
      const loginSchema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required(),
        type: Joi.number().required(),
      });

      const { error } = loginSchema.validate(req.body);
      if (error) return createError(res, 422, error.message);

      // check useremail
      const { email, password, type } = req.body;
      if (type !== 2) {
        return createError(res, 422, "Type is not Allowed!");
      }

      const user = await User.findOne({ email, type }).populate("customerId");
      if (!user) return createError(res, 422, "No such email registered!");

      // check user password using bcrypt
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch)
        return createError(res, 403, "email or password doesn't match!");
      let populatedUser = user;
      if (user.role === 2) {
        populatedUser = await user.populate("customerId");
      }
      const jwtBody =
        user.role === 1
          ? {
              _id: user._id,
              role: user.role,
            }
          : user.role === 2 && {
              _id: user._id,
              role: user.role,
              branch: user.branchId.branch_number,
            };
      // const { accessToken, refreshToken } = JwtService.generateToken(jwtBody);

      var token = await jwt.sign({ ...jwtBody }, privateKey);

      res.cookie("userToken", token, {
        // maxAge: 60000000,
        httpOnly: true,
        sameSite: "none",
        secure: true,
      });

      // const result = await JwtService.storeRefreshToken(refreshToken, user._id);
      // if (!result)
      //   return createError(
      //     res,
      //     500,
      //     "Internal server error.Cannot store refresh token"
      //   );

      // store  access token and refresh token in cookies
      // res.cookie("refreshtoken", refreshToken, {
      //   maxAge: 1000 * 60 * 60 * 24 * 30, //2 hour
      //   httpOnly: true,
      // });

      // res.cookie("accesstoken", accessToken, {
      //   maxAge: 1000 * 60 * 60, // 1 hour
      //   httpOnly: true,
      // });

      delete user.password;

      // const userdata = userDto(user);
      return successMessage(
        res,
        { user: user.role === 2 ? populatedUser : user, token: token },
        "Successfully Logged In!"
      );
    },
  };
}

module.exports = authControllers;
