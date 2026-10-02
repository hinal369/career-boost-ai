const { Router } = require("express");
const {
  registerUserController,
  loginUserController,
  logoutUserController,
  getMeController,
} = require("../controllers/auth.controller");
const { authUserMiddleware } = require("../middlewares/auth.middleware");


const authRouter = Router();

/**
 * @route POST /api/auth/register
 * @description Register a new user
 * @access public
 */

authRouter.post("/register", registerUserController);

/**
 * @route POST /api/auth/login
 * @description Login user with email and password
 * @access public
 */
authRouter.post("/login", loginUserController);

/**
 * @route GET /api/auth/logout
 * @description Clear the token cookie and add the token in blacklist.
 * @access public
 */
authRouter.get("/logout", logoutUserController);

/**
 * @route GET /api/auth/get-me
 * @description get the current logged in user details
 * @access private
 */
authRouter.get("/get-me", authUserMiddleware, getMeController);

module.exports = authRouter;
  