const userModel = require("../models/user.model");
const blacklistTokenModel = require("../models/blacklistToken.model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

/**
 * @name registerUserController 
 * @description Registers a new user with username, email, and password,
 *              hashes the password, generates a JWT token, and stores it in an HTTP cookie.
 * @access public
 * @param {import("express").Request} req - Request containing username, email, and password.
 * @param {import("express").Response} res - Response object. 
 */
const registerUserController = async (req, res) => {
  const { username, email, password } = req.body;

  try {
     if (!username || !email || !password) {
      return res.status(400).json({ message: "Please provide username, email and password" });
    }

    const isUserAlreadyExists = await userModel.findOne({
      $or: [ { username }, { email }]
    });

    if (isUserAlreadyExists) {
      if (isUserAlreadyExists.username === username) {
        return res.status(400).json({ message: "Account already exists with this username." });
      } else if (isUserAlreadyExists.email === email) {   
        return res.status(400).json({ message: "Account already exists with this email." });    
      }
    }

    const salt = bcrypt.genSaltSync(10);
    const hashPassword = await bcrypt.hash(password, salt);

    const user = await userModel.create({
      username,
      email,
      password: hashPassword,
    })

    const token = jwt.sign(
      { id: user._id, username, email },
      process.env.JWT_SECRET,
      { expiresIn: "1d"}
    )
    
    res.cookie("token", token);
    res.status(201).json({
      message: "User successfully registered.",
      user: {
        id: user._id,
        username,
        email
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal Server Error", error: error.message});
  }
}

/**
 * @name loginUserController 
 * @description Authenticates a user using email and password, generates a JWT token,
 *              and stores the token in an HTTP cookie.
 * @access public
 * @param {import("express").Request} req - Express request object containing
 *                                           email and password in req.body.
 * @param {import("express").Response} res - Express response object used to
 *                                            send the login response. 
 */
const loginUserController = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

     const token = jwt.sign(
      { id: user._id, username: user.username, email },
      process.env.JWT_SECRET,
      { expiresIn: "1d"}
    )
    
    res.cookie("token", token);
    res.status(201).json({
      message: "User successfully logged in.",
      user: {
        id: user._id,
        username: user.username,
        email,
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error", error: error.message});
  }
}

/**
 * @name logoutUserController 
 * @description Logs out the authenticated user by adding the JWT token to the
 *              blacklist and clearing the token cookie.
 * @access public
 * @param {import("express").Request} req - Request object containing the JWT token in cookies.
 * @param {import("express").Response} res - Response object.
 */
const logoutUserController = async (req, res) => {
  const token = req.cookies.token; 
  try {
    if (!token) {
      return res.status().json({ message: "No token found, user is not logged in." });
    }
      
    // Add token to blacklist
    await blacklistTokenModel.create({ token });

    // Clear the token cookie
    res.clearCookie("token");
    res.status(200).json({ message: "User successfully logged out." });
  } catch (error) {
    res.status(500).json({ message: "Internal Server Error", error: error.message});
  }
}

/**
 * @name getMeController
 * @description Fetches the details of the currently authenticated user
 *              using the user ID attached to the request by the authentication middleware.
 *  @param {import("express").Request} req - Request object containing the authenticated
 *                                          user's ID in req.user.id.
 * @param {import("express").Response} res - Response object.
 */
const getMeController = async (req, res) => {
  const user = await userModel.findById(req.user.id);

  return res.status(200).json({
    message: "User details fetched successfully.",
    user: {
      id: user._id,
      username: user.username,
      email: user.email,  
    }
  })
}

module.exports = {
  registerUserController, 
  loginUserController,
  logoutUserController,
  getMeController,
};