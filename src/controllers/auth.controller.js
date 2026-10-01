const userModel = require('../models/user.model');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

/**
 * @name registerUserController 
 * @description register a new user, expects username, email and password in the request
 * @access Public
 * @param {*} req 
 * @param {*} res 
 */
const registerUserController = async (req, res) => {
  const { username, email, password } = req.body;

  try {
     if (!username || !email || !password) {
      return res.status(400).json({ message: 'Please provide username, email and password' });
    }

    const isUserAlreadyExists = await userModel.findOne({
      $or: [ { username }, { email }]
    });

    if (isUserAlreadyExists) {
      if (isUserAlreadyExists.username === username) {
        return res.status(400).json({ message: 'Account already exists with this username.' });
      } else if (isUserAlreadyExists.email === email) {   
        return res.status(400).json({ message: 'Account already exists with this email.' });    
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
      { expiresIn: '1d'}
    )
    
    res.cookie('token', token);
    res.status(201).json({
      message: 'User successfully registered.',
      user: {
        id: user._id,
        username,
        email
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: 'Internal Server Error', error: error.message});
  }
}


const loginUserController = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

     const token = jwt.sign(
      { id: user._id, username: user.username, email },
      process.env.JWT_SECRET,
      { expiresIn: '1d'}
    )
    
    res.cookie('token', token);
    res.status(201).json({
      message: 'User successfully logged in.',
      user: {
        id: user._id,
        username: user.username,
        email,
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Internal Server Error', error: error.message});
  }
}

module.exports = {
  registerUserController, 
  loginUserController,
};