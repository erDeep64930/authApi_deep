const bcrypt = require("bcrypt");
const User = require("../models/user");
const { response } = require("express");
const jwt = require("jsonwebtoken");
require("dotenv").config();
// signup routes handler

exports.signup = async (req, res) => {
  try {
    // get data
    const { name, email, password, roles } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }
    // secure password
    let hashedPassword;
    try {
      hashedPassword = await bcrypt.hash(password, 10);
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: "error in hashing password",
      });
    }

    // create entry for user

    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      roles,
    });

    return res.status(200).json({
      success: true,
      message: "User created successfully",
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      success: false,
      message: "User not created !!",
    });
  }
};

// login

exports.login = async (req, res) => {
  try {
    // data fetch
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Please fill all the details carefully.",
      });
    }

    // check register user details
    const user = await User.findOne({ email });

    // if not register user

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "user is not registered",
      });
    }

    // verify password and generate JWT token

    const payload = {
      email: user.email,
      id: user._id,
      roles: user.roles,
    };

    if (await bcrypt.compare(password, user.password)) {
      // password matched
      let token = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: "2h",
      });
      user = user.toObject();
      user.token = token;
      console.log(user)
      // here password is not hide from database  but from local storage and hide
      user.password = undefined;
      console.log(user)
      
      const options = {
        expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
        httpOnly: true,
      };
      // create cookies 
      res.cookie("token", token, options).status(200).json({
        success: true,
        message: "user logged in successfully ",
      });
    } else {
      // password do not match
      return res.status(403).json({
        success: false,
        message: "password do not match",
      });
    }
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      success: false,
      message: "login failed",
    });
  }
};
 