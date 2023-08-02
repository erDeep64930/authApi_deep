// auth ,isStudent,isAdmin

const jwt = require("jsonwebtoken");
require("dotenv").config();

exports.auth = (req, res, next) => {
  try {
    // extract jwt token from body or cookies or headers
    //const token =req.body.token || req.cokkies.token || req.header.token
    const token = req.body.token;
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "token missing required",
      });
    }
    // verify the token
    try {
      const decode = jwt.verify(token, process.env.JWT_SECRET);
      console.log(decode);
      req.user = decode;
    } catch (err) {
      return res.status(401).json({
        success: false,
        message: "Invalid token",
      });
    }
    next();
  } catch (error) {
    return res.status(401).json({
        success: false,
        message: "something went wrong , while verifying the token",
    })
  }
};

// isStudent

exports.isStudent = (req,res,next) => {
    try {
      if(req.user.role!=="Student"){
        return res.status(401).json({
            success: false,
            message: "this is protected route for student",
        })
      } 
      next() 
    } catch (error) {
       return res.status(500).json({
        success: false,
        message: "user role is not matching",
       }) 
    }
}

// isadmin

exports.isAdmin = (req,res,next) => {
    try {
      if(req.user.role!=="Admin"){
        return res.status(401).json({
            success: false,
            message: "this is protected route for admin",
        })
      } 
      next() 
    } catch (error) {
       return res.status(500).json({
        success: false,
        message: "user role is not matching",
       }) 
    }
}
