const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: {
    type: "string",
    required: true,
    trim: true,
  },
  email: {
    type: "string",
    required: true,
    trim: true,
  },
  password: {
    type: "string",
    required: true,
    },
    roles:{
        type:String,
        enum:["admin", "Students","Visitors"],
    }
});

module.exports = mongoose.model("user",userSchema)
    