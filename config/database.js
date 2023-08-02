const mongoose = require('mongoose');

require('dotenv').config();

 dbConnect =()=>{
    mongoose.connect(process.env.MONGODB_URL, {
        useNewUrlParser:true,
        useUnifiedTopology:true,
    })
    .then(()=>{
        console.log("db connected successfully")
    })
    .catch((err)=>{
        console.log(err.message)
        process.exit(1);
        console.log("db connection error: " + err.message)
    })
}

module.exports = dbConnect;
