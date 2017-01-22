var mongoose = require("mongoose");
mongoose.connect('mongodb://localhost:27017/accounts');
var mongoSchema = mongoose.Schema;
var userSchema = {
  "uuid": String,
  "username": String,
  "password": String,
  "admin": Number,
  "accountType": Number
};
module.exports = mongoose.model('accounts', userSchema);
