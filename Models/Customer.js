const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const reqStr = {
  type: String,
  required: true,
};
const reqNum = {
  type: Number,
  required: true,
};

const CustomerSchema = new Schema({
  name: reqStr,
  email: reqStr,
  password: reqStr,
  cnic: reqStr,
  contact: reqStr,
  address: reqStr,
  ref: reqStr,
  page: reqNum,
  return_amount: { type: Number, default: 0, required: true },
  discount: { type: Number, default: 0, required: true },
  paid: { type: Number, default: 0, required: true },
  remaining: { type: Number, default: 0, required: true },
  total: { type: Number, default: 0, required: true },
  date: { type: Number, default: Math.floor(Date.now() / 1000) },
});

module.exports =
  mongoose.models.Customer || mongoose.model("Customer", CustomerSchema);
