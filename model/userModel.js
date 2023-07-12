import { Schema, model } from "mongoose";

const UserSchema = new Schema(
  {
    name: {
      type: String,
      required: false,
    },
    email: {
      type: String,
      required: false,
    },
    role: {
      type: String,
      default: "user",
      enum: ["user", "admin", "superadmin", "teacher", "student"],
    },
    username: {
      type: String,
      required: false,
    },
    password: {
      type: String,
      required: false,
    },
    fatherName: { type: String, required: false },
    phone: { type: Number, required: false },
    address: { type: String, required: false },
    collegeName: { type: String, required: false },
    university: { type: String, required: false },
    skills: { type: String, required: false },
    courseDuration: { type: String, required: false },
    feePaid: { type: String, required: false },
  },

  { timestamps: true }
);

module.exports = model("Auth", UserSchema);
