import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 50,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    username: {
      type: String,
      unique: true,
      sparse: true, 
      trim: true,
      minlength: 3,
      maxlength: 30,
    },
    gender: {
      type: String,
      enum: ["male", "female", "other"],
      default: "other",
    },
    bio: {
      type: String,
      maxlength: 160,
      default: "Hey there! I am using ChatApp 🚀",
    },
    password: {
      type: String,
      required: true,
      minlength: 4,
    },
    avatar: {
      type: String,
      default: "", 
    },
    isOnline: {
      type: Boolean,
      default: false,
    },
    lastSeen: {
      type: Date,
      default: Date.now,
    },
    refreshToken: {
      type: String,
    },blockedUsers: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
      }
    ],
    ,friends: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User"
      }
    ],
  },
  {
    timestamps: true
  }
);

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});


// Check password
userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// JWT methods
userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
  );
};

userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    { _id: this._id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
  );
};

export default mongoose.model("User", userSchema);
