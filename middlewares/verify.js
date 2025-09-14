// middlewares/authMiddleware.js
import jwt from "jsonwebtoken";
import { ApiError } from "../utils/ApiError.js";
import User from "../models/user.js";

export const verifyJWT = async (req, res, next) => {
  try {
    const token =
      req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      return next(new ApiError(401, "Unauthorized request"));
    }

    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    req.user = await User.findById(decoded._id).select("-password -refreshToken");

    if (!req.user) {
      return next(new ApiError(401, "User no longer exists"));
    }

    next();
  } catch (error) {
    console.error("JWT error:", error.message); // optional
    return next(new ApiError(401, "Invalid or expired token"));
  }
};

