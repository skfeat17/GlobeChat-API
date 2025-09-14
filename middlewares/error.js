import { ApiError } from "../utils/ApiError.js";

export const errorHandler = (err, req, res, next) => {
  console.error("❌ Error middleware caught:", err);

  if (err instanceof ApiError) {
    return res.status(err.statusCode).json({
      success: false,
      message: err.message,
      errors: err.errors || []
    });
  }

  // Default for unhandled errors
  res.status(500).json({
    success: false,
    message: "Internal Server Error",
    error: err.message
  });
};
