import User from "../models/user.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { uploadToCloudinary } from "../utils/cloudinaryUpload.js";
import jwt from "jsonwebtoken";
import { sendEmail } from "../utils/nodemailer.js";
import pkg from "simple-crypto-js";
const { default: SimpleCrypto } = pkg;
import {pusher} from "../utils/pusher.js";


const httpOptions = {
  httpOnly: true,
  secure: true,
};

// ✅ Generate Tokens
const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(500, "Error generating tokens");
  }
};

// ✅ REGISTER
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, username, password, gender } = req.body;

  if (!name || !email || !username || !password) {
    throw new ApiError(400, "All required fields must be provided");
  }

  const existingUser = await User.findOne({
    $or: [{ email }, { username }],
  });

  if (existingUser) {
    throw new ApiError(409, "User already exists with this email or username");
  }

  const user = await User.create({
    name,
    email,
    username,
    password,
    gender,
  });

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);

  const createdUser = await User.findById(user._id).select("-password -refreshToken");
  res.status(201)
    .cookie("accessToken", accessToken, httpOptions)
    .cookie("refreshToken", refreshToken, httpOptions)
    .json(new ApiResponse(201, { user: createdUser, accessToken, refreshToken }, "User registered successfully"));
});

// ✅ LOGIN
const logInUser = asyncHandler(async (req, res) => {
  const { email, username, password } = req.body;

  if ((!email && !username) || !password) {
    throw new ApiError(400, "Email/Username and password are required");
  }

  const user = await User.findOne({ $or: [{ email }, { username }] });
  if (!user) throw new ApiError(404, "User not found");

  const isPasswordCorrect = await user.isPasswordCorrect(password);
  if (!isPasswordCorrect) throw new ApiError(401, "Invalid credentials");

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);
  const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

  res.status(200)
    .cookie("accessToken", accessToken, httpOptions)
    .cookie("refreshToken", refreshToken, httpOptions)
    .json(new ApiResponse(200, { user: loggedInUser, accessToken, refreshToken }, "Login successful"));
});

// ✅ UPLOAD AVATAR / COVER PHOTO
const uploadAvatar = asyncHandler(async (req, res) => {
  if (!req.file) throw new ApiError(400, "No file uploaded");

  const result = await uploadToCloudinary(req.file.buffer, "avatar");
  const user = await User.findByIdAndUpdate(req.user._id, { avatar: result.secure_url }, { new: true }).select("-password -refreshToken");

  res.status(200).json(new ApiResponse(200, user, "Avatar uploaded successfully"));
});

//SEND OTP
const sendOTP = asyncHandler(async (req, res) => {
  const { email ,username} = req.body;
  if (!email&&!username) {
    throw new ApiError(400, "Email or Username is required");
  }
  // 1. Find user by email
  const user = await User.findOne({ $or:[{email} ,{username}]});
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  // 2. Generate OTP (4-digit)
  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  const secretKey = process.env.SIMPLE_CRYPTO_SECRET_KEY
  const simpleCrypto = new SimpleCrypto(secretKey)
  const cipherText = simpleCrypto.encrypt(otp)
  // 3. Send OTP via email
  await sendEmail({
    to: user.email,
    name: user.name,
    otp
  });

  // 4. Create a user-specific token (cookie) to verify later
  const credentialsToken = jwt.sign(
    { userId: user._id, otpToken: cipherText },
    process.env.OTP_TOKEN_SECRET,
    { expiresIn: "10m" }
  );

  // Cookie expires in 10 minutes
  const otpCookieOptions = {
    ...httpOptions,
    maxAge: 10 * 60 * 1000
  };

  // 5. Send response
  res
    .cookie("credentialsToken", credentialsToken, otpCookieOptions)
    .status(200)
    .json(
      new ApiResponse(200, { credentialsToken }, "OTP sent successfully")
    );
});
//FORGOT/RESET PASSWORD
const resetPassword = asyncHandler(async (req, res) => {
  const { otp, newPassword } = req.body;
  if (!otp || !newPassword) {
    throw new ApiError(400, "OTP and New Password Required");
  }

  const credentialsToken =
    req.cookies?.credentialsToken ||
    req.header("Authorization")?.replace("Bearer ", "");

  if (!credentialsToken) {
    throw new ApiError(401, "Unauthorized request");
  }

  let decoded;
  try {
    decoded = jwt.verify(credentialsToken, process.env.OTP_TOKEN_SECRET);
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      throw new ApiError(401, "OTP Expired");
    }
    throw new ApiError(400, "Invalid or malformed token");
  }

  const user = await User.findById(decoded.userId);
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  // Decrypt stored OTP
  const secretKey = process.env.SIMPLE_CRYPTO_SECRET_KEY;
  const simpleCrypto = new SimpleCrypto(secretKey);
  const originalOTP = simpleCrypto.decrypt(decoded.otpToken);

  const newOTP = otp.toString()
  if (newOTP != originalOTP) {
    throw new ApiError(401, "Incorrect OTP");
  }

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  // Clear OTP cookie
  res.clearCookie("credentialsToken", httpOptions);

  res
    .status(200)
    .json(new ApiResponse(200, {}, "Password reset successfully"));
});

// ✅ UPDATE PROFILE
const updateProfile = asyncHandler(async (req, res) => {
  const { name, bio, gender } = req.body;

  if (!name && !bio && !gender) throw new ApiError(400, "Nothing to update");

  const updatedUser = await User.findByIdAndUpdate(
    req.user._id,
    { name, bio, gender },
    { new: true }
  ).select("-password -refreshToken");

  res.status(200).json(new ApiResponse(200, updatedUser, "Profile updated successfully"));
});

// ✅ LOGOUT
const logOutUser = asyncHandler(async (req, res) => {
  res.clearCookie("accessToken", httpOptions).clearCookie("refreshToken", httpOptions);
  await User.findByIdAndUpdate(req.user._id, { $unset: { refreshToken: "" } });

  res.status(200).json(new ApiResponse(200, {}, "Logged out successfully"));
});

// ✅ REFRESH TOKEN
const refreshAccessToken = asyncHandler(async (req, res) => {
  const token = req.cookies?.refreshToken || req.header("Authorization")?.replace("Bearer ", "");
  if (!token) {
    throw new ApiError(401, "Unauthorized request")
  }
  let decoded;
  try {
    decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
  } catch (err) {
    throw new ApiError(401, "Invalid or expired refresh token");
  }
  const user = await User.findById(decoded._id);
  if (!user) {
    throw new ApiError(404, "User not found");
  }
  const storedRefreshToken = user.refreshToken;
  if (!storedRefreshToken) {
    throw new ApiError(404, "No refresh token stored for this user");
  }
  if (storedRefreshToken != token) {
    throw new ApiError(403, "Refresh token is invalid or expired");
  }
  const accessToken = user.generateAccessToken()
  res
    .cookie("accessToken", accessToken, httpOptions)
    .status(200)
    .json(new ApiResponse(200, { newAccessToken: accessToken }, "Access Token refreshed successfully"));

})

// ✅ CHANGE PASSWORD
const changeUserPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) throw new ApiError(400, "Both old and new password required");

  const user = await User.findById(req.user._id);
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);
  if (!isPasswordCorrect) throw new ApiError(401, "Incorrect password");

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  res.status(200).json(new ApiResponse(200, {}, "Password changed successfully"));
});

// ✅ GET USER PROFILE
const getUserProfile = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id).select("-password -refreshToken");
  if (!user) throw new ApiError(404, "User not found");

  res.status(200).json(new ApiResponse(200, user, "Profile fetched successfully"));
});

//MARK ONLINE STATUS
export const markOnline = asyncHandler(async (req,res) => {
  const userId = req.user._id;
   const user = await User.findByIdAndUpdate(
    userId,
    { isOnline: true },
    { new: true }
  );

  await pusher.trigger("users", "online_status_updated", {
    userId: user._id,
    isOnline: true,
  });
  res.status(200).json(new ApiResponse(200,null,"Marked Online"))
})
//MARK OFFLINE STATUS
export const markOffline = asyncHandler(async (req, res) => {
  const userId = req.user._id;

  const user = await User.findByIdAndUpdate(
    userId,
    { isOnline: false, lastSeen: new Date() },
    { new: true }
  );

  // 🔔 Trigger Pusher event
  await pusher.trigger("users", "online_status_updated", {
    userId: user._id,
    isOnline: false,
    lastSeen: user.lastSeen,
  });

  res.status(200).json(new ApiResponse(200, null, "Marked Offline"));
});


//PUSHER AUTHENTICATION 
export const pusherAuthenticate = asyncHandler(async (req,res) => {
  const socketId = req.body.socket_id;
  const channel = req.body.channel_name;

  if (!req.user) return res.status(403).send("Unauthorized");

  if(channel.startsWith("presence-")){
    const presenceData = {
      user_id: req.user._id, 
      user_info: { name: req.user.username }
    };
    const auth = pusher.authenticate(socketId, channel, presenceData);
    res.send(auth);
  } else {
    const auth = pusher.authenticate(socketId, channel);
    res.send(auth);
  }
});



export {
  registerUser,
  logInUser,
  uploadAvatar,
  updateProfile,
  logOutUser,
  refreshAccessToken,
  changeUserPassword,
  getUserProfile,
  sendOTP,resetPassword
};
