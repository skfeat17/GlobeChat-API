import { Router } from "express";
import {
  registerUser,
  logInUser,
  uploadAvatar,
  updateProfile,
  logOutUser,
  refreshAccessToken,
  changeUserPassword,
  getUserProfile,
  sendOTP,
  resetPassword,
  markOnline,
  markOffline,
  pusherAuthenticate,
  searchUsers,
  blockUser,
  unblockUser,
  getAllOnlineUsers,
  addFriend,
  removeFriend,
  getFriends,
  getUserDetails
} from "../controllers/user.js";
import beamsClient from "../config/beam.js";
import { verifyJWT } from "../middlewares/verify.js";
import { upload } from "../middlewares/multer.js";
import { ApiError } from "../utils/ApiError.js";

const router = Router();

/* ---------- AUTH ---------- */
router.post("/register", registerUser);
router.post("/login", logInUser);
router.post("/logout", verifyJWT, logOutUser);
router.post("/refresh-token", refreshAccessToken);
// router.post("/pusher/auth", verifyJWT, pusherAuthenticate);
router.post("/pusher/auth", pusherAuthenticate);

/* ---------- PROFILE ---------- */
router.get("/profile", verifyJWT, getUserProfile);
router.put("/profile", verifyJWT, updateProfile);
router.put("/avatar", verifyJWT, upload.single("avatar"), uploadAvatar);

/* ---------- PASSWORD & SECURITY ---------- */
router.post("/change-password", verifyJWT, changeUserPassword);
router.post("/send-otp", sendOTP);
router.post("/reset-password", resetPassword);

/* ---------- ONLINE STATUS ---------- */
router.post("/mark-online", verifyJWT, markOnline);
router.post("/mark-offline", verifyJWT, markOffline);

/* ---------- SEARCH & BLOCK ---------- */
router.get("/search", verifyJWT, searchUsers);
router.post("/block/:id", verifyJWT, blockUser);
router.post("/unblock/:id", verifyJWT, unblockUser);
router.get("/online-users", verifyJWT, getAllOnlineUsers);

/* ---------- FRIENDSHIP ---------- */
router.post("/friends/add/:id", verifyJWT, addFriend);
router.post("/friends/remove/:id", verifyJWT, removeFriend);
router.get("/friends", verifyJWT, getFriends);
router.get("/getUserDetails/:id", verifyJWT, getUserDetails);

///PUSH NOTIFICATIONS
router.post("/beams/auth",verifyJWT, (req, res) => {
 try {
  const userId = req.user._id.toString(); 
  const beamsToken = beamsClient.generateToken(userId);
  res.json(beamsToken);
 } catch (error) {
 throw new ApiError(500, err.message);
 } 
 
});
export default router;

