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
  unblockUser,getAllOnlineUsers
} from "../controllers/user.js";

import { verifyJWT } from "../middlewares/verify.js";
import { upload } from "../middlewares/multer.js";

const router = Router();

/* ---------- AUTH ---------- */
router.post("/register", registerUser);
router.post("/login", logInUser);
router.post("/logout", verifyJWT, logOutUser);
router.post("/refresh-token",refreshAccessToken);
router.post("/pusher/auth", verifyJWT, pusherAuthenticate)

/* ---------- PROFILE ---------- */
router.get("/profile", verifyJWT, getUserProfile);
router.put("/profile", verifyJWT, updateProfile);
router.put("/avatar", verifyJWT, upload.single("avatar"), uploadAvatar);

/* ---------- PASSWORD & SECURITY ---------- */
router.post("/change-password", verifyJWT, changeUserPassword);
router.post("/send-otp", sendOTP);
router.post("/reset-password", resetPassword);

/* ---------- OTHERS ---------- */
router.post('/mark-online', verifyJWT,markOnline) 
router.post('/mark-offline', verifyJWT, markOffline)
router.get("/search",verifyJWT, searchUsers);
router.post("/block/:id", verifyJWT,blockUser);
router.post("/unblock/:id", verifyJWT, unblockUser);
router.get("/online-users", verifyJWT, getAllOnlineUsers);
export default router;
