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
  pusherAuthenticate
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

/* ---------- STATUS ---------- */
router.post('/mark-online', verifyJWT,markOnline) 
router.post('/mark-offline', verifyJWT, markOffline)
export default router;
