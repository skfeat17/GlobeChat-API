import express from "express";
import { verifyJWT } from "../middlewares/verify.js";
import { upload } from "../middlewares/multer.js";
import {
  sendMessage,
  InboxList,
  getChatMessages,
  markMessagesRead,
} from "../controllers/message.js";

const router = express.Router();

/**
 * @route   POST /api/message/:id
 * @desc    Send a message (text or file)
 * @access  Private
 */
router.post("/send/:id", verifyJWT, upload.single("file"), sendMessage);

/**
 * @route   GET /api/inbox
 * @desc    Get inbox list (last message per user)
 * @access  Private
 */
router.get("/inbox", verifyJWT, InboxList);

/**
 * @route   GET /api/chat/:id
 * @desc    Get chat messages with a specific user
 * @query   ?limit=20&skip=40
 * @access  Private
 */
router.get("/chat/:id", verifyJWT, getChatMessages);

/**
 * @route   PATCH /api/chat/:chatUserId/read
 * @desc    Mark all messages from chatUserId as read
 * @access  Private
 */
router.patch("/chat/:chatUserId/read", verifyJWT, markMessagesRead);

export default router;
