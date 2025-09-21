import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import Message from "../models/message.js";
import pkg from "simple-crypto-js";
const { default: SimpleCrypto } = pkg;
import mongoose from "mongoose";
import { uploadToCloudinary } from "../utils/cloudinaryUpload.js";
import BlockDB from "../models/blocklist.js";
import beamsClient from "../config/beam.js";


// 🔑 Encryption helpers
const encryptMsg = (data) => {
  const secretKey = process.env.SIMPLE_CRYPTO_MESSAGE_SECRET_KEY;
  const simpleCrypto = new SimpleCrypto(secretKey);
  return simpleCrypto.encrypt(data);
};
const decryptMsg = (data) => {
  const secretKey = process.env.SIMPLE_CRYPTO_MESSAGE_SECRET_KEY;
  const simpleCrypto = new SimpleCrypto(secretKey);
  return simpleCrypto.decrypt(data);
};

// ✅ SEND MESSAGE
export const sendMessage = asyncHandler(async (req, res) => {
  const receiverId = req.params.id;
  if (!receiverId) throw new ApiError(404, "Receiver Account Not Found");

  const senderId = req.user._id;
  if (senderId.equals(receiverId))
    throw new ApiError(400, "Send failed, sender and receiver cannot be same");

  const { message } = req.body;
  if (!message && !req.file) {
    throw new ApiError(400, "Message or file is required");
  }

  // ✅ Check if blocked
  const blockRecord = await BlockDB.findOne({
    $or: [
      { user: senderId, blockedUser: receiverId },
      { user: receiverId, blockedUser: senderId },
    ],
  });
  if (blockRecord) {
    throw new ApiError(403, "Message cannot be sent as one user has blocked the other");
  }

  let fileUrl = null;

  // ✅ Upload file to Cloudinary
  if (req.file) {
    try {
      fileUrl = await uploadToCloudinary(req.file.buffer, "chat_files");
    } catch (err) {
      throw new ApiError(500, "File upload failed");
    }
  }

  // ✅ Save message
  const newMessage = {
    senderId,
    receiverId,
    message: message ? encryptMsg(message) : null,
    file: fileUrl,
  };
  const savedMessage = await Message.create(newMessage);


  // ✅ Push Notification (Web/PWA)
  try {
    const preview = message
      ? (message.length > 100 ? message.substring(0, 97) + "..." : message)
      : "📎 Sent you a file";

    await beamsClient.publishToInterests([`chat-${receiverId}`], {
      web: {
        notification: {
          title: `${req.user.name}`,
          body: preview,
          icon: req.user.avatar|| "https://cdn-icons-png.flaticon.com/512/726/726623.png",
          deep_link: `https://globe-chat-web-app.vercel.app/`,
        },
      },
      data: {
        senderId: senderId.toString(),
        messageId: savedMessage._id.toString(),
      },
    });

    console.log("✅ Push notification sent!");
  } catch (err) {
    console.error("❌ Push notification error:", err);
  }

  return res
    .status(201)
    .json(new ApiResponse(201, { savedMessage }, "Message Sent Successfully"));
});

// 📥 INBOX LIST
export const InboxList = asyncHandler(async (req, res) => {
  const user = req.user._id;
  const userId = new mongoose.Types.ObjectId(user);

  const inboxObj = await Message.aggregate([
    {
      $match: {
        $or: [{ senderId: userId }, { receiverId: userId }],
      },
    },
    { $sort: { createdAt: -1 } },
    {
      $addFields: {
        participant: {
          $cond: [{ $eq: ["$senderId", userId] }, "$receiverId", "$senderId"],
        },
      },
    },
    {
      $group: {
        _id: "$participant",
        lastMessage: { $first: "$$ROOT" },
      },
    },
    {
      $lookup: {
        from: "users",
        localField: "_id",
        foreignField: "_id",
        as: "participant",
        pipeline: [{ $project: { name: 1, avatar: 1, lastSeen: 1,isOnline:1 } }],
      },
    },
    { $unwind: "$participant" },
    { $sort: { "lastMessage.createdAt": -1 } },
  ]);

  if (!inboxObj || inboxObj.length === 0) {
    throw new ApiError(404, "No Messages Found");
  }

  inboxObj.forEach((conv) => {
    if (conv.lastMessage?.message) {
      conv.lastMessage.message = decryptMsg(conv.lastMessage.message);
    }
  });

  res
    .status(200)
    .json(new ApiResponse(200, inboxObj, "Inbox Fetched Successfully"));
});

// 💬 CHAT HISTORY
export const getChatMessages = asyncHandler(async (req, res) => {
  const userId = new mongoose.Types.ObjectId(req.user._id);
  const otherUserId = new mongoose.Types.ObjectId(req.params.id);

  const limit = parseInt(req.query.limit) || 20;
  const skip = parseInt(req.query.skip) || 0;

  let messages = await Message.aggregate([
    {
      $match: {
        $or: [
          { senderId: userId, receiverId: otherUserId },
          { senderId: otherUserId, receiverId: userId },
        ],
      },
    },
    {
      $lookup: {
        from: "users",
        localField: "senderId",
        foreignField: "_id",
        as: "sender",
        pipeline: [{ $project: { name: 1, lastseen: 1, avatar: 1 } }],
      },
    },
    { $unwind: "$sender" },
    { $sort: { createdAt: -1 } },
    { $skip: skip },
    { $limit: limit },
  ]);

  messages = messages.map((m) => ({
    ...m,
    message: m.message ? decryptMsg(m.message) : null,
  }));

  res
    .status(200)
    .json(new ApiResponse(200, messages, "Chat messages fetched"));
});

// ✅ MARK READ
export const markMessagesRead = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  const otherUserId = req.params.chatUserId;

  if (!otherUserId) throw new ApiError(404, "Chat User Id is Required");

  const result = await Message.updateMany(
    { senderId: otherUserId, receiverId: userId, isRead: false },
    { $set: { isRead: true } }
  );

  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        null,
        `${result.modifiedCount} messages marked as read`
      )
    );
});

//Delete Chat History
export const deleteChatHistory = asyncHandler(async (req, res) => {
  const userId = req.user._id;
  const otherUserId = req.params.id;

  if (!otherUserId) throw new ApiError(404, "Chat User Id is Required");

  const result = await Message.deleteMany({
    $or: [
      { senderId: userId, receiverId: otherUserId },
      { senderId: otherUserId, receiverId: userId },
    ],
  });
  if(result.deletedCount===0){
    throw new ApiError(404, "No chat history found to delete");
  }
  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        null,
        `${result.deletedCount} messages deleted from chat history`
      )
    );
});
