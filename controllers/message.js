// import { ApiError } from "../utils/ApiError.js";
// import { asyncHandler } from "../utils/asyncHandler.js";
// import { ApiResponse } from "../utils/ApiResponse.js";
// import Message from '../models/message.js'
// import pkg from "simple-crypto-js";
// const { default: SimpleCrypto } = pkg;
// import mongoose from "mongoose";

// const encryptMsg = (data)=>{
//     const secretKey = process.env.SIMPLE_CRYPTO_MESSAGE_SECRET_KEY
//     const simpleCrypto = new SimpleCrypto(secretKey)
//     return simpleCrypto.encrypt(data)
// }
// const decryptMsg = (data)=>{
//         const secretKey = process.env.SIMPLE_CRYPTO_MESSAGE_SECRET_KEY
//     const simpleCrypto = new SimpleCrypto(secretKey)
//     return simpleCrypto.decrypt(data)
// }

// //SEND MESSAGE
// export const sendMessage = asyncHandler(async (req,res) => {
//     const receiverId = req.params.id;
//     if(!receiverId){
//         throw new ApiError(404,"Receiver Account Not Found")
//     }
//     const senderId = req.user._id;
//     if(senderId==receiverId){
//         throw new ApiResponse(400,"Send failed,sender and receiver cannot be same")
//     }
//     const message = req.body.message
//         if(!message){
//         throw new ApiError(404,"Message cannot be left empty")
//     }
//     const messageObj = await Message.create({senderId,receiverId,message:encryptMsg(message)})
//     messageObj.message = message;
//     res.status(201).json(new ApiResponse(201,messageObj,"Message Sent Successfully"))
// })
// //LIST OF PEOPLE AND LAST MESSAGE OF EACH/inbox
// export const InboxList = asyncHandler(async (req,res) => {
//     const user = req.user._id;
//     const userId = new mongoose.Types.ObjectId(user);

//     const inboxObj = await Message.aggregate([
//         {
//             $match: {
//                 $or: [
//                     { senderId: userId },
//                     { receiverId: userId }
//                 ]
//             }
//         },
//         { $sort: { createdAt: -1 } },
//         {
//             $addFields: {
//                 participant: {
//                     $cond: [
//                         { $eq: ["$senderId", userId] },
//                         "$receiverId",
//                         "$senderId"
//                     ]
//                 }
//             }
//         },
//         {
//             $group: {
//                 _id: "$participant",
//                 lastMessage: { $first: "$$ROOT" }
//             }
//         },
//         {
//             $lookup: {
//                 from: "users",
//                 localField: "_id",
//                 foreignField: "_id",
//                 as: "participant",
//                 pipeline: [
//                     { $project: { name: 1, avatar: 1, lastseen: 1 } }
//                 ]
//             }
//         },
//         { $unwind: "$participant" },
//         { $sort: { "lastMessage.createdAt": -1 } }
//     ]);
//     if(inboxObj?.length==0){
//         throw new ApiError(404,"No Messages Found")
//     }
//     // 🔑 Decrypt messages here before sending response
//     inboxObj.forEach(conv => {
//         if (conv.lastMessage?.message) {
//             conv.lastMessage.message = decryptMsg(conv.lastMessage.message);
//         }
//     });

//     res.status(200).json(new ApiResponse(200,inboxObj,"Inbox Fetched Successfully"));
// });
// //Chat 
// export const getChatMessages = asyncHandler(async (req, res) => {
//   const userId = new mongoose.Types.ObjectId(req.user._id); // logged-in user
//   const otherUserId = new mongoose.Types.ObjectId(req.params.id); // chat partner

//   // from frontend: ?limit=20&skip=40
//   const limit = parseInt(req.query.limit) || 20;
//   const skip = parseInt(req.query.skip) || 0;

//   let messages = await Message.aggregate([
//     {
//       $match: {
//         $or: [
//           { senderId: userId, receiverId: otherUserId },
//           { senderId: otherUserId, receiverId: userId }
//         ]
//       }
//     },
//     {
//       $lookup: {
//         from: "users",
//         localField: "senderId",
//         foreignField: "_id",
//         as: "sender",
//         pipeline: [
//           { $project: { name: 1, lastseen: 1, avatar: 1 } }
//         ]
//       }
//     },
//     { $unwind: "$sender" },
//     { $sort: { createdAt: -1 } }, // newest first
//     { $skip: skip },
//     { $limit: limit }
//   ]);

//   // 🔑 Decrypt message text
//   messages = messages.map(m => ({
//     ...m,
//     message: decryptMsg(m.message)
//   }));

//   res.status(200).json(new ApiResponse(200, messages, "Chat messages fetched"));
// });
// //MARK MESSAGES AS READ
// export const markMessagesRead = asyncHandler(async (req, res) => {
//   const userId = req.user._id; // logged-in user
//   const otherUserId = req.params.chatUserId;

//   if (!otherUserId) {
//     res.status(400);
//     throw new ApiError(404,"Chat User Id is Required")
//   }

//   // Update all messages sent by otherUser to current user and not read yet
//   const result = await Message.updateMany(
//     { senderId: otherUserId, receiverId: userId, isRead: false },
//     { $set: { isRead: true } }
//   );

//   res.status(200).json(new ApiResponse(200,null,`${result.modifiedCount} messages marked as read`));
// });



import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import Message from "../models/message.js";
import pkg from "simple-crypto-js";
const { default: SimpleCrypto } = pkg;
import mongoose from "mongoose";
import Pusher from "pusher";
import { uploadToCloudinary } from "../utils/cloudinaryUpload.js";
// 🔔 Pusher setup
const pusher = new Pusher({
  appId: process.env.PUSHER_APP_ID,
  key: process.env.PUSHER_KEY,
  secret: process.env.PUSHER_SECRET,
  cluster: process.env.PUSHER_CLUSTER,
  useTLS: true,
});

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

  let fileUrl = null;

  // ✅ Upload file to Cloudinary if present
  if (req.file) {
    try {
      fileUrl = await uploadToCloudinary(req.file.buffer, "chat_files");
    } catch (err) {
      throw new ApiError(500, "File upload failed");
    }
  }

  // Prepare message object
  const newMessage = {
    senderId,
    receiverId,
    message: message ? encryptMsg(message) : null,
    file: fileUrl, // Cloudinary URL
  };

  const savedMessage = await Message.create(newMessage);

  // For response & realtime event, send decrypted message
  const payload = {
    _id: savedMessage._id,
    senderId,
    receiverId,
    message: message || null,
    file: savedMessage.file || null,
    createdAt: savedMessage.createdAt,
  };

  // 🔔 Trigger realtime event
  pusher.trigger(`private-chat-${receiverId}`, "new-message", payload);
  pusher.trigger(`private-chat-${senderId}`, "new-message", payload);

  return res
    .status(201)
    .json(new ApiResponse(201, payload, "Message Sent Successfully"));
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
