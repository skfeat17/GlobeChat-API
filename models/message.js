import mongoose from "mongoose";

const messageSchema = new mongoose.Schema(
  {
    senderId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    receiverId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    message: {
      type: String,
      required: true,
      trim: true
    },
    file:{
      type:String
    },
    isRead: {
      type: Boolean,
      default: false
    }
  },
  {
    timestamps: true
  }
);

export default mongoose.model("Message", messageSchema);
