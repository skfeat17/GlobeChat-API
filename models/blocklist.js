import mongoose from "mongoose";

const blockListSchema = new mongoose.Schema(
  {
    blockerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    blockedId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    }
  },
  {
    timestamps: true
  }
);

export default mongoose.model("BlockList", blockListSchema);
