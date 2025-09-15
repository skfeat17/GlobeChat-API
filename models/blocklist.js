import mongoose from "mongoose";

const blockListSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    blockedUser: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    }
  },
  {
    timestamps: true
  }
);

export default mongoose.model("BlockDB", blockListSchema);
blockListSchema.methods.remove = function() {
  return this.model('BlockDB').deleteOne({ _id: this._id });
}
