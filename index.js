import dotenv from "dotenv";
import mongoose from "mongoose";
import { app } from "./app.js";

// Load environment variables
dotenv.config({
  path: "./.env"
});
app.get("/", (req, res) => {
  res.status(200).json({message:"Api is Running Successfully"});
});

// MongoDB connection
const connectDB = async () => {
  try {
    const connectionInstance = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log(`\n✅ MongoDB connected !! DB HOST: ${connectionInstance.connection.host}`);
  } catch (error) {
    console.log("❌ MongoDB connection FAILED:", error);
    process.exit(1);
  }
};

// Start server only after DB connection
connectDB().then(() => {
  app.listen(process.env.PORT || 8000, () => {
    console.log(`🚀 Server running on port ${process.env.PORT || 8000}`);
  });
});
