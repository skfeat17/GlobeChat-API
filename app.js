import express from "express"
import cors from "cors"
import { errorHandler } from "./middlewares/error.js";
import cookieParser from "cookie-parser"
const app = express()


app.use(cors({ origin: true, credentials: true }));
app.use(express.json({limit: "16kb"}))
app.use(express.urlencoded({extended: true, limit: "16kb"}))
app.use(express.static("public"))
app.use(cookieParser())

//routes import
import userRouter from './routes/user.js'
import messageRouter from './routes/message.js'

//routes declaration
app.use("/api/v1/users", userRouter)
app.use("/api/v1/message",messageRouter)
app.use(errorHandler);


export { app }