import express from "express";
const app = express();
import './config/db';
import cors from "cors";
import passport from "passport";
import bodyParser from "body-parser";
import * as dotenv from 'dotenv'
dotenv.config()

import userRouter from "./routes/userRoute";

// ALL THE MIDDLEWARES GOES HERE
app.use(express.json());
app.use(
  cors({
    origin: "*",
    methods: "GET,POST,PUT,DELETE",
    credentials: true,
  })
);
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);
app.use(passport.initialize());
require("./middleware/passport")(passport);

// ALL THE ROUTES HERE
app.use("/auth", userRouter);

// welcome message
app.get('/', (req, res) => {
  return res.send('Hey welcome to the  Technogetic')
})

const port = 5001;

app.listen(port, () => {
  console.log(`Server is running on port ${port} 👍️`);
});