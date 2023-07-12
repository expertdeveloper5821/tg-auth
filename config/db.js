import mongoose from "mongoose";
import * as dotenv from 'dotenv'
dotenv.config()

mongoose.connect(
    `mongodb+srv://${process.env.DBUSERNAME}:${process.env.DBPASSWD}@technogetic-backend.ejilt4m.mongodb.net/?retryWrites=true&w=majority`)
  .then(() => {
    console.log("Database Connected 👍️");
  })
  .catch((error) => {
    console.log("Database not connected", error);
  });
