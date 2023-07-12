import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import passport from "passport";
import User from "../model/userModel";
import * as dotenv from "dotenv";
dotenv.config();
import transporter from "../middleware/email";
/**
 * To register the user (ADMIN, SUPER_ADMIN, USER)
 */
const userRegister = async (userDets, role, res) => {
  try {
    if (!userDets.username || userDets.username === "") {
      return res.status(400).json({
        message: `Username is required.`,
        success: false,
      });
    }

    if (!userDets.email || userDets.email === "") {
      return res.status(400).json({
        message: `Email is required.`,
        success: false,
      });
    }

    if (!userDets.password || userDets.password === "") {
      return res.status(400).json({
        message: `Password is required.`,
        success: false,
      });
    }

    if (!userDets.role || userDets.role === "") {
      return res.status(400).json({
        message: `role is required.`,
        success: false,
      });
    }

    if (!userDets.name || userDets.name === "") {
      return res.status(400).json({
        message: `name is required.`,
        success: false,
      });
    }
    // Check if username is not taken
    let usernameNotTaken = await validateUsername(userDets.username);
    if (!usernameNotTaken) {
      return res.status(400).json({
        message: `Username is already taken.`,
        success: false,
      });
    }

    // Check if email is not already registered
    let emailNotRegistered = await validateEmail(userDets.email);
    if (!emailNotRegistered) {
      return res.status(400).json({
        message: `Email is already registered.`,
        success: false,
      });
    }

    // Get the hashed password
    const password = await bcrypt.hash(userDets.password, 12);
    // create a new user
    const newUser = new User({
      ...userDets,
      password,
      role,
    });

    await newUser.save();
    return res.status(201).json({
      message: " You are successfully registered.",
      success: true,
    });
  } catch (err) {
    // Implement logger function (winston)
    return res.status(500).json({
      message: "Unable to create your account.",
      success: false,
    });
  }
};

/**
 * @DESC To create the role (ADMIN,  USER)
 */
const createRole = async (roleDetails, res) => {
  try {
    // Validate the username
    let usernameNotTaken = await validateUsername(roleDetails.username);
    if (!usernameNotTaken) {
      return res.status(400).json({
        message: `Username is already taken.`,
        success: false,
      });
    }

    // Validate the email
    let emailNotRegistered = await validateEmail(roleDetails.email);
    if (!emailNotRegistered) {
      return res.status(400).json({
        message: `Email is already registered.`,
        success: false,
      });
    }

    const password = await bcrypt.hash(roleDetails.password, 12);
    // Create a new role
    const newRole = new User({
      ...roleDetails,
      password,
    });

    await newRole.save();

    // Configure the email message
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: roleDetails.email,
      subject: `Login Credentials`,
      text: `Hello ${roleDetails.name},\n\nYour new role has been created successfully.\n\nUsername: ${roleDetails.username}\nPassword: ${roleDetails.password}\n\nPlease keep this information secure.\n\nRegards,\nYour Application`,
    };

    // Send the email
    await transporter.sendMail(mailOptions);

    return res.status(201).json({
      message:
        "Role created successfully. An email with login credentials has been sent.",
      success: true,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Unable to create role.",
      success: false,
    });
  }
};

/**
 * @DESC To Login the user (ADMIN, SUPER_ADMIN, USER)
 */
const userLogin = async (userCreds, res) => {
  let { username, password } = userCreds;

  // Check if the username is in the database
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(404).json({
      message: "Username is not found. Invalid login credentials.",
      success: false,
    });
  }

  // Check the password
  let isMatch = await bcrypt.compare(password, user.password);
  if (isMatch) {
    // Sign in the token and issue it to the user
    let token = jwt.sign(
      {
        user_id: user._id,
        role: user.role,
        username: user.username,
        email: user.email,
      },
      process.env.APP_SECRET,
      { expiresIn: "7 days" }
    );

    let result = {
      username: user.username,
      role: user.role,
      email: user.email,
      token: `Bearer ${token}`,
      expiresIn: 168,
    };

    return res.status(200).json({
      ...result,
      message: "Hurray! You are now logged in.",
      success: true,
    });
  } else {
    return res.status(403).json({
      message: "Incorrect password.",
      success: false,
    });
  }
};

const validateUsername = async (username) => {
  let user = await User.findOne({ username });
  return user ? false : true;
};

/**
 * @DESC Passport middleware
 */
const userAuth = passport.authenticate("jwt", { session: false });

/**
 * @DESC Check Role Middleware
 */
const checkRole = (roles) => (req, res, next) =>
  !roles.includes(req.user.role)
    ? res.status(401).json("Unauthorized")
    : next();

const validateEmail = async (email) => {
  let user = await User.findOne({ email });
  return user ? false : true;
};

const serializeUser = (user) => {
  return {
    username: user.username,
    email: user.email,
    name: user.name,
    _id: user._id,
    updatedAt: user.updatedAt,
    createdAt: user.createdAt,
  };
};

// get role by id
const getRoleById = async (req, res, next) => {
  try {
    const { id } = req.params;
    let data = await User.findById(id);
    return res.json({ data });
  } catch (error) {
    next(error);
  }
};

// get all roles
const getAllRoles = async (req, res, next) => {
  try {
    const roles = await User.find({});
    res.status(200).json(roles);
  } catch (err) {
    next(err);
  }
};

// update roly by id
const updateRoleById = async (req, res, next) => {
  try {
    const updateRole = await User.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    if (!updateRole) {
      return res.status(400).json({ error: { message: "Role is not update" } });
    }
    return res.status(200).json({ user: updateRole });
  } catch (error) {
    next(error);
  }
};

// delete role by id
const deleteRoleById = async (req, res, next) => {
  try {
    const roledelete = await User.findByIdAndDelete(req.params.id);
    if (!roledelete) {
      return res.status(400).json({ error: { message: "role not deleted" } });
    }
    return res.status(200).json({ message: "role deleted" });
  } catch (error) {
    next(error);
  }
};

// Declare otpStore variable
const otpStore = {};

// Send forget password email with OTP
const sendForgetPasswordEmail = async (req, res) => {
  const { email } = req.body;

  // Generate a 4-digit OTP
  const generateOTP = () => {
    const otp = Math.floor(1000 + Math.random() * 9000);
    return otp.toString();
  };

  try {
    // Check if the email is registered
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        message: "Email is not registered.",
        success: false,
      });
    }

    // Generate and store the OTP
    const otp = generateOTP();
    otpStore[email] = otp;

    // Configure the email message
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: "Reset Password - OTP Verification",
      text: `Your OTP for password reset is: ${otp}`,
    };

    // Send the email
    await transporter.sendMail(mailOptions);

    return res.status(200).json({
      message: "An email with OTP has been sent to your email address.",
      success: true,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Unable to send the forget password email.",
      success: false,
    });
  }
};

// Reset password using OTP
const resetPassword = async (req, res) => {
  const { email, otp, newPassword, confirmPassword } = req.body;

  try {
    // Check if the email is registered
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        message: "Email is not registered.",
        success: false,
      });
    }

    // Verify the OTP
    const storedOTP = otpStore[email];
    if (!storedOTP || otp !== storedOTP) {
      return res.status(400).json({
        message: "Invalid OTP.",
        success: false,
      });
    }

    // Check if the new password and confirm password match
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        message: "New password and confirm password do not match.",
        success: false,
      });
    }

    // Generate a hashed password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update the user's password
    user.password = hashedPassword;
    await user.save();

    // Clear the stored OTP
    delete otpStore[email];

    return res.status(200).json({
      message: "Password has been reset successfully.",
      success: true,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Unable to reset the password.",
      success: false,
    });
  }
};

// change password after login
const changePassword = async (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;
  const userId = req.params._id;
  try {
    // Find the user by their ID
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({
        message: "User not found.",
        success: false,
      });
    }

    // Verify the old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({
        message: "Invalid old password.",
        success: false,
      });
    }

    // Validate the new password
    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        message: "New password and confirm password do not match.",
        success: false,
      });
    }

    // Generate a hashed password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update the user's password
    user.password = hashedPassword;
    await user.save();

    return res.status(200).json({
      message: "Password has been changed successfully.",
      success: true,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Unable to change the password.",
      success: false,
    });
  }
};


// update student details by id
const updateStudentById = async (req, res) => {
  try {
    const { _id } = req.params;
    const update = req.body;
    const options = { new: true }; // Return the updated document
    const updatedDoc = await User.findByIdAndUpdate(_id, update, options);

    if (!updatedDoc) {
      return res.status(404).json({
        error: { message: `Student with ID ${_id} not found.` },
      });
    }

    res.status(200).json({
      message: "Student updated successfully.",
      data: updatedDoc,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Unable to change the password.",
      success: false,
    });
  }
};


module.exports = {
  userAuth,
  checkRole,
  userLogin,
  userRegister,
  serializeUser,
  createRole,
  getRoleById,
  getAllRoles,
  updateRoleById,
  deleteRoleById,
  sendForgetPasswordEmail,
  resetPassword,
  changePassword,
  updateStudentById
};
