import express from "express";
const router = express.Router();
import * as helper from '../utils/helper';



// Bring in the User Registration function
const {
  userAuth,
  userLogin,
  checkRole,
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
} = require("../controller/userController");



// Users Registeration Route
router.post("/register", async (req, res) => {
  const { role } = req.body;
  const allowedRoles = ["superadmin"];
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({
      message: `Invalid role: ${role}`,
      success: false,
    });
  }
  await userRegister(req.body, role, res);
});

// Superadmin create new role Route
router.post("/role", helper.verifyToken, async (req, res) => {
  if (req.user.role !== "superadmin") {
    return res.status(403).json({
      message: "You are not authorized to perform this operation.",
      success: false,
    });
  }

  await createRole(req.body, res);
});

// Login Route
router.post("/login", async (req, res) => {
  await userLogin(req.body, res);
});

// Profile Route
router.get("/profile", userAuth, async (req, res) => {
  return res.json(serializeUser(req.user));
});

// Users Protected Route
router.get(
  "/user-protectd",
  userAuth,
  checkRole(["user"]),
  async (req, res) => {
    return res.json("Hello User");
  }
);

// Admin Protected Route
router.get(
  "/admin-protectd",
  userAuth,
  checkRole(["admin"]),
  async (req, res) => {
    return res.json("Hello Admin");
  }
);

// Super Admin Protected Route
router.get(
  "/super-admin-protectd",
  userAuth,
  checkRole(["superadmin"]),
  async (req, res) => {
    return res.json("Hello Super Admin");
  }
);

// Super Admin Protected Route
router.get(
  "/super-admin-and-admin-protectd",
  userAuth,
  checkRole(["superadmin", "admin"]),
  async (req, res) => {
    return res.json("Super admin and Admin");
  }
);

// get role by id by super admin only
router.get("/role/:id", helper.verifyToken, async (req, res) => {
  if (req.user.role !== "superadmin") {
    return res.status(403).json({
      message: "You are not authorized to perform this operation.",
      success: false,
    });
  }

  await getRoleById(req, res);
});

// get all role by admin
router.get("/allrole", helper.verifyToken, async (req, res) => {
  if (req.user.role !== "superadmin") {
    return res.status(403).json({
      message: "You are not authorized to perform this operation.",
      success: false,
    });
  }

  await getAllRoles(req, res);
});

// update role by id by  admin
router.put("/updaterole/:id", helper.verifyToken, async (req, res) => {
  if (req.user.role !== "superadmin") {
    return res.status(403).json({
      message: "You are not authorized to perform this operation.",
      success: false,
    });
  }

  await updateRoleById(req, res);
});

// delete role by id by  admin
router.delete("/deleterole/:id", helper.verifyToken, async (req, res) => {
  if (req.user.role !== "superadmin") {
    return res.status(403).json({
      message: "You are not authorized to perform this operation.",
      success: false,
    });
  }

  await deleteRoleById(req, res);
});

//  send email for forget password
router.post('/forget-password', async (req, res) => { 
  await sendForgetPasswordEmail(req, res );
});

// reset password 
router.post('/reset-password', async (req, res) => {
  await resetPassword(req, res);
 });

// change password
router.post('/change-password/:_id', async (req, res) => {
  await changePassword(req, res);
 });

 // change password
router.put('/update-student-details/:_id', async (req, res) => {
  await updateStudentById(req, res);
 });
module.exports = router;
