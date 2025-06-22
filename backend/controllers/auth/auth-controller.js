import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../../model/user.js";

export const registerUser = async (req, res) => {
  const { firstName, lastName, email, password, compName, userType } = req.body;

  if (
    firstName == "" ||
    lastName == "" ||
    email == "" ||
    password == "" ||
    compName == "" ||
    userType == ""
  )
    return res.json({
      success: false,
      message: "No empty field allowed",
    });

  try {
    const findUser = await User.findOne({ email });
    if (findUser)
      return res.json({ success: false, message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      compName,
      userType,
    });

    const token = jwt.sign(
      {
        id: newUser._id,
        email: newUser.email,
        firstName: newUser.firstName,
        userType: newUser.userType,
      },
      "CLIENT_SECRET_KEY",
      { expiresIn: "24h" }
    );

    res
      .cookie("token", token, {
        httpOnly: true,
        secure: false,
        sameSite: 'Lax'
      })
      .json({
        success: true,
        message: "User Registered successfully",
        user: {
          id: newUser._id,
          firstName: newUser.firstName,
          lastName: newUser.lastName,
          email: newUser.email,
          compName: newUser.compName,
          userType: newUser.userType,
        },
      });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "SignUp failed, some error occured",
    });
  }
};

export const loginUser = async (req, res) => {
  const { email, password } = req.body;

  if (email == "" || password == "")
    return res.json({
      success: false,
      message: "No empty field is allowed",
    });

  try {
    const checkUser = await User.findOne({ email });
    if (!checkUser)
      return res.json({
        success: false,
        message: "Invalid email or password",
      });

    const checkPasswordMatch = await bcrypt.compare(
      password,
      checkUser.password
    );
    if (!checkPasswordMatch)
      return res.json({
        success: false,
        message: "Invalid Password, Please try again",
      });

    const token = jwt.sign(
      {
        id: checkUser._id,
        email: checkUser.email,
        firstName: checkUser.firstName,
        userType: checkUser.userType,
      },
      "CLIENT_SECRET_KEY",
      { expiresIn: "24h" }
    );

    res
      .cookie("token", token, {
        httpOnly: true,
        secure: false,
        sameSite: "Lax"
      })
      .json({
        success: true,
        message: "Logged in successfully",
        user: {
          id: checkUser._id,
          email: checkUser.email,
          firstName: checkUser.firstName,
          userType: checkUser.userType,
        },
      });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Login failed, some error occured",
    });
  }
};

export const logoutUser = async (req, res) => {
  res.clearCookie("token").json({
    message: "Logged out successfully",
    success: true,
  });
};

export const authMiddleware = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token)
    return res.status(401).json({
      success: false,
      message: "Unauthorized Useer",
    });

  try {
    const decoded = jwt.verify(token, "CLIENT_SECRET_KEY");
    req.user = decoded;
    console.log(decoded);
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      message: "Unauthorized user!",
    });
  }
};