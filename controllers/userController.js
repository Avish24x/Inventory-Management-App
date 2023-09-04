const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");

const bcrypt = require("bcryptjs");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");

// This code defines a function called 'generateToken' that is used to create a JSON Web Token (JWT).
// It takes an 'id' as an argument, which will be included as a property in the JWT payload.
// The JWT is signed using the secret key from the environment variable 'JWT_SECRET'.
// It also specifies that the token should expire after 1 day ('1d').

const generateToken = (id) => {
  // Create a JWT with the payload containing the 'id' property.
  // The payload is signed using the secret key from 'JWT_SECRET'.
  // The token is set to expire after 1 day.
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

// This code defines an asynchronous function called 'registerUser' that handles a request/response cycle.
// It uses the 'asyncHandler' middleware, which is likely used to catch and handle asynchronous errors.

// Register User

const registerUser = asyncHandler(async (req, res) => {
  // Destructuring the 'name', 'email', and 'password' properties from the request body.
  const { name, email, password } = req.body;

  // validation

  // This code checks if any of the 'name', 'email', or 'password' variables are falsy (empty or undefined).
  // If any of these variables are falsy, it responds with a 400 Bad Request status and throws an error.

  if (!name || !email || !password) {
    res.status(400); // Set the response status code to 400 Bad Request.
    throw new Error("Please fill in all the required fields"); // Throw an error with a descriptive message.
  }
  if (password.length < 6) {
    res.status(400); // Set the response status code to 400 Bad Request.
    throw new Error("Password must be up to 6 characters");
  }

  // check if user email already exists
  const userExists = await User.findOne({ email });
  if (userExists) {
    res.status(400); // Set the response status code to 400 Bad Request.
    throw new Error("Email has already been Used");
  }

  // create new user
  const user = await User.create({
    name,
    email,
    password,
  });

  // Generate Token
  const token = generateToken(user._id);

  // Send HTTP-only cookie
  // This code sets an HTTP cookie named "token" in the response.
  // The cookie is used for securely storing the JSON Web Token (JWT) that identifies a user's session.

  res.cookie("token", token, {
    // The cookie is named "token" and contains the 'token' variable as its value.

    path: "/", // The cookie is valid for all paths on the domain.

    httpOnly: true, // The cookie is marked as 'httpOnly,' making it accessible only via HTTP requests and not through JavaScript.

    expires: new Date(Date.now() + 1000 * 86400), // The cookie will expire in one day (86400 seconds) from the current time.

    sameSite: "none", // This attribute helps prevent cross-site request forgery (CSRF) attacks by specifying that the cookie should only be sent with same-site requests.

    secure: true, // The cookie will only be sent over secure HTTPS connections, enhancing its security.
  });

  if (user) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(201).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      token,
    });
  } else {
    res.status(400);
    throw new Error("Invalid User data");
  }
});

// Login User
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // validate request
  if (!email || !password) {
    res.status(400);
    throw new Error("Please add email and password");
  }

  // check if user exists
  const user = await User.findOne({ email });
  if (!user) {
    res.status(400);
    throw new Error("User not found, please signup");
  }

  // user exists we  check if password is correct

  // This code checks if the provided password matches the stored hashed password for a user.
  // If the user exists and the password is correct, it responds with the user's information.
  // If not, it throws an error indicating that the provided email or password is invalid.

  const passwordIsCorrect = await bcrypt.compare(password, user.password);
  // Generate Token
  const token = generateToken(user._id);

  // Send HTTP-only cookie
  // This code sets an HTTP cookie named "token" in the response.
  // The cookie is used for securely storing the JSON Web Token (JWT) that identifies a user's session.

  res.cookie("token", token, {
    // The cookie is named "token" and contains the 'token' variable as its value.

    path: "/", // The cookie is valid for all paths on the domain.

    httpOnly: true, // The cookie is marked as 'httpOnly,' making it accessible only via HTTP requests and not through JavaScript.

    expires: new Date(Date.now() + 1000 * 86400), // The cookie will expire in one day (86400 seconds) from the current time.

    sameSite: "none", // This attribute helps prevent cross-site request forgery (CSRF) attacks by specifying that the cookie should only be sent with same-site requests.

    secure: true, // The cookie will only be sent over secure HTTPS connections, enhancing its security.
  });

  if (user && passwordIsCorrect) {
    // If the user exists and the password is correct, respond with user information.
    const { _id, name, email, photo, phone, bio } = user;
    res.status(200).json({
      _id,
      name,
      email,
      photo,
      phone,
      bio,
      token,
    });
  } else {
    // If the user doesn't exist or the password is incorrect, throw an error.
    throw new Error("Invalid Email or Password");
  }
});

// Logout User
// This code defines an endpoint for logging a user out.
// It clears the user's session by removing the "token" cookie, and then responds with a success message.

const logout = asyncHandler(async (req, res) => {
  // Clear the "token" cookie by setting an empty value and an expiration date in the past.
  res.cookie("token", "", {
    path: "/", // The cookie is valid for all paths on the domain.
    httpOnly: true, // The cookie can only be accessed via HTTP requests.
    expires: new Date(0), // Setting an expiration date in the past effectively deletes the cookie.
    sameSite: "none", // The cookie is only sent with same-site requests.
    secure: true, // The cookie will only be sent over secure HTTPS connections.
  });

  // Respond with a status code of 200 (OK) and a success message.
  return res.status(200).json({
    message: "Successfully Logout",
  });
});

// Get User profile (data)
const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { _id, name, email, photo, phone, bio } = user;
    res.status(200).json({ _id, name, email, photo, phone, bio });
  } else {
    res.status(400);
    throw new Error("User Not Found");
  }
});

// Get Login Status
const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }
  // verified toekn
  const verified = jwt.verify(token, process.env.JWT_SECRET);
  if (verified) {
    return res.json(true);
  }
  return res.json(false);
});
// Update user
const updateUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (user) {
    const { name, email, photo, phone, bio } = user;
    // this will prevent the user from changing their email
    user.email = email;
    user.name = req.body.name || name;
    user.photo = req.body.photo || photo;
    user.phone = req.body.phone || phone;
    user.bio = req.body.bio || bio;

    // Once change this will update the change informations
    const updatedUser = await user.save();
    res.status(200).json({
      _id: updatedUser._id,
      name: updatedUser.name,
      email: updatedUser.email,
      photo: updatedUser.photo,
      phone: updatedUser.phone,
      bio: updatedUser.bio,
    });
  } else {
    res.status(404);
    throw new Error("User not found");
  }
});

const changePassword = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  const { oldpassword, password } = req.body;

  if (!user) {
    res.status(400);
    throw new Error("User not found, please signup");
  }
  // Validate
  if (!oldpassword || !password) {
    res.status(400);
    throw new Error("Please add old and new password");
  }

  // check if password matches password in the DB
  const passwordIsCorrect = await bcrypt.compare(oldpassword, user.password);

  // save new password
  if (user && passwordIsCorrect) {
    user.password = password;
    await user.save();
    res.status(200).send("Password change successful");
  } else {
    res.status(400);
    throw new Error("Old password is incorrect");
  }
});

const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
    res.status(404);
    throw new Error("User does not exist");
  }

  // Delete token if it exist in DB
  // check if the user have a token associated with the user
  // create a new reset token and then save it to the DB

  let token = await Token.findOne({ userId: user._id });
  if (token) {
    await token.deleteOne();
  }

  // create reset token
  let resetToken = crypto.randomBytes(32).toString("hex") + user._id;

  // Hash token before saving to DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // save token to DB
  await new Token({
    userId: user._id,
    token: hashedToken,
    CreatedAt: Date.now(),
    expiresAt: Date.now() + 30 * (60 * 1000), //30 minutes
  }).save();

  // construct a reset url
  const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`;

  // Reset Email
  const message = `<h2>Hello ${user.name}</h2>
  <p>Please use the url to reset your password</p>
  <p>This reset link is valid for only 30minutes.</p>
  
  <a href=${resetUrl} clicktracking=off>${resetUrl}</a>
  <p>Regards...</p>
  <p>Pin App Team</p>`;

  const subject = "Password Reset Request";
  const send_to = user.email;
  const sent_from = process.env.EMAIL_USER;

  try {
    await sendEmail(subject, message, send_to, sent_from);
    res.status(200).json({ success: true, message: "Reset Email Sent" });
  } catch (error) {
    res.status(500);
    throw new Error("Email not sent, Please try again");
  }
});

const resetPassword = asyncHandler(async (req, res) => {
  // get hashed token from params and check it exists in db or has expired already
  const { password } = req.body;
  const { resetToken } = req.params;

  // hash token, then compare to Token in DB
  const hashedToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  // find token in DB
  const userToken = await Token.findOne({
    token: hashedToken,
    // if greater than the current time date (now)
    expiresAt: { $gt: Date.now() },
  });

  if (!userToken) {
    res.status(404);
    throw new Error("Invalid of Expired Token");
  }

  // find user
  const user = await User.findOne({ _id: userToken.userId });
  user.password = password;
  await user.save();
  res.status(200).json({
    message: "Password reset successfully, Please Login",
  });
});
module.exports = {
  registerUser,
  loginUser,
  logout,
  getUser,
  loginStatus,
  updateUser,
  changePassword,
  forgotPassword,
  resetPassword,
};
