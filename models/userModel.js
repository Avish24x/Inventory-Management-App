const bcrypt = require("bcryptjs");

const mongoose = require("mongoose");

const userSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Please add a Name"],
    },
    email: {
      type: String,
      required: [true, "Email is Required"],
      unique: true,
      trim: true,
      match: [
        // Email REGEX
        /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        "Please enter a valid email",
      ],
    },

    password: {
      type: String,
      required: [true, "Please add a password"],
      minLength: [6, "Password must be up to 6 Characters"],
      // maxLength: [25, "Password must not be more than 25 Characters"],
    },

    photo: {
      type: String,
      required: [true, "Please add a Photo"],
      // if the user does not enter a photo
      default: "https://i.ibb.co/4pDNDk1/avatar.png",
    },

    phone: {
      type: String,
      default: "+230",
    },

    bio: {
      type: String,
      maxLength: [250, "Bio must noot be more than 250 characters"],
      default: "No Bio Provided Yet!",
    },
  },
  {
    // this is going to create a timeproperty for all the schema

    timestamps: true,
  }
);

// This code is defining a middleware function for a Mongoose schema.
// It runs before the 'save' operation on a document and is used to hash the user's password before storing it.

userSchema.pre("save", async function (next) {
  // This code is a conditional check inside a Mongoose middleware function.
  // It checks if the 'password' field of a document has been modified.
  // If it hasn't been modified, it immediately calls the 'next' function to proceed with the operation.

  if (!this.isModified("password")) {
    return next(); // If the 'password' field hasn't been modified, continue with the operation.
  }

  // Hash Password
  // Generate a salt for password hashing.
  const salt = await bcrypt.genSalt(10);

  // Hash the user's password using the generated salt.
  const hashedPassword = await bcrypt.hash(this.password, salt);

  // Update the 'password' field of the document with the hashed password.
  this.password = hashedPassword;
  // Continue with the save operation.
  next();
});

const User = mongoose.model("User", userSchema);
module.exports = User;
