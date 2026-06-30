const mongoose = require("mongoose");
const argon2 = require("argon2");

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
  },
  {
    timestamps: true,
  },
);
// Pre-save hook to hash the password before saving the user document
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }

  try {
    this.password = await argon2.hash(this.password);
  } catch (err) {
    next(err);
  }
});
// Method to compare the provided password with the hashed password in the database
userSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    return await argon2.verify(this.password, candidatePassword);
  } catch (err) {
    throw new Error("Error comparing passwords");
  }
};
// indexing the username field for faster queries
userSchema.index({ username: "text" });

const User = mongoose.model("User", userSchema);

module.exports = User;
