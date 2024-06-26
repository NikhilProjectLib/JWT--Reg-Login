const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const verifyToken = require("./token");
const User = require("./models/User");
const connectDB = require("./connection");

const app = express();
app.use(express.json());
connectDB();

app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }
    // Encrypt the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user with the hashed password
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(200).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Generate JWT token
    const token = jwt.sign({ email: user.email }, "60606060", {
      expiresIn: "1h",
    });

    // Set token in response header
    res.set("Authorization", `Bearer ${token}`);

    res.status(200).json({ message: "Login successful" });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
app.put("/user/info", verifyToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.userEmail });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    user.location = req.body.location || user.location;
    user.age = req.body.age || user.age;
    user.workDetails = req.body.workDetails || user.workDetails;
    await user.save();
    res.status(200).json({ message: "User details updated successfully" });
  } catch (error) {
    console.error("Error updating user details:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/user", verifyToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.userEmail });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    const userDetails = {
      email: user.email,
      location: user.location,
      age: user.age,
      workDetails: user.workDetails,
    };
    res.status(200).json(userDetails);
  } catch (error) {
    console.error("Error retrieving user details:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
