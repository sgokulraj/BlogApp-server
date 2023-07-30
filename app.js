const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const User = require("./models/userModel");
const Post = require("./models/postModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");
const bodyParser = require("body-parser");
const helmet = require("helmet")

dotenv.config();
const PORT = process.env.PORT;
const CONNECTION_URL = process.env.CONNECTION_URL;
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;
const salt = bcrypt.genSaltSync(10);


const app = express();
app.use(express.json());
app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" }));
app.use(bodyParser.json({ limit: "30mb", extended: true }));
app.use(bodyParser.urlencoded({ limit: "30mb", extended: true }));
// app.use(express.urlencoded({ extended: false }));
app.use(cors());
app.use("/assets", express.static(path.join(__dirname, "public/assets")));


// Multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/assets");
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});
const upload = multer({ storage });

app.post("/register", async (req, res) => {
  const { username, password, email } = req.body;

  try {
    const userDetails = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
      email: email.toLowerCase(),
    });
    res.status(201).json("ok");
  } catch (err) {
    res.status(400).json(err);
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      const crctPass = bcrypt.compareSync(password, user.password);
      if (crctPass) {
        const token = jwt.sign({ id: user._id }, JWT_SECRET_KEY);
        res.status(200).json({ token, user });
      } else {
        res.status(404).json("Invalid Credentials");
      }
    } else {
      res.status(404).json("User not Found");
    }
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

//jwt
const verifyToken = async (req, res, next) => {
  try {
    let token = req.header("Authorization");

    if (token && token.startsWith("Bearer ")) {
      token = token.slice(7, token.length).trimLeft();
      const verified = jwt.verify(token, process.env.JWT_SECRET_KEY);
      req.user = verified;
      next();
    } else {
      res.status(403).send("Access Denied");
    }
  } catch (err) {
    res.status(400).json({ msg: err.message });
  }
};

//to create post
app.post("/posts", verifyToken, upload.single("file"), async (req, res) => {
  try {
    const { title, summary, description, author } = req.body;
    const {originalname} = req.file;
    const createpost = new Post({
      title,
      summary,
      description,
      cover: originalname,
      author,
    });
    const savePost = await createpost.save();
    // const createpost = await Post.create({
    //   title,
    //   summary,
    //   description,
    //   cover: newPath ? newPath : null,
    //   author,
    // });
    res.status(200).json(savePost);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

//to get all Posts
app.get("/posts", verifyToken, async (req, res) => {
  const posts = await Post.find()
    .populate("author", ["username"])
    .sort({ createdAt: -1 });
  res.status(200).json(posts);
});

//to get single Post
app.get("/posts/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const post = await Post.findById(id).populate("author", ["username"]);
  res.status(200).json(post);
});

//to edit the post
app.put("/posts/:id", verifyToken, upload.single("file"), async (req, res) => {
  const { id, title, summary, description, userId } = req.body;
  const {originalname} = req.file;
  const postDetails = await Post.findById(id);
  const isAuthor =
    JSON.stringify(postDetails.author) === JSON.stringify(userId);
  if (!isAuthor) {
    return res.status(400).json("You are not allowed to edit this post");
  }
  await Post.findByIdAndUpdate(id, {
    title,
    summary,
    description,
    cover: originalname ? originalname : postDetails.cover,
    author: userId,
  });
  res.status(200).json({ success: true, message: "Post updated successfully" });
});

//deleting the post
app.delete("/posts/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  await Post.findByIdAndRemove(id);
  res.status(200).json("ok");
});

mongoose
  .connect(CONNECTION_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() =>
    app.listen(PORT, () => {
      console.log(`Server is running in 5000  `);
    })
  )
  .catch((err) => console.log(err));
