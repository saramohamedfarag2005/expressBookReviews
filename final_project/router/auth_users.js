const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const books = require("./booksdb");

const regd_users = express.Router();
const users = []; // in-memory store for the lab

// OPTIONAL: register (IBM rubric cares about login + review; register helps testing)
regd_users.post("/register", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ message: "Please provide both username and password" });
  if (users.find(u => u.username === username)) return res.status(409).json({ message: "User already exists" });

  const hash = await bcrypt.hash(password, 10);
  users.push({ username, passwordHash: hash });
  return res.status(201).json({ message: "User registered successfully. Please login." });
});

// Task 7: /customer/login (this router is mounted under /customer)
regd_users.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ message: "Please provide both correct username and password" });

  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ message: "User does not exist" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: "Wrong password" });

  const token = jwt.sign(
    { sub: username },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES || "1h" }
  );

  // IBM requirement: save JWT in session
  req.session.authorization = { accessToken: token };

  return res.status(200).json({ accessToken: token, type: "Bearer" });
});

// Task 8: add/modify a review (protected by /customer/auth/* guard in index.js)
regd_users.put("/auth/review/:isbn", (req, res) => {
  const { isbn } = req.params;
  const { review } = req.body;
  const username = req.user?.username;

  if (!username) return res.status(401).json({ message: "Unauthorized" });

  const book = books[isbn];
  if (!book) return res.status(404).json({ message: `No book with ISBN ${isbn}` });
  if (!review) return res.status(400).json({ message: "Review is required" });

  book.reviews = book.reviews || {};
  book.reviews[username] = review;
  return res.status(200).json({ message: "Review saved", reviews: book.reviews });
});

// Task 9: delete own review
regd_users.delete("/auth/review/:isbn", (req, res) => {
  const { isbn } = req.params;
  const username = req.user?.username;

  if (!username) return res.status(401).json({ message: "Unauthorized" });

  const book = books[isbn];
  if (!book) return res.status(404).json({ message: `No book with ISBN ${isbn}` });

  if (!book.reviews || !book.reviews[username]) {
    return res.status(404).json({ message: "No review by this user to delete" });
  }
  delete book.reviews[username];
  return res.status(200).json({ message: "Review deleted", reviews: book.reviews });
});

module.exports.authenticated = regd_users;
module.exports.users = users; 
