require("dotenv").config();
const express = require('express');
const cors = require("cors");
const session = require("express-session");
const jwt = require('jsonwebtoken');

const customer_routes = require('./router/auth_users.js').authenticated;
const genl_routes = require('./router/general.js').general;

const app = express();


app.use(express.json());
app.use(cors());

app.use("/customer",session({secret:"fingerprint_customer",resave: true, saveUninitialized: true}));

app.use("/customer/auth/*", function auth(req,res,next){
//Write the authenication mechanism here
app.use("/customer/auth/*", function auth(req, res, next) {
    const token = req.session?.authorization?.accessToken;
    if (!token) return res.status(401).json({ message: "Authentication required" });
    jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
      if (err) return res.status(401).json({ message: "Invalid or expired token" });
      req.user = { username: payload.sub };
      next();
    });
  });
  
});
 


app.use("/customer", customer_routes);
app.use("/", genl_routes);

app.get("/health", (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
