const express = require("express");
const User = require("../models/user");
const bcrypt = require("bcrypt");
const router = express.Router();

// Routes for Logged In User ONLY
router.get("/secret", (req, res, next) => {
  if (req.session.loggedInUser) {
    res.render("auth/secret");
  } else {
    res.render("error");
  }
});

router.get("/main", (req, res, next) => {
  if (req.session.loggedInUser) {
    res.render("auth/main");
  } else {
    res.render("error");
  }
});

router.get("/private", (req, res, next) => {
  if (req.session.loggedInUser) {
    res.render("auth/private");
  } else {
    res.render("auth/error");
  }
});

// Rendering the routes
router.get("/register", (req, res, next) => {
  res.render("auth/register");
});

router.get("/login", (req, res, next) => {
  res.render("auth/login");
});

// Login of the user
router.post("/login", (req, res, next) => {
  const { username, password } = req.body;

  // Check if one of the fields is empty
  if (username === "" || password === "") {
    res.render("auth/login", {
      errorMessage: "You need an username and a password to login"
    });
    return;
  }

  // Check if the provided username exists in the database
  User.findOne({ username })
    .then(user => {
      if (!user) {
        res.render("auth/login", {
          errorMessage: "Your shitty username was not found"
        });
        return;
      }
      // Compare the provided password with the hash version in the database
      if (bcrypt.compareSync(password, user.password)) {
        // Store the cookie for the user
        req.session.loggedInUser = user;
        res.redirect("/secret");
      } else {
        res.render("auth/login", {
          errorMessage: "Wrong password"
        });
      }
    })
    .catch(err => {
      console.error("Error while finding user", err);
    });
});

// Signup of the user
router.post("/register", (req, res, next) => {
  const { username, password } = req.body;

  // Generating the salt for the encryption
  const salt = bcrypt.genSaltSync();
  // Encryption of the password
  const hashPassword = bcrypt.hashSync(password, salt);

  // Check if one of the fields is empty
  if (username === "" || password === "") {
    res.render("auth/register", {
      errorMessage: "You need an username and a password to register"
    });
    return;
  }
  if (password.length < 2) {
    res.render("auth/register", {
      errorMessage: "Your password is lame"
    });
    return;
  }

  User.findOne({ username }).then(user => {
    if (user) {
      res.render("auth/register", {
        errorMessage: "Your shitty username is already used (and it sucks)"
      });
      return;
    }
    User.create({ username, password: hashPassword })
      .then(() => {
        res.redirect("/");
      })
      .catch(err => {
        console.error(err);
      });
  });
});

module.exports = router;
