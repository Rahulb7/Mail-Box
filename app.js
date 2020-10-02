// Load all the modules required
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const fetch = require('node-fetch');
const Bluebird = require('bluebird');

// Declaring a variable to store users mail address
let me = "";

// Using Bluebird to promsify node modules
fetch.Promise = Bluebird;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));

// Using Secret code saved in .env file to build session
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));

// Middleware to initialize Passport
app.use(passport.initialize());

// Middleware that alters the request object and change the 'user' value that is currently the session id (from the client cookie) into the true deserialized user object
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/usersDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", "true");

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  gmail: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    process.env['ACCESS_TOKEN']=accessToken;
    me = profile.emails[0].value;
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id, gmail: profile.emails[0].value }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
  res.render("home");
})

app.get("/auth/google",
  passport.authenticate("google", {scope: ["profile email https://mail.google.com"]})
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
  });

app.get("/login", (req, res) => {
  res.render("login");
})

app.get("/register", (req, res) => {
  res.render("register");
})

app.get("/secrets", (req, res) => {
  if(req.isAuthenticated()){
    res.render("secrets");
  } else{
    res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

app.post("/register", (req, res) => {
  User.register({username: req.body.username}, req.body.password, (err, user) => {
    if(err){
      console.log(err);
      res.redirect("/register");
    } else{
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      })
    }
  })
});

app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, (err) => {
    if(err){
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      })
    }
  })
});

app.get('/submit', (req, res) => {
  if(req.isAuthenticated()){
    res.render("submit");
  } else{
    res.redirect("/login");
  }
})

function makeBody(to, from, subject, message) {
    var str = ["Content-Type: text/plain; charset=\"UTF-8\"\n",
        "MIME-Version: 1.0\n",
        "Content-Transfer-Encoding: 7bit\n",
        "to: ", to, "\n",
        "from: ", from, "\n",
        "subject: ", subject, "\n\n",
        message
    ].join('');

    var encodedMail = Buffer.from(str).toString("base64").replace(/\+/g, '-').replace(/\//g, '_');
    return encodedMail;
}

app.post('/submit', (req, res) => {
  const to = req.body.to;
  const subject = req.body.subject;
  const message = req.body.message;
  var raw = makeBody(to, me, subject, message);
  fetch(`https://gmail.googleapis.com/gmail/v1/users/${me}/messages/send`, {
    method: 'POST',
    body: JSON.stringify({
      "raw": raw
    }),
    headers:{
      'Authorization': `Bearer ${process.env.ACCESS_TOKEN}`,
      'Accept': 'application/json'
    }
  }).then(response => res.render('secrets'));
});

app.listen(3000, () => {
  console.log("Server is running at port 3000");
});
