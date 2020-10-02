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


// Connecting to Local MongoDB Database
mongoose.connect("mongodb://localhost:27017/usersDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", "true");

/*
  Creating user Schema with 4 fields :
  email, password, googleId, gmail
  NOTE: I've just created this to make login page and register page work
  For assessment purpose we just need gmail and googleid which can be stored locally too.
*/
const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  gmail: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Creating a mongoose model
const User = new mongoose.model("User", userSchema);

// Using MongoDb model strategy for authenticating using passportjs
passport.use(User.createStrategy());

/*
  While loggin in, the credentials used to authenticate userswill be transmitted.
  If user is authenticated, a session will be created and maintained using Cookie.
  Passport will serialize and deserialize user instances to and from session
*/
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

/*
  Passport Google oauth 2.0 authentication strategy authenticates user using
  Google account and OAuth 2.0 tokens.
  The options like cliend Id, client Secret will be obtained by creating new Credentials
  at  ==>  https://console.developers.google.com/apis/credentials
  You can also obtain accessToken and refreshToken by specifying your scope
  in ==> https://developers.google.com/oauthplayground/

  I've saved accessToken as an environment variable so that it becomes easy  to access
  when sending mails.
  Next, finding if any or creating user and storing googleId and gmail
*/
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


/*   Home route [STARTING PAGE OF THE SITE]   */
app.get("/", (req, res) => {
  res.render("home");
})

/*
  Used when user is redirected for authenticaion using Google Oauth2.0
  scope is profile, email and mail.google.com to get access for sending mails.
*/
app.get("/auth/google",
  passport.authenticate("google", {scope: ["profile email https://mail.google.com"]})
);

/*
  Used as a Redirected URL
*/
app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
});

/*
  Login route [For assessment, use just a button(Signin with Google)]
*/
app.get("/login", (req, res) => {
  res.render("login");
})

/*
  Register Route
*/
app.get("/register", (req, res) => {
  res.render("register");
})


/*
  This is basically a page which will be rendered once user has registered
  or loggedin Successfully
*/
app.get("/secrets", (req, res) => {
  if(req.isAuthenticated()){
    res.render("secrets");
  } else{
    res.redirect("/login");
  }
});


/*
  Logout Route
*/
app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});


/*
  Register Route [For assessment, use only register button(Signup with Google)]
*/
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

/*
  Login post route which authenticates the user who registered using Email address
  [This route is Just for demo. No link with assessment task]
*/
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

/*
  Send Mail Page triggered from secrets page when clicked the button (Send Mail)
*/
app.get('/submit', (req, res) => {
  if(req.isAuthenticated()){
    res.render("submit");
  } else{
    res.redirect("/login");
  }
})


/*
  A makeBody function used to make a body template for sending mails
  Buffer is used to encode the mail content using base64.
*/
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


/*
  Once user submits the form giving details : to, subject and message,
  this route is called.

  makeBody functionis calledto obtain a base64 encoded string.

  Next, node-fetch module is used to call gmail API reference for sending mail.
  The base64 encoded raw message is passed as a body part which is stringified.
  Header contains some information including Authorization which is performed using the
  ACCESS_TOKEN enviornment variable stored when logged in.
  Finally, Once mail is sent it redirects to Secrets page .
*/
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

// END
