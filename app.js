require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const app = express();

app.set("view engine" , "ejs");
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({

secret: "This is the secret.",
resave: false,
saveUninitialized: false
}));

//connecting passport ot the current session
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema ({

username: String,
password: String,
googleId: String,
secret: String
});

//using passport local mongoose to hash and salt passwords when stored in Database
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User" , userSchema);

//used to create cookies and save them when user goes back
passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username, name: user.displayName });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

//using passport and google oauth to authenticate users using their google id
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



app.get("/" , function(req ,res){

  res.render("home");
});


app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);


app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login" , function(req ,res){

  res.render("login");
});


app.get("/logout" , function(req , res){

//deletes cookies and sessions when they logout
  req.logout();
  res.redirect("/");
});


app.get("/register" , function(req ,res){

  res.render("register");
});



app.get("/secrets" , function(req ,res){

User.find({"secret" : {$ne: null}}, function(err, foundUsers){

  if (err){
    console.log(err);
  }else {
    if (foundUsers){
      console.log(foundUsers);
      res.render("secrets" , {usersWithSecrets: messageList});
    }
  }
})
});


app.get("/submit" , function(req ,res){

  if (req.isAuthenticated()){

    res.render("submit");
  }else {

    res.redirect("/login");
  }
});

messageList = [{
  username: "test",
  message: "hello"
}]

app.post("/submit" , function(req ,res ){


  const submittedSecret = req.body.secret;
  console.log(req.user.id);

  User.findById(req.user.id , function(err , foundUser){

    if (err){
      console.log(err);
    }else {

      foundUser.secret = submittedSecret;
      messageList.push({
        username: foundUser.username,
        message: submittedSecret
      })
      foundUser.save(function(){
        res.redirect("/secrets");
      });

    }
  });
});

app.post("/register" , function(req , res){

//registering users using the username and password entered into the form
User.register({username: req.body.username}, req.body.password, function(err , user){

  if (err) {
    console.log(err);
    res.redirect("/register");
  } else {

//using passport to authenticate the users and then redirecting them to the right page if they were authenticated
    passport.authenticate("local")(req ,res ,function(){

      res.redirect("/secrets");
    });
  }
});

});


app.post("/login" , function(req ,res){

const user = new User({

username: req.body.username,
password: req.body.password
});

//req.login used from passport to login users and if they authenticated to go to secrets page
req.login(user, function(err){

  if(err) {

    console.log(err);

  }else {

    passport.authenticate("local")(req ,res ,function(){

      res.redirect("/secrets");
    });
  }
});

});














app.listen(3000, function(){

console.log("Server is running on port 3000!");
});
