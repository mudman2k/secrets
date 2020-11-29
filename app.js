//Load Dependencies

require('dotenv').config() //Required for Environment Variables
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const {
    forEach
} = require("lodash");
const _ = require('lodash');
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require('mongoose-findorcreate')
var GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

// Using Public Folder to save static pages and images.
app.use(express.static("public"));
// Setting Viewing Enging to EJS
app.set('view engine', 'ejs');
// Using Body Parser to acquire data from page
app.use(bodyParser.urlencoded({
    extended: true
}));
//Setup Session
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

//Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Remote DB Connection
mongoose.connect(process.env.MONGODB, {useNewUrlParser: true, useUnifiedTopology: true,});
mongoose.set('useFindAndModify', false);
mongoose.set('useCreateIndex', true);
//Create userSchema for users
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId:String,
    secret:String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// Create Model for users using userSchema above.
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
  //Implementing Google Authentication
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret:process.env.CLIENT_SECRET,
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



//Simple test on root route to make sure we have connectivity.
app.get("/", function (req, res) {
    res.render('home');
});
//Authentication thru Google
app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile'] }));

  app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });
//Get route for Login
app.get("/login", function (req, res) {
    res.render('login');
});

//Post route for Login
app.post("/login", function (req, res) {
 const user = new User({
     username: req.body.username,
     password: req.body.password
 });

 req.login(user, function(err){
     if(err){
         console.log(err);
     }else{
         passport.authenticate("local")(req,res, function(){
             res.redirect("/secrets");
         });
     }
 });

});
//Route validation for if user is authenticated or not. 
app.get("/secrets", function (req, res) {
       User.find({"secret":{$ne: null}}, function(err, foundUsers){
       if (err){
           console.log(err);
        }else{
            if(foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
   });
});
app.get("/register", function (req, res) {
    res.render('register');
});
//Logic to handle new Registrations
app.post("/register", function (req, res) {
    User.register({
        username: req.body.username
    }, req.body.password, function (err, user) {
        if (err) {
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
        }
    })

});

app.get("/submit", function(req,res){
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res){
    const submittedSecret = req.body.secret;
  
  //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
    // console.log(req.user.id);
  
    User.findById(req.user.id, function(err, foundUser){
      if (err) {
        console.log(err);
      } else {
        if (foundUser) {
          foundUser.secret = submittedSecret;
          foundUser.save(function(){
            res.redirect("/secrets");
          });
        }
      }
    });
  });


app.get("/logout", function(req, res){
    req.logout();
    res.redirect('/');
})

//Port Listen Logic
app.listen(process.env.PORT || 3000, function () {
    console.log("Server is running on port 3000");
})