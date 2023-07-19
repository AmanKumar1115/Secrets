require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose"); 
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose"); 
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');  
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
    secret:"Thisisourlittlesecret.",
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());



mongoose.connect("mongodb://127.0.0.1:27017/userDB",{ useNewUrlParser : true});


const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    githubId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(async function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(async function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});
 
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
    //userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  async function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FB_CLIENT_ID,
    clientSecret: process.env.FB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
  },
  async function(accessToken, refreshToken, profile, cb) {
  
    User.findOrCreate({ facebookId: profile.id }, async function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ githubId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

app.get("/",async function(req,res){
    res.render("home");
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

// app.get('/auth/facebook',
//   passport.authenticate('facebook', { scope: ['user_friends', 'manage_pages'] }));

app.get("/auth/facebook", passport.authenticate("facebook", { scope: ["profile"] }));

app.get('/auth/github', passport.authenticate('github', { scope: [ 'user:email','user:profile' ] }));

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  async function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

  app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  async function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login",async function(req,res){
    res.render("login");
})

app.get("/register",async function(req,res){
    res.render("register");
});

app.get("/secrets",async function(req,res){
    const foundUser =  await User.find({"secret": {$ne: null}});
    res.render("secrets", {usersWithSecrets: foundUser});
   
});

app.get("/submit",async function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit",async function(req,res){
    const submittedSecret = req.body.secret;
    const foundUser = await User.findById(req.user.id);
    foundUser.secret = submittedSecret;
    await foundUser.save();
    res.redirect("/secrets");
    

});

app.get("/logout",async function(req,res){
    req.logout(function(){});
    res.redirect("/");
});

app.post("/register",async function(req,res){

    User.register({username: req.body.username}, req.body.password, async function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res,async function(){
        res.redirect("/secrets");
      });
    }
  });
    
});

app.post("/login",async function(req,res){
    const user = new User({
        username:req.body.username,
        password:req.body.password
    });

    req.login(user,async function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.listen(3000, async function() {
  console.log("Server started on port 3000");
});

