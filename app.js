require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const app = express();
const ejs = require('ejs');
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const findOrCreate = require('mongoose-findorcreate');
// const md5 = require("md5");
const bcrypt = require("bcrypt");
const saltRounds = 10;
//  used for bcrypt
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));



app.use(session({
  secret: "Our awesome secret",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());
mongoose.connect("mongodb://localhost:27017/userDB");

const secretSchema = new mongoose.Schema({
  secret:String,
  userNam:String
});
const Secret = new mongoose.model("Secret", secretSchema);


const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  githubId : String,
  secret : [secretSchema],
  userName : String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User", userSchema);


passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, { id: user.id, username: user.username, name: user.name });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secret"
},
  function (accessToken, refreshToken, profile, cb) {
    console.log(profile.displayName);
    User.findOrCreate({username:profile.displayName, googleId: profile.id }, function (err, user) {
      user.userName = profile.displayName;
      user.save();
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_ID,
  clientSecret: process.env.FACEBOOK_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
  function (accessToken, refreshToken, profile, cb) {
    console.log(profile.displayName);
    User.findOrCreate({username:profile.displayName ,facebookId: profile.id }, function (err, user) {
      user.userName = profile.displayName;
      user.save();
      return cb(err, user);
    });
  }
));

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_ID,
  clientSecret: process.env.GITHUB_SECRET,
  callbackURL: "http://localhost:3000/auth/github/secrets"
},
  function (accessToken, refreshToken, profile, done) {
    console.log(profile.username);
    User.findOrCreate({username:profile.username ,githubId: profile.id }, function (err, user) {
      user.userName = profile.username;
      user.save();
      return done(err, user);
    });
  }
));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());



app.get("/", function (req, res) {
  res.render("home");
});
app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});
const item = new Secret({
  secret : "Working day"
});
item1 = new Secret({
  secret : "its trail"
});
item2 = new Secret({
  secret : "its trail2"
});
item3 = new Secret({
  secret : "its trail3"
});
defaultitems = [item1,item2,item3];
app.get("/secrets", function (req, res) {
  if(req.isAuthenticated()){
    Secret.find({},function(err,foundSecret){
      if(err){
        console.log(err);
      }else{
        User.find(req.user.id,function(err,foundUser){
            // console.log(foundUser.username);
            res.render("secrets",{userSecret:foundSecret});
        });
        // console.log(foundSecret);
      }
    });
  }
});
app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    // console.log(req.user.username);
    res.render("submit",{userName:req.user.username});
    // res.render("submit");
  }
})

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });

});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secret',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/github',
  passport.authenticate('github', { scope: ['user:email'] }));

app.get('/auth/github/secrets',
  passport.authenticate('github', { failureRedirect: '/login' }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
  
app.get("/submit", function (req, res) {
  User.find({"secret":{$ne:null}},function(err,foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        res.render("secrets",{userSecret:foundUser.secret});
      };
    };
  });
});

// console.log((md5("Hash")));

app.post("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    const submittedSecret = req.body.secret;
    // console.log(req.user.id); 
    User.findById(req.user.id,function(err,foundUser){
      if(err){
        console.log(err);
      }else{
        if(foundUser){
          // foundUser.userName = req.user.familyName;
          const item = new Secret({
            secret : submittedSecret,
            userNam: req.body.userName
          });
          item.save();
          foundUser.secret.push(item);
          foundUser.save(function(){
            res.redirect("/secrets");
          });
        };
      };
    });
  } else {
    res.redirect("/login");
  }
});

app.post("/register", function (req, res) {
  // bcrypt.hash(req.body.password,saltRounds,function(err,hash){
  //     const newUser = new User({
  //         email : req.body.username,
  //         password : hash
  //     });
  //     newUser.save(function(err){
  //         if(err){
  //             res.send(err);
  //         }else{
  //             res.render("secrets");
  //         };
  //     });
  // });
  User.register({ username: req.body.username }, req.body.password, function (err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      })
    }
  });


});



app.post("/login", function (req, res) {
  // const userName = req.body.username;
  // const password = req.body.password;

  // User.findOne({email:userName},function(err,foundUser){
  //     if(err){
  //         console.log(err);
  //     }else{
  //         if(foundUser){
  //             bcrypt.compare(password,foundUser.password,function(err,result){
  //                 if(result ===true){
  //                     res.redirect("/secrets");
  //                 }
  //             })
  //         };
  //     };
  // });

  // Using passport --- 

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        // console.log("success");
        res.redirect("/secrets");
      });
    }
  });
});

// Logout sessions =---- 









app.listen(process.env.PORT || 3000, function () {
  console.log("Server is running at server 3000");
});