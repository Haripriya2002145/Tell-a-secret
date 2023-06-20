require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const app = express();
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
// const bcrypt=require('bcrypt');
// const saltRounds=10;
//const md5=require('md5');
//const encrypt=require('mongoose-encryption');

app.set('view engine', 'ejs');
app.use(express.static("public"));
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());
//mongoDB and mongoose
mongoose.connect("mongodb://127.0.0.1/wikiDB", { useNewUrlParser: true });
//mongoose.set("useCreateIndex", true);

//schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

//using plugin for mongoDB/Mongoose Schema as passportLocalMongoose package.
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Data Encryption
//console.log(process.env.API_KEY);
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields:["password"]});

//model
const User = new mongoose.model('User', userSchema);

//Serialize and Deserialize sessions
passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser( function (user, done) {
    done(null, user.id);
});

// passport.deserializeUser( function (id, done) {
//     User.findById(id,function (err, user) {
//         done(err, user);
//     });
// });
passport.deserializeUser( function (id, done) {
    User.findById(id)
    .then(function(user) {
        done(null, user);
    })
    .catch(function(err){
        done(err, null);
        console.log(err);
    })
});


//GoogleStrategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));


//Routes
app.get("/", (req, res) => {
    res.render("home");
})

app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile"] }))

app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: '/login' }),
    function (req, res) {
        //successful authentication, redirect to secrets.
        res.redirect("/secrets");
    }
)

app.get("/login", (req, res) => {
    res.render("login");
})

app.get("/register", (req, res) => {
    res.render("register");
})

app.get("/secrets", (req, res) => {
    User.find({secret: {$ne: null}})
    .then(function(foundUsers){
        if(foundUsers){
            res.render("secrets", {usersWithSecrets: foundUsers})
        }
    })
    .catch((err)=>{
        console.log(err);
    })
})

app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (!err) {
            res.redirect("/");
        }
    });
});

app.get("/submit", function(req, res){
    if (req.isAuthenticated()) {
        res.render("submit");
    }
    else {
        res.redirect("/login");
    }
})

app.post("/submit", function(req, res){
    const submittedSecret= req.body.secret;
    User.findById(req.user.id)
    .then(function(foundUser){
        foundUser.secret=submittedSecret;
        foundUser.save()
        .then(function(){
            res.redirect("/secrets");
        })
        .catch(function(){
            console.log(err);
        })
    })
    .catch(function(err){
        console.log(err);
    })
})

app.post("/register", (req, res) => {

    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        }
        else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
        }
    })
})

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        }
        else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            })
        }
    })
})

/*
------------using BCRYPT------------
app.post("/register", (req, res)=>{
    
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        // Store hash in your password DB.
        const newUser=new User({
            email: req.body.username,
            password: hash
        })
        newUser.save()
        .then(function(){
            res.render("secrets");
        })
        .catch(function(err){
            console.log(err);
        })
    });
});

app.post("/login", (req, res)=>{
    const username=req.body.username;
    const password=req.body.password;

    User.findOne({email: username})
    .then(function(foundUser){
        if(foundUser){
            bcrypt.compare(password, foundUser.password, function(err, result) {
                if(result===true){
                    res.render("secrets");
                }
            });
        }
    })
    .catch(function(err){
        console.log(err);
    })
})
*/

app.listen(3000, () => {
    console.log("Server listening on port 3000");
})
