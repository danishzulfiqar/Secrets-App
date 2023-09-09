const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const ejs = require("ejs");
const path = require("path");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require('mongoose-findorcreate');
require("dotenv").config();
const port = 3000;


app.set('views', path.join(__dirname, '/views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, '/public')));
app.use(bodyParser.urlencoded({ extended: true }));


// using session
app.use(session({
    secret: `${process.env.secretKey}`,
    resave: false,
    saveUninitialized: true,
}));

// initializing passport
app.use(passport.initialize());
app.use(passport.session());


// setting mongoDb and schema
const dbURL = process.env.dbURL;
mongoose.connect(`${dbURL}`, { useNewUrlParser: true });

const UserSchema = new mongoose.Schema({
    strategy: {
        type: String,
    },
    email: {
        type: String,
    },
    username: {
        type: String,
    },
    password: {
        type: String,
    },
    googleId: {
        type: String
    },
    facebookId: {
        type: String
    },
    googleName: {
        type: String
    },
    facebookName: {
        type: String
    }
});

UserSchema.plugin(passportLocalMongoose);
UserSchema.plugin(findOrCreate);

const SecretSchema = new mongoose.Schema({
    content: {
        type: String,
        required: true
    }
});


// making model object for schema of user
const User = mongoose.model("User", UserSchema);

// setting cookies configs for User
passport.use(User.createStrategy());

passport.serializeUser(function (user, done) { done(null, user) });
passport.deserializeUser(function (user, done) { done(null, user) });


//Configure Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        // console.log(profile)
        const user = {
            strategy: "google",
            googleId: profile.id,
            googleName: profile.displayName
        }
        User.findOrCreate(user, function (err, user) {
            return cb(err, user);
        });
    }
));


//Configure FacebookStrategy
passport.use(new FacebookStrategy({
    clientID: process.env.FB_APP_ID,
    clientSecret: process.env.FB_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        // console.log(profile)
        const user = {
            strategy: "facebook",
            facebookId: profile.id,
            facebookName: profile.displayName
        }
        User.findOrCreate(user, function (err, user) {
            return cb(err, user);
        });
    }
));


const Secret = mongoose.model("Secret", SecretSchema);


// home route
app.route("/")
    .get(function (req, res) {
        res.render("home", {
            current_page: "home"
        });
    })


// login route
app.route("/login")
    .get(function (req, res) {
        if (req.isAuthenticated()) {
            res.redirect("/secrets");
        }
        else {
            res.render("login", {
                current_page: "login"
            });
        }
    })
    .post(function (req, res) {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });
        req.login(user, (err) => {
            if (err) {
                console.log(err);
            } else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets")
                });
            }
        });

    });


// signup route
app.route("/signup")
    .get(function (req, res) {
        if (req.isAuthenticated()) {
            res.redirect("/secrets");
        }
        else {
            res.render("signup", {
                current_page: "signup"
            });
        }
    })
    .post(async function (req, res) {
        try {
            const newUser = new User({
                strategy: "local",
                email: req.body.email,
                username: req.body.username
            })
            const registerUser = await User.register(newUser, req.body.password);
            if (registerUser) {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets");
                });
            } else {
                res.redirect("/signup");
            }
        } catch (err) {
            console.log(err)
            res.send("Error: " + err.message);
        }
    });


// google authentication
app.get('/auth/google',
    passport.authenticate('google', { scope: ["profile"] }
    ));

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: "/login" }),
    function (req, res) {
        res.redirect('/secrets');
    });


//Facebook auth route
app.get("/auth/facebook",
    passport.authenticate("facebook")
);
app.get("/auth/facebook/secrets",
    passport.authenticate("facebook", { failureRedirect: "/login" }),
    function (req, res) {
        res.redirect("/secrets");
    });


// secrets route
app.route("/secrets")
    .get(function (req, res) {
        if (req.isAuthenticated()) {
            Secret.find()
                .then(function (secrets) {
                    res.render("secrets", {
                        secrets: secrets
                    });
                })
        }
        else {
            res.redirect("/login");
        }
    })
    .post(function (req, res) {
        const newSecret = req.body;
        if (req.isAuthenticated()) {
            const secret = new Secret(newSecret);
            secret.save()
                .then(function () {
                    res.redirect("/secrets");
                })
        }
        else {
            res.redirect("/login");
        }

    });


// Logout user
app.post('/logout', function (req, res, next) {
    req.logout(function (err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});


app.listen(process.env.PORT || port, function () {
    if (process.env.PORT) {
        console.log(`App live on port:${process.env.PORT}`)
    }
    else {
        console.log(`App live on http://localhost:${port}`);
    }
});

