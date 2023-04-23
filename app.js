require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const validator = require('validator');

const passport = require('passport')
const session = require('express-session');
const passportLocalMongoose = require('passport-local-mongoose');

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
//const ejs = require('ejs');

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

// Session init
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

// Database init
mongoose.set('strictQuery', false);
mongoose.connect('mongodb://localhost:27017/userDB');

const secretSchema = new mongoose.Schema({
    secret: String
});

const Secret = new mongoose.model('secret', secretSchema);

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        validate: {
            validator: validator.isEmail,
            message: '{VALUE} is not a valid email',
            isAsync: false
          }
    },
    password: String,
    googleId: String,
    secrets: {
        type: Array,
        default: []
    }
});

// User plugins
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user.id);
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });
  
// Google strategy set-up
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/secrets',
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  (accessToken, refreshToken, profile, cb) => {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Get routes
app.get('/', (req, res) => {
    res.render('home');
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication, redirect to secrets page.
    res.redirect('/secrets');
  });

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.get('/secrets', (req, res) => {
    User.find({secrets: {$ne: null}}, (err, users) => {
        if(err){
            console.log(err);
        }else{
            console.log('users :', users);
            res.render('secrets', {'users': users});
        }
    });
    /* if(req.isAuthenticated()){
        res.render('secrets');
    }else{
        res.redirect('/login');
    } */
});

app.get('/submit', (req, res) => {
    if(req.isAuthenticated()){
        res.render('submit');
    }else{
        res.redirect('/login');
    }
});

app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if(err){
            return next(err);
        }else{
            res.redirect('/');
        }
    });
    
});

// Post routes
app.post('/submit', (req, res) => {
    User.findById(req.user, (err, user) => {
        if(err){
            console.log(err);
        }else{
            if(user){
                console.log(user);
                const secret = new Secret({
                    secret: req.body.secret
                });

                user.secrets = [...user.secrets, secret];
                console.log(user.secrets);
                user.save();
                console.log('New secret added!');

                res.redirect('/secrets');
            }else{
                res.redirect('/login');
            }
        }
    })
    console.log(req.user);
    
});

app.post('/register', (req, res) => {
    User.register({username: req.body.username}, req.body.password, (err, user) => {
        if(err){
            console.log(err);
            res.redirect('/register');
        }else{
            passport.authenticate('local')(req, res, () => {
                res.redirect('/secrets');
            });
        }
    });
});

app.post('/login', (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        if(err){
            console.log(err);
            res.redirect('/register');
        }else{
            passport.authenticate('local', { failureRedirect: '/register' })(req, res, () => {
                res.redirect('/secrets');
            });
        }
    });
});

app.listen(3000, () => {
    console.log('Listening on port 3000...');
})
