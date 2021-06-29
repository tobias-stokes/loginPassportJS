// Check for development
    if (process.env.NODE_ENV !== 'production') {
        require('dotenv').config();
    }

// Required
    const express = require('express');
        const app = express();
    const expressLayouts = require('express-ejs-layouts');
    const Datastore = require('nedb');
    const bcrypt = require('bcrypt');
    const passport = require('passport');
    const LocalStategy = require('passport-local').Strategy;
    const flash = require('express-flash');
    const session = require('express-session');
    const methodOverride = require('method-override');
const { response } = require('express');

// Global variables
    const port = process.env.PORT || 3000;

// Database files
    const userDB = new Datastore({ filename: 'user.db', autoload: true });

// App config
    app.set('view engine', 'ejs');
    app.set('views', `${__dirname}/views`);
    app.set('layout', 'layout/layout');

    app.use(expressLayouts);
    app.use(express.urlencoded({ extended: true }));
    app.use(flash());
    app.use(session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false
    }));
    app.use(passport.initialize());
    app.use(passport.session());
    app.use(methodOverride('_method'));

    app.listen(port, () => console.log(`Listening on port ${port}`));

// Routes
    // Home
        app.get('/', (request, response) => {
            response.render('index.ejs', {
                pageName: 'Home',
                auth: request.user
            });
        });
    
    // Login
        app.get('/login', checkNotAuthentication, (request, response) => {
            response.render('login.ejs', {
                pageName: 'Login',
                auth: request.user
            });
        });

            app.post('/login', checkNotAuthentication, passport.authenticate('local', {
                successRedirect: '/dashboard',
                failureRedirect: '/login',
                failureFlash: true
            }));

    // Register
        app.get('/register', checkNotAuthentication, (request, response) => {
            response.render('register.ejs', {
                pageName: 'Register',
                auth: request.user
            });
        });

            app.post('/register', checkNotAuthentication, async (request, response) => {
                const data = request.body;

                // Hashing password
                    const salt = await bcrypt.genSalt();
                    const hashedPass = await bcrypt.hash(data.password, salt);

                // Storing user into db
                    userDB.insert({
                        name: data.name,
                        username: data.username,
                        password: hashedPass
                    });

                // Redirecting after completion
                    response.redirect('/login');
            });

    // Dashboard
        app.get('/dashboard', checkAuthentication, (request, response) => {
            response.render('dashboard.ejs', {
                pageName: 'Dashboard',
                auth: request.user
            });
        });

    // Logout
        app.delete('/logout', checkAuthentication, (request, response) => {
            request.logout();
            response.redirect('/');
        });

// Authentication
    // Passport config
        passport.use(new LocalStategy(
            async (username, password, done) => {
                // Finding user
                    const user = await new Promise((resolve, reject) => {
                        userDB.findOne({ username }, (err, output) => {
                            if (err) {
                                console.log(err);
                                return done(err);
                            }
                            resolve(output);
                        });
                    });

                // Check if user was found
                    if (user == undefined) {
                        return done(null, false, { message: 'No account for that user' });
                    }

                // Check password
                    bcrypt.compare(password, user.password, (err, result) => {
                        if (err) {
                            console.log(err);
                            return done(err);
                        }
                        if (!result) {
                            return done(null, false, { message: 'Incorrect password' });
                        }
                        return done(null, user);
                    });
            }
        ));

        passport.serializeUser((user, done) => done(null, user._id));
        passport.deserializeUser(async (_id, done) => {
            const user = await new Promise((resolve, reject) => {
                userDB.findOne({ _id }, (err, output) => {
                    if (err) {
                        console.log(err);
                        return done(err);
                    }
                    resolve(output);
                });
            });
            return done(null, user);
        });

    // Middleware
        function checkAuthentication(request, response, next) {
            if (request.isAuthenticated()) {
                next();
            }
            else {
                response.redirect('/login');
            }
        }
        
        function checkNotAuthentication(request, response, next) {
            if (request.isAuthenticated()) {
                response.redirect('/dashboard');
            }
            else {
                next();
            }
        }