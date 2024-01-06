const express = require('express');
const path = require('path');
const eventsManager = require('./eventsManager');
require('dotenv').config({ path: './backend/.env' });
const db = require('../database/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { expressjwt } = require("express-jwt");
const cookieParser = require('cookie-parser');
const { sign, verify } = require('jsonwebtoken');

const app = express();

// Middleware for parsing JSON and urlencoded data
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

// Serve static files from the 'frontend' directory
app.use(express.static(path.join(__dirname, '..', 'frontend')));
app.use(express.static(path.join(__dirname, '..', 'frontend', 'public')));

// Middleware to validate token and set req.user
app.use(expressjwt({
    secret: process.env.JWT_SECRET,
    algorithms: ['HS256'],
    getToken: req => {
        if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
            return req.headers.authorization.split(' ')[1];
        } else if (req.cookies.token) {
            return req.cookies.token;
        }
        return null;
    }
}).unless({
    path: ['/', '/login', '/register']
}));

// Middleware to verify user has an active subscription
const isAuthenticatedAndSubscribed = (req, res, next) => {
    const token = req.cookies["token"]; 
    
    if (!token) {
        return res.status(401).send('Access denied. Active subscription required.');
    }
    try {
        const isValidToken = verify(token, process.env.JWT_SECRET);
        if(isValidToken) {
            req.authenticated = true;
            return next();
        }
    } catch (err) {
        return res.status(400).json({ error: err });
    }
};

// Define route for the homepage
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'views', 'index.html'));
});

app.get('/dashboard', isAuthenticatedAndSubscribed, (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'views', 'dashboard.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'views', 'login.html'));
});

app.get('/logout', (req, res) => {
    res.clearCookie('token'); // Clear the token cookie
    res.redirect('/'); // Redirect to the homepage
});


// Stripe events endpoint
app.post('/events', eventsManager);

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'views', 'register.html'));
});

app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if there's an active subscription for the given email
        const checkSubscriptionQuery = 'SELECT * FROM users WHERE email = ? AND is_subscribed = TRUE';
        db.get(checkSubscriptionQuery, [email], async (err, user) => {
            if (err) {
                console.error(err.message);
                return res.status(500).send('Error processing your request.');
            }

            if (user) {
                // User with active subscription exists, deny new registration
                return res.status(400).send('An account with this email already exists.');
            } else {
                // No active subscription found, proceed with registration
                const hashedPassword = await bcrypt.hash(password, 10);
                const insertQuery = 'INSERT INTO users (email, password, is_subscribed) VALUES (?, ?, ?)';
                db.run(insertQuery, [email, hashedPassword, false], function (insertErr) {
                    if (insertErr) {
                        console.error(insertErr.message);
                        res.status(500).send('Error registering new user.');
                    } else {
                        // User is registered, create a JWT token and log them in
                        const token = jwt.sign({ id: this.lastID, email: email }, process.env.JWT_SECRET, { expiresIn: '1h' });
                        res.cookie('token', token, { httpOnly: true }); // Use 'secure: true' if using HTTPS
                        res.redirect('/dashboard');
                        console.log(`A new user has been created with ID: ${this.lastID}`);
                    }
                });
            }
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).send('Error processing your request.');
    }
});

app.post('/login', async (req, res) => {
    try {
        // Check if the 'Remember Me' option was checked
        const rememberMe = req.body.rememberMe === 'remember';

        // Set token expiration: short duration if not remembered, longer if remembered
        const expirationTime = rememberMe ? '365d' : '1h';

        const createToken = (user) => {
            const accessToken = jwt.sign({ id: user.id, email: user.email, hasActiveSubscription: user.hasActiveSubscription }, process.env.JWT_SECRET, { expiresIn: expirationTime });
            return accessToken;
        }

        const query = 'SELECT * FROM users WHERE email = ?';       

        db.get(query, [req.body.email], async (err, user) => {
            if (err) {
                console.log("error logging in user");
                return res.status(500).send('Error logging in user.');
            }
            if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
                console.log("Invalid credentials");
                return res.status(401).send('Invalid credentials.');
            }

            const getToken = createToken(user);

            if (user.hasActiveSubscription) {       
                res.cookie('token', getToken, { 
                    maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 60 * 60 * 1000,
                    httpOnly: true 
                }); // Set the token in a cookie
                res.redirect('/dashboard'); // Redirect to the dashboard
            } else {
                console.log("not active");
                return res.status(403).send('Account is not active. Please subscribe.');
            }
        });
    } catch (e) {
        console.log(e);
        res.status(500).send('Server error');
    }
});

// Error handling for unauthorized errors
app.use(function (err, req, res, next) {
    if (err.name === 'UnauthorizedError') {
        res.redirect('/login');
        console.log('Invalid token or unauthorized access.');
    } else {
        // Log the error for debugging purposes
        console.error('Error occurred:', err);

        // Respond with 500 Internal Server Error for any other errors
        res.status(500).send('Something broke on the server!');
    } 
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
