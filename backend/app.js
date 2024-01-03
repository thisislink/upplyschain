const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const eventsManager = require('./eventsManager');
require('dotenv').config({ path: './backend/.env' });
const db = require('../database/database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

// Middleware for parsing JSON and urlencoded data
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
// Middleware to validate token and set req.user
//app.use(expressJwt({ secret: process.env.JWT_SECRET, algorithms: ['HS256'] }).unless({ path: ['/login', '/register'] }));

// Middleware to verify user has an active subscription
const isAuthenticatedAndSubscribed = (req, res, next) => {
    if (!req.user || !req.user.is_subscribed) {
        return res.status(401).send('Access denied. Active subscription required.');
    }
    next();
};

// Before redirect create session id for tracking and creating new customer
app.post('/create-checkout-session', async (req, res) => {
    const session = await stripe.checkout.sessions.create({
        // ... other session parameters ...
        success_url: 'https://upplyschain.com/register?session_id={CHECKOUT_SESSION_ID}',
        cancel_url: 'https://upplyschain.com/cancel',
    });

    res.json({ sessionId: session.id });
});


// Serve static files from the 'frontend' directory
app.use(express.static(path.join(__dirname, '..', 'frontend')));

app.use(function (err, req, res, next) {
    if (err.name === 'UnauthorizedError') {
        res.status(401).send('Invalid token or unauthorized access.');
    } else {
        res.status(500).send('Server error');
    }
});

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


app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM users WHERE email = ?';
    db.get(query, [email], async (err, user) => {
        if (err) {
            return res.status(500).send('Error logging in user.');
        }
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).send('Invalid credentials.');
        }
        if (!user.is_subscribed) {
            return res.status(403).send('Account is not active. Please subscribe.');
        }

        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
