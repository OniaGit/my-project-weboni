const express = require('express');
const session = require('express-session');
const path = require('path');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');


const app = express();
const PORT = 3000;

// Middleware to parse the request body
app.use(bodyParser.urlencoded({ extended: true }));

// Serve the static HTML files
app.use(express.static(path.join(__dirname, 'public')));

// Create or open the database
const db = new sqlite3.Database('./database/users.db', (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the users database.');
});

// Create the users table if it doesn't exist
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)`);
// Add this middleware before your routes
app.use(session({
    secret: 'your-secret-key', // Change this to a secure key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set true if using HTTPS
}));

// Serve the signup page
app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Handle user signup
app.post('/signup', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
        if (err) {
            if (err.message.includes("UNIQUE constraint failed")) {
                return res.send("Username already exists. Please choose another one.");
            }
            return res.status(500).send(err.message);
        }
        res.send("Account created successfully! You can now log in.");
    });
});

// Handle user login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (err) {
            return res.status(500).send(err.message);
        }
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.redirect('/?error=invalid');
        }
        res.redirect('/main.html');

    });
});

app.get('/logout', (req, res) => {
    // Here you would typically clear the user session
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send(err.message);
        }
        // Redirect to index.html after logging out
        res.redirect('/index.html');
    });
});


// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
