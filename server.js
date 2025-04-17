// server.js

const express = require('express');
const session = require('express-session');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');
const helmet = require('helmet');

const app = express();
const port = 3000;

// Use helmet to set secure HTTP headers
app.use(helmet());

// Parse incoming form data and JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Serve static files (if you have any in /public)
app.use(express.static(path.join(__dirname, 'public')));

// Set EJS as the templating engine (EJS auto‑escapes variables)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Session configuration (In production, store the secret securely, and use HTTPS with secure cookies)
app.use(session({
  secret: 'your_secret_key', // Replace with an environment variable in production
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set true when using HTTPS in production
}));

// Create MySQL connection pool
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '', 
  database: 'blog',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Simple middleware to check if a user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
}



// Home: redirect to blog if logged in, otherwise to login page
app.get('/', (req, res) => {
  if (req.session && req.session.userId) {
    res.redirect('/blog');
  } else {
    res.redirect('/login');
  }
});

// GET Login page
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// GET Register page
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

// Create a new user with a hashed password
app.post('/register', async (req, res) => {
  let { username, password } = req.body;
  
  // Validate input 
  if (!username || !password) {
    return res.render('register', { error: 'Please fill all fields.' });
  }

  try {
    // Check if the username already exists (prepared statement mitigates SQL injection)
    const query = 'SELECT * FROM users WHERE username = ?';
    pool.execute(query, [username], async (err, results) => {
      if (err) {
        console.error(err);
        return res.render('register', { error: 'Database error.' });
      }
      if (results.length > 0) {
        return res.render('register', { error: 'Username already exists.' });
      }
      // Hash the password (bcrypt automatically salts the hash)
      const password_hash = await bcrypt.hash(password, 10);
      // Insert the new user using a parameterized query
      const insertQuery = 'INSERT INTO users (username, password_hash) VALUES (?, ?)';
      pool.execute(insertQuery, [username, password_hash], (err) => {
        if (err) {
          console.error(err);
          return res.render('register', { error: 'Database error during registration.' });
        }
        res.redirect('/login');
      });
    });
  } catch (error) {
    console.error(error);
    res.render('register', { error: 'Unexpected error.' });
  }
});

// uthenticate user
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.render('login', { error: 'Please enter both username and password.' });
  }
  const query = 'SELECT * FROM users WHERE username = ?';
  pool.execute(query, [username], async (err, results) => {
    if (err) {
      console.error(err);
      return res.render('login', { error: 'Database error.' });
    }
    if (results.length === 0) {
      return res.render('login', { error: 'Invalid credentials.' });
    }
    const user = results[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.render('login', { error: 'Invalid credentials.' });
    }
    // Set session variables after successful login
    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect('/blog');
  });
});

// GET Blog page: Show all posts 
app.get('/blog', isAuthenticated, (req, res) => {
  const query = `
    SELECT posts.*, users.username 
    FROM posts 
    JOIN users ON posts.user_id = users.id 
    ORDER BY created_at DESC
  `;
  pool.execute(query, [], (err, posts) => {
    if (err) {
      console.error(err);
      return res.send('Database error.');
    }
    res.render('blog', { posts: posts, currentUser: req.session.userId, username: req.session.username });
  });
});

// POST Create a post
app.post('/blog/create', isAuthenticated, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) {
    return res.redirect('/blog');
  }
  const query = 'INSERT INTO posts (title, content, user_id, created_at) VALUES (?, ?, ?, NOW())';
  pool.execute(query, [title, content, req.session.userId], (err) => {
    if (err) {
      console.error(err);
      return res.send('Database error while creating post.');
    }
    res.redirect('/blog');
  });
});

// Edit a post (only allow if post belongs to the logged-in user)
app.post('/blog/edit/:id', isAuthenticated, (req, res) => {
  const postId = req.params.id;
  const { title, content } = req.body;
  const query = 'UPDATE posts SET title = ?, content = ? WHERE id = ? AND user_id = ?';
  pool.execute(query, [title, content, postId, req.session.userId], (err) => {
    if (err) {
      console.error(err);
      return res.send('Database error while updating post.');
    }
    res.redirect('/blog');
  });
});

// Delete a post (only allow if post belongs to the logged-in user)
app.post('/blog/delete/:id', isAuthenticated, (req, res) => {
  const postId = req.params.id;
  const query = 'DELETE FROM posts WHERE id = ? AND user_id = ?';
  pool.execute(query, [postId, req.session.userId], (err) => {
    if (err) {
      console.error(err);
      return res.send('Database error while deleting post.');
    }
    res.redirect('/blog');
  });
});

// Logout: Destroy session and return to login page
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
      return res.send('Error logging out.');
    }
    res.redirect('/login');
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
