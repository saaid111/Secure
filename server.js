// server.js - Vulnerable Version

const express = require('express');
const session = require('express-session');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const port = 3000;

// No security middleware like Helmet is used here (reducing secure defaults)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration with a hard-coded secret (Sensitive Data Exposure)
app.use(session({
  secret: 'vulnerable_secret_key',
  resave: false,
  saveUninitialized: false,
}));

// Set up EJS templating
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Create a direct MySQL connection
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', // as specified
  database: 'blog'
});

// Middleware to check if a user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
}

// Routes

// Home: Redirect based on authentication
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

// POST Register: Vulnerable to SQL Injection and Sensitive Data Exposure
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.render('register', { error: "Missing fields" });
  }
  // VULNERABILITY: SQL Injection by concatenating user input directly
  let queryCheck = "SELECT * FROM users WHERE username = '" + username + "'";
  connection.query(queryCheck, async (err, results) => {
    if (err) {
      // VULNERABILITY: Sensitive Data Exposure - Detailed error is returned to the client
      console.error("Error SQL: " + queryCheck, err);
      return res.send("Database error: " + err);
    }
    if (results.length > 0) {
      return res.render('register', { error: "Username already exists." });
    }
    let password_hash = await bcrypt.hash(password, 10);
    // VULNERABILITY: SQL Injection by concatenating values directly
    let queryInsert = "INSERT INTO users (username, password_hash) VALUES ('" + username + "', '" + password_hash + "')";
    connection.query(queryInsert, (err) => {
      if (err) {
        console.error("Error SQL: " + queryInsert, err);
        return res.send("Database error: " + err);
      }
      res.redirect('/login');
    });
  });
});

// POST Login: Vulnerable to SQL Injection and Sensitive Data Exposure
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.render('login', { error: "Missing fields" });
  }
  // VULNERABILITY: SQL Injection by concatenating user input directly
  let query = "SELECT * FROM users WHERE username = '" + username + "'";
  connection.query(query, async (err, results) => {
    if (err) {
      console.error("Error SQL: " + query, err);
      return res.send("Database error: " + err);
    }
    if (results.length === 0) {
      return res.render('login', { error: "Invalid credentials" });
    }
    let user = results[0];
    let passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.render('login', { error: "Invalid credentials" });
    }
    req.session.userId = user.id;
    req.session.username = user.username;
    res.redirect('/blog');
  });
});

// GET Blog page: Renders the blog.ejs view with posts
app.get('/blog', isAuthenticated, (req, res) => {
  let query = "SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id ORDER BY created_at DESC";
  connection.query(query, (err, posts) => {
    if (err) {
      console.error("Error SQL: " + query, err);
      return res.send("Database error: " + err);
    }
    // Pass the posts directly to the template which will render them unescaped
    res.render('blog', { posts: posts, currentUser: req.session.userId, username: req.session.username });
  });
});

// POST Create Post: Vulnerable to SQL Injection
app.post('/blog/create', isAuthenticated, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) return res.redirect('/blog');
  // VULNERABILITY: SQL Injection by concatenating user inputs directly
  let query = "INSERT INTO posts (title, content, user_id, created_at) VALUES ('" + title + "', '" + content + "', '" + req.session.userId + "', NOW())";
  connection.query(query, (err) => {
    if (err) {
      console.error("Error SQL: " + query, err);
      return res.send("Database error: " + err);
    }
    res.redirect('/blog');
  });
});

// POST Update Post: Vulnerable to SQL Injection
app.post('/blog/edit/:id', isAuthenticated, (req, res) => {
  const postId = req.params.id;
  const { title, content } = req.body;
  // VULNERABILITY: SQL Injection by concatenating inputs directly
  let query = "UPDATE posts SET title = '" + title + "', content = '" + content + "' WHERE id = '" + postId + "' AND user_id = '" + req.session.userId + "'";
  connection.query(query, (err) => {
    if (err) {
      console.error("Error SQL: " + query, err);
      return res.send("Database error: " + err);
    }
    res.redirect('/blog');
  });
});

// POST Delete Post: Vulnerable to SQL Injection
app.post('/blog/delete/:id', isAuthenticated, (req, res) => {
  const postId = req.params.id;
  // VULNERABILITY: SQL Injection by concatenating the postId directly
  let query = "DELETE FROM posts WHERE id = '" + postId + "' AND user_id = '" + req.session.userId + "'";
  connection.query(query, (err) => {
    if (err) {
      console.error("Error SQL: " + query, err);
      return res.send("Database error: " + err);
    }
    res.redirect('/blog');
  });
});

// GET Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

app.listen(port, () => {
  console.log("Vulnerable app listening at http://localhost:" + port);
});
