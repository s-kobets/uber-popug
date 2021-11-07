require('dotenv').config();
require('./config/database').connect();
const jwt = require('jsonwebtoken');
const express = require('express');
const bcrypt = require('bcryptjs');
const nunjucks = require('nunjucks');
const cookieParser = require('cookie-parser');
// importing user context
const User = require('./model/user');
const auth = require('./middleware/auth');

const app = express();

nunjucks.configure('views', {
  autoescape: true,
  express: app,
});

app.set('views', './views');

app.use(express.json());
app.use(cookieParser());

app.get('/verify', auth, (req, res) => {
  res.json('index.html', req.user);
});

app.get('/register', (req, res) => {
  res.render('register.html');
});

// Register
app.post('/register', async (req, res) => {
  try {
    // Get user input
    const { full_name, email, password } = req.body;

    // Validate user input
    if (!(email && password && full_name)) {
      return res.status(400).json({ err: 'All input is required' });
    }

    // check if user already exist
    // Validate if user exist in our database
    const oldUser = await User.findOne({ email });

    if (oldUser) {
      return res.status(409).json({ err: 'User Already Exist. Please Login' });
    }

    //Encrypt user password
    encryptedPassword = await bcrypt.hash(password, 10);

    // Create user in our database
    const user = await User.create({
      full_name,
      email: email.toLowerCase(), // sanitize: convert email to lowercase
      password: encryptedPassword,
    });

    // Create token
    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY,
      {
        expiresIn: '2h',
      }
    );
    // save user token
    user.token = token;

    // return new user
    res.status(201).json(user);
  } catch (err) {
    console.log(err);
  }
});

app.get('/login', (req, res) => {
  res.render('login.html');
});

// Login
app.post('/login', async (req, res) => {
  try {
    // Get user input
    const { email, password } = req.body;

    // Validate user input
    if (!(email && password)) {
      return res.status(400).json({ err: 'All input is required' });
    }
    // Validate if user exist in our database
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: '2h',
        }
      );

      // save user token
      user.token = token;

      // user
      res.status(200).json(user);
    } else {
      res.status(400).json({ err: 'Invalid Credentials' });
    }
  } catch (err) {
    console.log(err);
  }
});

module.exports = app;
