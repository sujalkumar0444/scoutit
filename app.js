import 'dotenv/config.js';
import express from 'express';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as LocalStrategy } from 'passport-local'; // Added
import session from 'express-session';
import pg from 'pg';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';

const app = express();
const port = 3000;
var flag=false;
const pool = new pg.Client({
  user: 'postgres',
  host: 'localhost',
  database: 'world',
  password: process.env.DB_PASSWORD,
  port: 5432,
});

pool.connect();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

app.use(
  session({
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

class User {
  static async findById(id) {
    try {
      const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
      return result.rows[0];
    } catch (error) {
      console.log(error);
      return null;
    }
  }

  static async findByEmail(email) {
    try {
      const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      return result.rows[0];
    } catch (error) {
      console.log(error);
      return null;
    }
  }

  static async register(email, password) {
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const result = await pool.query(
        'INSERT INTO users (email, password, secret) VALUES ($1, $2, $3) RETURNING *',
        [email, hashedPassword, null]
      );
      return result.rows[0];
    } catch (error) {
      console.log(error);
      return null;
    }
  }
}

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    const user = result.rows[0];
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});


// Second local strategy for admin users
const adminUser = {
  role:"admin",
  email: process.env.ADMIN_EMAIL,
  password: process.env.ADMIN_PASSWORD ,
};

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/customnuts',
      userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
    },
    async (token, tokenSecret, profile, done) => {
      try {
        const { id, displayName, emails } = profile;
        const email = emails[0].value;

        const result = await pool.query('SELECT * FROM users WHERE google_id = $1', [id]);
        const existingUser = result.rows[0];

        if (existingUser) {
          return done(null, existingUser);
        } else {
          const newUser = await pool.query(
            'INSERT INTO users (google_id, display_name, email, secret) VALUES ($1, $2, $3, $4) RETURNING *',
            [id, displayName, email, null]
          );
          return done(null, newUser.rows[0]);
        }
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

passport.use(
  new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
      const user = await User.findByEmail(email);

      if (!user) {
        return done(null, false, { message: 'Incorrect email.' });
      }

      const isPasswordMatch = await bcrypt.compare(password, user.password);

      if (!isPasswordMatch) {
        return done(null, false, { message: 'Incorrect password.' });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);

app.get('/admin/login', function (req, res) {
  res.render('admin-login');
}); 


app.post('/admin/login', async function (req, res) {
  const email = req.body.username.toLowerCase(); // Assuming your login form has an input with the name 'email'
  const password = req.body.password;

  try {
    const user = await User.findByEmail(email);

    if (!user || adminUser.role!=="admin") {
      // User with the provided email doesn't exist
     res.render('admin-login', { message : "Not an admin" });
    }
    else
    {
    if (password===adminUser.password) {
      // Passwords match, log in the user
      flag=true;
      req.login(user, (err) => {
        if (err) {
          console.log(err);
          return res.status(500).send('Internal Server Error');
        }
        return res.redirect('/admin/dashboard');
      });
    } else {
      // Incorrect password
      res.render('admin-login', { message : "Incorrect password" });
    }
    }
  } catch (error) {
    console.log(error);
    res.status(500).send('Internal Server Error');
  }
});
app.get('/admin/dashboard', async function (req, res) {
  // Ensure only authenticated admin users can access the dashboard
  if (req.isAuthenticated() && req.user.email === adminUser.email && flag) {
    try {
      const result = await pool.query('SELECT * FROM users');
      const allUsers = result.rows;

      res.render('admin-dashboard', { users: allUsers });
    } catch (error) {
      console.log(error);
      res.status(500).send('Internal Server Error');
    }
  } else {
    // Redirect to admin login if not authenticated
    res.redirect('/admin/login');
  }
});


app.post('/admin/delete', async function (req, res) {
  // Ensure only authenticated admin users can delete users
  if (req.isAuthenticated() && req.user.email === adminUser.email &&flag) {
    const userIdToDelete = req.body.userId;

    try {
      await pool.query('DELETE FROM users WHERE id = $1', [userIdToDelete]);
      res.redirect('/admin/dashboard');
    } catch (error) {
      console.log(error);
      res.status(500).send('Internal Server Error');
    }
  } else {
    // Redirect to admin login if not authenticated
    res.redirect('/admin/login');
  }
});



app.get('/', function (req, res) {
  res.render('home');
});

app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get(
  '/auth/google/customnuts',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function (req, res) {
    res.redirect('/secrets');
  }
);

app.get('/login', function (req, res) {
  res.render('login');
});

app.get('/register', function (req, res) {
  res.render('register');
});

app.get('/secrets', async function (req, res) {

  if (req.isAuthenticated()) {
    try {
      const result = await pool.query('SELECT * FROM users WHERE secret IS NOT NULL');
      const foundUsers = result.rows;
  
      res.render('secrets', { usersWithSecrets: foundUsers });
    } catch (error) {
      console.log(error);
      res.status(500).send('Internal Server Error');
    }
  } else {
    res.redirect('/login');
  }

});

app.get('/submit', function (req, res) {
  if (req.isAuthenticated()) {
    res.render('submit');
  } else {
    res.redirect('/login');
  }
});

app.post('/submit', async function (req, res) {
  const submittedSecret = req.body.secret;

  try {
    const result = await pool.query('UPDATE users SET secret = $1 WHERE id = $2', [submittedSecret, req.user.id]);
    res.redirect('/secrets');
  } catch (error) {
    console.log(error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/logout', function (req, res) {
  flag=false;
  req.logout(function (err) {
    if (err) {
      console.error(err);
      return res.status(500).send('Internal Server Error');
    }
    req.session.destroy(function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
      }
      res.redirect('/');
    });
  });
});




app.post('/register', async function (req, res) {
  const email = req.body.username.toLowerCase(); // Convert email to lowercase for case-insensitivity
  const password = req.body.password;

  try {
    // Check if the user with the provided email already exists
    const existingUser = await User.findByEmail(email);

    if (existingUser) {
      // User already exists, handle it (e.g., show a message or redirect to registration page)
      res.render('register', { message : "User already exists"});
      // return res.redirect('/register');
    }

    // User doesn't exist, proceed with registration
    else
    {
    const newUser = await User.register(email, password);

    if (newUser) {
      req.login(newUser, (err) => {
        if (err) {
          console.log(err);
          return res.status(500).send('Internal Server Error');
        } else {
          res.redirect('/secrets');
        }
      });
    } else {
      res.redirect('/register');
    }
}
  } catch (error) {
    console.log(error);
    res.status(500).send('Internal Server Error');
  }
});


// Add this route after the app.post('/register', ...) route
app.post('/login', async function (req, res) {
  const email = req.body.username.toLowerCase(); // Assuming your login form has an input with the name 'email'
  const password = req.body.password;

  try {
    const user = await User.findByEmail(email);

    if (!user) {
      // User with the provided email doesn't exist
  
     res.render('login', { message : "User doesn't exist" });
    }
    else
    {
    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (isPasswordMatch) {
      // Passwords match, log in the user
      req.login(user, (err) => {
        if (err) {
          console.log(err);
          return res.status(500).send('Internal Server Error');
        }
        return res.redirect('/secrets');
      });
    } else {
      // Incorrect password
      res.render('login', { message : "Incorrect password" });
    }
    }
  } catch (error) {
    console.log(error);
    res.status(500).send('Login with google');
  }
});


app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
