import 'dotenv/config.js';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as LocalStrategy } from 'passport-local'; // Added
import pg from 'pg';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import express from 'express';
import session from 'express-session';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import http from 'http';
import { Server as SocketIO } from 'socket.io';
import twilio from "twilio";
import axios from 'axios';

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads'); // Define the destination folder for uploaded files
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({ storage: storage });
const app = express();
const server = http.createServer(app);
const io = new SocketIO(server);
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
app.use(bodyParser.json());
app.use(
  session({
    name: 'user-session-id',
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: false,
  })
);
// Use express-session middleware with a custom name for the retailer's session cookie
app.use(session({
  name: 'retailer-session-id',
  secret: 'your_secret_key', // Change this to a secure random string
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }, // Set to true for HTTPS
}));
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
  app.use('/admin', express.static('public'));
  res.render('adminLogin');
}); 
app.post('/admin/login', async function (req, res) {
  app.use('/admin', express.static('public'));
  const email = req.body.username.toLowerCase(); // Assuming your login form has an input with the name 'email'
  const password = req.body.password;
  try {
    const user = await User.findByEmail(email);
    if (!user || adminUser.role!=="admin") {
      // User with the provided email doesn't exist
     res.render('adminLogin', { message : "Not an admin" });
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
      res.render('adminLogin', { message : "Incorrect password" });
    }
    }
  } catch (error) {
    console.log(error);
    res.status(500).send('Internal Server Error');
  }
});
app.get('/admin/dashboard', async function (req, res) {
  app.use('/admin', express.static('public'));
  // Ensure only authenticated admin users can access the dashboard
  if (req.isAuthenticated() && req.user.email === adminUser.email && flag) {
    try {
      const result = await pool.query('SELECT * FROM users where id>1');
      const allUsers = result.rows;
      const result2 = await pool.query('SELECT * FROM retailers');
      const allRetailers = result2.rows;
      res.render('adminDashboard', { users: allUsers,retailers:allRetailers });
    } catch (error) {
      console.log(error);
      res.status(500).send('Internal Server Error');
    }
  } else {
    // Redirect to admin login if not authenticated
    res.redirect('/admin/login');
  }
});
app.post('/admin/deleteUser', async function (req, res) {
  app.use('/admin', express.static('public'));
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
app.post('/admin/deleteRetailer', async function (req, res) {
  app.use('/admin', express.static('public'));
  // Ensure only authenticated admin users can delete users
  if (req.isAuthenticated() && req.user.email === adminUser.email &&flag) {
    const retailerIdToDelete = req.body.retailerId;
    try {
      await pool.query('DELETE FROM retailers WHERE id = $1', [retailerIdToDelete]);
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
app.get('/user', function (req, res) {
  res.render('user');
});
app.get('/retailer', function (req, res) {
  res.render('retailer');
});
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);
app.get(
  '/auth/google/customnuts',
  passport.authenticate('google', { failureRedirect: '/userLogin' }),
  function (req, res) {
    res.redirect('/user/search');
  }
);
app.get('/user/login', function (req, res) {
  app.use('/user', express.static('public'));
  if(req.isAuthenticated())
  {
    res.redirect('/user/search');
  }
  else
  {
  res.render('userLogin');
  }
});
app.get('/user/register', function (req, res) {
  app.use('/user', express.static('public'));
  res.render('userRegister');
});
app.get('/retailer/login', function (req, res) {
  app.use('/retailer', express.static('public'));
  if(req.session.retailerId)
  {
    res.redirect('/retailer/dashboard');
 
  }
  else
  {
    res.render('retailerLogin');
  }
});
app.get('/retailer/register', function (req, res) {
  app.use('/retailer', express.static('public'));
  res.render('retailerRegister');
});
app.post('/retailer/register', async (req, res) => {
  app.use('/retailer', express.static('public'));
  const { full_name, shop_name, phone_number, email, password, latitude, longitude } = req.body;
  try {
      // Hash the password
      const passwordHash = await bcrypt.hash(password, 10);

      // Check if the retailer with the provided email/phone already exists
      const existingRetailer = await pool.query(
          'SELECT * FROM retailers WHERE  phone_number = $1',
          [phone_number]
      );
      if (existingRetailer.rows.length > 0) {
          return res.render('retailerRegister', { message: 'Retailer already exists. Please log in.' });
      }
      // Insert retailer into the PostgreSQL database
      const result = await pool.query(
          'INSERT INTO retailers (full_name, shop_name, phone_number, email, password_hash, latitude, longitude) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
          [full_name, shop_name, phone_number, email, passwordHash, latitude, longitude]
      );
      // Redirect to a success page or the homepage
      res.redirect('/retailer/login');
  } catch (error) {
      console.error('Error inserting retailer into the database:', error);
      res.status(500).send('Internal Server Error');
  }
});
const ACCOUNT_SID = process.env.ACCOUNT_SID;
const AUTH_TOKEN = process.env.AUTH_TOKEN;
const VERIFY_SID = process.env.VERIFY_SID;
const client = twilio(ACCOUNT_SID, AUTH_TOKEN);
app.post('/retailer/generateOtp', async function (req, res) {
  const phoneNumber = req.body.phone_number;
  try {
    const verification = await client.verify.v2.services(VERIFY_SID).verifications.create({
      to: phoneNumber,
      channel: 'sms'
    });
    console.log(verification.status); // Log the verification status (optional)
    res.json({ success: true, message: 'OTP sent successfully.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Failed to send OTP.' });
  }
});
app.post('/retailer/verifyOtp', async function (req, res) {
  const phoneNumber = req.body.phone_number;
  const otpCode = req.body.otp;
  try {
    const verificationCheck = await client.verify.v2.services(VERIFY_SID).verificationChecks.create({
      to: phoneNumber,
      code: otpCode
    });
    console.log(verificationCheck.status); // Log the verification check status (optional)
    if (verificationCheck.status === 'approved') {
      res.json({ success: true, message: 'OTP verified successfully.' });
    } else {
      res.json({ success: false, message: 'Invalid OTP. Please try again.' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Failed to verify OTP.' });
  }
});
app.post('/retailer/login', async (req, res) => {
  app.use('/retailer', express.static('public'));
  const { email_phone, password } = req.body;
  try {
      // Check if the retailer with the provided email/phone exists
      const result = await pool.query(
          'SELECT * FROM retailers WHERE email = $1 OR phone_number = $1',
          [email_phone]
      );
      if (result.rows.length === 0) {
          return res.render('retailerLogin', { message: 'Retailer not found. Please check your email/phone.' });
      }
      const retailer = result.rows[0];
      // Check if the password is correct
      const passwordMatch = await bcrypt.compare(password, retailer.password_hash);
      if (!passwordMatch) {
          return res.render('retailerLogin', { message: 'Invalid password. Please try again.' });
      }
      // Store retailer information in the session
      req.session.retailerId = retailer.id;
      // Redirect to the dashboard upon successful login
      res.redirect('/retailer/dashboard');
  } catch (error) {
      console.error('Error during retailer login:', error);
      res.status(500).send('Internal Server Error');
  }
});
// Retailer dashboard page
app.get('/retailer/dashboard', async (req, res) => {
  app.use('/retailer', express.static('public'));
  // Check if the retailer is logged in
  if (!req.session.retailerId) {
      return res.redirect('/retailer/login');
  }
  // Retrieve retailer details from the session or database
  const retailerId = req.session.retailerId;
  pool.query('SELECT * FROM retailers WHERE id = $1', [retailerId],async (err, result) => {
      if (err || result.rows.length === 0) {
          console.error('Error retrieving retailer details:', err);
          return res.status(500).send('Internal Server Error');
      }
      const retailer = result.rows[0];
      const itemsResult = await pool.query('SELECT * FROM items WHERE retailer_id = $1', [retailerId]);
      const items = itemsResult.rows;
      const usernumbers = await pool.query('SELECT COUNT(DISTINCT user_id) FROM orders WHERE retailer_id = $1', [retailerId]);
      const orders = usernumbers.rows[0].count;
      res.render('retailerDashboard', { retailer, items ,orders});
  });
});
app.post('/retailer/addItem', upload.single('itemImage'), async (req, res) => {
  app.use('/retailer', express.static('public'));
  if (!req.session.retailerId) {
    return res.redirect('/retailer/login');
}
app.use('/retailer', express.static('public'));
  const { itemName, itemPrice, itemUnits, itemDescription, itemStatus,itemQuantity } = req.body;
  // Handle file upload (item image)
  const itemImage = req.file;
  const retailerId = req.session.retailerId;
  try {
    const result = await pool.query(
      'INSERT INTO items (retailer_id,name, price, units, description, availability, image_path,quantity) VALUES ($1, $2, $3, $4, $5, $6,$7,$8) RETURNING *',
      [retailerId,itemName, itemPrice, itemUnits, itemDescription, itemStatus, itemImage.filename,itemQuantity]
    );
   res.render('addItem');
    // Redirect to the retailer dashboard after successful item addition
  } catch (error) {
    console.error('Error adding item:', error);
    res.status(500).send('Internal Server Error');
  }
});
// Add this route after the retailer dashboard route
app.get('/retailer/updateProfile', (req, res) => {
  app.use('/retailer', express.static('public'));
  // Check if the retailer is logged in
  if (!req.session.retailerId) {
    return res.redirect('/retailer/login');
  }
  // Retrieve retailer details from the session or database
  const retailerId = req.session.retailerId;
  pool.query('SELECT * FROM retailers WHERE id = $1', [retailerId], (err, result) => {
    if (err || result.rows.length === 0) {
      console.error('Error retrieving retailer details:', err);
      return res.status(500).send('Internal Server Error');
    }
    const retailer = result.rows[0];
    res.render('updateProfile', { retailer });
  });
});
// Add this route after the updateProfile GET route
app.post('/retailer/updateProfile', async (req, res) => {
  app.use('/retailer', express.static('public'));
  // Check if the retailer is logged in
  if (!req.session.retailerId) {
    return res.redirect('/retailer/login');
  }
  // Retrieve retailer details from the session or database
  const retailerId = req.session.retailerId;
  // Extract updated details from the form
  const { fullName, shopName, phoneNumber, email,latitude,longitude /*, other fields */ } = req.body;
  try {
    // Update retailer details in the PostgreSQL database
    const result = await pool.query(
      'UPDATE retailers SET full_name = $1, shop_name = $2, phone_number = $3, email = $4,latitude = $5,longitude=$6 WHERE id = $7 RETURNING *',
      [fullName, shopName, phoneNumber, email,latitude,longitude, retailerId]
    );
    // Redirect to the updated retailer dashboard or another page
    res.redirect('/retailer/dashboard');
  } catch (error) {
    console.error('Error updating retailer profile:', error);
    res.status(500).send('Internal Server Error');
  }
});
app.post('/retailer/update/:itemId', async (req, res) => {
  app.use('/retailer/update', express.static('public'));
  // Check if the retailer is logged in
  if (!req.session.retailerId) {
      return res.redirect('/retailer/login');
  }
  const itemId = req.params.itemId;
  try {
      // Fetch item details from the database
      const result = await pool.query('SELECT * FROM items WHERE id = $1', [itemId]);
      if (result.rows.length === 0) {
          return res.status(404).send('Item not found');
      }
     else
     {
      const item = result.rows[0];
      res.render('updateItem', { item });
     }
  } catch (error) {
      console.error('Error fetching item details for update:', error);
     
      res.status(500).send('Internal Server Error');
  }
});
// POST route to handle the item update form submission
app.post('/retailer/updateItem/:itemId', upload.single('itemImage'), async (req, res) => {
  app.use('/retailer/updateItem', express.static('public'));
  // Check if the retailer is logged in
  if (!req.session.retailerId) {
    return res.redirect('/retailer/login');
  }
  const itemId = req.params.itemId;
  // Extract updated details from the form
  const { name, price, quantity, units, description, availability } = req.body;
  // Extract the uploaded image file path or retain the existing path
  const imagePath = req.file ? req.file.filename : undefined;
  try {
    // Fetch the existing item details
    const existingItemResult = await pool.query('SELECT * FROM items WHERE id = $1', [itemId]);
    if (existingItemResult.rows.length === 0) {
      return res.status(404).send('Item not found');
    }
    const existingItem = existingItemResult.rows[0];
    // Use the existing image path if no new image is provided
    const finalImagePath = imagePath || existingItem.image_path;
    // Update item details in the PostgreSQL database
    const result = await pool.query(
      'UPDATE items SET name = $1, price = $2, quantity = $3, units = $4, description = $5, availability = $6, image_path = $7 WHERE id = $8 RETURNING *',
      [name, price, quantity, units, description, availability, finalImagePath, itemId]
    );
    if (imagePath) {
      const PathToDelete = path.join('public', 'uploads',  existingItem.image_path);
      fs.unlinkSync(PathToDelete);
    }
    // Redirect to the retailer dashboard or another page
    res.redirect('/retailer/dashboard');
  } catch (error) {
    console.error('Error updating item:', error);
    res.status(500).send('Internal Server Error');
  }
});
app.post('/retailer/deleteItem/:itemId', async (req, res) => {
  app.use('/retailer/deleteItem', express.static('public'));
  // Check if the retailer is logged in
  if (!req.session.retailerId) {
    return res.redirect('/retailer/login');
  }
  const itemId = req.params.itemId;
  const retailerId = req.session.retailerId;
  try {
    // Verify if the item belongs to the logged-in retailer
    const result = await pool.query('SELECT * FROM items WHERE id = $1 AND retailer_id = $2', [itemId, retailerId]);
    if (result.rows.length === 0) {
      // Item not found or doesn't belong to the retailer, handle accordingly
      return res.status(404).send('Item not found or you do not have permission to delete it.');
    }
    // Get the image path from the database result
    const imagePath = result.rows[0].image_path;
    // Delete the item from the database
    await pool.query('DELETE FROM items WHERE id = $1', [itemId]);
    // Delete the image file from the uploads folder
    if (imagePath) {
      const imagePathToDelete = path.join('public', 'uploads', imagePath);
      fs.unlinkSync(imagePathToDelete);
    }
    // Redirect to the retailer dashboard or another relevant page after deletion
    res.redirect('/retailer/dashboard');
  } catch (error) {
    console.error('Error deleting item:', error);
    res.status(500).send('Internal Server Error');
  }
});
// Retailer logout endpoint
app.get('/retailer/logout', (req, res) => {
  // Clear retailer information from the session
  app.use('/retailer', express.static('public'));
  req.session.destroy();
  // Redirect to the login page after logout
  res.redirect('/retailer/login');
});
app.get('/retailer/addItem', function (req, res) {
  app.use('/retailer', express.static('public'));
  if(req.session.retailerId)
  {
    res.render('addItem');
  }
  else
  {
    res.render('retailerLogin');
  }
});
// Add this route in your existing code
app.post('/retailer/toggleOnlineStatus', async (req, res) => {
  // Check if the retailer is logged in
  if (!req.session.retailerId) {
      return res.redirect('/retailer/login');
  }
  const retailerId = req.session.retailerId;
  try {
      // Retrieve the retailer from the database
      const result = await pool.query('SELECT * FROM retailers WHERE id = $1', [retailerId]);
      if (result.rows.length === 0) {
          // Retailer not found, handle accordingly
          return res.status(404).send('Retailer not found.');
      }
      const retailer = result.rows[0];
      // Toggle the online status
      const updatedStatus = !retailer.is_online;
      // Update the retailer's online status in the database
      await pool.query('UPDATE retailers SET is_online = $1 WHERE id = $2', [updatedStatus, retailerId]);
      // Redirect back to the retailer dashboard or another relevant page
      res.redirect('/retailer/dashboard');
  } catch (error) {
      console.error('Error toggling online status:', error);
      res.status(500).send('Internal Server Error');
  }
});
function haversine(lat1, lon1, lat2, lon2) {
  const R = 6371; // Radius of the Earth in kilometers
  const dLat = toRadians(lat2 - lat1);
  const dLon = toRadians(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRadians(lat1)) * Math.cos(toRadians(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  const distance = R * c;
  return Math.round(distance*1000 * 100) / 100;
}
function toRadians(degrees) {
  return degrees * (Math.PI / 180);
}
app.post('/user/search', async function (req, res) {
  app.use('/user', express.static('public'));
  if(req.isAuthenticated())
  {
  const itemName = req.body.itemName.toLowerCase(); // Convert to lowercase for case-insensitivity
  const userLatitude = parseFloat(req.body.userLatitude);
  const userLongitude = parseFloat(req.body.userLongitude);
  try {
    // Fetch items related to the search query from the database
    const result = await pool.query(
      'SELECT items.*, retailers.shop_name, retailers.full_name, retailers.phone_number, retailers.latitude, retailers.longitude ' +
      'FROM items ' +
      'JOIN retailers ON items.retailer_id = retailers.id ' +
      'WHERE LOWER(items.name) LIKE $1 AND retailers.is_online = true',
      [`%${itemName}%`]
    );
    const searchResults = result.rows.map((item) => {
      // Calculate the distance between user and shop using geolib
      const shopLatitude = parseFloat(item.latitude);
      const shopLongitude = parseFloat(item.longitude);
      const distance = haversine(userLatitude, userLongitude, shopLatitude, shopLongitude);
      return {
        ...item,
        distance: distance,
      };
    });
      // Render the search results page with the relevant data
      res.render('searchResults', { searchResults, itemName });
  } catch (error) {
      console.error('Error fetching search results:', error);
      res.status(500).send('Internal Server Error');
  }
} else{
  res.render('userLogin');
}});
app.get('/user/search', async function (req, res) {
  app.use('/user', express.static('public'));
  if (req.isAuthenticated()) {
  res.render('search');
  }
  else{
    res.render('userLogin');
  }
});
app.get('/user/viewProfile', async (req, res) => {
  app.use('/user', express.static('public'));
  const retailerId = req.query.retailerId;
  if (req.isAuthenticated()) {
  try {
    const id = req.user.id;
    // Fetch retailer details and items from the database
    const retailerResult = await pool.query('SELECT * FROM retailers WHERE id = $1', [retailerId]);
    const itemsResult = await pool.query('SELECT * FROM items WHERE retailer_id = $1', [retailerId]);
    if (retailerResult.rows.length === 0) {
      return res.status(404).send('Retailer not found.');
    }
    const retailer = retailerResult.rows[0];
    const items = itemsResult.rows;
    // Render the retailer profile page with the relevant data
    res.render('viewProfile', { retailer, items,id }); // Pass both retailer and items
  } catch (error) {
    console.error('Error fetching retailer details for view profile:', error);
    res.status(500).send('Internal Server Error');
  }
}
  else{
    res.render('userLogin');
  }
});
io.on('connection', (socket) => {
  console.log("user connected");
  socket.on('disconnect', () => {
    console.log("user disconnected");
  });
  socket.on('join', (room) => {
    socket.join(room);
  });
  socket.on('sendMessageToUser', ({ userId, message }) => {
    // Broadcast the message to the specific user room
    io.to(`user_${userId}`).emit('newMessage', { message });
  });
app.post('/user/pack', async function (req, res) {
  app.use('/user', express.static('public'));
  if (req.isAuthenticated()) {
    const id = req.user.id;
    const retailerId=req.body.retailerId;
    const phonenumber= req.body.orderDetails.phoneNumber;
    const items=req.body.orderDetails.items;
    for (const key in items) {
 
     let y =items[key];
     let x = +key;
   await pool.query(
        ' INSERT INTO orders(phone_number, retailer_id, user_id, item_id, quantity)VALUES($1, $2, $3, $4, $5)',
        [phonenumber, retailerId, id, x, y]
      );

    }
    const retailerRoom = `retailer_${retailerId}`;
    io.to(retailerRoom).emit('newOrder');
    res.status(200).send('Order received successfully');
} else {
  res.redirect('/user/login');
}
});
});
app.get('/retailer/orders', async (req, res) => {
  app.use('/retailer', express.static('public'));
  // Check if the retailer is logged in
  if (!req.session.retailerId) {
    return res.redirect('/retailer/login');
  }
  // Retrieve retailer details from the session or database
  const retailerId = req.session.retailerId;
  try {
    // Fetch orders related to the retailer from the database
    const result = await pool.query(
      'SELECT * FROM orders ' +
      'JOIN items ON orders.item_id = items.id ' +
      'JOIN users ON orders.user_id = users.id ' +
      'WHERE items.retailer_id = $1 ' +
      'ORDER BY orders.user_id', [retailerId]
    );

    const orders = result.rows;

    // Group orders by user ID
    const groupedOrders = {};
    orders.forEach(order => {
      const userId = order.user_id;

      if (!groupedOrders[userId]) {
        groupedOrders[userId] = [];
      }

      groupedOrders[userId].push(order);
    });

    // Render the orders page with the grouped orders
    res.render('retailerOrders', { groupedOrders });
  } catch (error) {
    console.error('Error fetching retailer orders:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/retailer/deleteOrder/:userId', async (req, res) => {
  app.use('/retailer/deleteOrder', express.static('public'));
  // Check if the retailer is logged in
  if (!req.session.retailerId) {
    return res.redirect('/retailer/login');
  }

  const userId = req.params.userId;
  const retailerId = req.session.retailerId;

  try {
  
    await pool.query('DELETE FROM orders WHERE user_id = $1 and retailer_id = $2', [userId,retailerId]);

    // Redirect to the retailer dashboard or another relevant page after deletion
    res.redirect('/retailer/orders');
  } catch (error) {
    console.error('Error deleting item:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/user/logout', function (req, res) {
  app.use('/user', express.static('public'));
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




app.post('/user/register', async function (req, res) {
  app.use('/user', express.static('public'));
  const email = req.body.username.toLowerCase(); // Convert email to lowercase for case-insensitivity
  const password = req.body.password;

  try {
    // Check if the user with the provided email already exists
    const existingUser = await User.findByEmail(email);

    if (existingUser) {
      // User already exists, handle it (e.g., show a message or redirect to registration page)
      res.render('userRegister', { message : "User already exists"});
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
          res.redirect('/user/search');
        }
      });
    } else {
      res.redirect('/user/register');
    }
}
  } catch (error) {
    console.log(error);
    res.status(500).send('Internal Server Error');
  }
});




// Add this route after the app.post('/register', ...) route
app.post('/user/login', async function (req, res) {
  app.use('/user', express.static('public'));
  const email = req.body.username.toLowerCase(); // Assuming your login form has an input with the name 'email'
  const password = req.body.password;

  try {
    const user = await User.findByEmail(email);

    if (!user) {
      // User with the provided email doesn't exist
  
     res.render('userLogin', { message : "User doesn't exist" });
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
        return res.redirect('/user/search');
      });
    } else {
      // Incorrect password
      res.render('userLogin', { message : "Incorrect password" });
    }
    }
  } catch (error) {
    console.log(error);
    res.status(500).send('Login with google');
  }
});

app.get("/api", (req, res) => {
  res.json({ message: "Hello from server!" });
});


server.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
