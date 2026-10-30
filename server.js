import express from 'express';
import session from 'express-session';
import mongoose from 'mongoose';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as GitHubStrategy } from 'passport-github2';
import bcrypt from 'bcryptjs';
import { createClient } from '@supabase/supabase-js';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// CONFIG & KONEKSI DATABASE
// ==========================================
const MONGO_URI = process.env.MONGO_URI;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;

// Init Supabase
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Init MongoDB
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB Terhubung...'))
  .catch(err => console.error('MongoDB Error:', err));

// Schema MongoDB untuk User
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, unique: true, sparse: true },
  password: { type: String }, // Kosong jika OAuth
  avatar: { type: String, default: 'https://cdn.arulz.biz.id/files/X1F0Cn.png' },
  bio: { type: String, default: 'Developer Enthusiast' },
  googleId: { type: String },
  githubId: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'secret_key_pastecode_arulz',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.useSession());

// Static Files
app.use(express.static(__dirname));

// ==========================================
// PASSPORT CONFIGURATION
// ==========================================
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Local Strategy
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ username });
    if (!user) return done(null, false, { message: 'Username tidak ditemukan' });
    
    if (!user.password) return done(null, false, { message: 'Silakan login dengan Google/GitHub' });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return done(null, false, { message: 'Password salah' });
    
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// Google Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
      user = await User.create({
        username: profile.displayName.replace(/\s+/g, '').toLowerCase() + Math.floor(1000 + Math.random() * 9000),
        email: profile.emails[0]?.value,
        avatar: profile.photos[0]?.value,
        googleId: profile.id
      });
    }
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

// GitHub Strategy
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: '/auth/github/callback'
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ githubId: profile.id });
    if (!user) {
      user = await User.create({
        username: profile.username || 'github_user_' + Math.floor(1000 + Math.random() * 9000),
        email: profile.emails?.[0]?.value,
        avatar: profile.photos?.[0]?.value,
        githubId: profile.id
      });
    }
    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

// Helper Auth Check Middleware
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ status: false, message: 'Silakan login terlebih dahulu' });
}

// ==========================================
// ROUTES AUTHENTICATION
// ==========================================
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.json({ status: false, message: 'Username & Password wajib diisi' });

    const existingUser = await User.findOne({ username });
    if (existingUser) return res.json({ status: false, message: 'Username sudah digunakan' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ username, password: hashedPassword });

    req.login(newUser, (err) => {
      if (err) return res.json({ status: false, message: 'Gagal auto login' });
      return res.json({ status: true, message: 'Registrasi berhasil' });
    });
  } catch (err) {
    res.json({ status: false, message: err.message });
  }
});

app.post('/api/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return res.json({ status: false, message: err.message });
    if (!user) return res.json({ status: false, message: info.message || 'Login gagal' });
    
    req.login(user, (err) => {
      if (err) return res.json({ status: false, message: 'Error logging in' });
      return res.json({ status: true, message: 'Login berhasil' });
    });
  })(req, res, next);
});

// OAuth Google & GitHub Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login.html' }), (req, res) => {
  res.redirect('/home.html');
});

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
app.get('/auth/github/callback', passport.authenticate('github', { failureRedirect: '/login.html' }), (req, res) => {
  res.redirect('/home.html');
});

app.get('/api/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/login.html');
  });
});

app.get('/api/user-status', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ loggedIn: true, user: req.user });
  } else {
    res.json({ loggedIn: false });
  }
});

// Update Profile
app.post('/api/profile/update', isAuthenticated, async (req, res) => {
  try {
    const { bio, avatar } = req.body;
    await User.findByIdAndUpdate(req.user.id, { bio, avatar });
    res.json({ status: true, message: 'Profil berhasil diperbarui' });
  } catch (err) {
    res.json({ status: false, message: err.message });
  }
});

// ==========================================
// ROUTES SUPABASE SNIPPETS API
// ==========================================

// GET ALL SNIPPETS
app.get('/api/pastecode', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('snippets')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json({ status: true, data });
  } catch (err) {
    res.status(500).json({ status: false, message: err.message });
  }
});

// CREATE NEW SNIPPET
app.post('/api/pastecode/create', isAuthenticated, async (req, res) => {
  try {
    const { title, desc, content, language, readme } = req.body;
    
    if (!title || !content) {
      return res.json({ status: false, message: 'Judul dan Konten Kode wajib diisi!' });
    }

    const snippetId = Math.random().toString(36).substring(2, 10);
    const newSnippet = {
      id: snippetId,
      title,
      desc: desc || '',
      content,
      language: language || 'javascript',
      readme: readme || '',
      username: req.user.username,
      avatar: req.user.avatar,
      date: new Date().toLocaleDateString('id-ID')
    };

    const { data, error } = await supabase.from('snippets').insert([newSnippet]);
    if (error) throw error;

    res.json({ status: true, message: 'Snippet berhasil dibuat!', snippetId });
  } catch (err) {
    res.json({ status: false, message: err.message });
  }
});

// PAGE ROUTING SLUGS
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'home.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/snippet', (req, res) => res.sendFile(path.join(__dirname, 'snippet.html')));
app.get('/profile', (req, res) => res.sendFile(path.join(__dirname, 'profile.html')));

app.listen(PORT, () => console.log(`Server berjalan di http://localhost:${PORT}`));
