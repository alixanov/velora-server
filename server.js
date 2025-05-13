const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();

// Environment variables with defaults
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'JWT_SECRET_VELORA';
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://alixonovshukurullo13:7IHnFvbrj1UeOy81@cluster0.ym3m8ms.mongodb.net/atelie?retryWrites=true&w=majority';

// CORS configuration
const allowedOrigins = [
  'https://velora-client-wheat.vercel.app',
  'http://localhost:3000'
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());

// MongoDB connection
mongoose
  .connect(MONGO_URI, {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000
  })
  .then(() => console.log('MongoDB connected successfully'))
  .catch((err) => console.error('MongoDB connection error:', err));

// User schema and model
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Review schema and model
const reviewSchema = new mongoose.Schema({
  author: { type: String, required: true, trim: true },
  text: { type: String, required: true, trim: true },
  createdAt: { type: Date, default: Date.now },
});

const Review = mongoose.model('Review', reviewSchema);

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, error: 'Все поля обязательны для заполнения' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, error: 'Пароль должен содержать минимум 6 символов' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, error: 'Неверный формат email' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'Пользователь с таким email уже существует' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign(
      { userId: user._id, name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (err) {
    console.error('Register Error:', err);
    res.status(500).json({
      success: false,
      error: 'Произошла ошибка при регистрации',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email и пароль обязательны' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, error: 'Неверные учетные данные' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, error: 'Неверные учетные данные' });
    }

    const token = jwt.sign(
      { userId: user._id, name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).json({
      success: false,
      error: 'Произошла ошибка при авторизации',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Protected route
app.get('/api/protected', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ success: false, error: 'Требуется авторизация' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(decoded.userId).select('-password -__v -createdAt -updatedAt');
    if (!user) {
      return res.status(401).json({ success: false, error: 'Пользователь не найден' });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (err) {
    console.error('Protected Route Error:', err);
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, error: 'Срок действия токена истек' });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ success: false, error: 'Неверный токен' });
    }
    res.status(500).json({
      success: false,
      error: 'Произошла ошибка при проверке токена',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Get all reviews
app.get('/api/reviews', async (req, res) => {
  try {
    const reviews = await Review.find()
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    res.json({
      success: true,
      count: reviews.length,
      reviews
    });
  } catch (err) {
    console.error('Get Reviews Error:', err);
    res.status(500).json({
      success: false,
      error: 'Не удалось загрузить отзывы',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Submit a new review
app.post('/api/reviews', async (req, res) => {
  try {
    const { author, text } = req.body;

    if (!author || !text) {
      return res.status(400).json({ success: false, error: 'Все поля обязательны' });
    }
    if (author.length < 2) {
      return res.status(400).json({ success: false, error: 'Имя должно содержать минимум 2 символа' });
    }
    if (text.length < 10) {
      return res.status(400).json({ success: false, error: 'Текст отзыва должен содержать минимум 10 символов' });
    }

    const review = new Review({ author, text });
    await review.save();

    res.status(201).json({
      success: true,
      review
    });
  } catch (err) {
    console.error('Submit Review Error:', err);
    res.status(500).json({
      success: false,
      error: 'Не удалось сохранить отзыв',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ success: false, error: 'Маршрут не найден' });
});

// Error Handler
app.use((err, req, res, next) => {
  console.error('Server Error:', err);
  res.status(500).json({
    success: false,
    error: 'Внутренняя ошибка сервера',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});