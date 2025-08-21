require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const app = express();

// Middlewares
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json());
app.use(cookieParser());

// CORS: allow your frontend and Postman
app.use(cors({
    origin: true, // reflect request origin
    credentials: true
}));

// Routes
app.use('/api/auth', require('./routes/auth'));

// Health check
app.get('/', (_req, res) => res.json({ ok: true }));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on http://localhost:${port}`));