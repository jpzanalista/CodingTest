const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
require('dotenv').config();

const User = require('./models/User');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;
const CLIENT_URL = process.env.CLIENT_URL;
const MONGODB_URI = process.env.MONGODB_URI;

// Conecte-se ao MongoDB
mongoose.connect(MONGODB_URI)
    .then(() => console.log('Conectado ao MongoDB'))
    .catch(err => console.error('Erro de conexão com o MongoDB:', err));

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: CLIENT_URL, credentials: true }));

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
    const token = req.cookies.auth_token;
    if (!token) {
        return res.status(401).json({ message: 'Acesso não autorizado: token não fornecido' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(403).json({ message: 'Acesso proibido: token inválido' });
    }
};

// Rota de Registro
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'Usuário já existe.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'Usuário registrado com sucesso.' });
    } catch (err) {
        res.status(500).json({ message: 'Erro ao registrar usuário.', error: err.message });
    }
});

// Rota de Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Usuário ou senha inválidos.' });
        }

        const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });

        res.cookie('auth_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
        });

        res.status(200).json({ message: 'Login bem-sucedido.' });
    } catch (err) {
        res.status(500).json({ message: 'Erro ao fazer login.', error: err.message });
    }
});

// Rota de Logout
app.post('/logout', (req, res) => {
    res.clearCookie('auth_token');
    res.status(200).json({ message: 'Logout bem-sucedido.' });
});

// Rota Protegida (para verificar a sessão)
app.get('/profile', authenticateToken, (req, res) => {
    res.json({ message: `Bem-vindo, ${req.user.username}!`, username: req.user.username });
});

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});