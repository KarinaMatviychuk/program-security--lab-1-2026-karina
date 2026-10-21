/**
 * BookTrace - Secure Reading Tracker API & Server
 * Лабораторна робота №3 з дисципліни "Безпека програм і даних"
 * Виконила: Матвійчук Каріна (ПЗ-23-1)
 */

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const crypto = require('crypto'); // Вбудований модуль Node.js для генерації UUID
const path = require('path');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Віддаємо статичний візуальний інтерфейс
app.use(express.static(path.join(__dirname, 'public')));

// Налаштування безпечної сесії
app.use(session({
    secret: 'super-secret-booktrace-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, // захист від XSS
        maxAge: 3600000 // 1 година
    }
}));

// "База даних" у пам'яті
const db = {
    users: [],
    books: [],
    loginAttempts: {}
};

// Мідлвар перевірки автентифікації
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Помилка доступу: спочатку увійдіть у систему' });
    }
    next();
}

// ================= API ЕНДПОІНТИ =================

// 1. Реєстрація
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, role } = req.body;

        if (!email || !password || password.length < 8) {
            return res.status(400).json({ error: 'Пароль повинен містити мінімум 8 символів' });
        }

        const existingUser = db.users.find(u => u.email === email);
        if (existingUser) {
            return res.status(400).json({ error: 'Користувач із таким email вже існує' });
        }

        // Хешування пароля через bcrypt (12 раундів)
        const hashedPassword = await bcrypt.hash(password, 12);
        
        // Генерація TOTP секрету для 2FA (МФА)
        const mfaSecret = speakeasy.generateSecret({ length: 20 });

        const newUser = {
            id: crypto.randomUUID(), // Використовуємо вбудовану безпечну генерацію UUID
            email: email,
            passwordHash: hashedPassword,
            role: role === 'ADMIN' ? 'ADMIN' : 'READER',
            mfaEnabled: false,
            mfaSecret: mfaSecret.base32
        };

        db.users.push(newUser);

        res.status(201).json({
            message: 'Користувача успішно зареєстровано!',
            mfaSecret: mfaSecret.base32
        });
    } catch (err) {
        res.status(500).json({ error: 'Помилка сервера' });
    }
});

// 2. Вхід
app.post('/api/auth/login', async (req, res) => {
    const { email, password, mfaToken } = req.body;

    const attempts = db.loginAttempts[email] || 0;
    if (attempts >= 5) {
        return res.status(429).json({ error: 'Акаунт тимчасово заблоковано через 5 помилкових спроб входу' });
    }

    const user = db.users.find(u => u.email === email);
    if (!user) {
        db.loginAttempts[email] = attempts + 1;
        return res.status(400).json({ error: 'Невірні автентифікаційні дані' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
        db.loginAttempts[email] = attempts + 1;
        return res.status(400).json({ error: 'Невірні автентифікаційні дані' });
    }

    if (user.mfaEnabled) {
        if (!mfaToken) {
            return res.status(403).json({ error: 'Потрібно ввести 6-значний МФА TOTP-код' });
        }
        const isValidTotp = speakeasy.totp.verify({
            secret: user.mfaSecret,
            encoding: 'base32',
            token: mfaToken
        });
        if (!isValidTotp) {
            return res.status(400).json({ error: 'Невірний МФА код' });
        }
    }

    db.loginAttempts[email] = 0;

    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.role = user.role;

    res.json({
        message: 'Успішний вхід!',
        user: { id: user.id, email: user.email, role: user.role }
    });
});

// 3. Вихід
app.post('/api/auth/logout', requireAuth, (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.json({ message: 'Сеанс завершено' });
    });
});

// 4. Отримання списку книг користувача
app.get('/api/books', requireAuth, (req, res) => {
    const userBooks = db.books.filter(b => b.userId === req.session.userId);
    res.json({ books: userBooks, user: { email: req.session.email, role: req.session.role } });
});

// 5. Додавання книги
app.post('/api/books', requireAuth, (req, res) => {
    const { title, author, totalPages } = req.body;

    const newBook = {
        id: crypto.randomUUID(),
        userId: req.session.userId,
        title,
        author,
        totalPages: parseInt(totalPages),
        readPages: 0,
        notes: []
    };

    db.books.push(newBook);
    res.status(201).json({ message: 'Книгу додано!', book: newBook });
});

// 6. Оновлення прогресу
app.put('/api/books/:id/progress', requireAuth, (req, res) => {
    const book = db.books.find(b => b.id === req.params.id);
    if (!book) return res.status(404).json({ error: 'Книгу не знайдено' });

    if (book.userId !== req.session.userId) {
        return res.status(403).json({ error: 'Це не ваша книга' });
    }

    const { readPages, note } = req.body;
    if (readPages !== undefined) book.readPages = parseInt(readPages);
    if (note) book.notes.push({ text: note, date: new Date().toLocaleString() });

    res.json({ message: 'Прогрес оновлено', book });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`================================================`);
    console.log(`🚀 Сервер BookTrace успішно запущено!`);
    console.log(`👉 Відкрийте в браузері: http://localhost:${PORT}`);
    console.log(`================================================`);
});