/**
 * BookTrace - Secure Reading Tracker API & Server
 * Лабораторна робота №3 та №4 з дисципліни "Безпека програм і даних"
 * Виконила: Матвійчук Каріна (ПЗ-23-1)
 */

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const crypto = require('crypto');
const path = require('path');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Безпечна сесія
app.use(session({
    secret: 'super-secret-booktrace-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 3600000 }
}));

// ======================================================
// КРИПТОГРАФІЧНИЙ МОДУЛЬ (AES-256-GCM AEAD - ЛАБОРАТОРНА №4)
// ======================================================
// Генерація криптографічно стійкого майстер-ключа для шифрування нотаток (256 біт)
const DB_ENCRYPTION_KEY = crypto.randomBytes(32); 

/**
 * Зашифрувати текст нотатки за допомогою AES-256-GCM
 */
function encryptNote(plainText) {
    const iv = crypto.randomBytes(12); // Унікальний IV 96 біт для GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', DB_ENCRYPTION_KEY, iv);
    
    let encrypted = cipher.update(plainText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag().toString('hex'); // Мітка цілісності (16 байтів)

    return {
        ciphertext: encrypted,
        iv: iv.toString('hex'),
        authTag: authTag
    };
}

/**
 * Розшифрувати нотатку з перевіркою цілісності (Auth Tag)
 */
function decryptNote(encryptedObj) {
    try {
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm', 
            DB_ENCRYPTION_KEY, 
            Buffer.from(encryptedObj.iv, 'hex')
        );
        
        decipher.setAuthTag(Buffer.from(encryptedObj.authTag, 'hex'));
        
        let decrypted = decipher.update(encryptedObj.ciphertext, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (err) {
        console.error("❌ Помилка перевірки цілісності AES-GCM! Дані підроблено або пошкоджено.");
        return "[ПОМИЛКА ЦІЛІСНОСТІ: Дані нотатки підроблені!]";
    }
}

// "База даних" у пам'яті
const db = {
    users: [],
    books: [],
    loginAttempts: {}
};

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Помилка доступу: увійдіть у систему' });
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
            return res.status(400).json({ error: 'Користувач з таким email вже існує' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const mfaSecret = speakeasy.generateSecret({ length: 20 });

        const newUser = {
            id: crypto.randomUUID(),
            email,
            passwordHash: hashedPassword,
            role: role === 'ADMIN' ? 'ADMIN' : 'READER',
            mfaEnabled: false,
            mfaSecret: mfaSecret.base32
        };

        db.users.push(newUser);
        res.status(201).json({ message: 'Користувача зареєстровано!', mfaSecret: mfaSecret.base32 });
    } catch (err) {
        res.status(500).json({ error: 'Помилка сервера' });
    }
});

// 2. Вхід
app.post('/api/auth/login', async (req, res) => {
    const { email, password, mfaToken } = req.body;
    const attempts = db.loginAttempts[email] || 0;
    
    if (attempts >= 5) {
        return res.status(429).json({ error: 'Заблоковано через 5 помилкових спроб' });
    }

    const user = db.users.find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        db.loginAttempts[email] = attempts + 1;
        return res.status(400).json({ error: 'Невірні автентифікаційні дані' });
    }

    if (user.mfaEnabled) {
        if (!mfaToken || !speakeasy.totp.verify({ secret: user.mfaSecret, encoding: 'base32', token: mfaToken })) {
            return res.status(400).json({ error: 'Невірний МФА код' });
        }
    }

    db.loginAttempts[email] = 0;
    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.role = user.role;

    res.json({ message: 'Успішний вхід!', user: { id: user.id, email: user.email, role: user.role } });
});

// 3. Вихід
app.post('/api/auth/logout', requireAuth, (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.json({ message: 'Сеанс завершено' });
    });
});

// 4. Отримання списку книг (із розшифруванням захищених нотаток AES-256-GCM)
app.get('/api/books', requireAuth, (req, res) => {
    const userBooks = db.books
        .filter(b => b.userId === req.session.userId)
        .map(b => ({
            ...b,
            // Розшифровуємо зашифровані нотатки перед відправкою клієнту
            notes: b.notes.map(n => ({
                text: decryptNote(n.encryptedData),
                date: n.date
            }))
        }));

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

// 6. Оновлення прогресу та ШИФРУВАННЯ НОТАТКИ (AES-256-GCM)
app.put('/api/books/:id/progress', requireAuth, (req, res) => {
    const book = db.books.find(b => b.id === req.params.id);
    if (!book) return res.status(404).json({ error: 'Книгу не знайдено' });
    if (book.userId !== req.session.userId) return res.status(403).json({ error: 'Це не ваша книга' });

    const { readPages, note } = req.body;
    if (readPages !== undefined) book.readPages = parseInt(readPages);
    
    if (note && note.trim() !== "") {
        // Зашифровуємо нотатку перед збереженням у базу
        const encryptedResult = encryptNote(note);
        book.notes.push({
            encryptedData: encryptedResult,
            date: new Date().toLocaleString()
        });
        console.log("🔒 [AES-256-GCM] Нотатку зашифровано:", encryptedResult);
    }

    res.json({ message: 'Прогрес та зашифровану нотатку збережено!', book });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`================================================`);
    console.log(`🚀 Сервер BookTrace (з AES-256-GCM) запущено!`);
    console.log(`👉 Відкрийте в браузері: http://localhost:3000`);
    console.log(`================================================`);
});