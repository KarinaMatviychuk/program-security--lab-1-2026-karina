/**
 * BookTrace - Secure Reading Tracker API & Server
 * Лабораторні роботи №3, №4 та №5 з дисципліни "Безпека програм і даних"
 * Виконала: Матвійчук Каріна (ПЗ-23-1), Варіант 8
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

app.use(session({
    secret: 'super-secret-booktrace-key-2026',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 3600000 }
}));

// ======================================================
// ЛАБ 4: КРИПТОГРАФІЧНИЙ МОДУЛЬ (AES-256-GCM AEAD)
// ======================================================
const DB_ENCRYPTION_KEY = crypto.randomBytes(32);

function encryptNote(plainText) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', DB_ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(plainText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');
    return { ciphertext: encrypted, iv: iv.toString('hex'), authTag };
}

function decryptNote(encryptedObj) {
    try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', DB_ENCRYPTION_KEY, Buffer.from(encryptedObj.iv, 'hex'));
        decipher.setAuthTag(Buffer.from(encryptedObj.authTag, 'hex'));
        let decrypted = decipher.update(encryptedObj.ciphertext, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (err) {
        return "[ПОМИЛКА ЦІЛІСНОСТІ: Дані нотатки підроблені!]";
    }
}

// ======================================================
// ЛАБ 5: ЦИФРОВИЙ ПІДПИС ED25519 (ЛІЦЕНЗУВАННЯ) ТА HMAC
// ======================================================
// Генерація пари асиметричних ключів Ed25519 розробника
const { publicKey: LICENSE_PUBLIC_KEY, privateKey: LICENSE_PRIVATE_KEY } = crypto.generateKeyPairSync('ed25519');
const INTEGRITY_HMAC_SECRET = crypto.randomBytes(32);

// Генерація підписаної PRO-ліцензії (виконується на стороні сервера ліцензування)
function issueProLicense(email) {
    const payload = JSON.stringify({
        product: "BookTrace-PRO",
        email: email,
        plan: "PRO",
        maxBooks: 9999,
        issuedAt: new Date().toISOString()
    });
    const payloadBase64 = Buffer.from(payload, 'utf8').toString('base64');
    const signature = crypto.sign(null, Buffer.from(payloadBase64, 'utf8'), LICENSE_PRIVATE_KEY).toString('hex');
    return `${payloadBase64}.${signature}`;
}

// Перевірка ліцензії відкритим ключем Ed25519 (не дозволяє підробити ліцензію)
function verifyProLicense(licenseKey, expectedEmail) {
    try {
        const parts = licenseKey.split('.');
        if (parts.length !== 2) return { valid: false, reason: 'Невірний формат ліцензійного ключа' };

        const [payloadBase64, signatureHex] = parts;
        const isSignatureValid = crypto.verify(
            null,
            Buffer.from(payloadBase64, 'utf8'),
            LICENSE_PUBLIC_KEY,
            Buffer.from(signatureHex, 'hex')
        );

        if (!isSignatureValid) {
            return { valid: false, reason: 'Порушено цілісність! Цифровий підпис Ed25519 недійсний.' };
        }

        const data = JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf8'));
        if (data.email !== expectedEmail) {
            return { valid: false, reason: 'Ліцензія видана на інший обліковий запис!' };
        }

        return { valid: true, data };
    } catch (e) {
        return { valid: false, reason: 'Помилка перевірки підпису ліцензії' };
    }
}

// Обчислення HMAC-SHA256 для контролю цілісності прогресу читання
function computeProgressHmac(book) {
    const raw = `${book.id}|${book.userId}|${book.totalPages}|${book.readPages}`;
    return crypto.createHmac('sha256', INTEGRITY_HMAC_SECRET).update(raw).digest('hex');
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

app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, role } = req.body;
        if (!email || !password || password.length < 8) {
            return res.status(400).json({ error: 'Пароль повинен містити мінімум 8 символів' });
        }

        if (db.users.find(u => u.email === email)) {
            return res.status(400).json({ error: 'Користувач з таким email вже існує' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const mfaSecret = speakeasy.generateSecret({ length: 20 });

        const newUser = {
            id: crypto.randomUUID(),
            email,
            passwordHash: hashedPassword,
            role: role === 'ADMIN' ? 'ADMIN' : 'READER',
            plan: 'FREE', // За замовчуванням Freemium тариф (до 2 книг)
            mfaEnabled: false,
            mfaSecret: mfaSecret.base32
        };

        db.users.push(newUser);
        res.status(201).json({ message: 'Користувача зареєстровано (тариф FREE)!', mfaSecret: mfaSecret.base32 });
    } catch (err) {
        res.status(500).json({ error: 'Помилка сервера' });
    }
});

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

    res.json({
        message: 'Успішний вхід!',
        user: { id: user.id, email: user.email, role: user.role, plan: user.plan }
    });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.json({ message: 'Сеанс завершено' });
    });
});

// Випуск демонстраційної підписаної ліцензії Ed25519 для поточного користувача
app.post('/api/license/issue-demo', requireAuth, (req, res) => {
    const licenseKey = issueProLicense(req.session.email);
    console.log("🔑 [Ed25519] Згенеровано підписану ліцензію PRO:", licenseKey);
    res.json({ licenseKey });
});

// Активація ліцензії PRO з перевіркою цифрового підпису Ed25519
app.post('/api/license/activate', requireAuth, (req, res) => {
    const { licenseKey } = req.body;
    const check = verifyProLicense(licenseKey, req.session.email);

    if (!check.valid) {
        console.warn("⛔ [Ed25519] Відхилено невалідну ліцензію:", check.reason);
        return res.status(403).json({ error: check.reason });
    }

    const user = db.users.find(u => u.id === req.session.userId);
    user.plan = 'PRO';
    console.log("✅ [Ed25519] Активовано підписку PRO для:", user.email);
    res.json({ message: 'Ліцензію PRO підтверджено підписом Ed25519 та активовано!', plan: 'PRO' });
});

// Отримання списку книг з перевіркою цілісності HMAC
app.get('/api/books', requireAuth, (req, res) => {
    const user = db.users.find(u => u.id === req.session.userId);
    const userBooks = db.books
        .filter(b => b.userId === req.session.userId)
        .map(b => {
            const expectedHmac = computeProgressHmac(b);
            const integrityOk = (b.hmac === expectedHmac);
            return {
                ...b,
                integrityOk,
                notes: b.notes.map(n => ({
                    text: decryptNote(n.encryptedData),
                    date: n.date
                }))
            };
        });

    res.json({
        books: userBooks,
        user: { email: user.email, role: user.role, plan: user.plan }
    });
});

// Додавання книги (з контролем Freemium-обмеження)
app.post('/api/books', requireAuth, (req, res) => {
    const user = db.users.find(u => u.id === req.session.userId);
    const userBooksCount = db.books.filter(b => b.userId === req.session.userId).length;

    // Перевірка ліцензійного обмеження Freemium (макс. 2 книги на FREE)
    if (user.plan === 'FREE' && userBooksCount >= 2) {
        return res.status(403).json({
            error: 'Ліміт тарифу FREE (макс. 2 книги)! Активуйте PRO-ліцензію з підписом Ed25519.'
        });
    }

    const { title, author, totalPages } = req.body;
    const pages = parseInt(totalPages);
    if (!title || !author || isNaN(pages) || pages <= 0) {
        return res.status(400).json({ error: 'Некоректні дані книги або кількість сторінок' });
    }

    const newBook = {
        id: crypto.randomUUID(),
        userId: req.session.userId,
        title,
        author,
        totalPages: pages,
        readPages: 0,
        notes: []
    };
    newBook.hmac = computeProgressHmac(newBook);

    db.books.push(newBook);
    res.status(201).json({ message: 'Книгу додано!', book: newBook });
});

// Оновлення прогресу з контролем інваріантів цілісності та перерахунком HMAC
app.put('/api/books/:id/progress', requireAuth, (req, res) => {
    const book = db.books.find(b => b.id === req.params.id);
    if (!book) return res.status(404).json({ error: 'Книгу не знайдено' });
    if (book.userId !== req.session.userId) return res.status(403).json({ error: 'Це не ваша книга' });

    const { readPages, note } = req.body;
    if (readPages !== undefined && readPages !== '') {
        const parsedPages = parseInt(readPages);
        if (isNaN(parsedPages) || parsedPages < 0 || parsedPages > book.totalPages) {
            return res.status(400).json({
                error: `Порушення цілісності даних: кількість прочитаних сторінок має бути від 0 до ${book.totalPages}`
            });
        }
        book.readPages = parsedPages;
        book.hmac = computeProgressHmac(book); // Оновлення HMAC після валідної зміни
    }

    if (note && note.trim() !== "") {
        const encryptedResult = encryptNote(note);
        book.notes.push({
            encryptedData: encryptedResult,
            date: new Date().toLocaleString()
        });
    }

    res.json({ message: 'Прогрес та цілісність оновлено!', book });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`================================================`);
    console.log(`🚀 Сервер BookTrace (Lab 5: Ed25519 + HMAC + GCM) запущено!`);
    console.log(`👉 Відкрийте в браузері: http://localhost:${PORT}`);
    console.log(`================================================`);
});