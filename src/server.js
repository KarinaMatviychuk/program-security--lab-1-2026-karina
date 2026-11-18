/**
 * BookTrace - Secure Reading Tracker API & Server
 * Лабораторні роботи №3, №4, №5 та №6 з дисципліни "Безпека програм і даних"
 * Виконала: Матвійчук Каріна (ІПЗ-23-1), Варіант 8
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const crypto = require('crypto');
const path = require('path');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

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
const { publicKey: LICENSE_PUBLIC_KEY, privateKey: LICENSE_PRIVATE_KEY } = crypto.generateKeyPairSync('ed25519');
const INTEGRITY_HMAC_SECRET = crypto.randomBytes(32);

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

function computeProgressHmac(book) {
    const raw = `${book.id}|${book.userId}|${book.totalPages}|${book.readPages}`;
    return crypto.createHmac('sha256', INTEGRITY_HMAC_SECRET).update(raw).digest('hex');
}

// ======================================================
// ЛАБ 6: КЛІЄНТ-СЕРВЕРНА МОДЕЛЬ ДОВІРИ ТА BEARER-ТОКЕНИ
// ======================================================
const TOKEN_SIGNING_SECRET = crypto.randomBytes(32);
const TOKEN_TTL_SECONDS = 1800; // 30 хвилин

// Генерація підписаного токена доступу (HMAC-SHA256)
function generateAccessToken(user) {
    const now = Math.floor(Date.now() / 1000);
    const payloadObj = {
        sub: user.id,
        email: user.email,
        role: user.role,
        iat: now,
        exp: now + TOKEN_TTL_SECONDS
    };
    const encodedPayload = Buffer.from(JSON.stringify(payloadObj), 'utf8').toString('base64url');
    const signature = crypto
        .createHmac('sha256', TOKEN_SIGNING_SECRET)
        .update(encodedPayload)
        .digest('base64url');
    return `${encodedPayload}.${signature}`;
}

// Верифікація Bearer-токена на стороні сервера
function verifyAccessToken(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 2) return null;

        const [encodedPayload, signature] = parts;
        const expectedSig = crypto
            .createHmac('sha256', TOKEN_SIGNING_SECRET)
            .update(encodedPayload)
            .digest('base64url');

        if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) {
            return null;
        }

        const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp <= now) {
            return null; // Строк дії токена вичерпано
        }
        return payload;
    } catch (err) {
        return null;
    }
}

// Middleware перевірки заголовка Authorization: Bearer <token>
function authenticateBearer(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Відсутній заголовок Authorization: Bearer <token>' });
    }

    const token = authHeader.slice(7).trim();
    const payload = verifyAccessToken(token);
    if (!payload) {
        return res.status(401).json({ error: 'Недійсний або прострочений токен доступу' });
    }

    // Встановлюємо довірений контекст користувача на сервері
    req.auth = {
        userId: payload.sub,
        email: payload.email,
        role: payload.role,
        exp: payload.exp
    };
    next();
}

// "База даних" у пам'яті
const db = {
    users: [],
    books: [],
    loginAttempts: {}
};

// ================= API ЕНДПОІНТИ =================

// Публічний маршрут: інформація про API
app.get('/api/status', (req, res) => {
    res.json({
        service: 'BookTrace Secure API',
        authScheme: 'Bearer Token (HMAC-SHA256)',
        trustBoundary: 'Server-side Authorization & Ownership Check'
    });
});

// 1. Реєстрація
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
            plan: 'FREE',
            mfaEnabled: false,
            mfaSecret: mfaSecret.base32
        };

        db.users.push(newUser);
        res.status(201).json({ message: 'Користувача зареєстровано (тариф FREE)!', mfaSecret: mfaSecret.base32 });
    } catch (err) {
        res.status(500).json({ error: 'Помилка сервера' });
    }
});

// 2. Вхід та видача Bearer-токена
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
    const accessToken = generateAccessToken(user);

    res.json({
        message: 'Успішний вхід!',
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: TOKEN_TTL_SECONDS,
        user: { id: user.id, email: user.email, role: user.role, plan: user.plan }
    });
});

// 3. Перевірка поточного автентифікованого суб'єкта (/api/whoami)
app.get('/api/whoami', authenticateBearer, (req, res) => {
    const user = db.users.find(u => u.id === req.auth.userId);
    if (!user) return res.status(404).json({ error: 'Користувача не знайдено' });
    res.json({
        userId: user.id,
        email: user.email,
        role: user.role,
        plan: user.plan,
        tokenExpiresAt: new Date(req.auth.exp * 1000).toISOString()
    });
});

// 4. Випуск демонстраційної підписаної ліцензії Ed25519
app.post('/api/license/issue-demo', authenticateBearer, (req, res) => {
    const licenseKey = issueProLicense(req.auth.email);
    res.json({ licenseKey });
});

// 5. Активація ліцензії PRO з перевіркою підпису Ed25519 на сервері
app.post('/api/license/activate', authenticateBearer, (req, res) => {
    const { licenseKey } = req.body;
    const check = verifyProLicense(licenseKey, req.auth.email);

    if (!check.valid) {
        return res.status(403).json({ error: check.reason });
    }

    const user = db.users.find(u => u.id === req.auth.userId);
    user.plan = 'PRO';
    res.json({ message: 'Ліцензію PRO підтверджено підписом Ed25519 та активовано!', plan: 'PRO' });
});

// 6. Отримання списку книг (тільки для власника req.auth.userId)
app.get('/api/books', authenticateBearer, (req, res) => {
    const user = db.users.find(u => u.id === req.auth.userId);
    if (!user) return res.status(404).json({ error: 'Користувача не знайдено' });

    const userBooks = db.books
        .filter(b => b.userId === req.auth.userId)
        .map(b => ({
            ...b,
            integrityOk: b.hmac === computeProgressHmac(b),
            notes: b.notes.map(n => ({
                text: decryptNote(n.encryptedData),
                date: n.date
            }))
        }));

    res.json({
        books: userBooks,
        user: { email: user.email, role: user.role, plan: user.plan }
    });
});

// 7. Додавання книги (серверна авторизація Freemium-обмеження)
app.post('/api/books', authenticateBearer, (req, res) => {
    const user = db.users.find(u => u.id === req.auth.userId);
    const userBooksCount = db.books.filter(b => b.userId === req.auth.userId).length;

    if (user.plan === 'FREE' && userBooksCount >= 2) {
        return res.status(403).json({
            error: 'Ліміт тарифу FREE (макс. 2 книги)! Активуйте PRO-ліцензію.'
        });
    }

    const { title, author, totalPages } = req.body;
    const pages = parseInt(totalPages);
    if (!title || !author || isNaN(pages) || pages <= 0) {
        return res.status(400).json({ error: 'Некоректні дані книги або кількість сторінок' });
    }

    const newBook = {
        id: crypto.randomUUID(),
        userId: req.auth.userId,
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

// 8. Оновлення прогресу (серверна перевірка власності та інваріантів)
app.put('/api/books/:id/progress', authenticateBearer, (req, res) => {
    const book = db.books.find(b => b.id === req.params.id);
    if (!book) return res.status(404).json({ error: 'Книгу не знайдено' });
    if (book.userId !== req.auth.userId) return res.status(403).json({ error: 'Доступ заборонено: ви не власник книги' });

    const { readPages, note } = req.body;
    if (readPages !== undefined && readPages !== '') {
        const parsedPages = parseInt(readPages);
        if (isNaN(parsedPages) || parsedPages < 0 || parsedPages > book.totalPages) {
            return res.status(400).json({
                error: `Порушення цілісності даних: сторінки мають бути від 0 до ${book.totalPages}`
            });
        }
        book.readPages = parsedPages;
        book.hmac = computeProgressHmac(book);
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
    console.log(`🚀 Сервер BookTrace (Lab 6: Bearer Auth + Trust Model) запущено!`);
    console.log(`👉 Відкрийте в браузері: http://localhost:${PORT}`);
    console.log(`================================================`);
});