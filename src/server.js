/**
 * BookTrace - Secure Reading Tracker API & Server
 * Лабораторні роботи №3–8 з дисципліни "Безпека програм і даних"
 * Виконала: Матвійчук Каріна (ІПЗ-23-1), Варіант 8
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ======================================================
// ЛАБ 7-8: СТРУКТУРОВАНЕ СЕРВЕРНЕ ЛОГУВАННЯ ТА МОНІТОРИНГ
// ======================================================
const LOG_DIR = path.join(__dirname, '..', 'logs');
const LOG_FILE = path.join(LOG_DIR, 'app.log');
const MAX_LOG_SIZE_BYTES = 1024 * 1024; // 1 МБ (ротація журналів)

if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

// Метрики моніторингу стану системи
const metrics = {
    startedAt: new Date().toISOString(),
    totalRequests: 0,
    failedLogins: 0,
    accessDeniedCount: 0,
    serverErrors: 0,
    alerts: []
};

// Перевірка та виконання ротації логів
function rotateLogsIfNeeded() {
    try {
        if (fs.existsSync(LOG_FILE)) {
            const stats = fs.statSync(LOG_FILE);
            if (stats.size >= MAX_LOG_SIZE_BYTES) {
                const archiveName = path.join(LOG_DIR, `app-${Date.now()}.log`);
                fs.renameSync(LOG_FILE, archiveName);
            }
        }
    } catch (e) {
        console.error('Помилка ротації журналу:', e.message);
    }
}

// Запис структурованої події (без секретів, паролів і токенів)
function writeAuditLog({ level = 'INFO', component = 'api', requestId = '-', subject = 'anonymous', ip = '-', action, outcome, details = '' }) {
    rotateLogsIfNeeded();
    const entry = {
        timestamp: new Date().toISOString(),
        level,
        component,
        requestId,
        subject,
        ip,
        action,
        outcome,
        details
    };
    const line = JSON.stringify(entry);
    fs.appendFileSync(LOG_FILE, line + '\n', 'utf8');

    if (level === 'WARNING' || level === 'ERROR' || level === 'CRITICAL') {
        metrics.alerts.push({ timestamp: entry.timestamp, level, action, subject, details });
        if (metrics.alerts.length > 20) metrics.alerts.shift();
    }
}

// Middleware присвоєння Request-ID та збору метрик моніторингу
app.use((req, res, next) => {
    req.requestId = crypto.randomUUID().slice(0, 8);
    req.clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
    metrics.totalRequests++;

    res.on('finish', () => {
        if (res.statusCode === 401 || res.statusCode === 403) {
            metrics.accessDeniedCount++;
        } else if (res.statusCode >= 500) {
            metrics.serverErrors++;
        }
    });
    next();
});

// ======================================================
// ЛАБ 4–6: КРИПТОГРАФІЯ (AES-256-GCM, ED25519, HMAC, BEARER)
// ======================================================
let DB_ENCRYPTION_KEY = crypto.randomBytes(32);
let { publicKey: LICENSE_PUBLIC_KEY, privateKey: LICENSE_PRIVATE_KEY } = crypto.generateKeyPairSync('ed25519');
let INTEGRITY_HMAC_SECRET = crypto.randomBytes(32);
const TOKEN_SIGNING_SECRET = crypto.randomBytes(32);
const TOKEN_TTL_SECONDS = 1800;

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
        return "[ПОМИЛКА ЦІЛІСНОСТІ: Дані нотатки підроблені або ключ втрачено!]";
    }
}

function issueProLicense(email) {
    const payload = JSON.stringify({
        product: "BookTrace-PRO",
        email,
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
    const signature = crypto.createHmac('sha256', TOKEN_SIGNING_SECRET).update(encodedPayload).digest('base64url');
    return `${encodedPayload}.${signature}`;
}

function verifyAccessToken(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 2) return null;

        const [encodedPayload, signature] = parts;
        const expectedSig = crypto.createHmac('sha256', TOKEN_SIGNING_SECRET).update(encodedPayload).digest('base64url');
        if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) return null;

        const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
        if (payload.exp <= Math.floor(Date.now() / 1000)) return null;
        return payload;
    } catch (err) {
        return null;
    }
}

function authenticateBearer(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ')) {
        writeAuditLog({
            level: 'WARNING',
            component: 'auth-middleware',
            requestId: req.requestId,
            ip: req.clientIp,
            action: `ACCESS_${req.method}_${req.path}`,
            outcome: 'DENIED',
            details: 'Відсутній Bearer токен'
        });
        return res.status(401).json({ error: 'Відсутній заголовок Authorization: Bearer <token>' });
    }

    const token = authHeader.slice(7).trim();
    const payload = verifyAccessToken(token);
    if (!payload) {
        writeAuditLog({
            level: 'WARNING',
            component: 'auth-middleware',
            requestId: req.requestId,
            ip: req.clientIp,
            action: `ACCESS_${req.method}_${req.path}`,
            outcome: 'DENIED',
            details: 'Недійсний або прострочений токен'
        });
        return res.status(401).json({ error: 'Недійсний або прострочений токен доступу' });
    }

    req.auth = { userId: payload.sub, email: payload.email, role: payload.role, exp: payload.exp };
    next();
}

// "База даних" у пам'яті
const db = {
    users: [],
    books: [],
    loginAttempts: {}
};

// ======================================================
// ЛАБ 7-8: РЕЗЕРВНЕ КОПІЮВАННЯ ТА АВАРІЙНЕ ВІДНОВЛЕННЯ
// ======================================================
const BACKUP_DIR = path.join(__dirname, '..', 'backups');
if (!fs.existsSync(BACKUP_DIR)) {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

// Створення повної резервної копії БД + криптоключів + SHA-256 маніфест
function createFullBackup(initiatorEmail = 'system') {
    const backupId = `backup_${Date.now()}`;
    const backupPayload = {
        backupId,
        createdAt: new Date().toISOString(),
        data: {
            users: db.users,
            books: db.books
        },
        cryptoKeys: {
            dbEncryptionKeyHex: DB_ENCRYPTION_KEY.toString('hex'),
            hmacSecretHex: INTEGRITY_HMAC_SECRET.toString('hex'),
            licensePublicPem: LICENSE_PUBLIC_KEY.export({ type: 'spki', format: 'pem' }),
            licensePrivatePem: LICENSE_PRIVATE_KEY.export({ type: 'pkcs8', format: 'pem' })
        }
    };

    const jsonContent = JSON.stringify(backupPayload, null, 2);
    const sha256Hash = crypto.createHash('sha256').update(jsonContent, 'utf8').digest('hex');

    const backupFilePath = path.join(BACKUP_DIR, `${backupId}.json`);
    const hashFilePath = path.join(BACKUP_DIR, `${backupId}.sha256`);

    fs.writeFileSync(backupFilePath, jsonContent, 'utf8');
    fs.writeFileSync(hashFilePath, `${sha256Hash}  ${backupId}.json\n`, 'utf8');

    writeAuditLog({
        level: 'INFO',
        component: 'backup-service',
        subject: initiatorEmail,
        action: 'BACKUP_CREATED',
        outcome: 'SUCCESS',
        details: `Створено копію ${backupId}.json (SHA-256: ${sha256Hash.slice(0, 16)}...)`
    });

    return { backupId, sha256Hash, usersCount: db.users.length, booksCount: db.books.length };
}

// Відновлення системи з перевіркою цілісності SHA-256
function restoreFromBackup(backupId, initiatorEmail = 'system') {
    const backupFilePath = path.join(BACKUP_DIR, `${backupId}.json`);
    const hashFilePath = path.join(BACKUP_DIR, `${backupId}.sha256`);

    if (!fs.existsSync(backupFilePath) || !fs.existsSync(hashFilePath)) {
        throw new Error('Файл резервної копії або SHA-256 маніфест не знайдено!');
    }

    const jsonContent = fs.readFileSync(backupFilePath, 'utf8');
    const expectedHash = fs.readFileSync(hashFilePath, 'utf8').trim().split(/\s+/)[0];
    const actualHash = crypto.createHash('sha256').update(jsonContent, 'utf8').digest('hex');

    if (expectedHash !== actualHash) {
        writeAuditLog({
            level: 'CRITICAL',
            component: 'recovery-service',
            subject: initiatorEmail,
            action: 'BACKUP_RESTORE',
            outcome: 'FAIL',
            details: `Порушено цілісність SHA-256 копії ${backupId}!`
        });
        throw new Error('Порушено цілісність резервної копії (невідповідність SHA-256)!');
    }

    const parsed = JSON.parse(jsonContent);
    db.users = parsed.data.users || [];
    db.books = parsed.data.books || [];
    DB_ENCRYPTION_KEY = Buffer.from(parsed.cryptoKeys.dbEncryptionKeyHex, 'hex');
    INTEGRITY_HMAC_SECRET = Buffer.from(parsed.cryptoKeys.hmacSecretHex, 'hex');
    LICENSE_PUBLIC_KEY = crypto.createPublicKey(parsed.cryptoKeys.licensePublicPem);
    LICENSE_PRIVATE_KEY = crypto.createPrivateKey(parsed.cryptoKeys.licensePrivatePem);

    writeAuditLog({
        level: 'INFO',
        component: 'recovery-service',
        subject: initiatorEmail,
        action: 'BACKUP_RESTORED',
        outcome: 'SUCCESS',
        details: `Відновлено стан з ${backupId} (користувачів: ${db.users.length}, книг: ${db.books.length})`
    });

    return { backupId, usersCount: db.users.length, booksCount: db.books.length };
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
            plan: 'FREE',
            mfaEnabled: false,
            mfaSecret: mfaSecret.base32
        };

        db.users.push(newUser);
        writeAuditLog({
            level: 'INFO',
            component: 'auth-service',
            requestId: req.requestId,
            subject: email,
            ip: req.clientIp,
            action: 'USER_REGISTER',
            outcome: 'SUCCESS',
            details: `Зареєстровано нового користувача (plan=FREE)`
        });

        res.status(201).json({ message: 'Користувача зареєстровано (тариф FREE)!', mfaSecret: mfaSecret.base32 });
    } catch (err) {
        res.status(500).json({ error: 'Помилка сервера' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password, mfaToken } = req.body;
    const attempts = db.loginAttempts[email] || 0;

    if (attempts >= 5) {
        writeAuditLog({
            level: 'CRITICAL',
            component: 'auth-service',
            requestId: req.requestId,
            subject: email,
            ip: req.clientIp,
            action: 'USER_LOGIN',
            outcome: 'BLOCKED',
            details: 'Виявлено атаку підбору пароля (5+ невдалих спроб)'
        });
        return res.status(429).json({ error: 'Заблоковано через 5 помилкових спроб' });
    }

    const user = db.users.find(u => u.email === email);
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        db.loginAttempts[email] = attempts + 1;
        metrics.failedLogins++;
        writeAuditLog({
            level: 'WARNING',
            component: 'auth-service',
            requestId: req.requestId,
            subject: email || 'unknown',
            ip: req.clientIp,
            action: 'USER_LOGIN',
            outcome: 'FAIL',
            details: `Невдала спроба входу (спроба #${db.loginAttempts[email]})`
        });
        return res.status(400).json({ error: 'Невірні автентифікаційні дані' });
    }

    if (user.mfaEnabled) {
        if (!mfaToken || !speakeasy.totp.verify({ secret: user.mfaSecret, encoding: 'base32', token: mfaToken })) {
            return res.status(400).json({ error: 'Невірний МФА код' });
        }
    }

    db.loginAttempts[email] = 0;
    const accessToken = generateAccessToken(user);

    writeAuditLog({
        level: 'INFO',
        component: 'auth-service',
        requestId: req.requestId,
        subject: user.email,
        ip: req.clientIp,
        action: 'USER_LOGIN',
        outcome: 'SUCCESS',
        details: 'Успішна автентифікація, видано Bearer токен'
    });

    res.json({
        message: 'Успішний вхід!',
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: TOKEN_TTL_SECONDS,
        user: { id: user.id, email: user.email, role: user.role, plan: user.plan }
    });
});

app.post('/api/license/issue-demo', authenticateBearer, (req, res) => {
    const licenseKey = issueProLicense(req.auth.email);
    writeAuditLog({
        level: 'INFO',
        component: 'license-service',
        requestId: req.requestId,
        subject: req.auth.email,
        ip: req.clientIp,
        action: 'LICENSE_ISSUED',
        outcome: 'SUCCESS',
        details: 'Згенеровано демонстраційний PRO-ключ Ed25519'
    });
    res.json({ licenseKey });
});

app.post('/api/license/activate', authenticateBearer, (req, res) => {
    const { licenseKey } = req.body;
    const check = verifyProLicense(licenseKey, req.auth.email);

    if (!check.valid) {
        writeAuditLog({
            level: 'WARNING',
            component: 'license-service',
            requestId: req.requestId,
            subject: req.auth.email,
            ip: req.clientIp,
            action: 'LICENSE_ACTIVATE',
            outcome: 'DENIED',
            details: check.reason
        });
        return res.status(403).json({ error: check.reason });
    }

    const user = db.users.find(u => u.id === req.auth.userId);
    user.plan = 'PRO';
    writeAuditLog({
        level: 'INFO',
        component: 'license-service',
        requestId: req.requestId,
        subject: req.auth.email,
        ip: req.clientIp,
        action: 'LICENSE_ACTIVATE',
        outcome: 'SUCCESS',
        details: 'Активовано тариф PRO'
    });
    res.json({ message: 'Ліцензію PRO підтверджено підписом Ed25519 та активовано!', plan: 'PRO' });
});

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

    res.json({ books: userBooks, user: { email: user.email, role: user.role, plan: user.plan } });
});

app.post('/api/books', authenticateBearer, (req, res) => {
    const user = db.users.find(u => u.id === req.auth.userId);
    const userBooksCount = db.books.filter(b => b.userId === req.auth.userId).length;

    if (user.plan === 'FREE' && userBooksCount >= 2) {
        writeAuditLog({
            level: 'WARNING',
            component: 'books-service',
            requestId: req.requestId,
            subject: req.auth.email,
            ip: req.clientIp,
            action: 'BOOK_CREATE',
            outcome: 'DENIED',
            details: 'Перевищено ліміт тарифу FREE (2 книги)'
        });
        return res.status(403).json({ error: 'Ліміт тарифу FREE (макс. 2 книги)! Активуйте PRO-ліцензію.' });
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

    writeAuditLog({
        level: 'INFO',
        component: 'books-service',
        requestId: req.requestId,
        subject: req.auth.email,
        ip: req.clientIp,
        action: 'BOOK_CREATE',
        outcome: 'SUCCESS',
        details: `Додано книгу "${title}" (id=${newBook.id})`
    });

    res.status(201).json({ message: 'Книгу додано!', book: newBook });
});

app.put('/api/books/:id/progress', authenticateBearer, (req, res) => {
    const book = db.books.find(b => b.id === req.params.id);
    if (!book) return res.status(404).json({ error: 'Книгу не знайдено' });
    if (book.userId !== req.auth.userId) return res.status(403).json({ error: 'Доступ заборонено' });

    const { readPages, note } = req.body;
    if (readPages !== undefined && readPages !== '') {
        const parsedPages = parseInt(readPages);
        if (isNaN(parsedPages) || parsedPages < 0 || parsedPages > book.totalPages) {
            return res.status(400).json({ error: `Сторінки мають бути від 0 до ${book.totalPages}` });
        }
        book.readPages = parsedPages;
        book.hmac = computeProgressHmac(book);
    }

    if (note && note.trim() !== "") {
        book.notes.push({ encryptedData: encryptNote(note), date: new Date().toLocaleString() });
    }

    writeAuditLog({
        level: 'INFO',
        component: 'books-service',
        requestId: req.requestId,
        subject: req.auth.email,
        ip: req.clientIp,
        action: 'BOOK_PROGRESS_UPDATE',
        outcome: 'SUCCESS',
        details: `Оновлено прогрес книги id=${book.id} (${book.readPages}/${book.totalPages})`
    });

    res.json({ message: 'Прогрес та цілісність оновлено!', book });
});

// ================= ЕНДПОІНТИ МОНІТОРИНГУ ТА БЕКАПІВ =================

app.get('/api/monitoring/health', authenticateBearer, (req, res) => {
    const recentLogs = fs.existsSync(LOG_FILE)
        ? fs.readFileSync(LOG_FILE, 'utf8').trim().split('\n').slice(-6)
        : [];

    res.json({
        status: db.users.length > 0 ? 'HEALTHY' : 'DEGRADED (EMPTY_DB)',
        uptimeSeconds: Math.floor(process.uptime()),
        usersInDb: db.users.length,
        booksInDb: db.books.length,
        metrics,
        recentLogs
    });
});

app.post('/api/backup/create', authenticateBearer, (req, res) => {
    const result = createFullBackup(req.auth.email);
    res.json({
        message: `Резервну копію ${result.backupId} створено! SHA-256: ${result.sha256Hash.slice(0, 16)}...`,
        backup: result
    });
});

// Імітація збою / втрати даних бази (для перевірки аварійного відновлення)
app.post('/api/backup/simulate-crash', authenticateBearer, (req, res) => {
    db.books = [];
    DB_ENCRYPTION_KEY = crypto.randomBytes(32); // Втрата ключів шифрування
    writeAuditLog({
        level: 'CRITICAL',
        component: 'database',
        requestId: req.requestId,
        subject: req.auth.email,
        ip: req.clientIp,
        action: 'DATA_LOSS_INCIDENT',
        outcome: 'CRITICAL',
        details: 'Змодельовано критичний збій: втрачено список книг та ключі шифрування!'
    });
    res.json({ message: '⚠️ Імітація аварії: дані книг та ключі шифрування втрачено!' });
});

app.post('/api/backup/restore', authenticateBearer, (req, res) => {
    try {
        const { backupId } = req.body;
        const result = restoreFromBackup(backupId, req.auth.email);
        res.json({
            message: `✅ Систему успішно відновлено з копії ${result.backupId} (книг: ${result.booksCount})!`,
            restored: result
        });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

const PORT = 3000;
app.listen(PORT, () => {
    writeAuditLog({
        level: 'INFO',
        component: 'server',
        action: 'SERVER_START',
        outcome: 'SUCCESS',
        details: `Сервер запущено на порту ${PORT}`
    });
    console.log(`================================================`);
    console.log(`🚀 Сервер BookTrace (Lab 7-8: Logging + Backup/DR) запущено!`);
    console.log(`👉 Відкрийте в браузері: http://localhost:${PORT}`);
    console.log(`================================================`);
});