const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// Рядок за завданням: "pass: [прізвище_студента]"
const targetPassword = "pass: Матвійчук";

// Словник із 20 кандидатів (правильний кандидат — 20-й)
const dictionary = [
    "pass:12345", "pass:admin", "pass:root", "pass:secret", "pass:qwerty",
    "pass:user", "pass:guest", "pass:test", "pass:karina", "pass:2026",
    "pass:variant8", "pass:ukraine", "pass:security", "pass:booktrace", "pass:reading",
    "pass:library", "pass:auth", "pass:password", "pass:master", targetPassword
];

// 1. Хеш №5 (SHA-256) та Хеш №6 (bcrypt 12 rounds)
const hash5 = crypto.createHash('sha256').update(targetPassword).digest('hex');
console.log("Генеруємо bcrypt хеш з 12 раундами (зачекайте кількох секунд)...");
const hash6 = bcrypt.hashSync(targetPassword, bcrypt.genSaltSync(12));

console.log("\nХеш №5 (SHA-256):", hash5);
console.log("Хеш №6 (bcrypt 12 rounds):", hash6);

// 2. Брутфорс-атака на SHA-256
console.log("\n=== СТАРТ БРУТФОРСУ SHA-256 ===");
const startSha = process.hrtime.bigint();
for (const candidate of dictionary) {
    const candHash = crypto.createHash('sha256').update(candidate).digest('hex');
    if (candHash === hash5) {
        console.log("Знайдено пароль SHA-256:", candidate);
        break;
    }
}
const endSha = process.hrtime.bigint();
const timeShaMs = Number(endSha - startSha) / 1000000;

console.log(`Час брутфорсу SHA-256: ${timeShaMs.toFixed(3)} мс`);

// 3. Брутфорс-атака на bcrypt (12 rounds)
console.log("\n=== СТАРТ БРУТФОРСУ BCRYPT (12 Rounds) ===");
const startBcrypt = process.hrtime.bigint();
for (const candidate of dictionary) {
    if (bcrypt.compareSync(candidate, hash6)) {
        console.log("Знайдено пароль bcrypt:", candidate);
        break;
    }
}
const endBcrypt = process.hrtime.bigint();
const timeBcryptMs = Number(endBcrypt - startBcrypt) / 1000000;

console.log(`Час брутфорсу bcrypt (12 rounds): ${timeBcryptMs.toFixed(3)} мс (${(timeBcryptMs / 1000).toFixed(2)} сек)`);