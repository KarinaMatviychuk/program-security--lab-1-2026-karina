const bcrypt = require('bcryptjs');

// 1. Формування базового рядка для Варіанту 8
// Формат: [поточний_рік]_[група]_[прізвище_студента]_[ім'я_студента]_варіант: [номер_варіанту]_
let baseStr = "2026_ПЗ-23-1_Матвійчук_Каріна_варіант:8_";

// Доповнюємо символами "_" до довжини у 72 байти в кодуванні UTF-8
while (Buffer.byteLength(baseStr, 'utf8') < 72) {
    baseStr += "_";
}
baseStr = Buffer.from(baseStr, 'utf8').slice(0, 72).toString('utf8');

console.log("=== ЕКСПЕРИМЕНТ 1 (ВАРІАНТ 8) ===");
console.log("Базовий рядок:", baseStr);
console.log("Розмір у байтах:", Buffer.byteLength(baseStr, 'utf8'));

// 2. Модифіковані рядки
const str1 = baseStr;                                          // Рядок 1 (72 байти)
const str2 = baseStr + "1";                                   // Рядок 2 (+ "1" після 72 байта)
const str3 = baseStr + "0123456789";                          // Рядок 3 (+ 10 символів)
const str4 = Buffer.from(baseStr, 'utf8').slice(0, 71).toString('utf8'); // Рядок 4 (- 1 символ)

// 3. Хешування через bcrypt
const salt = bcrypt.genSaltSync(10);
const hash1 = bcrypt.hashSync(str1, salt);
const hash2 = bcrypt.hashSync(str2, salt);
const hash3 = bcrypt.hashSync(str3, salt);
const hash4 = bcrypt.hashSync(str4, salt);

console.log("\n--- ХЕШІ BCRYPT ---");
console.log("Хеш №1 (72 байти):", hash1);
console.log("Хеш №2 (+ '1'):    ", hash2);
console.log("Хеш №3 (+ 10симв): ", hash3);
console.log("Хеш №4 (- 1симв):  ", hash4);

console.log("\n--- ПОПАРНА ПЕРЕВІРКА BCRYPT.COMPARE ---");
console.log("Рядок 1 проти Хеш №1:", bcrypt.compareSync(str1, hash1)); // true
console.log("Рядок 2 проти Хеш №1:", bcrypt.compareSync(str2, hash1)); // TRUE! (бо зміна після 72 байта)
console.log("Рядок 3 проти Хеш №1:", bcrypt.compareSync(str3, hash1)); // TRUE! (бо зміна після 72 байта)
console.log("Рядок 4 проти Хеш №1:", bcrypt.compareSync(str4, hash1)); // FALSE (зміна в межах 72 байтів)