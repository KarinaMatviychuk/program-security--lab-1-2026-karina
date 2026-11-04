const crypto = require('crypto');

console.log("=== ЛАБОРАТОРНА РОБОТА №4: ЕКСПЕРИМЕНТИ (ВАРІАНТ 08) ===");

// 1. Початковий рядок (Завдання 2)
const plainText1 = "2026_ПЗ-23-1_Матвійчук_Каріна_варіант:08_";
console.log("\n[1] Початковий текст:", plainText1);

// 2. Генерація Ключа №1 (256 біт) та Вектора Ініціалізації №1 (128 біт)
const key1 = crypto.randomBytes(32); // 256 біт
const iv1 = crypto.randomBytes(16);  // 128 біт

console.log("Ключ №1 (HEX):  ", key1.toString('hex'));
console.log("Вектор №1 (HEX):", iv1.toString('hex'));

// 3. Завдання 6: Шифрування AES-256-CTR -> Шифротекст №1
const cipher1 = crypto.createCipheriv('aes-256-ctr', key1, iv1);
const ciphertext1 = Buffer.concat([cipher1.update(plainText1, 'utf8'), cipher1.final()]);
console.log("\n[Завдання 6] Шифротекст №1 (HEX):", ciphertext1.toString('hex'));

// 4. Завдання 7.2: Атака відомого відкритого тексту -> Отримання Гами №1
// Гама = Plaintext1 XOR Ciphertext1
const ptBuffer1 = Buffer.from(plainText1, 'utf8');
const gamma1 = Buffer.alloc(ptBuffer1.length);
for (let i = 0; i < ptBuffer1.length; i++) {
    gamma1[i] = ptBuffer1[i] ^ ciphertext1[i];
}
console.log("\n[Завдання 7.2] Відновлена Гама №1 (HEX):", gamma1.toString('hex'));

// 5. Завдання 7.3: Альтернативний текст з варіантом "99"
const plainText2 = "2026_ПЗ-23-1_Матвійчук_Каріна_варіант:99_";
console.log("\n[Завдання 7.3] Альтернативний текст:", plainText2);

// 6. Завдання 7.4: Формування Сфабрикованого Шифротексту №2 без знання ключа!
// Ciphertext2 = Plaintext2 XOR Gamma1
const ptBuffer2 = Buffer.from(plainText2, 'utf8');
const ciphertext2 = Buffer.alloc(ptBuffer2.length);
for (let i = 0; i < ptBuffer2.length; i++) {
    ciphertext2[i] = ptBuffer2[i] ^ gamma1[i];
}
console.log("[Завдання 7.4] Сфабрикований Шифротекст №2 (HEX):", ciphertext2.toString('hex'));

// 7. Завдання 8: Перевірка легітимним розшифруванням (Ключ №1 + Вектор №1)
const decipher = crypto.createDecipheriv('aes-256-ctr', key1, iv1);
const decrypted2 = Buffer.concat([decipher.update(ciphertext2), decipher.final()]);

console.log("\n=== [Завдання 8] РЕЗУЛЬТАТ РОЗШИФРУВАННЯ СФАБРИКОВАНОГО ШИФРОТЕКСТУ №2 ===");
console.log("Отриманий відновий текст:", decrypted2.toString('utf8'));