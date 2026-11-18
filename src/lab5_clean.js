const readline = require('readline');

// Ключ №1 (Варіант 8)
const KEY_1 = "2026_ПЗ-23-1_Матвійчук_Каріна_варіант:08_";

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question("Введіть ключ доступу: ", (userInput) => {
    if (userInput === KEY_1) {
        console.log("Доступ дозволено");
    } else {
        console.log("Доступ заборонено");
    }
    rl.close();
});