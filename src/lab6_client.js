/**
 * Клієнт REST API для навчального сервера (Лабораторна робота №6)
 * Варіант 8: Матвійчук Каріна (група ІПЗ-23-1)
 */

const BASE_URL = 'http://127.0.0.1:8080';
const CLIENT_ID = 'dahlia-08';
const CLIENT_SECRET = 'C4sJ8nM1xL5q';

async function runClient() {
    console.log('=== ЗАПУСК REST API КЛІЄНТА (ВАРІАНТ 8) ===\n');

    // 1. Автентифікація та отримання токена доступу
    console.log('1. Виконуємо автентифікацію на /auth/token...');
    const authRes = await fetch(`${BASE_URL}/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET
        })
    });

    if (!authRes.ok) {
        console.error('Помилка автентифікації:', await authRes.text());
        return;
    }

    const authData = await authRes.json();
    const accessToken = authData.access_token;
    console.log(`✔ Токен отримано! Тип: ${authData.token_type}, діє: ${authData.expires_in} сек.`);
    console.log(`✔ Токен: ${accessToken}\n`);

    // Допоміжна функція для захищених запитів із Bearer-токеном
    const authHeaders = {
        'Authorization': `Bearer ${accessToken}`,
        'Accept': 'application/json'
    };

    // 2. Отримання даних поточного читача (/whoami)
    console.log('2. Дані поточного читача (/whoami):');
    const whoamiRes = await fetch(`${BASE_URL}/whoami`, { headers: authHeaders });
    const whoamiData = await whoamiRes.json();
    console.log(whoamiData, '\n');

    // 3. Отримання списку книг (/api/books)
    console.log('3. Список доступних книг (/api/books):');
    const booksRes = await fetch(`${BASE_URL}/api/books`, { headers: authHeaders });
    const booksData = await booksRes.json();
    console.log(`Всього книг: ${booksData.count}`);
    booksData.books.forEach(b => {
        console.log(`  - [${b.id}] "${b.title}" (${b.author})`);
    });
    console.log();

    // 4. Отримання детальної інформації про першу книгу (/api/books/{id})
    if (booksData.books && booksData.books.length > 0) {
        const firstBookId = booksData.books[0].id;
        console.log(`4. Деталі книги ${firstBookId} (/api/books/${firstBookId}):`);
        const singleBookRes = await fetch(`${BASE_URL}/api/books/${firstBookId}`, { headers: authHeaders });
        console.log(await singleBookRes.json(), '\n');
    }

    // 5. Отримання активних позик (/api/loans)
    console.log('5. Активні позики читача (/api/loans):');
    const loansRes = await fetch(`${BASE_URL}/api/loans`, { headers: authHeaders });
    console.log(await loansRes.json(), '\n');

    // 6. Отримання зведеної інформації (/api/summary)
    console.log('6. Зведена інформація (/api/summary):');
    const summaryRes = await fetch(`${BASE_URL}/api/summary`, { headers: authHeaders });
    console.log(await summaryRes.json(), '\n');
}

runClient().catch(err => console.error('Помилка підключення до сервера:', err.message));