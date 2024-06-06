const sqlite = require('sqlite');
const sqlite3 = require('sqlite3');

// Placeholder for the database file name
const dbFileName = 'microblog.db';

async function showDatabaseContents() {
    const db = await sqlite.open({ filename: dbFileName, driver: sqlite3.Database });

    console.log('Opening database file:', dbFileName);

    const users = await db.all('SELECT * FROM users');
    console.log('Users:', users);

    const posts = await db.all('SELECT * FROM posts');
    console.log('Posts:', posts);

    await db.close();
}

showDatabaseContents().catch(err => {
    console.error('Error showing database contents:', err);
});
