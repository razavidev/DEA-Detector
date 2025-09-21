import sqlite3 from "sqlite3";
import { open } from "sqlite";


async function getRemoteBlacklist() {
    const db = await open({
        filename: '../disposable_emails.db',
        driver: sqlite3.Database
    });

    try {

        await db.exec(`
      CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_name TEXT UNIQUE
      )
    `);

        // Fetch data
        let b1 = await fetch("https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt");
        let b2 = await fetch("https://github.com/disposable-email-domains/disposable-email-domains/blob/main/disposable_email_blocklist.conf");
        if (!b1.ok || !b2.ok) throw new Error(`HTTP Error: statuses ", ${b1.status}, ${b2.status}`);
        b1 = await b1.text();
        b2 = await b2.text();

        const domains =
            b1.split("\n").filter(Boolean).concat(b2.split("\n").filter(Boolean));

        await db.exec('BEGIN TRANSACTION');
        const stmt = await db.prepare('INSERT OR IGNORE INTO domains (domain_name) VALUES (?)');

        for (const domain of domains) {
            await stmt.run(domain);
        }

        await stmt.finalize();
        await db.exec('COMMIT');

        console.log('Domains inserted to DB');



    } catch (err) {
        console.error('Error While inserting to DB: ', err);
        await db.exec('ROLLBACK');
    } finally {
        db.close();
    }

    try {

    } catch (err) {
        console.log("Error while retrieving remote blacklist: " + err);
    }
}

export default getRemoteBlacklist