import { open } from 'sqlite';
import sqlite3 from 'sqlite3';

const dbPath = '../disposable_emails.db';

export async function queryBlacklist(domain) {
  const db = await open({
    filename: dbPath,
    driver: sqlite3.Database
  });

  try {
    const result = await db.get(
      'SELECT EXISTS(SELECT 1 FROM domains WHERE domain_name = ?) AS found',
      [domain.toLowerCase()]
    );
    return result.found === 1;
  } catch (error) {
    console.error('Database query failed:', error);
    return false;
  } finally {
    await db.close();
  }
}

// // Example usage:
// (async () => {
//   const testDomain = 'mailinator.com';
//   const isFound = await isDisposable(testDomain);
//   console.log(`Is '${testDomain}' disposable?`, isFound);

//   const testDomain2 = 'example.com';
//   const isFound2 = await isDisposable(testDomain2);
//   console.log(`Is '${testDomain2}' disposable?`, isFound2);
// })();
