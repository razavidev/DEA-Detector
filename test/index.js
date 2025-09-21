import express, { json } from 'express';
import verifyEmail from '../funcs/verifyEmail.js';
import getRemoteBlacklist from '../funcs/getRemoteBlacklist.js';
import path, { dirname } from 'path'
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express();
const port = process.env.PORT || 3000;
const host  = "0.0.0.0"

app.use(json());

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/dea-detector', async (req, res) => {
    const { value } = req.body;
    console.log('---NEW REQUEST---')
    
    if (!value) {
        return res.status(400).json({ error: 'Value is required' });
    }
    
    try {
        const data = await verifyEmail(value)

        res.json({ value, data });
        console.log('---RESPONSE SENT---')
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Start the server and pre-load the list
async function startServer() {
    try {
        await getRemoteBlacklist()
        await verifyEmail('initial_load'); // Trigger the initial load
        app.listen(port, host, () => {
            console.log(`Server listening on http://localhost:${port}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();


// --- TESTING ---
// (async () => {
//     const emailsToTest = [
//         'miran@hisrher.com',
//         'turkey93289@aminating.com',
//         'm.razavi.dev@gmail.com',
//         'mr.razavidev@gmail.com',
//         'contact@razavi.dev',
//         'mortaza.razavi@gmail.com',
//         'press@google.com',
//         'media.help@apple.com',
//         'press@amazon.com',
//         'news@microsoft.com',
//         'press@twitter.com',
//         'press@fb.com',
//         'pr@adobe.com',
//         'feedback@nytimes.com',
//         'webmaster@coca-cola.com',
//         'press@starbucks.com',
//         'press@tesla.com',
//         'media.relations@nike.com',
//         'info@ibm.com',
//         'info@harvard.edu',
//         'news@walmart.com',
//         'mediarelations@fedex.com',
//         'media@delta.com',
//         'press.corporate@disney.com',
//         'mediarelations@boeing.com',
//         "sardine59005@mailshan.com",
//         "mitefid250@cspaus.com",
//     ];

//     console.log('--- Comprehensive DEA Risk Assessment ---');
//     for (const email of emailsToTest) {
//         const result = await checkEmailForDEA(email);
//         console.log(`Email: ${email.padEnd(25)} => Score: ${result.score.toFixed(2)} (Details: ${JSON.stringify(result.details, null, 2)})`);
//     }
// })();