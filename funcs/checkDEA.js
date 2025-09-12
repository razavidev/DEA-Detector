import { promises as dns } from "dns";
import fs from 'fs/promises';
import path from "path";

const getData = async function (d) {
    const txt = await dns.resolveTxt(d);
    const mx = await dns.resolveMx(d);
    const aaaa = await dns.resolve6(d);
    const aa = await dns.resolve4(d);

    console.log('TXT: ===========================================================');
    console.log(txt);
    console.log('MX: ===========================================================');
    console.log(mx);
    console.log('IPv6: ===========================================================');
    console.log(aaaa);
    console.log('IPv4============================================================');
    console.log(aa);
};


async function searchBlacklist(value) {
    let blacklistSet;
    try {
        const listFilePath = '../files/blacklist.txt';
        console.log(path);
        const fileContent = await fs.readFile(listFilePath, 'utf8');
        const items = fileContent.split('\n').map(item => item.trim());
        blacklistSet = new Set(items);
    } catch (error) {
        throw new Error('Error loading the blacklist file: ' + error.message);
    }
    // console.log('isBlacklisted: '+blacklistSet.has(value.trim()))
    return blacklistSet.has(value.trim());
}

function shannonEntropy(s) {
    if (s.length === 0) return 0;
    const frequencies = {};
    for (const char of s) {
        frequencies[char] = (frequencies[char] || 0) + 1;
    }

    let entropy = 0;
    const len = s.length;
    for (const char in frequencies) {
        const p = frequencies[char] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}


function checkStringRandomness(text) {
    if (text.length < 5) return 0.0;

    let score = 0.0;
    const normalizedText = text.toLowerCase();
    const len = text.length;

    const entropyWeight = 0.40;
    const varietyWeight = 0.25;
    const monobitWeight = 0.20;
    const runsWeight = 0.15;

    // Factor 1: Shannon Entropy
    const entropy = shannonEntropy(normalizedText);
    const maxPossibleEntropy = Math.log2(len) || 1;
    const normalizedEntropy = entropy / maxPossibleEntropy;
    score += normalizedEntropy * entropyWeight;

    // Factor 2: Character Variety and Distribution
    const hasLetters = /[a-zA-Z]/.test(normalizedText);
    const hasNumbers = /[0-9]/.test(normalizedText);
    const hasSymbols = /[^a-zA-Z0-9]/.test(normalizedText);
    const varietyCount = [hasLetters, hasNumbers, hasSymbols].filter(Boolean).length;
    score += (varietyCount / 3) * varietyWeight;

    // Factor 3: Monobit Test
    const halfLen = len / 2;
    let lowCharCount = 0;
    for (const char of normalizedText) {
        if (char.charCodeAt(0) < 100) {
            lowCharCount++;
        }
    }
    const monobitDeviation = Math.abs(lowCharCount - halfLen) / halfLen;
    score += (1 - monobitDeviation) * monobitWeight;

    // Factor 4: Longest Run Test
    let maxRun = 0;
    let currentRun = 0;
    for (let i = 0; i < len; i++) {
        if (i > 0 && text[i] === text[i - 1]) {
            currentRun++;
        } else {
            currentRun = 1;
        }
        if (currentRun > maxRun) {
            maxRun = currentRun;
        }
    }
    const runLengthRatio = maxRun / len;
    score -= runLengthRatio * runsWeight;

    return Math.max(0, Math.min(1.0, score));
}


// --- Main DEA Check Function ---

// Hardcoded list of major, trusted email providers.
const MAJOR_PROVIDERS = new Set([
    'gmail.com',
    'yahoo.com',
    'outlook.com',
    'hotmail.com',
    'aol.com',
    'icloud.com',
    'zoho.com'
]);


function getEmailParts(email) {
    const parts = email.split('@');
    return parts.length === 2 ? { localPart: parts[0], domain: parts[1].toLowerCase() } : null;
}


async function checkEmailForDEA(email) {
    let score = 0.0;
    const details = {
        domain: null,
        localPart: null,
        isMajorProvider: false,
        mxRecordsFound: false,
        suspiciousMxHostname: false,
        aaaaRecordsFound: false,
        spfRecordFound: false,
        isBlacklisted: false,
        shufflenessScore: 0,
    };

    const parts = getEmailParts(email);
    if (!parts) {
        return { score: 1.0, details: { ...details, error: 'Invalid email format.' } };
    }
    details.localPart = parts.localPart;
    details.domain = parts.domain;

    // --- Scoring Logic ---

    // Factor 1: Major Provider Check (Weight: 0.2)
    details.isMajorProvider = MAJOR_PROVIDERS.has(details.domain);
    if (!details.isMajorProvider) {
        score += 0.2;
    }

    // Factor 2: DNS Record Checks
    try {
        const mxRecords = await dns.resolveMx(details.domain);
        console.log(mxRecords);
        details.mxRecordsFound = mxRecords && mxRecords.length > 0;
        if (details.mxRecordsFound) {
            // Check for suspicious MX hostnames
            const mxHostname = mxRecords[0].exchange;
            const mxDomain = mxHostname.split('.').slice(-2).join('.');
            // If MX record doesn't point to major provider and hostname seems off
            if (!details.isMajorProvider && mxDomain !== details.domain && !MAJOR_PROVIDERS.has(mxDomain)) {
                // Heuristic for suspicious MX: generic names, known DEA indicators
                if (/(tempmail|guerrilla|mailinator)/i.test(mxHostname) || /^mx\./.test(mxHostname)) {
                    details.suspiciousMxHostname = true;
                    score += 0.2; // Significant penalty
                }
            }
        }
    } catch (e) {
        if (e.code === 'ENODATA' || e.code === 'NODATA') {
            score += 0.3; // High penalty for no MX
        } else {
            score += 0.3;
        }
    }

    try {
        const txtRecords = await dns.resolveTxt(details.domain);
        console.log(txtRecords);
        details.spfRecordFound = txtRecords.some(
            record => record.some(txt => txt.startsWith('v=spf1'))
        );
        if (!details.spfRecordFound) {
            score += 0.1;
        }
    } catch (e) {
        if (e.code === 'ENODATA' || e.code === 'NODATA') {
            score += 0.1;
        }
    }

    try {
        await dns.resolve6(details.domain);
        details.aaaaRecordsFound = true;
    } catch (e) {
        if (e.code === 'ENODATA' || e.code === 'NODATA') {
            score += 0.05;
        }
    }

    // Factor 3: Local Part Randomness (Weight: 0.3)
    const shufflenessScore = checkStringRandomness(details.localPart);
    details.shufflenessScore = shufflenessScore;
    score += shufflenessScore * 0.3;

    // Factor 4: Is Domain Blacklisted (Weight: 0.7)
    const isBlacklisted = await searchBlacklist(details.domain);
    details.isBlacklisted = isBlacklisted;
    score += isBlacklisted ? 0.7 : 0;

    // Cap score at 1.0
    const finalScore = Math.min(1.0, score);
    return { isDEA: finalScore > 0.70, details };
}

export default checkEmailForDEA;