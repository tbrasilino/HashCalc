// app_ts.js - Compiled TypeScript
// Similar to app.js

// ... existing code from app.js but with TS types in comments

const hashFunctions = [
    // Web Crypto API
    {
        name: 'SHA-1 (WebCrypto TS)',
        async hash(buffer) {
            const t0 = performance.now();
            const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
            const t1 = performance.now();
            return { name: 'SHA-1 (WebCrypto TS)', hash: bufferToHex(hashBuffer), time: t1 - t0 };
        }
    },
    // Add more...
];

function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function runBenchmarksTS(file) {
    const arrayBuffer = await file.arrayBuffer();
    const results = [];
    for (const fn of hashFunctions) {
        try {
            const { hash, time } = await fn.hash(arrayBuffer);
            results.push({ name: fn.name, hash, time });
        } catch (e) {
            results.push({ name: fn.name, hash: 'Erro', time: 0 });
        }
    }
    return results;
}

window.runBenchmarksTS = runBenchmarksTS;