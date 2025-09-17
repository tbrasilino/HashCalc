// app.js
// Bibliotecas de hash: crypto.subtle (SHA), SparkMD5, jsSHA, etc.
// SparkMD5: https://cdnjs.cloudflare.com/ajax/libs/spark-md5/3.0.2/spark-md5.min.js
// jsSHA: https://cdnjs.cloudflare.com/ajax/libs/jsSHA/3.2.0/sha.js

// Carregar bibliotecas externas dinamicamente
function loadScript(url) {
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = url;
        script.onload = resolve;
        script.onerror = reject;
        document.head.appendChild(script);
    });
}

const hashFunctions = [
    // Web Crypto API
    {
        name: 'SHA-1 (WebCrypto)',
        async hash(buffer) {
            const t0 = performance.now();
            const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
            const t1 = performance.now();
            return { hash: bufferToHex(hashBuffer), time: t1 - t0 };
        }
    },
    {
        name: 'SHA-256 (WebCrypto)',
        async hash(buffer) {
            const t0 = performance.now();
            const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
            const t1 = performance.now();
            return { hash: bufferToHex(hashBuffer), time: t1 - t0 };
        }
    },
    {
        name: 'SHA-512 (WebCrypto)',
        async hash(buffer) {
            const t0 = performance.now();
            const hashBuffer = await crypto.subtle.digest('SHA-512', buffer);
            const t1 = performance.now();
            return { hash: bufferToHex(hashBuffer), time: t1 - t0 };
        }
    },
    // CryptoJS
    {
        name: 'SHA-256 (CryptoJS)',
        async hash(buffer) {
            const t0 = performance.now();
            const wordArray = CryptoJS.lib.WordArray.create(new Uint8Array(buffer));
            const hash = CryptoJS.SHA256(wordArray).toString(CryptoJS.enc.Hex);
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    {
        name: 'MD5 (CryptoJS)',
        async hash(buffer) {
            const t0 = performance.now();
            const wordArray = CryptoJS.lib.WordArray.create(new Uint8Array(buffer));
            const hash = CryptoJS.MD5(wordArray).toString(CryptoJS.enc.Hex);
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    // js-sha256
    {
        name: 'SHA-256 (js-sha256)',
        async hash(buffer) {
            const t0 = performance.now();
            const hash = sha256(new Uint8Array(buffer));
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    // hash-wasm
    {
        name: 'SHA-256 (hash-wasm)',
        async hash(buffer) {
            const t0 = performance.now();
            const hash = await hashwasm.sha256(new Uint8Array(buffer));
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    {
        name: 'MD5 (hash-wasm)',
        async hash(buffer) {
            const t0 = performance.now();
            const hash = await hashwasm.md5(new Uint8Array(buffer));
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    // node-object-hash
    {
        name: 'Object Hash (node-object-hash)',
        async hash(buffer) {
            const t0 = performance.now();
            const objHash = objectHash();
            const hash = objHash.hash(Array.from(new Uint8Array(buffer)));
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    // SJCL
    {
        name: 'SHA-256 (SJCL)',
        async hash(buffer) {
            const t0 = performance.now();
            const bitArray = sjcl.codec.bytes.toBits(Array.from(new Uint8Array(buffer)));
            const hash = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(bitArray));
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    // hash.js
    {
        name: 'SHA-256 (hash.js)',
        async hash(buffer) {
            const t0 = performance.now();
            const hash = hashjs.sha256().update(new Uint8Array(buffer)).digest('hex');
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    // sha.js
    {
        name: 'SHA-256 (sha.js)',
        async hash(buffer) {
            const t0 = performance.now();
            const hash = (new window.sha256()).update(new Uint8Array(buffer)).digest('hex');
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    // md5
    {
        name: 'MD5 (md5)',
        async hash(buffer) {
            const t0 = performance.now();
            const hash = md5(new Uint8Array(buffer));
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    // js-md5
    {
        name: 'MD5 (js-md5)',
        async hash(buffer) {
            const t0 = performance.now();
            const hash = md5_2(new Uint8Array(buffer));
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    // SparkMD5
    {
        name: 'MD5 (SparkMD5)',
        async hash(buffer) {
            const t0 = performance.now();
            const hex = SparkMD5.ArrayBuffer.hash(buffer);
            const t1 = performance.now();
            return { hash: hex, time: t1 - t0 };
        }
    },
    // jsSHA
    {
        name: 'SHA-3-512 (jsSHA)',
        async hash(buffer) {
            const t0 = performance.now();
            const shaObj = new jsSHA('SHA3-512', 'ARRAYBUFFER');
            shaObj.update(buffer);
            const hash = shaObj.getHash('HEX');
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    }
];
// js-md5 e md5 possuem nomes conflitantes, então criamos um alias para js-md5
const md5_2 = window.md5 || window['md5'];

function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function runBenchmarks(file) {
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

function saveResultsToLocalStorage(results) {
    const prev = JSON.parse(localStorage.getItem('hashBenchmarks') || '[]');
    prev.push({ date: new Date().toISOString(), results });
    localStorage.setItem('hashBenchmarks', JSON.stringify(prev));
}

function showResults(results) {
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = '<h2>Resultados</h2>' +
        '<ul>' + results.map(r => `<li><b>${r.name}:</b> ${r.hash} <br><i>${r.time.toFixed(2)} ms</i></li>`).join('') + '</ul>';
}

function plotChart(results) {
    const ctx = document.getElementById('hashChart').getContext('2d');
    if (window.hashChartInstance) window.hashChartInstance.destroy();
    window.hashChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: results.map(r => r.name),
            datasets: [{
                label: 'Tempo de cálculo (ms)',
                data: results.map(r => r.time),
                backgroundColor: 'rgba(54, 162, 235, 0.6)'
            }]
        },
        options: {
            responsive: false,
            plugins: {
                legend: { display: false },
                title: { display: true, text: 'Tempo de cálculo dos Hashes' }
            },
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
}

async function main() {
    // Carregar SparkMD5 e jsSHA
    await loadScript('https://cdnjs.cloudflare.com/ajax/libs/spark-md5/3.0.2/spark-md5.min.js');
    await loadScript('https://cdnjs.cloudflare.com/ajax/libs/jsSHA/3.2.0/sha.js');

    document.getElementById('uploadForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const file = document.getElementById('fileInput').files[0];
        if (!file) return;
        document.getElementById('results').innerHTML = 'Calculando...';
        const results = await runBenchmarks(file);
        saveResultsToLocalStorage(results);
        showResults(results);
        plotChart(results);
    });
}

main();
