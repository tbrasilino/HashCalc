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
    {
        name: 'SHA-1 (CryptoJS)',
        async hash(buffer) {
            const t0 = performance.now();
            const wordArray = CryptoJS.lib.WordArray.create(new Uint8Array(buffer));
            const hash = CryptoJS.SHA1(wordArray).toString(CryptoJS.enc.Hex);
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    {
        name: 'SHA-512 (CryptoJS)',
        async hash(buffer) {
            const t0 = performance.now();
            const wordArray = CryptoJS.lib.WordArray.create(new Uint8Array(buffer));
            const hash = CryptoJS.SHA512(wordArray).toString(CryptoJS.enc.Hex);
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
            if (!window.hashwasm) {
                console.error('hashwasm não encontrado:', window.hashwasm);
                throw new Error('hashwasm não encontrado');
            }
            const t0 = performance.now();
            try {
                const hash = await window.hashwasm.sha256(new Uint8Array(buffer));
                const t1 = performance.now();
                return { hash, time: t1 - t0 };
            } catch (e) {
                console.error('Erro hash-wasm SHA-256:', e);
                throw e;
            }
        }
    },
    {
        name: 'MD5 (hash-wasm)',
        async hash(buffer) {
            if (!window.hashwasm) {
                console.error('hashwasm não encontrado:', window.hashwasm);
                throw new Error('hashwasm não encontrado');
            }
            const t0 = performance.now();
            try {
                const hash = await window.hashwasm.md5(new Uint8Array(buffer));
                const t1 = performance.now();
                return { hash, time: t1 - t0 };
            } catch (e) {
                console.error('Erro hash-wasm MD5:', e);
                throw e;
            }
        }
    },
    // node-object-hash
        // sha.js
    // SJCL
    {
        name: 'SHA-256 (SJCL)',
        async hash(buffer) {
            if (!window.sjcl) {
                console.error('SJCL não encontrado:', window.sjcl);
                throw new Error('SJCL não encontrado');
            }
            const t0 = performance.now();
            try {
                // SJCL espera string ou bitArray. Vamos tentar string.
                const str = new TextDecoder().decode(buffer);
                const hash = window.sjcl.codec.hex.fromBits(window.sjcl.hash.sha256.hash(str));
                const t1 = performance.now();
                return { hash, time: t1 - t0 };
            } catch (e) {
                console.error('Erro SJCL:', e);
                throw e;
            }
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
    },
    {
        name: 'SHA-1 (jsSHA)',
        async hash(buffer) {
            const t0 = performance.now();
            const shaObj = new jsSHA('SHA-1', 'ARRAYBUFFER');
            shaObj.update(buffer);
            const hash = shaObj.getHash('HEX');
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    {
        name: 'SHA-224 (jsSHA)',
        async hash(buffer) {
            const t0 = performance.now();
            const shaObj = new jsSHA('SHA-224', 'ARRAYBUFFER');
            shaObj.update(buffer);
            const hash = shaObj.getHash('HEX');
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    {
        name: 'SHA-256 (jsSHA)',
        async hash(buffer) {
            const t0 = performance.now();
            const shaObj = new jsSHA('SHA-256', 'ARRAYBUFFER');
            shaObj.update(buffer);
            const hash = shaObj.getHash('HEX');
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    {
        name: 'SHA-384 (jsSHA)',
        async hash(buffer) {
            const t0 = performance.now();
            const shaObj = new jsSHA('SHA-384', 'ARRAYBUFFER');
            shaObj.update(buffer);
            const hash = shaObj.getHash('HEX');
            const t1 = performance.now();
            return { hash, time: t1 - t0 };
        }
    },
    {
        name: 'SHA-512 (jsSHA)',
        async hash(buffer) {
            const t0 = performance.now();
            const shaObj = new jsSHA('SHA-512', 'ARRAYBUFFER');
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
            console.error(`Erro em ${fn.name}:`, e);
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
    // Ordenar por tamanho do hash (menor para maior)
    results.sort((a, b) => a.hash.length - b.hash.length);
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = '<h2>Resultados</h2>' +
        '<ul>' + results.map(r => `<li><b>${r.name}:</b> ${r.hash} <br><i>${r.time.toFixed(2)} ms</i></li>`).join('') + '</ul>';
}

function plotChart(results) {
    // Ordenar por tamanho do hash (menor para maior)
    results.sort((a, b) => a.hash.length - b.hash.length);
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

    // Inicializar Pyodide
    let pyodide = null;
    try {
        pyodide = await loadPyodide();
        await pyodide.runPythonAsync(`
import sys
sys.path.append('.')
`);
    } catch (e) {
        console.warn('Pyodide não carregou:', e);
    }

    // Inicializar Opal
    let opal = null;
    try {
        opal = Opal;
    } catch (e) {
        console.warn('Opal não carregou:', e);
    }

    document.getElementById('uploadForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const file = document.getElementById('fileInput').files[0];
        if (!file) return;
        document.getElementById('results').innerHTML = 'Calculando...';

        const language = document.getElementById('languageSelect').value;
        let results = [];

        if (language === 'js') {
            results = await runBenchmarks(file);
        } else if (language === 'ts') {
            // Load TS compiled JS
            await loadScript('app_ts.js');
            results = await window.runBenchmarksTS(file);
        } else if (language === 'py' && pyodide) {
            const fileData = await file.arrayBuffer();
            const uint8Array = new Uint8Array(fileData);
            // Load app.py
            const response = await fetch('app.py');
            const pyCode = await response.text();
            await pyodide.runPythonAsync(pyCode);
            pyodide.globals.set('file_bytes', uint8Array);
            const pyResults = await pyodide.runPythonAsync(`
results = benchmark(file_bytes)
results
`);
            results = pyResults.toJs();
        } else if (language === 'rb' && opal) {
            const fileData = await file.arrayBuffer();
            const uint8Array = new Uint8Array(fileData);
            // Load app.rb
            const response = await fetch('app.rb');
            const rbCode = await response.text();
            Opal.eval(rbCode);
            const rbResults = Opal.eval(`benchmark(${JSON.stringify(Array.from(uint8Array))})`);
            results = rbResults.$to_a().map(r => ({
                name: r.$fetch('name'),
                hash: r.$fetch('hash'),
                time: r.$fetch('time')
            }));
        } else {
            alert('Linguagem não suportada ou não carregada.');
            return;
        }

        saveResultsToLocalStorage(results);
        showResults(results);
        plotChart(results);
    });
}

main();
