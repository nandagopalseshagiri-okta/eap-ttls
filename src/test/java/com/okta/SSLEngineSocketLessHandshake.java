package com.okta;

import com.okta.radius.eap.StreamUtils;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/**
 * Created by nandagopal.seshagiri on 8/10/18.
 */
public class SSLEngineSocketLessHandshake {

    private static boolean logging = true;

    private static boolean debug = false;

    private SSLContext sslc;

    private SSLEngine clientEngine;
    private ByteBuffer clientOut;

    private SSLEngine serverEngine;
    private ByteBuffer serverOut;

    private static String keyStoreFile = "/Users/nandagopal.seshagiri/keystore.jks";
    private static String trustStoreFile = keyStoreFile;
    private static String passwd = "password";

    private int netBufferMax = 4096;
    private int appBufferMax = 4096;

    private StreamUtils.ByteBufferOutputStream clientOutstream;
    private StreamUtils.ByteBufferInputStream clientInStream;

    private StreamUtils.ByteBufferOutputStream serverOutStream;
    private StreamUtils.ByteBufferInputStream serverInStream;

    private static class MemQueuePipe implements StreamUtils.ByteBufferOutputStream, StreamUtils.ByteBufferInputStream {
        private BlockingQueue<ByteBuffer> byteBufferBlockingQueue;

        public MemQueuePipe(BlockingQueue<ByteBuffer> queue) {
            byteBufferBlockingQueue = queue;
        }

        public ByteBuffer read() {
            try {
                ByteBuffer buffer = byteBufferBlockingQueue.take();
                buffer.flip();
                return buffer;
            } catch (InterruptedException e) {
                return null;
            }
        }

        public void write(ByteBuffer byteBuffer) {
            ByteBuffer buffer = clone(byteBuffer);
            byteBufferBlockingQueue.add(buffer);
        }

        public static ByteBuffer clone(ByteBuffer original) {
            original.flip();
            ByteBuffer clone = ByteBuffer.allocate(original.limit());
            clone.put(original.array(), 0, original.limit());
            return clone;
        }
    }

    public static void main(String args[]) throws Exception {
        if (debug) {
            System.setProperty("javax.net.debug", "all");
        }

        log("SSLEngineResult format is: \n" +
                "\t\"getStatus() / getHandshakeStatus()\" +\n" +
                "\t\"bytesConsumed() / bytesProduced()\"\n");

        SSLEngineSocketLessHandshake socketLessHandshake = new SSLEngineSocketLessHandshake();
        socketLessHandshake.performSocketLessSSL();

        System.out.println("Handshake Completed.");
    }

    public SSLEngineSocketLessHandshake() throws Exception {

        KeyStore ks = KeyStore.getInstance("JKS");
        KeyStore ts = KeyStore.getInstance("JKS");

        char[] passphrase = passwd.toCharArray();

        ks.load(new FileInputStream(keyStoreFile), passphrase);
        ts.load(new FileInputStream(trustStoreFile), passphrase);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, passphrase);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);

        SSLContext sslCtx = SSLContext.getInstance("TLS");

        sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        sslc = sslCtx;
    }

    // Loop until engine is close - wrap and then call unwrap
    // calling wrap with application data will initiate ssl hand shake (as the engine
    // would know it has not completed hand shake)
    // The hand shake data like say client hello (if the engine is in server mode there will not
    // be anything returned by wrap call - it would simple return NEED_UNWRAP the first time wrap is called)
    // would be returned as output buffer - which will be transported to the server using in memory queue.
    //
    private void sslEnginePeerLoop(String name, SSLEngine sslEngine, ByteBuffer appData, StreamUtils.ByteBufferOutputStream outputStream,
                            StreamUtils.ByteBufferInputStream inputStream) throws Exception {
        boolean dataSent = false;


        ByteBuffer outgoingEncBuffer = ByteBuffer.allocate(netBufferMax);
        ByteBuffer incomingPlainBuffer = ByteBuffer.allocate(appBufferMax + 50);

        SSLEngineResult sslEngineResult;
        ByteBuffer unwrapBuffer = ByteBuffer.allocate(netBufferMax * 2);
        unwrapBuffer.clear();

        while (!isEngineClosed(sslEngine)) {

            log("***** " + name + " Write start ******");

            sslEngineResult = sslEngine.wrap(appData, outgoingEncBuffer);
            log(name + " wrap: ", sslEngineResult);
            runDelegatedTasks(sslEngineResult, sslEngine);
            outputStream.write(outgoingEncBuffer);

            outgoingEncBuffer.clear();

            if (sslEngineResult.bytesConsumed() >= appData.limit()) {
                dataSent = true;
                log(name + ": sent all the application data. sslEngineResult.bytesConsumed = " + sslEngineResult.bytesConsumed());
            }

            log("---- " + name + " Read start -----");

            ByteBuffer peerData = inputStream.read();
            if (peerData == null) {
                log("Input stream returned a null byte buffer");
                break;
            }

            unwrapBuffer.put(peerData);
            unwrapBuffer.flip();

            log(name + ": read buffer with limit=" + peerData.limit());

            sslEngineResult = sslEngine.unwrap(unwrapBuffer, incomingPlainBuffer);
            log(name + " unwrap: ", sslEngineResult);
            runDelegatedTasks(sslEngineResult, sslEngine);
            unwrapBuffer.compact();

            if (dataSent) {
                break;
            }
        }
    }

    private void createOutputStreams() {
        MemQueuePipe clientOutServerIn = new MemQueuePipe(new ArrayBlockingQueue<ByteBuffer>(16));
        clientOutstream = clientOutServerIn;
        serverInStream = clientOutServerIn;

        MemQueuePipe clientInServerOut = new MemQueuePipe(new ArrayBlockingQueue<ByteBuffer>(16));
        clientInStream = clientInServerOut;
        serverOutStream = clientInServerOut;
    }

    private void performSocketLessSSL() throws Exception {
        boolean dataDone = false;

        createSSLEngines();
        createBuffers();

        createOutputStreams();

        Thread client = new Thread(new Runnable() {
            public void run() {
                try {
                    sslEnginePeerLoop("client", clientEngine, clientOut, clientOutstream, clientInStream);
                } catch (Exception e) {
                    log("Client side exception = " + e);
                }
            }
        });

        Thread server = new Thread(new Runnable() {
            public void run() {
                try {
                    sslEnginePeerLoop("server", serverEngine, serverOut, serverOutStream, serverInStream);
                } catch (Exception e) {
                    log("server side exception = " + e);
                }
            }
        });

        client.start();
        server.start();

        client.join();
        server.join();
    }

    private void createSSLEngines() throws Exception {
        serverEngine = sslc.createSSLEngine();
        serverEngine.setUseClientMode(false);
        serverEngine.setNeedClientAuth(true);

        clientEngine = sslc.createSSLEngine("client", 80);
        clientEngine.setUseClientMode(true);
    }

    private void createBuffers() {
        SSLSession session = clientEngine.getSession();
        appBufferMax = session.getApplicationBufferSize();
        netBufferMax = session.getPacketBufferSize();

        clientOut = ByteBuffer.wrap("a".getBytes());
        serverOut = ByteBuffer.wrap("b".getBytes());
    }

    private static void runDelegatedTasks(SSLEngineResult result,
                                          SSLEngine engine) throws Exception {

        if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                log("   running delegated task...");
                runnable.run();
            }
            SSLEngineResult.HandshakeStatus hsStatus = engine.getHandshakeStatus();
            if (hsStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                throw new Exception(
                        "handshake shouldn't need additional tasks");
            }
            log("   new HandshakeStatus: " + hsStatus);
        }
    }

    private static boolean isEngineClosed(SSLEngine engine) {
        return (engine.isOutboundDone() && engine.isInboundDone());
    }

    private static void log(String str, SSLEngineResult result) {
        if (!logging) {
            return;
        }

        SSLEngineResult.HandshakeStatus hsStatus = result.getHandshakeStatus();
        log(str +
                result.getStatus() + "/" + hsStatus + ", " +
                result.bytesConsumed() + "/" + result.bytesProduced() +
                " bytes");
        if (hsStatus == SSLEngineResult.HandshakeStatus.FINISHED) {
            log("\t...finished handshake - will transfer app data");
        }
    }

    private static void log(String str) {
        if (logging) {
            System.out.println(str);
        }
    }
}