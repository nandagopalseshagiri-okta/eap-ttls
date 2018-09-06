package com.okta.radius.eap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import static com.okta.radius.eap.TargetBoundAppProtocolContext.makeAppProtocolContext;

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

    private int netBufferMax = 4096;
    private int appBufferMax = 4096;

    private StreamUtils.ByteBufferOutputStream clientOutstream;
    private StreamUtils.ByteBufferInputStream clientInStream;

    private StreamUtils.ByteBufferOutputStream serverOutStream;
    private StreamUtils.ByteBufferInputStream serverInStream;

    private SSLContextInitializer sslContextInitializer;

    public static class MemQueuePipe implements StreamUtils.ByteBufferOutputStream, StreamUtils.ByteBufferInputStream {

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
            // Assume a flipped ByteBuffer
            ByteBuffer buffer = clone(byteBuffer);
            byteBufferBlockingQueue.add(buffer);
        }

        public static ByteBuffer clone(ByteBuffer original) {
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
        String keyStoreFile = "/Users/nandagopal.seshagiri/keystore.jks";
        String passwd = "password";

        sslContextInitializer = new SSLContextInitializer(keyStoreFile, keyStoreFile, passwd);
        sslc = sslContextInitializer.getSslc();
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
            outgoingEncBuffer.flip();
            if (outgoingEncBuffer.limit() <= 0) {
                log(name + " Writing outgoingEncBuffer with sub zero length=" + outgoingEncBuffer.limit());
            } else {
                outputStream.write(outgoingEncBuffer);
            }

            outgoingEncBuffer.clear();

            if (sslEngineResult.bytesConsumed() >= appData.limit()) {
                dataSent = true;
                log(name + ": sent all the application data. sslEngineResult.bytesConsumed = " + sslEngineResult.bytesConsumed());
            }

            if (sslEngineResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
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
            }

            if (dataSent) {
                break;
            }
        }
    }

    private ByteBuffer sslEnginePeerLoopEx(String name, SSLEngine sslEngine, ByteBuffer appData, StreamUtils.ByteBufferOutputStream outputStream,
                                   StreamUtils.ByteBufferInputStream inputStream) throws Exception {
        SSLByteBufferIOStream sslByteBufferIOStream = new SSLByteBufferIOStream(sslEngine, outputStream, inputStream,
                netBufferMax, appBufferMax, name);

        ByteBuffer result = null;
        if ("server".equals(name)) {
            result = sslByteBufferIOStream.read();
        } else {
            sslByteBufferIOStream.write(appData);
        }

        return result;
    }

    public static class SSLByteBufferIOStream implements StreamUtils.ByteBufferOutputStream,
            StreamUtils.ByteBufferInputStream {
        private boolean sslHandShakeDone = false;
        private SSLEngine sslEngine;
        private StreamUtils.ByteBufferOutputStream outputStream;
        private StreamUtils.ByteBufferInputStream inputStream;

        private int netBufferMax = 4096;
        private int appBufferMax = 4096;
        private String name;

        public SSLByteBufferIOStream(SSLEngine se, StreamUtils.ByteBufferOutputStream outStream,
                                     StreamUtils.ByteBufferInputStream inStream, int netBuffer, int appBuffer,
                                     String nameForLogging) {
            sslEngine = se;
            outputStream = outStream;
            inputStream = inStream;
            netBufferMax = netBuffer;
            appBufferMax = appBuffer;
            name = nameForLogging;
        }

        @Override
        public void write(ByteBuffer byteBuffer) {
            try {
                handshakeLoop(byteBuffer, false);
            } catch (Exception e) {
                throw new TTLSProtocolException("Write to SSL outstream failed", e);
            }
        }

        @Override
        public ByteBuffer read() {
            ByteBuffer unwrapBuffer = ByteBuffer.allocate(netBufferMax * 2);
            try {
                if (!sslHandShakeDone) {
                    handshakeLoop(ByteBuffer.wrap(new byte[]{0}), true);
                }
                return unwrap(unwrapBuffer);
            } catch (Exception e) {
                throw new TTLSProtocolException("Read from SSL stream failed", e);
            }
        }

        private void handshakeLoop(ByteBuffer appData, boolean dummyData) throws Exception {
            boolean dataSent = false;

            ByteBuffer outgoingEncBuffer = ByteBuffer.allocate(netBufferMax);

            SSLEngineResult sslEngineResult;
            ByteBuffer unwrapBuffer = ByteBuffer.allocate(netBufferMax * 2);
            unwrapBuffer.clear();

            while (!isEngineClosed(sslEngine)) {

                log("***** " + name + " Write start ******");

                sslEngineResult = sslEngine.wrap(appData, outgoingEncBuffer);
                log(name + " wrap: ", sslEngineResult);
                runDelegatedTasks(sslEngineResult, sslEngine);

                if (sslEngineResult.bytesConsumed() >= appData.limit() &&
                        (sslEngineResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED ||
                        sslEngineResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING)) {
                    // we are assuming that hand-shake data and app data will not be encrypted together
                    // inside the outgoingEncBuffer in one call to wrap.
                    sslHandShakeDone = true;
                }

                outgoingEncBuffer.flip();
                if (outgoingEncBuffer.limit() <= 0) {
                    log(name + " Writing outgoingEncBuffer with sub zero length=" + outgoingEncBuffer.limit());
                } else {
                    if (sslHandShakeDone && dummyData) {
                        break;
                    }
                    outputStream.write(outgoingEncBuffer);
                }

                outgoingEncBuffer.clear();

                if (sslEngineResult.bytesConsumed() >= appData.limit()) {
                    dataSent = true;
                    log(name + ": sent all the application data. sslEngineResult.bytesConsumed = " + sslEngineResult.bytesConsumed());
                }

                if (sslEngineResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                    log("---- " + name + " Read start -----");
                    unwrap(unwrapBuffer);
                    unwrapBuffer.compact();
                }

                if (dataSent) {
                    break;
                }
            }
        }

        private ByteBuffer unwrap(ByteBuffer unwrapBuffer) throws Exception {
            ByteBuffer peerData = inputStream.read();
            if (peerData == null) {
                log("Input stream returned a null byte buffer");
                return null;
            }

            unwrapBuffer.put(peerData);
            unwrapBuffer.flip();

            log(name + ": read buffer with limit=" + peerData.limit());

            ByteBuffer incomingPlainBuffer = ByteBuffer.allocate(appBufferMax + 50);
            SSLEngineResult sslEngineResult = sslEngine.unwrap(unwrapBuffer, incomingPlainBuffer);
            log(name + " unwrap: ", sslEngineResult);
            runDelegatedTasks(sslEngineResult, sslEngine);

            return incomingPlainBuffer;
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

    private void createUdpOutputStreams() {
        try {
            final int port = 2002;
            AppProtocolContext contextServer = makeAppProtocolContext(256, "Server", true);
            AppProtocolContext contextClient = makeAppProtocolContext(256, "Client", false);
            EAPStackBuilder.ByteBufferSinkNSource server = EAPStackBuilder.makeUdpReadWritePair(port, contextServer);
            EAPStackBuilder.ByteBufferSinkNSource client = EAPStackBuilder.makeUdpReadWritePair(port, InetAddress.getByName("127.0.0.1"),
                    contextClient);
            clientOutstream = client.outputStream;
            serverInStream = server.inputStream;

            clientInStream = client.inputStream;
            serverOutStream = server.outputStream;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void performSocketLessSSL() throws Exception {
        createSSLEngines();
        createBuffers();

        //logging = false;
        //createOutputStreams();
        createUdpOutputStreams();

        Thread client = new Thread(new Runnable() {
            public void run() {
                try {
                    sslEnginePeerLoopEx("client", clientEngine, clientOut, clientOutstream, clientInStream);
                } catch (Exception e) {
                    log("Client side exception = " + e);
                }
            }
        });

        Thread server = new Thread(new Runnable() {
            public void run() {
                try {
                    ByteBuffer buffer = sslEnginePeerLoopEx("server", serverEngine, serverOut, serverOutStream, serverInStream);
                    buffer.flip();
                    assertTrue(Arrays.equals(clientOut.array(), Arrays.copyOfRange(buffer.array(), 0, buffer.limit())));
                } catch (Exception e) {
                    log("server side exception = " + e);
                }
            }
        });

        server.start();
        Thread.sleep(1000);

        client.start();


        client.join();
        server.join();
    }

    private void assertTrue(boolean equals) {
        if (!equals) {
            throw new RuntimeException("Assertion failed");
        }
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