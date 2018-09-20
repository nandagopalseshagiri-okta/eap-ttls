package com.okta.radius.eap;

import org.tinyradius.packet.RadiusPacket;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import static com.okta.radius.eap.TargetBoundAppProtocolContext.makeAppProtocolContext;

/**
 * Created by nandagopal.seshagiri on 8/10/18.
 */
public class SSLEngineSocketLessHandshake {

    public static class Pair<A, B> {
        public final A fst;
        public final B snd;

        public Pair(A var1, B var2) {
            this.fst = var1;
            this.snd = var2;
        }

        public String toString() {
            return "Pair[" + this.fst + "," + this.snd + "]";
        }

        public boolean equals(Object var1) {
            return var1 instanceof Pair && Objects.equals(this.fst, ((Pair)var1).fst) && Objects.equals(this.snd, ((Pair)var1).snd);
        }

        public int hashCode() {
            return this.fst == null?(this.snd == null?0:this.snd.hashCode() + 1):(this.snd == null?this.fst.hashCode() + 2:this.fst.hashCode() * 17 + this.snd.hashCode());
        }

        public static <A, B> Pair<A, B> of(A var0, B var1) {
            return new Pair(var0, var1);
        }
    }


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

    public interface RadiusRequestPacketProvider {
        RadiusPacket getRequestPacket();
        void setRequestPacket(RadiusPacket packet);
    }

    public static class MemQueuePipe implements StreamUtils.ByteBufferOutputStream, StreamUtils.ByteBufferInputStream {

        private BlockingQueue<Pair<ByteBuffer,RadiusPacket>> byteBufferBlockingQueue;

        private RadiusRequestPacketProvider radiusRequestPacketProvider;

        public MemQueuePipe() {
            byteBufferBlockingQueue = new ArrayBlockingQueue<>(50);
        }

        public ByteBuffer read() {
            try {
                Pair<ByteBuffer, RadiusPacket> packetPair = byteBufferBlockingQueue.take();
                if (radiusRequestPacketProvider != null) {
                    radiusRequestPacketProvider.setRequestPacket(packetPair.snd);
                }

                ByteBuffer buffer = packetPair.fst;
                buffer.flip();
                return buffer;
            } catch (InterruptedException e) {
                return null;
            }
        }

        public void write(ByteBuffer byteBuffer) {
            write(byteBuffer, null);
        }

        public void write(ByteBuffer byteBuffer, RadiusPacket radiusPacket) {
            // Assume a flipped ByteBuffer
            ByteBuffer buffer = clone(byteBuffer);
            byteBufferBlockingQueue.add(new Pair<>(buffer, radiusPacket));
        }

        public static ByteBuffer clone(ByteBuffer original) {
            ByteBuffer clone = ByteBuffer.allocate(original.limit());
            clone.put(original.array(), 0, original.limit());
            return clone;
        }

        void setRadiusRequestPacketProvider(RadiusRequestPacketProvider rrpp) {
            radiusRequestPacketProvider = rrpp;
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
                if (!unwrapBuffer.hasRemaining()) {
                    log("---- " + name + " Read start -----");
                    ByteBuffer peerData = inputStream.read();
                    if (peerData == null) {
                        log("Input stream returned a null byte buffer");
                        break;
                    }

                    log(name + ": read buffer with limit=" + peerData.limit());

                    unwrapBuffer.put(peerData);
                    unwrapBuffer.flip();
                }

                sslEngineResult = sslEngine.unwrap(unwrapBuffer, incomingPlainBuffer);
                log(name + " unwrap: ", sslEngineResult);
                runDelegatedTasks(sslEngineResult, sslEngine);
                log ("unwrapBuffer position/limit = " + unwrapBuffer.position() + "/" + unwrapBuffer.limit());
                if (!unwrapBuffer.hasRemaining()) {
                    unwrapBuffer.compact();
                }
            }

            if (dataSent) {
                break;
            }
        }
    }

    private ByteBuffer sslEnginePeerLoopEx(String name, SSLEngine sslEngine, ByteBuffer appData, StreamUtils.ByteBufferOutputStream outputStream,
                                   StreamUtils.ByteBufferInputStream inputStream) throws Exception {
        SSLByteBufferIOStream sslByteBufferIOStream = new SSLByteBufferIOStream(sslEngine, outputStream, inputStream, name);

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
        private static final int MAX_BUFFER_LIMIT = 16 * 1024 * 1024;
        private boolean sslHandShakeDone = false;
        private SSLEngine sslEngine;
        private StreamUtils.ByteBufferOutputStream outputStream;
        private StreamUtils.ByteBufferInputStream inputStream;

        private int netBufferMax = 4096;
        private int appBufferMax = 4096;
        private String name;
        private boolean hasUnreadData = false;

        public SSLByteBufferIOStream(SSLEngine se, StreamUtils.ByteBufferOutputStream outStream,
                                     StreamUtils.ByteBufferInputStream inStream,
                                     String nameForLogging) {
            sslEngine = se;
            outputStream = outStream;
            inputStream = inStream;

            SSLSession session = se.getSession();
            appBufferMax = session.getApplicationBufferSize();
            netBufferMax = session.getPacketBufferSize();

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

        public static ByteBuffer expand(ByteBuffer existing) {
            int newCapacity = existing.capacity() * 2;
            if (newCapacity > MAX_BUFFER_LIMIT) {
                throw new RuntimeException("Buffer limit cannot be expanded to - " + newCapacity);
            }

            ByteBuffer newBuffer = ByteBuffer.allocate(newCapacity);
            existing.flip();
            newBuffer.put(existing);
            return newBuffer;
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
                } else if (sslEngineResult.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    outgoingEncBuffer = expand(outgoingEncBuffer);
                } else if (sslEngineResult.getStatus() != SSLEngineResult.Status.OK) {
                    log("SSL engine wrap status is not OK " + sslEngineResult.getStatus());
                }

                if (outgoingEncBuffer.position() <= 0) {
                    log(name + " Writing outgoingEncBuffer with sub zero length=" + outgoingEncBuffer.position());
                } else {
                    if (sslHandShakeDone && dummyData) {
                        break;
                    }
                    if (sslHandShakeDone || (!hasUnreadData &&
                            sslEngineResult.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_WRAP)) {
                        // Explaining here when we do not want to write to output stream,
                        // If there is unread data from last unwrap then we should wait and consume it before
                        // sending out wrapped output because there could be more wrapped data after we consume
                        // the data from remote peer via next unwrap call.
                        // Or, if the handshake result comes out as NEED_WRAP - loop and call wrap again to get more
                        // data before sending out the partial data.

                        // If we are done with handshaking don't look at anything - just send the output buffer from
                        // wrap
                        outgoingEncBuffer.flip();
                        outputStream.write(outgoingEncBuffer);
                        outgoingEncBuffer.clear();
                    }
                }

                if (sslEngineResult.bytesConsumed() >= appData.limit()) {
                    dataSent = true;
                    log(name + ": sent all the application data. sslEngineResult.bytesConsumed = " + sslEngineResult.bytesConsumed());
                }

                if (sslEngineResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                    unwrap(unwrapBuffer);
                    if (!hasUnreadData) {
                        unwrapBuffer.clear();
                    } else {
                        log("not all the data was unwrapped - so will skip read until all is read. remaining = " + unwrapBuffer.remaining());
                    }
                }

                if (dataSent) {
                    break;
                }
            }
        }

        private ByteBuffer unwrap(ByteBuffer unwrapBuffer) throws Exception {
            if (!hasUnreadData) {
                log("---- " + name + " Read start -----");
                ByteBuffer peerData = inputStream.read();
                if (peerData == null) {
                    log("Input stream returned a null byte buffer");
                    return null;
                }

                unwrapBuffer.put(peerData);
                unwrapBuffer.flip();

                log(name + ": read buffer with limit=" + peerData.limit());
            }

            ByteBuffer incomingPlainBuffer = ByteBuffer.allocate(appBufferMax + 50);
            int totalBytes = unwrapBuffer.limit() - unwrapBuffer.position();
            SSLEngineResult sslEngineResult = sslEngine.unwrap(unwrapBuffer, incomingPlainBuffer);
            hasUnreadData = totalBytes > sslEngineResult.bytesConsumed();
            log(name + " unwrap: ", sslEngineResult);
            runDelegatedTasks(sslEngineResult, sslEngine);

            return incomingPlainBuffer;
        }
    }

    private void createOutputStreams() {
        MemQueuePipe clientOutServerIn = new MemQueuePipe();
        clientOutstream = clientOutServerIn;
        serverInStream = clientOutServerIn;

        MemQueuePipe clientInServerOut = new MemQueuePipe();
        clientInStream = clientInServerOut;
        serverOutStream = clientInServerOut;
    }

    private static final int port = 2005;

    private DatagramSocket socket;
    private TLSTransceiver tlsTransceiver;
    private EAPStackBuilder.UdpByteBufferStream readStream;

    private void createUdpOutputStreams() {
        try {
            AppProtocolContext contextServer = makeAppProtocolContext(256, "Server", true);
            AppProtocolContext contextClient = makeAppProtocolContext(256, "Client", false);
            socket = new DatagramSocket(port);
            EAPStackBuilder.ByteBufferSinkNSource server = EAPStackBuilder.makeUdpReadWritePair(socket, contextServer);
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

    private ByteBufferReceiver createTransceivers(ByteBufferReceiver finalReceiver) {
        try {
            // make sure createUdpOutputStreams - is called before this - as this depends on socket
            // being initialized.
            AppProtocolContext contextServer = makeAppProtocolContext(256, "Server", true);
            readStream = new EAPStackBuilder.UdpByteBufferStream(socket);
            EAPStackBuilder.UdpFlusher udpFlusher = new EAPStackBuilder.UdpFlusher(socket, readStream);
            tlsTransceiver = new TLSTransceiver(serverEngine, "server", null, finalReceiver);
            EAPTTLSTransceiver eapttlsTransceiver = new EAPTTLSTransceiver(contextServer, tlsTransceiver, udpFlusher);
            tlsTransceiver.chain((ByteBufferTransmitter) eapttlsTransceiver);
            return eapttlsTransceiver;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void runServer(ByteBufferReceiver eapttls) {
        final boolean[] condition = new boolean[] {true};
        tlsTransceiver.chain(new ByteBufferReceiver() {
            @Override
            public void receive(ByteBuffer buffer) {
                assertTrue(Arrays.equals(clientOut.array(), Arrays.copyOfRange(buffer.array(), 0, buffer.limit())));
                log("Received app data");
                condition[0] = false;
            }
        });
        while (condition[0]) {
            ByteBuffer bb = readStream.read();
            System.out.println("Server read data length = " + bb.remaining());
            eapttls.receive(bb);
        }
    }

    private void performSocketLessSSL() throws Exception {
        createSSLEngines();
        createBuffers();

        //logging = false;
        //createOutputStreams();
        createUdpOutputStreams();

        final ByteBufferReceiver eapttlsReceiver = createTransceivers(null);

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
                    runServer(eapttlsReceiver);
//                    ByteBuffer buffer = sslEnginePeerLoopEx("server", serverEngine, serverOut, serverOutStream, serverInStream);
//                    buffer.flip();
//                    assertTrue(Arrays.equals(clientOut.array(), Arrays.copyOfRange(buffer.array(), 0, buffer.limit())));
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
        serverEngine.setNeedClientAuth(false);

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

    public static SSLEngineResult.HandshakeStatus runDelegatedTasks(SSLEngineResult result,
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
            return hsStatus;
        }

        return result.getHandshakeStatus();
    }

    public static boolean isEngineClosed(SSLEngine engine) {
        return (engine.isOutboundDone() && engine.isInboundDone());
    }

    public static void log(String str, SSLEngineResult result) {
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

    public static void log(String str) {
        if (logging) {
            System.out.println(str);
        }
    }
}