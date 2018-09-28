package com.okta.radius.eap;

import com.google.common.base.Charsets;
import org.tinyradius.attribute.RadiusAttribute;
import org.tinyradius.attribute.VendorSpecificAttribute;
import org.tinyradius.packet.RadiusPacket;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * Created by nandagopal.seshagiri on 8/28/18.
 */
public class EAPOrchestrator implements EAPMessageHandler {

    static byte[] generateKeyingMaterial(SSLEngine sslEngine, Object handShaker) {
        try {
            Class handShakerClass = handShaker.getClass().getSuperclass();

            Field clientRandomField = handShakerClass.getDeclaredField("clnt_random");
            clientRandomField.setAccessible(true);

            Field serverRandomField = handShakerClass.getDeclaredField("svr_random");
            serverRandomField.setAccessible(true);

            Object clientRandom = clientRandomField.get(handShaker);
            Object serverRandom = serverRandomField.get(handShaker);

            SSLSession session = sslEngine.getSession();
            Field masterSecretField = session.getClass().getDeclaredField("masterSecret");
            masterSecretField.setAccessible(true);

            Object masterSecret = masterSecretField.get(session);
            Field keyField = masterSecret.getClass().getDeclaredField("key");
            keyField.setAccessible(true);

            Object keyBytes = keyField.get(masterSecret);

            Field randomBytesField = clientRandom.getClass().getDeclaredField("random_bytes");
            randomBytesField.setAccessible(true);

            byte[] clientRandBytes = (byte[]) randomBytesField.get(clientRandom);
            byte[] serverRandBytes = (byte[]) randomBytesField.get(serverRandom);

            Class tlsPRFGenerator = Class.forName("com.sun.crypto.provider.TlsPrfGenerator");
            Method tls10PRF = tlsPRFGenerator.getDeclaredMethod("doTLS10PRF", new Class[] {byte[].class, byte[].class, byte[].class, int.class});
            tls10PRF.setAccessible(true);

            return (byte[]) tls10PRF.invoke(null, keyBytes, "ttls keying material".getBytes(Charsets.UTF_8),
                    concat(clientRandBytes, serverRandBytes), new Integer(128));
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Cannot get keying material from TLS session", e);
        }
    }

    private static byte[] packAsMSMPPEKey(byte[] key, int offset, int length, byte[] sharedSecret,
                                          byte[] requestAuthenticator) {
        byte[] zeros = new byte[15];
        StreamUtils.DataCollector bos = new StreamUtils.DataCollector(2 * length);
        bos.write(length);
        bos.write(key, offset, length);

        int paddingLen = 16 - (length + 1) % 16;
        bos.write(zeros, 0, paddingLen);

        byte[] salt = new byte[2];
        new SecureRandom().nextBytes(salt);

        byte[] c = concat(requestAuthenticator, salt);

        MessageDigest md5 = getMd5OrThrow();

        for (int i = 0; i < bos.getBytes().length; i += 16) {
            md5.update(sharedSecret);
            md5.update(c);
            byte[] b = md5.digest();
            md5.reset();
            xor(bos.getBytes(), i, 16, b);
            c = Arrays.copyOfRange(bos.getBytes(), i, i + 16);
        }

        StreamUtils.DataCollector result = new StreamUtils.DataCollector(bos.size() + 2);
        result.write(salt, 0, salt.length);
        result.write(bos.getBytes(), 0, bos.size());

        return result.getBytes();
    }

    private static void xor(byte[] leftAndDest, int leftOffset, int leftLen, byte[] right) {
        if (leftLen != right.length) {
            throw new IllegalArgumentException("leftLen and right.length does not match");
        }

        for (int i = 0; i < leftLen; ++i) {
            leftAndDest[leftOffset + i] = (byte) (leftAndDest[leftOffset + i] ^ right[i]);
        }
    }

    private static MessageDigest getMd5OrThrow() {
        try {
            return MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 algorithm could not be found", e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    public static class TragetNotBoundException extends RuntimeException {
    }

    private static class TargetedDataoutputStream extends ByteArrayOutputStream {
        private DatagramPacketSink datagramPacketSink;
        private InetSocketAddress target;

        public TargetedDataoutputStream(DatagramPacketSink dps, InetSocketAddress address) {
            datagramPacketSink = dps;
            target = address;
        }

        @Override
        public void flush() throws IOException {
            if (target == null) {
                throw new TragetNotBoundException();
            }
            super.flush();
            datagramPacketSink.send(new DatagramPacket(this.buf, 0, this.count, target));
            this.reset();
        }
    }
    private SSLEngineSocketLessHandshake.MemQueuePipe eapInPacketQueue =
            new SSLEngineSocketLessHandshake.MemQueuePipe();

    private EAPStackBuilder.ByteBufferSinkNSource eapSinkNSource;

    private SourceBasedMultiplexingPacketQueue multiplexingPacketQueue =
            new SourceBasedMultiplexingPacketQueue();

    private volatile boolean eapProcessorStopped = false;

    private ThreadPoolExecutor threadPoolExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(20);

    private SSLContextInitializer sslContextInitializer;



    private SSLEngine newSSLEngine() {
        SSLEngine serverEngine = sslContextInitializer.getSslc().createSSLEngine();
        serverEngine.setUseClientMode(false);
        serverEngine.setNeedClientAuth(false);
        serverEngine.setEnabledProtocols(new String[] {"TLSv1"});
        return serverEngine;
    }

    private String shareSecret;

    public EAPOrchestrator(String sharedSecret) {
        // It is ok to pass null for output stream because NO packets will be attempted to be written via
        // this returned eapSink.
        eapSinkNSource = EAPStackBuilder.buildEAPOnlyStack(null, eapInPacketQueue, new TargetBoundAppProtocolContext());
        this.shareSecret = sharedSecret;
        Path path = FileSystems.getDefault().getPath("keystore.jks");
        sslContextInitializer = new SSLContextInitializer(path.toAbsolutePath().toString(), path.toAbsolutePath().toString(), "password");
    }

    private void onEAPIdentityPacketReceived(InetSocketAddress fromAddress,
                                             RadiusPacket radiusRequest,
                                             DatagramPacketSink datagramPacketSink) {

        UUID uuidRadiusState = UUID.randomUUID();
        final TargetBoundAppProtocolContext boundAppProtocolContext = new TargetBoundAppProtocolContext(256, "server", true);
        RadiusPacketSink.RadiusRequestInfoProviderImpl rrpp = new RadiusPacketSink.RadiusRequestInfoProviderImpl(radiusRequest);
        RadiusPacketSink radiusPacketSink = new RadiusPacketSink(uuidRadiusState.toString(), rrpp, shareSecret,
                datagramPacketSink, boundAppProtocolContext);

        TargetedDataoutputStream tds = new TargetedDataoutputStream(radiusPacketSink, fromAddress);
        StreamUtils.ByteBufferInputStream packetStream = multiplexingPacketQueue.addSourceNSinkFor(uuidRadiusState, rrpp);

        final EAPStackBuilder.ByteBufferSinkNSource ss = EAPStackBuilder.buildEAPTTLSStack(new DataOutputStream(tds), packetStream,
                boundAppProtocolContext);

        final SSLEngineSocketLessHandshake.SSLByteBufferIOStream sslByteBufferIOStream =
                new SSLEngineSocketLessHandshake.SSLByteBufferIOStream(newSSLEngine(), ss.outputStream, ss.inputStream, "server");

        threadPoolExecutor.submit(new Runnable() {
            @Override
            public void run() {
                eapPacketProcessingThread(sslByteBufferIOStream,
                        ((TTLSByteBufferOutputStream) ss.outputStream).getEapttlsOutStream(), boundAppProtocolContext);
            }
        });
    }

    private void onEAPIdentityPacketReceivedEx(InetSocketAddress fromAddress,
                                             RadiusPacket radiusRequest,
                                             DatagramPacketSink datagramPacketSink) {
        UUID uuidRadiusState = UUID.randomUUID();
        final TargetBoundAppProtocolContext contextServer = new TargetBoundAppProtocolContext(256, "server", true);
        RadiusPacketSink.RadiusRequestInfoProviderImpl rrpp = new RadiusPacketSink.RadiusRequestInfoProviderImpl(radiusRequest);
        RadiusPacketSink radiusPacketSink = new RadiusPacketSink(uuidRadiusState.toString(), rrpp, shareSecret,
                datagramPacketSink, contextServer);

        TargetBoundedTransmitter targetBoundedTransmitter = new TargetBoundedTransmitter(rrpp, radiusPacketSink);

        TLSTransceiver tlsTransceiver = new TLSTransceiver(newSSLEngine(), "server", null, null);
        EAPTTLSTransceiver eapttlsTransceiver = new EAPTTLSTransceiver(contextServer, tlsTransceiver, targetBoundedTransmitter);
        tlsTransceiver.chain((ByteBufferTransmitter) eapttlsTransceiver);

        rrpp.chain(eapttlsTransceiver);

        multiplexingPacketQueue.addSourceNSinkFor(uuidRadiusState, rrpp);

        rrpp.setRequestPacket(radiusRequest);
        rrpp.setTargetAddress(fromAddress);

        RadiusAttributeReceiver radiusAttributeReceiver = new RadiusAttributeReceiver(contextServer, eapttlsTransceiver);

        tlsTransceiver.chain(radiusAttributeReceiver);

        RadiusResponseModulatorImpl radiusResponseModulator = new RadiusResponseModulatorImpl(tlsTransceiver, shareSecret);
        contextServer.setRadiusResponseModulator(radiusResponseModulator);

        contextServer.setStartFlag();
        // not writing any data - just EAP TTLS packet indicating start of TTLS
        eapttlsTransceiver.transmitEmptyEAPPacket();
        contextServer.resetFlags();
    }

    @Override
    public void handleEAPMessage(InetSocketAddress fromAddress, ByteBuffer eapPacket,
                                 DatagramPacketSink datagramPacketSink, RadiusPacket radiusPacket) {
        if (multiplexingPacketQueue.routePacketIfKnownSource(fromAddress, radiusPacket, eapPacket)) {
            return;
        }

        EAPPacket.EAPPacketStream eapPacketStream = (EAPPacket.EAPPacketStream) eapSinkNSource.inputStream;
        try {
            eapInPacketQueue.write(eapPacket);
            StreamUtils.PacketAndData<EAPPacket> packetAndData = eapPacketStream.readPacket();
            if (packetAndData.packet.getCode() != 2 || packetAndData.data.limit() <= 0) {
                // if it is not a response EAP packet or there is no data return
                return;
            }

            if (packetAndData.data.array()[0] != 1) {
                // not a identity packet - ignore
                return;
            }

            onEAPIdentityPacketReceivedEx(fromAddress, radiusPacket, datagramPacketSink);
        } catch (InvalidEAPPacketException e) {
            // ignore invalid eap packets.
        }
    }

    private void eapPacketProcessingThread(SSLEngineSocketLessHandshake.SSLByteBufferIOStream sslByteBufferIOStream,
                                           DataOutputStream eapTTLSSink,
                                           TargetBoundAppProtocolContext context) {
        try {
            context.setStartFlag();
            // not writing any data - just EAP TTLS packet indicating start of TTLS
            eapTTLSSink.flush();
            context.resetFlags();

            while (!eapProcessorStopped) {
                sslByteBufferIOStream.read();
                System.out.println("Done with SSL handshake... exiting");
                // TODO: once the hand-shake is done - we should forward to upstream protocol and finally send EAP SUCCESS
                // for now we just break out.
                break;
            }
        } catch (Exception e) {
            System.out.println("Caught exception in eapPacketProcessingThread e=" + e);
        }
    }

    private static class RadiusResponseModulatorImpl implements RadiusResponseModulator {

        public RadiusResponseModulatorImpl(TLSTransceiver tlsTransceiver, String shareSecret) {
            this.tlsTransceiver = tlsTransceiver;
            this.sharedSecret = shareSecret;
        }

        private TLSTransceiver tlsTransceiver;

        private String sharedSecret;

        private static final int MICROSOFT_VENDOR_ID = 311;
        // define in last line of 1st page of - https://tools.ietf.org/html/rfc2548

        private static final int MS_MPPR_SEND_KEY = 16;
        private static final int MS_MPPR_RECV_KEY = 17;

        @Override
        public void modulateResponse(RadiusPacket request, RadiusPacket response) {
            byte[] keyMaterial = generateKeyingMaterial(tlsTransceiver.getSslEngine(), tlsTransceiver.releaseHandShaker());

            byte[] ss = sharedSecret.getBytes(Charsets.UTF_8);

            byte[] mppeRecvKey = packAsMSMPPEKey(keyMaterial, 0, 32, ss, request.getAuthenticator());
            byte[] mppeSendKey = packAsMSMPPEKey(keyMaterial, 32, 64, ss, request.getAuthenticator());

            VendorSpecificAttribute vsa = new VendorSpecificAttribute(MICROSOFT_VENDOR_ID);
            vsa.addSubAttribute(newVendorSubAttr(MS_MPPR_RECV_KEY, mppeRecvKey));
            vsa.addSubAttribute(newVendorSubAttr(MS_MPPR_SEND_KEY, mppeSendKey));

            response.addAttribute(vsa);
        }

        private  RadiusAttribute newVendorSubAttr(int type, byte[] data) {
            RadiusAttribute ra = new RadiusAttribute(type, data);
            ra.setVendorId(MICROSOFT_VENDOR_ID);
            return ra;
        }
    }
}
