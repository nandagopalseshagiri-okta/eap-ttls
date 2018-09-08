package com.okta.radius.eap;

import com.google.common.base.Charsets;
import org.tinyradius.attribute.RadiusAttribute;
import org.tinyradius.packet.RadiusPacket;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by nandagopal.seshagiri on 8/28/18.
 */
public class SourceBasedMultiplexingPacketQueue {
    private static class PacketQueueInfo {
        public RadiusPacketSink.RadiusRequestPacketProvider rrpp;
        public SSLEngineSocketLessHandshake.MemQueuePipe queuePipe;

        public PacketQueueInfo(RadiusPacketSink.RadiusRequestPacketProvider rrpp,
                               SSLEngineSocketLessHandshake.MemQueuePipe queuePipe) {
            this.rrpp = rrpp;
            this.queuePipe = queuePipe;
        }
    }

    private Map<UUID, PacketQueueInfo> sourceIPPortToSS = new ConcurrentHashMap<>();

    public StreamUtils.ByteBufferInputStream addSourceNSinkFor(UUID radiusState, RadiusPacketSink.RadiusRequestPacketProvider rrpp) {
        PacketQueueInfo queuePipe = null;
        synchronized (this) {
            if (!sourceIPPortToSS.containsKey(radiusState)) {
                queuePipe = new PacketQueueInfo(rrpp,
                        new SSLEngineSocketLessHandshake.MemQueuePipe(new ArrayBlockingQueue<ByteBuffer>(50)));
                sourceIPPortToSS.put(radiusState, queuePipe);
            } else {
                queuePipe = sourceIPPortToSS.get(radiusState);
            }
        }

        return queuePipe.queuePipe;
    }

    public boolean routePacketIfKnownSource(RadiusPacket radiusPacket, ByteBuffer packetData) {
        UUID stateUuid = fromRadiusPacketState(radiusPacket);
        if (stateUuid == null) {
            return false;
        }

        PacketQueueInfo queueInfo = sourceIPPortToSS.get(stateUuid);
        if (queueInfo == null) {
            return false;
        }

        queueInfo.rrpp.setRequestPacket(radiusPacket);
        queueInfo.queuePipe.write(packetData);
        return true;
    }

    private static UUID fromRadiusPacketState(RadiusPacket radiusPacket) {
        final int stateAttr = 24;

        List states = radiusPacket.getAttributes(stateAttr);
        if (states == null || states.size() != 1) {
            return null;
        }

        return fromBytes(((RadiusAttribute) states.get(0)).getAttributeData());
    }

    private static UUID fromBytes(byte[] bytes) {
        try {
            String str = new String(bytes, Charsets.UTF_8);
            return UUID.fromString(str);
        } catch (Exception e) {
            return null;
        }
    }
}
