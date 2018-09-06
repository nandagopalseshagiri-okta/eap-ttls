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
    private Map<UUID, SSLEngineSocketLessHandshake.MemQueuePipe> sourceIPPortToSS = new ConcurrentHashMap<>();

    public StreamUtils.ByteBufferInputStream addSourceNSinkFor(UUID radiusState, ByteBuffer packet) {
        SSLEngineSocketLessHandshake.MemQueuePipe queuePipe = null;
        synchronized (this) {
            if (sourceIPPortToSS.containsKey(radiusState)) {
                queuePipe = sourceIPPortToSS.get(radiusState);
            } else {
                queuePipe = new SSLEngineSocketLessHandshake.MemQueuePipe(new ArrayBlockingQueue<ByteBuffer>(50));
                sourceIPPortToSS.put(radiusState, queuePipe);
            }
        }

        if (packet != null) {
            queuePipe.write(packet);
        }

        return queuePipe;
    }

    public boolean routePacketIfKnownSource(RadiusPacket radiusPacket, ByteBuffer packetData) {
        UUID stateUuid = fromRadiusPacketState(radiusPacket);
        if (stateUuid == null) {
            return false;
        }

        SSLEngineSocketLessHandshake.MemQueuePipe queuePipe = sourceIPPortToSS.get(stateUuid);
        if (queuePipe == null) {
            return false;
        }

        queuePipe.write(packetData);
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
