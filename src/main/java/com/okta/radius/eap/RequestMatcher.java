package com.okta.radius.eap;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.tinyradius.packet.RadiusPacket;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Created by nikolay
 */
public class RequestMatcher {

    final private Cache<RequestPacket, Object> recentPackets;

    public RequestMatcher(int maxSize, long duration, TimeUnit timeUnit) {
        recentPackets = CacheBuilder.newBuilder()
                .expireAfterWrite(duration, timeUnit)
                .maximumSize(maxSize)
                .build();
    }

    public boolean checkIfDuplicateOrRegisterPacket(RadiusPacket packet, InetSocketAddress address) {
        RequestPacket requestPacket = new RequestPacket(packet, address);
        if (recentPackets.getIfPresent(requestPacket) != null) {
            return true;
        }

        recentPackets.put(requestPacket, new Object());
        return false;
    }

    private static class RequestPacket {
        public int packetIdentifier;
        public InetSocketAddress address;
        public byte[] authenticator;

        public RequestPacket(RadiusPacket packet, InetSocketAddress address) {
            this.address = address;
            this.packetIdentifier = packet.getPacketIdentifier();
            this.authenticator = packet.getAuthenticator();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }

            if (o == null || getClass() != o.getClass()) {
                return false;
            }

            RequestPacket that = (RequestPacket) o;

            if (packetIdentifier != that.packetIdentifier) {
                return false;
            }
            if (!Objects.equals(address, that.address)) {
                return false;
            }

            return Arrays.equals(authenticator, that.authenticator);
        }

        @Override
        public int hashCode() {
            int result = packetIdentifier;
            if (address != null) {
                result = 31 * result + address.hashCode();
            }
            if (authenticator != null) {
                result = 31 * result + Arrays.hashCode(authenticator);
            }
            return result;
        }
    }
}
