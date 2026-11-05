
package com.apifuzzer.security;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

public class TargetAddressValidator {

    /**
     * Resolve once and return the exact addresses that passed validation.
     * These addresses must be reused by the HTTP transport.
     */
    public List<InetAddress> resolveAndValidate(
            URI uri,
            boolean allowNonPublicAddresses
    ) {
        if (uri == null || uri.getHost() == null) {
            throw new IllegalArgumentException(
                    "Target hostname is missing"
            );
        }

        final InetAddress[] addresses;

        try {
            addresses = InetAddress.getAllByName(uri.getHost());
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(
                    "Target hostname could not be resolved"
            );
        }

        if (addresses.length == 0) {
            throw new IllegalArgumentException(
                    "Target hostname resolved to no addresses"
            );
        }

        List<InetAddress> validated = Arrays.asList(addresses);

        for (InetAddress address : validated) {
            if (!allowNonPublicAddresses && !isPublicAddress(address)) {
                throw new IllegalArgumentException(
                        "Target resolves to a non-public IP address"
                );
            }
        }

        return List.copyOf(validated);
    }

    /**
     * Compatibility method for existing callers and tests.
     */
    public void validate(
            URI uri,
            boolean allowNonPublicAddresses
    ) {
        resolveAndValidate(uri, allowNonPublicAddresses);
    }

    private boolean isPublicAddress(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return false;
        }

        if (address instanceof Inet4Address) {
            return isPublicIpv4(address.getAddress());
        }

        if (address instanceof Inet6Address) {
            return isPublicIpv6(address.getAddress());
        }

        return false;
    }

private boolean isPublicIpv4(byte[] bytes) {

    String[] blockedRanges = {
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "192.88.99.0/24",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "255.255.255.255/32"
    };

    for (String range : blockedRanges) {
        if (isInCidr(bytes, range)) {
            return false;
        }
    }

    return true;
}

private boolean isPublicIpv6(byte[] bytes) {

    // Only accept IPv6 global unicast space: 2000::/3.
    if (!isInCidr(bytes, "2000::/3")) {
        return false;
    }

    String[] blockedRanges = {
            "2001::/23",
            "2001:db8::/32",
            "2002::/16",
            "3fff::/20"
    };

    for (String range : blockedRanges) {
        if (isInCidr(bytes, range)) {
            return false;
        }
    }

    return true;
}

private boolean isInCidr(byte[] addressBytes, String cidr) {

    try {
        String[] parts = cidr.split("/");

        byte[] networkBytes =
                InetAddress.getByName(parts[0]).getAddress();

        if (addressBytes.length != networkBytes.length) {
            return false;
        }

        int prefixLength = Integer.parseInt(parts[1]);

        if (prefixLength < 0
                || prefixLength > addressBytes.length * 8) {
            throw new IllegalArgumentException(
                    "Invalid CIDR prefix"
            );
        }

        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;

        for (int i = 0; i < fullBytes; i++) {
            if (addressBytes[i] != networkBytes[i]) {
                return false;
            }
        }

        if (remainingBits > 0) {
            int mask = (0xFF << (8 - remainingBits)) & 0xFF;

            if (((addressBytes[fullBytes] & 0xFF) & mask)
                    != ((networkBytes[fullBytes] & 0xFF) & mask)) {
                return false;
            }
        }

        return true;

    } catch (UnknownHostException e) {
        throw new IllegalStateException(
                "Invalid hardcoded CIDR range: " + cidr,
                e
        );
    }
}

 
}

