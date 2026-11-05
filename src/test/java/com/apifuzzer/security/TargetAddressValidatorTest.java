
package com.apifuzzer.security;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

class TargetAddressValidatorTest {

    private final TargetAddressValidator validator =
            new TargetAddressValidator();

    @Test
    void shouldRejectLoopbackAddress() {

        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(
                        URI.create("http://127.0.0.1"),
                        false
                )
        );
    }

    @Test
    void shouldRejectPrivateIpv4Address() {

        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(
                        URI.create("http://192.168.1.10"),
                        false
                )
        );
    }

    @Test
    void shouldRejectCarrierGradeNatAddress() {

        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(
                        URI.create("http://100.64.0.1"),
                        false
                )
        );
    }

    @Test
    void shouldRejectLinkLocalAddress() {

        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(
                        URI.create("http://169.254.10.20"),
                        false
                )
        );
    }

    @Test
    void shouldRejectDocumentationAddress() {

        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(
                        URI.create("http://192.0.2.10"),
                        false
                )
        );
    }

    @Test
    void shouldAllowNonPublicAddressOnlyWithExplicitOptIn() {

        assertDoesNotThrow(
                () -> validator.validate(
                        URI.create("http://127.0.0.1"),
                        true
                )
        );
    }

    @Test
    void shouldRejectMissingHostname() {

        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(
                        URI.create("file:///tmp/test"),
                        false
                )
        );
    }

    @Test
    void shouldRejectUnresolvableHostname() {

        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(
                        URI.create(
                                "http://this-host-should-not-exist.invalid"
                        ),
                        false
                )
        );
    }
    
    
        @Test
    void shouldRejectAllAddressesInPrivateIpv4Ranges() {
        String[] addresses = {
                "10.0.0.1",
                "172.16.0.1",
                "172.31.255.254",
                "192.168.0.1"
        };

        for (String address : addresses) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> validator.validate(
                            URI.create("http://" + address),
                            false
                    ),
                    "Expected private address to be rejected: " + address
            );
        }
    }

    @Test
    void shouldRejectBenchmarkTestingAddressRange() {
        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(
                        URI.create("http://198.18.0.1"),
                        false
                )
        );
    }

    @Test
    void shouldRejectReservedIpv4AddressRanges() {
        String[] addresses = {
                "0.0.0.1",
                "240.0.0.1",
                "255.255.255.255"
        };

        for (String address : addresses) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> validator.validate(
                            URI.create("http://" + address),
                            false
                    ),
                    "Expected reserved address to be rejected: " + address
            );
        }
    }

    @Test
    void shouldRejectIpv6LoopbackAddress() {
        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(
                        URI.create("http://[::1]"),
                        false
                )
        );
    }

    @Test
    void shouldRejectIpv6UniqueLocalAddress() {
        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(
                        URI.create("http://[fc00::1]"),
                        false
                )
        );
    }

    @Test
    void shouldRejectIpv6LinkLocalAddress() {
        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(
                        URI.create("http://[fe80::1]"),
                        false
                )
        );
    }

    @Test
    void shouldRejectIpv6DocumentationAddress() {
        assertThrows(
                IllegalArgumentException.class,
                () -> validator.validate(
                        URI.create("http://[2001:db8::1]"),
                        false
                )
        );
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}

