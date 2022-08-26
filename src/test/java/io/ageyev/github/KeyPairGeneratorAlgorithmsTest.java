package io.ageyev.github;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class KeyPairGeneratorAlgorithmsTest {

    @Test
    void checkValues() {
        assertEquals(KeyPairGeneratorAlgorithms.DiffieHellman, "DiffieHellman");
        assertEquals(KeyPairGeneratorAlgorithms.DSA, "DSA");
        assertEquals(KeyPairGeneratorAlgorithms.RSA, "RSA");
        assertEquals(KeyPairGeneratorAlgorithms.EC, "EC");
    }

}