package io.ageyev.github;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.junit.jupiter.api.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

class KeyToolsTest {

    private static PGPSecretKey secretKeyOne;
    private static String currentWorkingDirectory;
    private static final String TEST_OUTPUT_DIR = "/testDir/";

    @BeforeAll
    // @BeforeAll annotated method MUST be a static method in the test class.
    public static void beforeAll() throws PGPException, NoSuchAlgorithmException, NoSuchProviderException {
        secretKeyOne = KeyTools.createPgpSecretKey(
                KeyPairGeneratorAlgorithms.RSA,
                1024,
                "Tester",
                "tester@test.com",
                "password"
        );
        String fingerprint = KeyTools.getFingerprintString(secretKeyOne.getPublicKey());
        System.out.println(fingerprint);

        currentWorkingDirectory = Path.of("").toAbsolutePath().toString();
    }

    @BeforeEach
    void setUp() {
    }

    @AfterEach
    void tearDown() {
    }

    @Test
    void createPgpSecretKey() {

    }

    @Test
    void getPrintableKeyId() {
        String keyId = KeyTools.getPrintableKeyId(secretKeyOne.getPublicKey());
        System.out.println(keyId);
    }

    @Test
    void getFingerprintString() {
        // String fingerprint = KeyTools.getFingerprintString(secretKeyOne.getPublicKey());
    }

    @Test
    void writeAndReadPgpPublicKeyToDir() throws IOException, PGPException {

        String currentWorkingDirectory = Path.of("").toAbsolutePath().toString();
        // System.out.println(currentWorkingDirectory);
        KeyTools.writePgpPublicKeyToDir(secretKeyOne.getPublicKey(), currentWorkingDirectory + TEST_OUTPUT_DIR);
        File file = new File(currentWorkingDirectory + TEST_OUTPUT_DIR + KeyTools.getFingerprintString(secretKeyOne.getPublicKey()) + ".PUBLIC.asc");
        Assertions.assertTrue(file.exists());

        PGPPublicKey pgpPublicKey = KeyTools.readPublicKey(file.getPath());
        Assertions.assertEquals(secretKeyOne.getPublicKey().getKeyID(), pgpPublicKey.getKeyID());
    }

    @Test
    void writeAndReadPgpSecretKey() throws IOException, PGPException {

        KeyTools.writePgpSecretKeyToDir(secretKeyOne, currentWorkingDirectory + TEST_OUTPUT_DIR);
        File file = new File(currentWorkingDirectory + TEST_OUTPUT_DIR + KeyTools.getFingerprintString(secretKeyOne.getPublicKey()) + ".SECRET.asc");

        // System.out.println(file.getPath());
        Assertions.assertTrue(file.exists());

        PGPSecretKey secKey = KeyTools.readSecretKey(file.getPath());

        Assertions.assertEquals(secKey.getKeyID(), secretKeyOne.getKeyID());

    }


    @Test
    void readPublicKey() {

    }
}