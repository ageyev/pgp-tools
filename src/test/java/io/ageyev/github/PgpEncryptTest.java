package io.ageyev.github;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

class PgpEncryptTest {

    private static PGPSecretKey secretKeyOne;
    private static String currentWorkingDirectory;
    private static final String TEST_FILE_NAME = "testFile.json";
    private static final String TEST_FILE_DIR = "/src/test/resources/";
    private static final String PUBLIC_KEY_FILE = "/src/test/resources/37397FD3DE88EC25F7BF67BCF00AAF22ADAC99EF.PUBLIC.asc";
    private static final String TEST_OUTPUT_DIR = "/testDir/";

    @BeforeAll
    // @BeforeAll annotated method MUST be a static method in the test class.
    public static void beforeAll() {
        currentWorkingDirectory = Path.of("").toAbsolutePath().toString();
    }

    @Test
    void encryptFileBinary() throws PGPException, IOException {

        String outputFilePath = currentWorkingDirectory + TEST_OUTPUT_DIR + TEST_FILE_NAME + ".enc";
        File encryptedFile = new File(outputFilePath);
        if (encryptedFile.exists()) {
            encryptedFile.delete();
        }

        PgpEncrypt.encryptFile(
                outputFilePath,
                currentWorkingDirectory + TEST_FILE_DIR + TEST_FILE_NAME,
                currentWorkingDirectory + PUBLIC_KEY_FILE,
                false,
                true
        );

        Assertions.assertTrue(encryptedFile.exists());

    }

    @Test
    void encryptFileAsciiArmored() throws PGPException, IOException {

        String outputFilePath = currentWorkingDirectory + TEST_OUTPUT_DIR + TEST_FILE_NAME + ".asc";
        File encryptedFile = new File(outputFilePath);
        if (encryptedFile.exists()) {
            encryptedFile.delete();
        }

        PgpEncrypt.encryptFile(
                outputFilePath,
                currentWorkingDirectory + TEST_FILE_DIR + TEST_FILE_NAME,
                currentWorkingDirectory + PUBLIC_KEY_FILE,
                true,
                true
        );

        Assertions.assertTrue(encryptedFile.exists());

    }
}