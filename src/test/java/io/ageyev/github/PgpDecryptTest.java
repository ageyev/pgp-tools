package io.ageyev.github;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.NoSuchProviderException;

class PgpDecryptTest {


    private static PGPSecretKey secretKeyOne;
    private static String currentWorkingDirectory;
    private static final String TEST_FILE_NAME = "testFile.json";
    private static final String ENCRYPTED_BINARY_FILE_NAME = "testFile.json.enc";
    private static final String ENCRYPTED_ARMORED_FILE_NAME = "testFile.json.asc";

    private static final String TEST_FILE_DIR = "/src/test/resources/";

    private static final String SECRET_KEY_FILE = "37397FD3DE88EC25F7BF67BCF00AAF22ADAC99EF.SECRET.asc";
    private static final String SECRET_KEY_PASSWORD = "password";

    private static final String TEST_OUTPUT_DIR = "/testDir/Decrypted/";
    private static final String DEFAULT_OUTPUT_FILE_NAME = "decrypted_" + TEST_FILE_NAME;

    @BeforeAll
    // @BeforeAll annotated method MUST be a static method in the test class.
    public static void beforeAll() {
        currentWorkingDirectory = Path.of("").toAbsolutePath().toString();
    }

    @Test
    void decryptBinaryFile() throws PGPException, IOException, NoSuchProviderException {

        String encryptedFilePath = currentWorkingDirectory + TEST_FILE_DIR + ENCRYPTED_BINARY_FILE_NAME;
        String secretKeyFilePath = currentWorkingDirectory + TEST_FILE_DIR + SECRET_KEY_FILE;
        String outputFileDir = currentWorkingDirectory + TEST_OUTPUT_DIR;

        File outputDir = new File(outputFileDir);
        // delete old directory if exists
        if (outputDir.exists()) {
            System.out.println("deleting old output dir: " + outputDir.getPath());
        }
        // create directory for output
        if (!outputDir.exists()) {
            outputDir.mkdir();
        }

        File encryptedFile = new File(encryptedFilePath);
        if (!encryptedFile.exists()) {
            throw new IllegalArgumentException("encrypted file " + encryptedFilePath + " does not exist");
        }

        File secretKeyFile = new File(secretKeyFilePath);
        if (!secretKeyFile.exists()) {
            throw new IllegalArgumentException("secret key file " + secretKeyFilePath + " does not exist");
        }

        File outputFile = new File(outputFileDir + DEFAULT_OUTPUT_FILE_NAME);
        if (outputFile.exists()) {
            outputFile.delete();
        }

        PgpDecrypt.decryptFile(
                encryptedFilePath,
                secretKeyFilePath,
                SECRET_KEY_PASSWORD,
                outputFileDir,
                DEFAULT_OUTPUT_FILE_NAME
        );

        // check if output directory is not empty
        System.out.println("decrypted file:");
        for (String fileName : outputDir.list()) {
            System.out.println(outputDir.getPath() + fileName);
        }
        Assertions.assertTrue(outputDir.length() > 0);

    }
}