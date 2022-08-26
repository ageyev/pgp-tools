package io.ageyev.github;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

/*
 * See:
 * https://github.com/bcgit/bc-java/blob/master/pg/src/main/java/org/bouncycastle/openpgp/examples/PGPExampleUtil.java
 * */

public class KeyTools {

    /*
     * Creates KeyPairGenerator instance for specified algorithm and key size using BouncyCastleProvider
     * */
    private static KeyPairGenerator createKeyPairGenerator(String algorithm, int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {

        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                algorithm,
                "BC"
        );

        keyPairGenerator.initialize(keySize);

        return keyPairGenerator;
    }

    private static PGPKeyPair createPgpKeyPair(KeyPairGenerator keyPairGenerator) throws PGPException, NoSuchAlgorithmException {

        int algorithm;
        String algorithmName = keyPairGenerator.getAlgorithm();
        algorithm = switch (algorithmName) {
            case "DH" -> PGPPublicKey.DIFFIE_HELLMAN;
            case "DSA" -> PGPPublicKey.DSA;
            case "RSA" -> PGPPublicKey.RSA_GENERAL;
            case "EC" -> PGPPublicKey.ECDH;
            default -> throw new NoSuchAlgorithmException();
        };

        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(
                algorithm,
                keyPairGenerator.generateKeyPair(),
                new Date()
        );

        return pgpKeyPair;
    }


    public static PGPSecretKey createPgpSecretKey(String algorithm, int keySize, String userName, String userEmail, String passphrase)
            throws NoSuchAlgorithmException, NoSuchProviderException, PGPException {

        KeyPairGenerator keyPairGenerator = createKeyPairGenerator(algorithm, keySize);
        PGPKeyPair pgpKeyPair = createPgpKeyPair(keyPairGenerator);

        char[] passphraseByteArray = passphrase.toCharArray();
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);

        PGPSecretKey pgpSecretKey = new PGPSecretKey(
                PGPSignature.DEFAULT_CERTIFICATION,
                pgpKeyPair,
                userName + " <" + userEmail + ">",
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(pgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passphraseByteArray));

        return pgpSecretKey;

    }

    public static String getPrintableKeyId(PGPPublicKey pgpPublicKey) {

        StringBuilder outStr = new StringBuilder();
        Iterator<String> iter = pgpPublicKey.getUserIDs();

        outStr.append("[0x");
        outStr.append(Integer.toHexString((int) pgpPublicKey.getKeyID()).toUpperCase());
        outStr.append("] ");

        while (iter.hasNext()) {
            outStr.append(iter.next().toString());
            outStr.append("; ");
        }

        return outStr.toString();
    }

    public static String getFingerprintString(PGPPublicKey pgpPublicKey) {
        String fingerprint = Hex.toHexString(pgpPublicKey.getFingerprint()).toUpperCase();
        return fingerprint;
    }

    public static void writePgpPublicKeyToDir(PGPPublicKey pgpPublicKey, String path) throws IOException {

        String fingerprint = getFingerprintString(pgpPublicKey);
        String fileName = fingerprint + ".PUBLIC.asc";
        File file = new File(path + fileName);
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(file));
        pgpPublicKey.encode(armoredOutputStream);
        armoredOutputStream.close();

    }

    public static void writePgpSecretKeyToDir(PGPSecretKey pgpSecretKey, String path) throws IOException {

        PGPPublicKey pgpPublicKey = pgpSecretKey.getPublicKey();
        String fingerprint = getFingerprintString(pgpPublicKey);
        String fileName = fingerprint + ".SECRET.asc";

        File filePath = new File(path);
        if (!filePath.exists()) {
            filePath.mkdir();
        }

        File file = new File(path + fileName);

        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(new FileOutputStream(file));
        pgpSecretKey.encode(armoredOutputStream);
        armoredOutputStream.close();

    }

    /**
     * A simple routine that opens a key ring file and loads the first available key
     * suitable for signature generation.
     *
     * @param input stream to read the secret key ring collection from.
     * @return a secret key.
     * @throws IOException  on a problem with using the input stream.
     * @throws PGPException if there is an issue parsing the input stream.
     */
    public static PGPSecretKey readSecretKey(InputStream input) throws IOException, PGPException {

        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input),
                new JcaKeyFingerprintCalculator()
        );

        Iterator keyRingIter = pgpSec.getKeyRings();

        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getSecretKeys();

            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey) keyIter.next();

                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring");
    }

    public static PGPSecretKey readSecretKey(String filePath) throws IOException, PGPException {

        PGPSecretKey pgpSecretKey;
        File file = new File(filePath);

        if (file.exists()) {
            InputStream keyIn = new BufferedInputStream(new FileInputStream(file));
            pgpSecretKey = readSecretKey(keyIn);
            keyIn.close();
            return pgpSecretKey;
        }

        throw new IllegalArgumentException("File " + file.getPath() + " does not exists");

    }

    /**
     * A simple routine that opens a key ring file and loads the first available key
     * suitable for encryption.
     * <p>
     * see: https://github.com/bcgit/bc-java/blob/master/pg/src/main/java/org/bouncycastle/openpgp/examples/PGPExampleUtil.java
     *
     * @param input data stream containing the public key data
     * @return the first public key found.
     * @throws IOException
     * @throws PGPException
     */
    public static PGPPublicKey readPublicKey(InputStream input) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) keyIter.next();

                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    public static PGPPublicKey readPublicKey(String fileName) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPublicKey(keyIn);
        keyIn.close();
        return pubKey;
    }

}
