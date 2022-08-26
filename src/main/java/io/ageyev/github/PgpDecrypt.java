package io.ageyev.github;

/*
 * See:
 * https://github.com/bcgit/bc-java/blob/master/pg/src/main/java/org/bouncycastle/openpgp/examples/KeyBasedLargeFileProcessor.java
 * */

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Iterator;

public class PgpDecrypt {

    /**
     * Search a secret key ring collection for a secret key corresponding to keyID if it
     * exists.
     *
     * @param pgpSec a secret key ring collection.
     * @param keyID  keyID we want.
     * @param pass   passphrase to decrypt secret key with.
     * @return the private key.
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException, NoSuchProviderException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    }

    /**
     * decrypt the passed in message stream
     */
    public static void decryptFile(
            InputStream in,
            InputStream keyIn,
//            char[] passwd,
            String password,
            String outputDir,
            String defaultFileName
    )
            throws IOException, NoSuchProviderException, PGPException {

        Security.addProvider(new BouncyCastleProvider());

        char[] passwd = password.toCharArray();
        in = PGPUtil.getDecoderStream(in);

//        try {
        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
        PGPEncryptedDataList enc;

        Object o = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        //
        // find the secret key
        //
        Iterator it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

        while (sKey == null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();

            sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
        }

        if (sKey == null) {
            throw new IllegalArgumentException("secret key for message not found.");
        }

        InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

        PGPCompressedData cData = (PGPCompressedData) plainFact.nextObject();

        InputStream compressedStream = new BufferedInputStream(cData.getDataStream());
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedStream);

        Object message = pgpFact.nextObject();

        if (message instanceof PGPLiteralData) {

            PGPLiteralData ld = (PGPLiteralData) message;

            String outFileName = outputDir + ld.getFileName();

            if (outFileName.length() == 0) {
                outFileName = outputDir + defaultFileName;
            }

            InputStream unc = ld.getInputStream();

            OutputStream fOut = new FileOutputStream(outFileName);

            Streams.pipeAll(unc, fOut, 8192);

            fOut.close();

        } else if (message instanceof PGPOnePassSignatureList) {
            throw new PGPException("encrypted message contains a signed message - not literal data.");
        } else {
            throw new PGPException("message is not a simple encrypted file - type unknown.");
        }

        if (pbe.isIntegrityProtected()) {
            if (!pbe.verify()) {
                System.err.println("message failed integrity check");
            } else {
                System.out.println("message integrity check passed");
            }
        } else {
            System.err.println("no message integrity check");
        }
    }

//        catch (PGPException e) {
//            System.err.println(e);
//            if (e.getUnderlyingException() != null) {
//                e.getUnderlyingException().printStackTrace();
//            }
//        }

    public static void decryptFile(
            String inputFileName,
            String keyFileName,
            String password,
            String outPutFileDir,
            String defaultFileName
    )
            throws IOException, NoSuchProviderException, PGPException {

        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
        decryptFile(in, keyIn, password, outPutFileDir, defaultFileName);
        keyIn.close();
        in.close();
    }

}

