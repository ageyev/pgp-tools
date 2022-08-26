package io.ageyev.github;

/*
 * See:
 * https://github.com/bcgit/bc-java/blob/master/pg/src/main/java/org/bouncycastle/openpgp/examples/KeyBasedLargeFileProcessor.java
 * */

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.security.SecureRandom;
import java.security.Security;

public class PgpEncrypt {

    public static void encryptFile(
            String outputFileName,
            String inputFileName,
            String encKeyFileName,
            boolean armor,
            boolean withIntegrityCheck)
            throws IOException, PGPException {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
        PGPPublicKey encKey = KeyTools.readPublicKey(encKeyFileName);

        encryptFile(out, inputFileName, encKey, armor, withIntegrityCheck);

        out.close();
    }

    public static void encryptFile(
            OutputStream out,
            String fileName,
            PGPPublicKey encKey,
            boolean armor,
            boolean withIntegrityCheck)
            throws IOException, PGPException {

        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        Security.addProvider(new BouncyCastleProvider());

//        try {
        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC")
        );

        cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));

        OutputStream cOut = cPk.open(out, new byte[1 << 16]);

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedData.ZIP);

        PGPUtil.writeFileToLiteralData(comData.open(cOut), PGPLiteralData.BINARY, new File(fileName), new byte[1 << 16]);

        comData.close();

        cOut.close();

        if (armor) {
            out.close();
        }
//        } catch (PGPException e) {
//            System.err.println(e);
//            if (e.getUnderlyingException() != null) {
//                e.getUnderlyingException().printStackTrace();
//            }
//        }
    }
}
