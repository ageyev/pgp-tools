package io.ageyev.github;

/*
 * The algorithm names that can be specified when generating an instance of KeyPairGenerator.
 * see: https://docs.oracle.com/javase/9/docs/specs/security/standard-names.html
 * */
public class KeyPairGeneratorAlgorithms {

    // Generates keypairs for the Diffie-Hellman KeyAgreement algorithm.
    //Note: key.getAlgorithm() will return "DH" instead of "DiffieHellman".
    public static final String DiffieHellman = "DiffieHellman";

    // Generates keypairs for the Digital Signature Algorithm.
    public static final String DSA = "DSA";

    // Generates keypairs for the RSA algorithm (Signature/Cipher).
    public static final String RSA = "RSA";

    // Generates keypairs for the Elliptic Curve algorithm.
    public static final String EC = "EC";

}
