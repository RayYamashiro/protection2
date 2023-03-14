package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;


public  class RSAUtil {
    /*
        private static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgFGVfrY4jQSoZQWWygZ83roKXWD4YeT2x2p41dGkPixe73rT2IW04glagN2vgoZoHuOPqa5and6kAmK2ujmCHu6D1auJhE2tXP+yLkpSiYMQucDKmCsWMnW9XlC5K7OSL77TXXcfvTvyZcjObEz6LIBRzs6+FqpFbUO9SJEfh6wIDAQAB";
        private static String privateKey = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKAUZV+tjiNBKhlBZbKBnzeugpdYPhh5PbHanjV0aQ+LF7vetPYhbTiCVqA3a+Chmge44+prlqd3qQCYra6OYIe7oPVq4mETa1c/7IuSlKJgxC5wMqYKxYydb1eULkrs5IvvtNddx+9O/JlyM5sTPosgFHOzr4WqkVtQ71IkR+HrAgMBAAECgYAkQLo8kteP0GAyXAcmCAkA2Tql/8wASuTX9ITD4lsws/VqDKO64hMUKyBnJGX/91kkypCDNF5oCsdxZSJgV8owViYWZPnbvEcNqLtqgs7nj1UHuX9S5yYIPGN/mHL6OJJ7sosOd6rqdpg6JRRkAKUV+tmN/7Gh0+GFXM+ug6mgwQJBAO9/+CWpCAVoGxCA+YsTMb82fTOmGYMkZOAfQsvIV2v6DC8eJrSa+c0yCOTa3tirlCkhBfB08f8U2iEPS+Gu3bECQQCrG7O0gYmFL2RX1O+37ovyyHTbst4s4xbLW4jLzbSoimL235lCdIC+fllEEP96wPAiqo6dzmdH8KsGmVozsVRbAkB0ME8AZjp/9Pt8TDXD5LHzo8mlruUdnCBcIo5TMoRG2+3hRe1dHPonNCjgbdZCoyqjsWOiPfnQ2Brigvs7J4xhAkBGRiZUKC92x7QKbqXVgN9xYuq7oIanIM0nz/wq190uq0dh5Qtow7hshC/dSK3kmIEHe8z++tpoLWvQVgM538apAkBoSNfaTkDZhFavuiVl6L8cWCoDcJBItip8wKQhXwHp0O3HLg10OEd14M58ooNfpgt+8D8/8/2OOFaR0HzA+2Dm";

        public static PublicKey getPublicKey(String base64PublicKey){
            PublicKey publicKey = null;
            try{
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes())); // преобразуем открытый ключ в формате base64 обратно в x509
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                publicKey = keyFactory.generatePublic(keySpec);
                return publicKey;
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }
            return publicKey;
        }

        public void RSAKeyPairGenerator() throws NoSuchAlgorithmException {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024);
            KeyPair pair = keyGen.generateKeyPair();
            this.privateKey = pair.getPrivate().toString();
            this.publicKey = pair.getPublic().toString();
        }
        public String getPrivateKey() {
            return privateKey;
        }
        public String getPublicKey() {
            return publicKey;
        }


        public static PrivateKey getPrivateKey(String base64PrivateKey){
            PrivateKey privateKey = null;
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
            KeyFactory keyFactory = null;
            try {
                keyFactory = KeyFactory.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            try {
                privateKey = keyFactory.generatePrivate(keySpec);
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }
            return privateKey;
        }

        public static byte[] encrypt(String data, String publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
            return cipher.doFinal(data.getBytes());
        }

        public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(data));
        }

        public static String decrypt(String data, String base64PrivateKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
            return decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey(base64PrivateKey));
        }

        public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException {
            try {
                String encryptedString = Base64.getEncoder().encodeToString(encrypt("Per aspera ad astra", publicKey));
                System.out.println(encryptedString);
                String decryptedString = RSAUtil.decrypt(encryptedString, privateKey);
                System.out.println(decryptedString);
            } catch (NoSuchAlgorithmException e) {
                System.err.println(e.getMessage());
            }

        }

     */


    /*
    1) Given two prime integers p and q, find n = p*q
    2) Find (p-1)*(q-1)
    3) Choose an integer e as the encryption key such that e is relatively prime to (p-1)*(q-1)
    4) Find the decryption key d such that d is the multiplicative inverse of e in the class modulo (p-1)*(q-1)
     */
    public static void main(String[] args) {
        Random rand1=new Random(System.currentTimeMillis());
        Random rand2=new Random(System.currentTimeMillis()*10);
        int pubkey=32; // начальный публичный ключ

        BigInteger p = BigInteger.probablePrime(32,rand1);
        BigInteger q = BigInteger.probablePrime(32,rand2);


        //multiplying p and q BigInteger n-p.multiply(q);
        BigInteger n = p.multiply(q);
        BigInteger p_1 = p.subtract(new BigInteger("1")); // p-1
        BigInteger q_1 = q.subtract(new BigInteger("1")); // q-1
        BigInteger z = p_1.multiply(q_1); // (p-1)*(q-1)

        //генерируем публичный ключ
        while (true)
        {
            BigInteger GCD = z.gcd(new BigInteger("" +pubkey));
            if(GCD.equals(BigInteger.ONE))
            {
                break;
            }
            pubkey++;
        }

        BigInteger big_pubkey = new BigInteger("" + pubkey);
        BigInteger prvkey = big_pubkey.modInverse(z);

        System.out.println("public key " + (BigInteger) big_pubkey );
        System.out.println("private key " + (BigInteger) prvkey );


        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter message");
        String msg = scanner.nextLine();
        byte [] bytes = msg.getBytes();
        StringBuilder encode = new StringBuilder();
        StringBuilder decode = new StringBuilder();
        for(int i = 0; i < msg.length(); i++)
        {
            int temp = bytes[i];
            BigInteger val = new BigInteger(String.valueOf(temp));
            BigInteger tempVal = val.modPow(big_pubkey, n);
            //System.out.println("encode " + tempVal);
            encode.append(tempVal);


            BigInteger plainVal = tempVal.modPow(prvkey, n);
            int i_plainVal = plainVal.intValue();
            //System.out.println("decode " + (char) i_plainVal);
            decode.append((char) i_plainVal);
        }

        System.out.println("encode " + encode.toString());
        System.out.println("decode " + decode.toString());
    }
}
