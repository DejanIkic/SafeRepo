package main;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;

import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.cert.X509v3CertificateBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.nio.Buffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Date;

public class Cripto {

    public static final String BC_PROVIDER = "BC";
    public static final String HASH_ALG = "SHA-256";
    public static final String KEY_ALG = "RSA";
    public static final String CA_CERT_PATH = "src" + File.separator + "ca" + File.separator + "rootca.pem";


    ///// izdavanje sertifikata

    public static X509Certificate getUserSertificate(KeyPair userKeys) {
        X509Certificate userCert = null;
        try {
            FileInputStream fis = new FileInputStream(CA_CERT_PATH);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CACert = (X509Certificate) cf.generateCertificate(fis);


            ////////// Zahtjev za sert
            String subjectDN = "CN=John Doe, OU=IT, O=My Organization, L=City, ST=State, C=Country";
            String subject = "CN=";
            System.out.println("Ime (common name): ");
            subject += Main.sc.nextLine();
            System.out.println("Naziv organizacione jedinice [ETF]: ");
            subject += ", OU=" + Main.sc.nextLine();
            System.out.println("Naziv organizacije [Elektrotehniciki fakultet]: ");
            subject += ", O=" + Main.sc.nextLine();
            System.out.println("Grad [Banja Luka]: ");
            subject += ", L=" + Main.sc.nextLine();
            System.out.println("Savezna drzava, entitet, provincija [RS]: ");
            subject += ", ST=" + Main.sc.nextLine();
            System.out.println("Drzava [BA]: ");
            subject += ", C=" + Main.sc.nextLine();


            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                    CACert.getSubjectX500Principal(),
                    BigInteger.valueOf(System.currentTimeMillis()).multiply(BigInteger.valueOf(10)),
                    new Date(System.currentTimeMillis() - 1000L * 5),
                    new Date(System.currentTimeMillis() + 180L * 24 * 60 * 60 * 100),
                    new X500Principal(subject), userKeys.getPublic());

            FileInputStream caFIS = new FileInputStream( new File("src" + File.separator + "ca"
                + File.separator + "private"+File.separator+ "private4096.key"));
            PrivateKey caPrivateKey = (PrivateKey) PrivateKeyFactory.createKey(caFIS);
            X509CertificateHolder certificateHolder = certificateBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").build(caPrivateKey));

            // Convert the certificate holder to X509Certificate
            return new JcaX509CertificateConverter().getCertificate(certificateHolder);
        } catch (CertificateException | OperatorCreationException | IOException ex) {
            throw new RuntimeException(ex);
        }
    }




    ///// hesiranje lozinke ili fajla
    public static String hashBytes(byte[] bytes) {
        String result = "";
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALG);
            byte[] digestByte = new byte[digest.getDigestLength()];
            digest.update(bytes);
            digest.digest(digestByte, 0, digestByte.length);

            result = String.format("%064x", new BigInteger(1, digestByte));
        } catch (Exception e) {
            System.out.println("Izuzetak kod hesiranja lozinke/fajla");
        }
        return result;
    }

    ///// digitalni potpis fajla ( enkripcija hesa )

    ///// generisanje para kljuceva
    public static KeyPair generisiKljuceve(File putanjaKorisnika) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance(KEY_ALG, BC_PROVIDER);
            keygen.initialize(2048);
            KeyPair keyPair = keygen.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();

            ///// ispis kljuca u pem formatu u folder korisnika
            StringWriter stringWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(stringWriter);
            PemObject pemObject = new PemObject("PRIVATE KEY", privateKey.getEncoded());
            pemWriter.writeObject(pemObject);
            pemWriter.close();
            String keyInPemFormat = stringWriter.toString();

            FileWriter fw = new FileWriter(putanjaKorisnika + File.separator + "privateKey.pem");
            fw.write(keyInPemFormat);
            fw.close();

            return keyPair;

        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            System.out.println("izuzetak kod generisanja para kljuceva: " + e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return null;
    }



}
