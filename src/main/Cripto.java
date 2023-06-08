package main;

import jdk.jshell.execution.Util;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.dvcs.CPDRequestBuilder;
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
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

public class Cripto {

    public static final String BC_PROVIDER = "BC";
    public static final String HASH_ALG = "SHA-256";
    public static final String KEY_ALG = "RSA";
    public static final String AES_SIFRA = "sigurnost";
    public static final String CA_CERT_PATH = "src" + File.separator + "ca" + File.separator + "rootca.pem";
    public static final String FS = File.separator;


    public static void generisiSertifikat(String username) {

        String skripta = "." + FS + "scripts" + FS + "generisiSertifikat.sh";
        String[] komanda = {"bash", skripta, username};
        System.out.println(pokreniSkriptu(komanda));

    }

    public static void provjeriSertifikat(String username) {
        String skripta = "." + FS + "scripts" + FS + "provjeriSertifikat.sh";
        String[] komanda = {"bash", skripta, username};
        System.out.println(pokreniSkriptu(komanda));
    }

    public static boolean provjeraLozinke(String username, String plainPass) {

        try {
            File userDir = new File(Utils.USERS_PATH + FS + username + FS + "password");
            FileReader fr = new FileReader(userDir);
            BufferedReader br = new BufferedReader(fr);

            String passHashBase = br.readLine();

            if (passHashBase.equals(hashBytes(plainPass.getBytes(StandardCharsets.UTF_8)))) {
                return true;
            } else return false;

        } catch (IOException e) {
            System.out.println("izuzetak kod provjere lozinke");
        }

        return false;
    }

    public static void prikazFajlova(String username) {
        /// za svaki fajl od ovog korisnika
        /// provjeriti potpis fajla i vrijednost u bazi
        /// izmijenjeni fajl
        try {
            File filesContentFile = new File(Utils.DATABASE_PATH);
            List<String> content = null;

            content = Files.readAllLines(filesContentFile.toPath());


            for (String s : content) {
                String[] arr = s.split(",");

                if (arr[0].equals(username)){

                    File tempProvjera = sastaviSegmente(username, arr[1], arr[2]);

                    int result = verifikujPoptis(username, arr[1], tempProvjera.getAbsolutePath());
                    System.out.println( (result==0 )?( ""+ arr[1] ):("[CORRUPTED] " + arr[1] ));
                }
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static File sastaviSegmente(String username, String fileName, String brSegmenata ) throws IOException{
        String resultDec = "";
        for (int i = 0; i < Integer.valueOf(brSegmenata); i++) {
            File tempD = new File(Utils.REPO_PATH + FS + "tempD");
            String brSegmenta = String.format("%02d", i + 1);

            dekriptujFajl(username, brSegmenta, AES_SIFRA, fileName);
            resultDec += Files.readString(tempD.toPath());
        }

        // provjeri potpis fajla
        File tempProvjera = new File(Utils.REPO_PATH +FS + "tempProvjera");
        FileWriter fw = new FileWriter(tempProvjera);
        BufferedWriter bw = new BufferedWriter(fw);

        bw.write(resultDec);
        bw.flush();
        return tempProvjera;
    }

    private static int verifikujPoptis(String username, String imeFajla, String fajl){

        String skripta = "." + FS + "scripts" + FS + "verifikujPoptis.sh";
        String[] komanda = {"bash", skripta, username, imeFajla, fajl};
        return pokreniSkriptu(komanda);
    }




    public static void dodajFajl(String username, File file) {

        int brojSegmenata = Main.random.nextInt(4, 11);
        brojSegmenata=3;
        if (!file.exists()) {
            System.out.println("Fajl ne postoji!");
            return;
        }

        try {
            File dbFile = new File(Utils.DATABASE_PATH);
            List<String> sviFajlovi = Files.readAllLines(dbFile.toPath());
            String provjeraFajla = username + "," + file.getName();
            //System.out.println("Svi fajlovi: " + provjeraFajla);
            boolean postojiFajl = false;
            for (String s : sviFajlovi) {
                if (s.contains(provjeraFajla)) {
                    System.out.println("fajl sa tim imenom vec postoji");
                    postojiFajl = true;
                }
            }

            if (!postojiFajl) {


                poptisiFajl(username, file.getName(), file.getAbsolutePath());


                FileWriter databaseFW = new FileWriter(dbFile, true);
                databaseFW.write(provjeraFajla + "," + brojSegmenata + "\n"); //ovjde treba append
                databaseFW.close();


                FileWriter fw = null;
                String sadrzajFajla = Files.readString(file.toPath());

                List<String> segmenti = podijeliString(sadrzajFajla, brojSegmenata);

                for (int i = 0; i < brojSegmenata; i++) {
                    String brSegmenta = String.format("%02d", i + 1);

                    File temp = new File(Utils.REPO_PATH + FS + "temp");
                    fw = new FileWriter(temp);
                    fw.write(segmenti.get(i));
                    fw.flush();

                    enkriptujFajl(username, brSegmenta, AES_SIFRA, file.getName());
                }

                fw.close();
            }

        } catch (IOException e) {
            System.out.println("dodaj fajl izuzetak!! " + e);
        }

    }



    public static void preuzmiFajl(String username, String fileName, String newPath){
        File file = new File(Utils.DATABASE_PATH);
        try {
            List<String> content = Files.readAllLines(file.toPath());
            File source = null;
            for (String s : content){
                String[] arr = s.split(",");
                if (arr[0].equals(username) && arr[1].equals(fileName)) {
                    source = sastaviSegmente(username,arr[1], arr[2]);
                }
            }


            File newFile = new File(newPath);
            Files.copy(source.toPath(), newFile.toPath(), StandardCopyOption.REPLACE_EXISTING);

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    private static int poptisiFajl(String username, String imeFajla, String putanjaFajla) {

        String skripta = "." + FS + "scripts" + FS + "potpisiFajl.sh";
        String[] komanda = {"bash", skripta, username, imeFajla, putanjaFajla};
        System.out.println(pokreniSkriptu(komanda));

        return 1;
    }

    private static int enkriptujFajl(String username, String brojSegmenta, String sifraAES, String imeFajla) {

        String skripta = "." + FS + "scripts" + FS + "enkriptujFajl.sh";
        String[] komanda = {"bash", skripta, username, brojSegmenta, sifraAES, imeFajla};


        return pokreniSkriptu(komanda);
    }

    private static int dekriptujFajl(String username, String brojSegmenta, String sifraAES, String imeFajla) {
        String skripta = "." + FS + "scripts" + FS + "dekriptujFajl.sh";
        String[] komanda = {"bash", skripta, username, brojSegmenta, sifraAES, imeFajla};
        return pokreniSkriptu(komanda);
    }

    private static List<String> podijeliString(String ulaz, int brojSegmenata) {
        ArrayList<String> result = new ArrayList<>(brojSegmenata);

        int duzinaTeksta = ulaz.length();
        int velicinaSegmenta = duzinaTeksta / brojSegmenata;
        int ostatak = duzinaTeksta % brojSegmenata;

        int startIndex = 0;
        int endIndex;

        for (int i = 0; i < brojSegmenata; i++) {
            endIndex = startIndex + velicinaSegmenta;
            if (i < ostatak) {
                endIndex++;
            }
            result.add(ulaz.substring(startIndex, endIndex));
            startIndex = endIndex;
        }
        return result;
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


    private static int pokreniSkriptu(String[] komanda) {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(komanda);
            processBuilder.directory(new File(System.getProperty("user.dir") + FS + "src" + FS + "ca"));
            //processBuilder.redirectOutput(ProcessBuilder.Redirect.INHERIT);
            //processBuilder.redirectError(ProcessBuilder.Redirect.INHERIT);
            Process process = processBuilder.start();

            return process.waitFor();

        } catch (InterruptedException | IOException e) {
            e.printStackTrace();
        }
        return 1;
    }
}



