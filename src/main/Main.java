package main;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.DigestException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

public class Main {

    public static Scanner sc = new Scanner(System.in);
    public static Random random = new Random();
    private static String username;
    private static String password;

    public static void main(String[] args) throws NoSuchAlgorithmException, DigestException {
        //homePage();

        /*String l = "lozinka";
        System.out.println("pass hash: "+Cripto.hashBytes(l.getBytes(StandardCharsets.UTF_8)));


        File file = new File(Utils.USERS_PATH +"dejan/proba.txt");
        try {
            byte[] arr = Files.readAllBytes(file.toPath());
            System.out.println("fajl hash: "+ Cripto.hashBytes(arr));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }*/

        //Cripto.getUserSertificate();

        homePage();

        //Cripto.prikazFajlova("dejan");
    }

    private static void printEq(String str) {
        System.out.println("\n***************************************************************************************");
        System.out.printf("*     %-80s*", str);
        System.out.println("\n***************************************************************************************");
    }

    private static void homePage() {

        String input;
        while (true) {

            printEq("Glavni Meni");
            System.out.println("[ R -registracija\t P -prijava \t I -izlazak]");
            input = sc.nextLine();
            if (input.length()==0) {
                input=" "; // u slucaju pritiskanja <Enter> ulazi u default case
            }

            switch (input.toUpperCase().charAt(0)) {
                case 'P': {
                    ////////////Prijava na sistem
                    if (prijavaNaSistem()) {
                        kopirajPrivatniKljuc(username, true);

                        String izbor = "";
                        while (!izbor.equalsIgnoreCase("o")) {
                            printEq("Prijavljen korisnik: " + username);
                            System.out.println("[D- dodaj\t P -preuzmi \t O -odjava\t V - prikaz fajlova]");
                            izbor = sc.nextLine();

                            if (izbor.length()==0) {
                                izbor=" "; // u slucaju pritiskanja <Enter> ulazi u default case
                            }
                            switch (izbor.toUpperCase().charAt(0)) {
                                case 'D': {
                                    Cripto.prikazFajlova(username);
                                    dodajFajl();
                                    break;
                                }
                                case 'P': {
                                    preuzmiFajl();
                                    break;
                                }
                                case 'V': {
                                    printEq("Fajlovi korisnika: " + username);
                                    Cripto.prikazFajlova(username);
                                    break;
                                }
                                case 'O': {
                                    System.out.println("Uspjesno ste se odjavili!\n");
                                    kopirajPrivatniKljuc(username, false);
                                    break;
                                }
                                default: {
                                    System.out.println("Pogresno slovo!");
                                }
                            }
                        }

                    } else {
                        return;
                    }

                    continue;
                }
                case 'R': {
                    ////////////Registracija novog korisnika
                    registracijaNaSistem();
                    continue;
                }
                case 'I': {
                    return;
                }
                default: {
                    System.out.println("Pogresno slovo, probajte ponovo");
                }
            }
        }

    }

    private static boolean prijavaNaSistem() {

        printEq("Prijava");
        boolean certTrue = false;
        int j = -2;
        String imeSert="";

        while (j== -2) {
            System.out.println("Unesite ime fajla sertifikata:\n  [src/ca/scerts/$fajlSertifikata]");
             imeSert = sc.nextLine();
            j = Cripto.provjeriSertifikat(imeSert);

        }

        certTrue = j == 0;

        if (certTrue) {
            int i = 3;

            while (i != 0) {
                System.out.print("Korisnicko ime: ");
                username = sc.nextLine();
                System.out.print("Unesite lozinku: ");
                password = sc.nextLine();
                /////////////////////////// provjera sifre i imena
                boolean rezultatProvjere = Cripto.provjeraLozinke(username, password);

                if (rezultatProvjere) { ///uspjesna prijava
                    System.out.println("Uspjesna prijava ");
                    return true;
                } else {  ///neuspjesna prijava
                    if (--i != 0) System.out.println(" Pogresni kredencijali, " +
                            "probajte ponovo, imate jos " + i + " pokusaj(a)!\n");
                }
                if (i == 0) { ///suspenzija
                    Cripto.suspendujSertifikat(imeSert);
                    System.out.println("Vas sertifikat[src/ca/certs/" + imeSert + "] je suspendovan! \n" +
                            "Izaberite opciju " + "\n[-o obnova sertifikata, -r registracija novog naloga]");
                    String input = sc.nextLine();


                    switch (input.toUpperCase().charAt(0)) {
                        case 'O': {
                            obnovaSertifikata();
                            break;
                        }
                        case 'R': {
                            registracijaNaSistem();
                            break;
                        }
                    }
                    return false;
                }
            }
        } else {
            System.out.println("Vas sertifikat nije validan, zelite li da ga obnovite?[y/n]");
            String obnova = sc.nextLine();
            if (obnova.toUpperCase().equals("Y")) {
                obnovaSertifikata();
            }

        }
        return certTrue;
    }

    private static void registracijaNaSistem() {
        /////////// unos imena
        printEq("Registracija");
        File usersPath = new File(Utils.USERS_PATH);
        String[] usersList = usersPath.list();
        File newUser = null;
        boolean uslov = true;
        do {

            System.out.println("Unesite korisnicko ime: ");
            username = sc.nextLine();

            if (Arrays.asList(usersList).contains(username)) {
                System.out.println("Korisnicko ime je zauzeto!");
            } else {
                newUser = new File(usersPath + File.separator + username);
                newUser.mkdir();
                uslov = false;
            }
        } while (uslov);

        /////////// unos lozinke
        System.out.println("Unesite lozinku: ");
        password = sc.nextLine();
        String hashLozinke = Cripto.hashBytes(password.getBytes(StandardCharsets.UTF_8));
        try {
            File file = new File(newUser, "password");
            FileWriter fw = new FileWriter(file);
            fw.write(hashLozinke);
            fw.close();
        } catch (IOException e) {
        }

        KeyPair klucevi = Cripto.generisiKljuceve(newUser);

        Cripto.generisiSertifikat(username);

        System.out.println("Uspjesno ste se registrovali!");
    }

    private static void preuzmiFajl() {
        printEq("Preuzimanje fajla");


        int res= Cripto.prikazFajlova(username);
        if (res == -1){
            System.out.println("Nema dostupnih fajlova!");
            return;
        }
        System.out.println("\nDostupni fajlovi");
        System.out.println("Izaberite fajl koji preuzimate: ");
        String fajl = sc.nextLine();
        System.out.println("Unesite lokaciju na kojoj ce se smjestiti fajl (sa njegovim imenom)");
        String putanjaNovog = sc.nextLine();

        Cripto.preuzmiFajl(username, fajl, putanjaNovog);

        System.out.println("Fajl je uspjesno preuzet!");

    }

    private static void dodajFajl() {
        printEq("Dodavanje fajla");

        System.out.println("Unesite putanju do fajla [apsolutna putanja]:  ");
        String putanja = sc.nextLine();
        //String putanja  = "/home/dejan/Desktop/mrs/SafeRepo/src/resources/test.txt";
        File file = new File(putanja);

        Cripto.dodajFajl(username, file);
        System.out.println("Fajl je uspjesno dodan!");

    }

    private static void obnovaSertifikata() {
        System.out.println("Unesite ime fajla sertifikata:\n[src/ca/scerts/$fajlSertifikata]: ");
        String imeSertifikata = sc.nextLine();
        System.out.print("Korisnicko ime: ");
        username = sc.nextLine();
        System.out.print("Unesite lozinku: ");
        password = sc.nextLine();
        if (Cripto.provjeraLozinke(username, password)) {
            Cripto.obnoviSertifikat(imeSertifikata);
            System.out.println("Sertifikat uspjesno obnovljen! ");
            prijavaNaSistem();
        } else {
            System.out.println("Ponovo pogresni kredencijali, terminacija!");
        }
    }

    private static void kopirajPrivatniKljuc(String username, boolean action) { //action ako je prijavljen, false nakon odjave
        File kljuc = new File(Utils.USERS_PATH + File.separator + username
                + File.separator + "privateKey.pem");
        File kljucUCA = new File("src" + File.separator + "ca" + File.separator + "private"
                        + File.separator + "user" + "." + "privateKey.pem"
        );


        try {
            if (action) {
                Files.copy(kljuc.toPath(), kljucUCA.toPath(),StandardCopyOption.REPLACE_EXISTING);
            } else {
                Files.delete(kljucUCA.toPath());
            }
        } catch (IOException e) {
            System.out.println("Izuzetak kod kopiranja privatnog kljuca prijavljenog!\n " + e);
        }

    }
}
