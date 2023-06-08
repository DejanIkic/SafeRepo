package main;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
        System.out.println("\n====================================");
        System.out.printf("||%30s||\n",str);
        System.out.println("====================================");
    }

    private static void homePage() {
        printEq("Dobrodosli!");
        int i = 0;
        char input;
        boolean whileCond = true;
        while (whileCond) {

            System.out.println("\nPritisnite dugme [ r -registracija\b p -prijava ]");
            input = sc.nextLine().charAt(0);
            input = Character.toUpperCase(input);
            switch (input) {
                case 'P': {
                    ////////////Prijava na sistem
                    if (prijavaNaSistem()) {

                        printEq("Prijavljen korisnik: " + username +"" +
                                "\nIspis fajlova");

                        Cripto.prikazFajlova(username);
                        dodajFajl();
                        preuzmiFajl();

                    } else {
                        return;
                    }
                    whileCond = false;
                    break;
                }
                case 'R': {
                    ////////////Registracija novog korisnika
                    registracijaNaSistem();
                    whileCond = false;
                    break;
                }
                default: {
                    System.out.println("Pogresno slovo, probajte ponovo");
                }
            }
        }

    }

    private static boolean prijavaNaSistem() {

        printEq("Prijava");
        boolean certTrue = true;


        System.out.println("Unesite korisnicko ime: ");
        username = sc.nextLine();
        Cripto.provjeriSertifikat(username + ".crt");


        if (certTrue) {
            int i = 3;

            while (i != 0) {
                System.out.print("Lorisnicko ime: " + username + "\n");
                System.out.print("Unesite lozinku: ");
                password = sc.nextLine();
                /////////////////////////// provjera sifre i imena
                boolean rezultatProvjere = Cripto.provjeraLozinke(username, password);

                if (rezultatProvjere) { ///uspjesna prijava
                    System.out.println("Uspjesna prijava ");
                    return true;
                } else {  ///neuspjesna prijava
                    System.out.println(" Pogresni kredencijali, probajte ponovo, imate jos " + --i + " pokusaj(a)!\n");
                }
                if (i == 0) { ///suspenzija
                    /////////////////////// suspenduj sertifikat i ponudi reaktivaciju;
                    System.out.println("Vas sertifikat je suspendovan! \nIzaberite opciju" +
                            "\n[-o obnova sertifikata, -r registracija novog naloga]");
//                    String input = sc.nextLine();
                    String input = "o";

                    switch (input.toUpperCase().charAt(0)) {
                        case 'O': {

                        }
                        case 'R': {
                            registracijaNaSistem();
                        }
                    }
                    return false;
                }
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

    }

    private static void preuzmiFajl(){
        printEq("Preuzimanje fajla");
        System.out.println("Da li zelite da preuzmete neki fajl [y/n]");
        String input = sc.nextLine();

        switch (input.toUpperCase().charAt(0)){
            case 'Y' :{

                System.out.println("\nDostupni fajlovi");
                Cripto.prikazFajlova(username);
                System.out.println("Izaberite fajl koji preuzimate: ");
                String fajl = sc.nextLine();
                System.out.println("Unesite lokaciju na kojoj ce se smjestiti fajl (sa njegovim imenom)");
                String putanjaNovog= sc.nextLine();

                Cripto.preuzmiFajl(username,fajl,putanjaNovog);


            } case 'N':{
            }
        }

    }

    private static void dodajFajl(){
        printEq("Dodavanje fajla");
        System.out.println("Da li zelite da dodate neki fajl [y/n]");
        String input = sc.nextLine();



        switch (input.toUpperCase().charAt(0)){
            case 'Y' :{
                System.out.println("Unesite putanju do fajla [apsolutna putanja]:  ");
                String putanja = sc.nextLine();
                //String putanja  = "/home/dejan/Desktop/mrs/SafeRepo/src/resources/test.txt";
                File file = new File( putanja);

                Cripto.dodajFajl(username, file);

            } case 'N':{
            }
        }
    }
}
