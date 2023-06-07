package main;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.DigestException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class Main {

    public static Scanner sc = new Scanner(System.in);
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
        registracijaNaSistem();
    }

    private static void printEq() {
        System.out.println("===================================");
        System.out.println("===================================");
    }

    private static void homePage() {
        printEq();
        int i = 0;
        char input;
        boolean whileCond = true;
        while (whileCond) {

            System.out.println("Dobrodosli!\nPritisnite dugme [ r -registracija\b p -prijava ]");
            input= sc.nextLine().charAt(0);
            input = Character.toUpperCase(input);
            switch (input) {
                case 'P': {
                    ////////////Prijava na sistem
                    prijavaNaSistem();
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

    private static void prijavaNaSistem(){

        printEq();
        boolean certTrue = true;


        System.out.println("Unesite putanju do svog sertifikata { /ca/certs/username");
        ////////////////////////////////Provjera
        System.out.println("provjera sertifikata == " + certTrue);

        if (certTrue){
            int i = 3;
            while (true){

                System.out.print("Unesite korisnicko ime: " );
                username = sc.nextLine();
                System.out.print("Unesite lozinku: " );
                password = sc.nextLine();
                /////////////////////////// provjera sifre i imena
                boolean rezultatProvjere = true;

                if (rezultatProvjere){
                    break;
                } else i--;
                if (i == 0) {
                    /////////////////////// suspenduj sertifikat i ponudi reaktivaciju;
                }
            }
        }

    }

    private static void registracijaNaSistem(){

        /////////// unos imena
        printEq();
        File usersPath = new File(Utils.USERS_PATH);
        String[] usersList = usersPath.list();
        File newUser = null;
        boolean uslov = true;
        do{

            System.out.println("Unesite korisnicko ime: ");
            username = sc.nextLine();

            if (Arrays.asList(usersList).contains(username)){
                System.out.println("Korisnicko ime je zauzeto!");
            } else {
                 newUser = new File(usersPath +File.separator+ username );
                newUser.mkdir();
                uslov = false;
                //System.out.println("korisnik " + username + " je kreiran");
            }
        } while (uslov);


        /////////// unos lozinke

        System.out.println("Unesite lozinku: ");
        password = sc.nextLine();
        String hashLozinke = Cripto.hashBytes(password.getBytes(StandardCharsets.UTF_8));


        KeyPair klucevi =  Cripto.generisiKljuceve(  newUser);




        /////////// izdavanje sertifikata
       //Cripto.createUser("dejan1","dejan1","dejan1","dejan1");


    }
}