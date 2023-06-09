package main;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.x509.KeyFactory;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Utils {


    public static final String USERS_PATH = "src" + File.separator +"users" + File.separator;
    public static final String REPO_PATH = "src" + File.separator +"repo" + File.separator;
    public static final String RESOURCES_PATH = "src" + File.separator +"resources" + File.separator;
    public static final String SIGNATURES_PATH = "src" + File.separator +"signatures" + File.separator;
    public static final String DATABASE_PATH = REPO_PATH +"database.txt";

    public static final File PROBNI_FAJL = new File( RESOURCES_PATH + File.separator + "probniFajl.txt" );




}
