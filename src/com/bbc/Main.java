package com.bbc;

import org.apache.pdfbox.cos.COSDocument;
import org.apache.pdfbox.exceptions.*;
import org.apache.pdfbox.io.*;
import org.apache.pdfbox.io.RandomAccessFile;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Scanner;

/**
 * Created by gab88slash on 17/12/14.
 */
public class Main {

    /**d
     * Constructor.
     */
    public Main()
    {
        super();
    }
    private static BouncyCastleProvider provider = new BouncyCastleProvider();
    public static PDDocument document;

    /**
     * This will create a hello world PDF document.
     * <br />
     * see usage() for commandline
     *
     * @param args Command line arguments.
     */
    public static void main(String[] args)
    {
        System.out.println("This program will generate an example pdf. Then it will sign it programmatically\n" +
                "checking if the crypted digest is equal to a previously calculated one\n then it will provide a \n" +
                "visible sign");

        CreatePdfWithText creator = new CreatePdfWithText();
        try {
            document = creator.doIt("./resources/prova.pdf","la minchia moscia");
            COSDocument d = document.getDocument();

            BufferedReader br = new BufferedReader(new FileReader("./resources/prova.pdf"));
            PrintWriter writer = new PrintWriter("./resources/output_before_sign.txt", "UTF-8");
            for (String line; (line = br.readLine()) != null;) {
                writer.println(line);
            }
            writer.close();
            Scanner keyboard = new Scanner(System.in);
            System.out.println("enter password");
            String mypassword = keyboard.nextLine();
            CreateSignature signator = new CreateSignature("resources/Consiglio_s198283.p12",mypassword);

            File documento = new File("./resources/prova.pdf");
            documento = signator.signPDF(documento);

            br = new BufferedReader(new FileReader(documento));
            writer = new PrintWriter("./resources/output_after_sign.txt", "UTF-8");
            for (String line; (line = br.readLine()) != null;) {
                writer.println(line);
            }
            writer.close();



            documento = new File("./resources/prova.pdf");
            CreateVisibleSignature signing = new CreateVisibleSignature("resources/Consiglio_s198283.p12",mypassword);

            FileInputStream image = new FileInputStream("resources/Motto_polito.jpg");

            PDVisibleSignDesigner visibleSig = new PDVisibleSignDesigner("./resources/prova.pdf", image, 1);
            visibleSig.xAxis(0).yAxis(300).zoom(-50).signatureFieldName("signature");

            PDVisibleSigProperties signatureProperties = new PDVisibleSigProperties();

            signatureProperties.signerName("name").signerLocation("location").signatureReason("Security").preferredSize(0)
                    .page(1).visualSignEnabled(true).setPdVisibleSignature(visibleSig).buildSignature();

            documento = signing.signPDF(documento, signatureProperties);

            br = new BufferedReader(new FileReader(documento));
            writer = new PrintWriter("./resources/output_after_sign_visible.txt", "UTF-8");
            for (String line; (line = br.readLine()) != null;) {
                writer.println(line);
            }
            writer.close();

            StepByStepSignature mystep_by_step = new StepByStepSignature("resources/Consiglio_s198283.p12",mypassword);


            File documentoFirmato = new File("resources/prova_signed.pdf");
            RandomAccess docFirmato = new RandomAccessFile(documentoFirmato,"rw");
//            documento = mystep_by_step.signPDF(documento);
            COSDocument cosFirmato = new COSDocument(docFirmato);

            PDDocument PDfirmato = new PDDocument(cosFirmato);
            PDSignature firma = PDfirmato.getLastSignatureDictionary();
            byte[] signedcontent = firma.getContents(new FileInputStream(documentoFirmato));

            StringBuffer ex_signature = new StringBuffer();
            for (int i=0;i<signedcontent.length;i++) {
                ex_signature.append(Integer.toHexString(0xFF & signedcontent[i]));
            }
            System.out.println("Hex signature extracted : " + ex_signature.toString());



            File ksFile = new File("resources/Consiglio_s198283.p12");
            KeyStore keystore = KeyStore.getInstance("PKCS12", provider);
            char[] pin = mypassword.toCharArray();
            keystore.load(new FileInputStream(ksFile), pin);

            Enumeration<String> aliases = keystore.aliases();
            String alias = null;
            if (aliases.hasMoreElements())
            {
                alias = aliases.nextElement();
            }
            else
            {
                throw new RuntimeException("Could not find alias");
            }
            PrivateKey privKey = (PrivateKey) keystore.getKey(alias, pin);
            Certificate[] cert = keystore.getCertificateChain(alias);

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            documento = new File("./resources/prova.pdf");
            md.update(IOUtils.toByteArray(new FileInputStream(documento)));
            byte[] digest = md.digest();
            //convert the byte to hex format method 2
            StringBuffer hexString = new StringBuffer();
            for (int i=0;i<digest.length;i++) {
                hexString.append(Integer.toHexString(0xFF & digest[i]));
            }

            System.out.println("Hex format : " + hexString.toString());

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privKey);
            byte[] cipherData = cipher.doFinal(hexString.toString().getBytes());
            StringBuffer signature = new StringBuffer();
            for (int i=0;i<cipherData.length;i++) {
                signature.append(Integer.toHexString(0xFF & cipherData[i]));
            }
            System.out.println("Hex signature : " + signature.toString());

        } catch (IOException e) {
            e.printStackTrace();
        } catch (COSVisitorException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (org.apache.pdfbox.exceptions.SignatureException e) {
            e.printStackTrace();
        }

    }


}
