package com.bbc;


import org.apache.pdfbox.cos.COSDocument;
import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.PKCS9Attributes;
import sun.security.pkcs.SignerInfo;
import sun.security.x509.AlgorithmId;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;
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
        CreatePdfWithText creator = new CreatePdfWithText();
        try {

            /*
            Creation of document
             */
            document = creator.doIt("./resources/document.pdf","A pdf try - Hello World");
            COSDocument d = document.getDocument();



            BufferedReader br = new BufferedReader(new FileReader("./resources/document.pdf"));
            PrintWriter writer = new PrintWriter("./resources/output_before_sign.txt", "UTF-8");
            for (String line; (line = br.readLine()) != null;) {
                writer.println(line);
            }
            writer.close();
            /*
            end of creation
             */

            /*

            First Signature

             */
            Scanner keyboard = new Scanner(System.in);
            System.out.println("enter password");
            String mypassword = keyboard.nextLine();
            CreateSignature signator = new CreateSignature("resources/certificate.p12",mypassword);

            File documento = new File("./resources/document.pdf");
            documento = signator.signPDF(documento);


            documento = new File("./resources/document_signed.pdf");

            br = new BufferedReader(new FileReader(documento));
            writer = new PrintWriter("./resources/output_after_sign.txt", "UTF-8");
            for (String line; (line = br.readLine()) != null;) {
                writer.println(line);
            }
            writer.close();
            /*
            end of First Signature
             */

            /*
            Visual Signature
             */
            documento = new File("./resources/document.pdf");
            CreateVisibleSignature signing = new CreateVisibleSignature("resources/certificate.p12",mypassword);

            FileInputStream image = new FileInputStream("resources/Motto_polito.jpg");

            PDVisibleSignDesigner visibleSig = new PDVisibleSignDesigner("./resources/document.pdf", image, 1);
            visibleSig.xAxis(0).yAxis(300).zoom(-50).signatureFieldName("signature");

            PDVisibleSigProperties signatureProperties = new PDVisibleSigProperties();

            signatureProperties.signerName("name").signerLocation("location").signatureReason("Security").preferredSize(0)
                    .page(1).visualSignEnabled(true).setPdVisibleSignature(visibleSig).buildSignature();

            documento = signing.signPDF(documento, signatureProperties);
            documento = new File("./resources/document_signed_visible.pdf");

            br = new BufferedReader(new FileReader(documento));
            writer = new PrintWriter("./resources/output_after_sign_visible.txt", "UTF-8");
            for (String line; (line = br.readLine()) != null;) {
                writer.println(line);
            }
            writer.close();
            /*
            End of Visual Signature
             */


            /*
            Verification Of signature
             */


            /*
            extraction of pkcs7
             */
            File documentoFirmato = new File("resources/document_signed.pdf");
            PDDocument PDfirmato = PDDocument.load(documentoFirmato);
            PDSignature firma = PDfirmato.getLastSignatureDictionary();

            /*
            this is the encoded pkcs#7 package inside the signature dictionary it's padded with trailing zeroes
             */
            byte[] pkcs7_encoded = firma.getContents(new FileInputStream(documentoFirmato));

            System.out.println("Hex pkcs7 padded extracted : " + toHex(pkcs7_encoded));

            /*
            this is the content of the pdf on which is calculated the cripted digest. Is obtained using the Byte range.
             */
            byte[] signedContentFromSignature = firma.getSignedContent(new FileInputStream(documentoFirmato));


            writer = new PrintWriter("./resources/output_after_sign_extracted.txt", "UTF-8");
            for (int i=0;i<signedContentFromSignature.length;i++) {
                writer.write(signedContentFromSignature[i]);
            }
            writer.close();

            /*
            Extraction of the keys and certificates from the keystore
             */

            File ksFile = new File("resources/certificate.p12");
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

            /*
            End of extraction
             */
            /*
            Calculation of the digest SHA-256 of the PDF signed content
             */
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(signedContentFromSignature);
            byte[] digest = md.digest();

            System.out.println("Digest of PDF signedContent : " + toHex(digest));
            /*
            Analisys of pkcs7 information and integrity check on pkcs7
             */
            PKCS7 pkcs7_decoded = new PKCS7(pkcs7_encoded);

            /*
            Information about Algorithm used for the signature
             */
            SignerInfo[] signer_info = pkcs7_decoded.getSignerInfos();
            AlgorithmId digalgoritmo = signer_info[0].getDigestAlgorithmId();
            AlgorithmId encalgoritmo = signer_info[0].getDigestEncryptionAlgorithmId();
            System.out.println("Algorithms used: "+digalgoritmo.toString()+" "+encalgoritmo.toString());

            /*
            Extration of signed attributes
             */
            PKCS9Attributes signedattributes = signer_info[0].getAuthenticatedAttributes();

            /*
            Extraction of the stored digest of the PDF signed content
             */
            Object messageDigest = signedattributes.getAttribute("MessageDigest").getValue();
            System.out.println("Extracted Digest of PDF signed Content: "+toHex((byte[])messageDigest) );
            System.out.println("Digest are equals? :"+Arrays.equals(digest,(byte[]) messageDigest));

            /*
            Integrity check on PKCS7 SignedAttributes
             */

            /*
            Digest of the signedattributes
             */
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] derSignedAttributesHash = sha256.digest(signedattributes.getDerEncoding());

            /*
            Extraction of encrypted digest and decryption
             */
            byte[] encripted_digest = signer_info[0].getEncryptedDigest();
            Cipher decipher = Cipher.getInstance("RSA");
            decipher.init(Cipher.DECRYPT_MODE,cert[0]);
            byte[] decipherData = decipher.doFinal(encripted_digest);
            ASN1Object object = ASN1Object.fromByteArray(decipherData);
            DigestInfo digestInfo = new DigestInfo(ASN1Sequence.getInstance(object.toASN1Object()));
            System.out.println("Decripted digest  : " + toHex(digestInfo.getDigest()));
            System.out.println("Signed Attributes Hash: " + toHex(derSignedAttributesHash));
            System.out.println("Digest are equals? :"+Arrays.equals(digestInfo.getDigest(),derSignedAttributesHash));

            PDfirmato.close();

        } catch (IOException e) {
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
        } catch (COSVisitorException e) {
            e.printStackTrace();
        }
    }

    public static String toHex(byte[] bytes){

        StringBuffer digestStringBuffer = new StringBuffer();
        for (int i=0;i<bytes.length;i++) {
            digestStringBuffer.append(String.format("%02x", 0xFF & bytes[i]));
        }

        return digestStringBuffer.toString();
    }
}

