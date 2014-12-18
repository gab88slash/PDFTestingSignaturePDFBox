package com.bbc;

import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.exceptions.SignatureException;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

/**
 * Created by gab88slash on 18/12/14.
 */
public class StepByStepSignature implements SignatureInterface {


    private static BouncyCastleProvider provider = new BouncyCastleProvider();

    private PrivateKey privKey;

    private Certificate[] cert;

    private SignatureOptions options;
    public StepByStepSignature(String keyfile, String password)
    {
        try
        {
            Security.addProvider(provider);
            File ksFile = new File(keyfile);
            KeyStore keystore = KeyStore.getInstance("PKCS12", provider);
            char[] pin = password.toCharArray();
            keystore.load(new FileInputStream(ksFile), pin);
      /*
       * grabs the first alias from the keystore and get the private key. An
       * alternative method or constructor could be used for setting a specific
       * alias that should be used.
       */
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
            privKey = (PrivateKey) keystore.getKey(alias, pin);
            cert = keystore.getCertificateChain(alias);
        }
        catch (KeyStoreException e)
        {
            e.printStackTrace();
        }
        catch (UnrecoverableKeyException e)
        {
            System.err.println("Could not extract private key.");
            e.printStackTrace();
        }
        catch (NoSuchAlgorithmException e)
        {
            System.err.println("Unknown algorithm.");
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     * Creates a cms signature for the given content
     *
     * @param content is the content as a (Filter)InputStream
     * @return signature as a byte array
     */
    @Override
    public byte[] sign(InputStream content) throws SignatureException, IOException {

        byte[] cipherData = new byte[0];


        try {
            CMSProcessableInputStream input = new CMSProcessableInputStream(content);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            // CertificateChain
            List<Certificate> certList = Arrays.asList(cert);

            CertStore certStore = null;
            certStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(certList), provider);
            gen.addSigner(privKey, (X509Certificate) certList.get(0),
                    CMSSignedGenerator.DIGEST_SHA256);
            gen.addCertificatesAndCRLs(certStore);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();


            // Fake code simulating the copy
// You can generally do better with nio if you need...
// And please, unlike me, do something about the Exceptions :D
            byte[] buffer = new byte[1024];
            int len;
            while ((len = content.read(buffer)) > -1 ) {
                baos.write(buffer, 0, len);
            }
            baos.flush();

            // Open new InputStreams using the recorded bytes
// Can be repeated as many times as you wish
            InputStream is1 = new ByteArrayInputStream(baos.toByteArray());
            MessageDigest md = null;
            md = MessageDigest.getInstance("SHA-256");
            md.update(IOUtils.toByteArray(is1));
            byte[] digest = md.digest();
            //convert the byte to hex format method 2
            StringBuffer hexString = new StringBuffer();
            for (int i=0;i<digest.length;i++) {
                hexString.append(Integer.toHexString(0xFF & digest[i]));
            }

            System.out.println("Hex format : " + hexString.toString());

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privKey);
            cipherData = cipher.doFinal(hexString.toString().getBytes());
            StringBuffer signature = new StringBuffer();
            for (int i=0;i<cipherData.length;i++) {
                signature.append(Integer.toHexString(0xFF & cipherData[i]));
            }
            System.out.println("Hex signature mine : " + signature.toString());


        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (CertStoreException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (CMSException e) {
            e.printStackTrace();
        }

        return cipherData;
    }

    /**
     * Signs the given pdf file.
     *
     * @param document is the pdf document
     * @return the signed pdf document
     * @throws java.io.IOException
     * @throws org.apache.pdfbox.exceptions.COSVisitorException
     * @throws java.security.SignatureException
     */
    public File signPDF(File document) throws IOException, COSVisitorException,
            java.security.SignatureException, org.apache.pdfbox.exceptions.SignatureException {
        byte[] buffer = new byte[8 * 1024];
        if (document == null || !document.exists())
        {
            new RuntimeException("Document for signing does not exist");
        }

        // creating output document and prepare the IO streams.
        String name = document.getName();
        String substring = name.substring(0, name.lastIndexOf("."));

        File outputDocument = new File(document.getParent(), substring+"_signed_step_by_step.pdf");
        FileInputStream fis = new FileInputStream(document);
        FileOutputStream fos = new FileOutputStream(outputDocument);

        int c;
        while ((c = fis.read(buffer)) != -1)
        {
            fos.write(buffer, 0, c);
        }
        fis.close();
        fis = new FileInputStream(outputDocument);

        // load document
        PDDocument doc = PDDocument.load(document);

        // create signature dictionary
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter
        // subfilter for basic and PAdES Part 2 signatures
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("signer name");
        signature.setLocation("signer location");
        signature.setReason("reason for signature");

        // the signing date, needed for valid signature
        signature.setSignDate(Calendar.getInstance());

        // register signature dictionary and sign interface
        if (options==null)
        {
            doc.addSignature(signature, this);
        }
        else
        {
            doc.addSignature(signature, this, options);
        }

        // write incremental (only for signing purpose)
        doc.saveIncremental(fis, fos);

        return outputDocument;
    }



}
