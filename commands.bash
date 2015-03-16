#!/bin/sh

#copy the digested pdf file.

{ dd bs=1 count=59795 ; dd skip=12800 bs=1 ; dd bs=1 count=4914; }<hello_by_py_gabry_signed.pdf 2>/dev/null > contentfordigest

openssl dgst -sha256 -binary contentfordigest >digestedPDF

#extract the pkcs7 hex encoded

{ dd bs=1 skip=59795 count=12800 ; dd bs=1 skip=4914; }<hello_by_py_gabry_signed.pdf 2>/dev/null > pkcs7_extracted

#to binary

xxd -r -p pkcs7_extracted > pkcs7_extracted.bin

#decoding the asn1 formatted pkcs7

openssl asn1parse -inform DER <pkcs7_extracted.bin >pkcs7_extracted_decoded

# decodification considering CMS standards

openssl cms -inform DER -in pkcs7_extracted.bin -noout -cmsout -print >pkcs7.info

# extraction of digest 5193:d=8  hl=2 l=  32

dd if=pkcs7_extracted.bin of=extracted.pdf.digest.bin bs=1 skip=$[ 5193 + 2 ] count=32

validityFlagDigest=$(cmp -b extracted.pdf.digest.bin digestedPDF)
if [ -z $validityFlagDigest ]; then
    echo "The PDF digest and the messageDigest in the pkcs7 file are equal. Now we'll check the signedAttributes' integrity ";
else
    echo "The PDF digest and messageDigest are different. Integrity check failed";
fi

#extraction the signature  5242:d=5  hl=4 l= 256 prim: OCTET STRING

dd if=pkcs7_extracted.bin of=extracted.sign.bin bs=1 skip=$[ 5242 + 4 ] count=256

#decrypt

openssl rsautl -verify -pubin -inkey CHIAVEPUBBLICA.pem < extracted.sign.bin > verified.bin

# simple decode of the asn1 formatted result
openssl asn1parse -inform der -in verified.bin

# extraction of decrypted hash 17:d=1  hl=2 l=  32

dd if=verified.bin of=decrypted.hash.bin bs=1 skip=$[ 17 + 2 ] count=32

# extraction of the signed attributes and conversion of the first byte in generic
dd if=pkcs7_extracted.bin of=sigAttributes.bin bs=1 skip=5133 count=$[5193+2+32-5133]
printf '\x31' | dd conv=notrunc of=sigAttributes.bin bs=1 seek=0


# creation of the digest and final verification

openssl dgst -sha256 -binary sigAttributes.bin >sigAttributes.hash.bin

validityFlag=$(cmp -b decrypted.hash.bin sigAttributes.hash.bin)
if [ -z $validityFlag ]; then
    echo "The signedAttributes' integrity is verified";
else
    echo "Integrity check failed";
fi
