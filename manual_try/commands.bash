#!/bin/sh

#copy the digested pdf file.

{ dd bs=1 count=59795 ; dd skip=12800 bs=1 ; dd bs=1 count=4914; }<hello_by_py_gabry_signed.pdf 2>/dev/null > contentfordigest

openssl dgst -sha256 -binary contentfordigest >digestedPDF

#extract the pkcs7 hex encoded

{ dd bs=1 skip=59795 count=12800 ; dd bs=1 skip=4914; }<hello_by_py_gabry_signed.pdf 2>/dev/null > pkcs7_extracted

#to binary

xxd -r -p pkcs7_extracted > pkcs7_extracted.bin

#decoding the pkcs7

openssl asn1parse -inform DER <pkcs7_extracted.bin >pkcs7_extracted_decoded


# 5193:d=8  hl=2 l=  32 prim: OCTET STRING      [HEX DUMP]:18B399D208A08815DDF23C93B1B63B13757A6AA24B1932569D7A69D0DB3A34C2
dd if=pkcs7_extracted.bin of=extracted.pdf.digest.bin bs=1 skip=$[ 5193 + 2 ] count=32

validityFlagDigest=$(cmp -b extracted.pdf.digest.bin digestedPDF)
if [ -z $validityFlagDigest ]; then
    echo "The PDF digest and the messageDigest in the pkcs7 file are equal. Now we'll check the signedAttributes' integrity ";
else
    echo "The PDF digest and messageDigest are different. Integrity check failed";
fi
#extraction the signature

dd if=pkcs7_extracted.bin of=extracted.sign.bin bs=1 skip=$[ 5242 + 4 ] count=256

#decrypt

openssl rsautl -verify -pubin -inkey CHIAVEPUBBLICA.pem < extracted.sign.bin > verified.bin

#decode of result
openssl asn1parse -inform der -in verified.bin

dd if=verified.bin of=decrypted.hash.bin bs=1 skip=$[ 17 + 2 ] count=32

#better analysis of the pkcs7 file
openssl cms -inform DER -in pkcs7_extracted.bin -noout -cmsout -print >pkcs7.info

#extraction of the signed attributes and conversion of the first byte in generic
dd if=pkcs7_extracted.bin of=sigAttributes.bin bs=1 skip=5133 count=$[5193+2+32-5133]
printf '\x31' | dd conv=notrunc of=sigAttributes.bin bs=1 seek=0


# http://qistoph.blogspot.it/2012/01/manual-verify-pkcs7-signed-data-with.html

openssl dgst -sha256 -binary sigAttributes.bin >sigAttributes.hash.bin

validityFlag=$(cmp -b decrypted.hash.bin sigAttributes.hash.bin)
if [ -z $validityFlag ]; then
    echo "The signedAttributes' integrity is verified";
else
    echo "Integrity check failed";
fi
