# RSA Benchmarks

This project runs hash tests on various CPU's using the OpenSSL cryptographic library.

Note: equivalent [aesbench](https://github.com/lelegard/aesbench) and
[shabench](https://github.com/lelegard/shabench) projects exist for AES
and SHA hash functions.

## Performance results

TBC

## RSA key pairs generation

The RSA key pairs in this repository are used to run the tests. The same keys
are used on all platforms. These keys were generated using the following commands:

~~~
for s in 2048 3072 4096; do
    openssl genpkey -quiet -algorithm RSA -pkeyopt rsa_keygen_bits:$s \
        -out keys/rsa-$s-prv.pem -outpubkey keys/rsa-$s-pub.pem -outform PEM 
done
~~~

To view the key content:

~~~
openssl rsa -in rsa-2048-prv.pem -text
openssl rsa -in rsa-2048-pub.pem -pubin -text
~~~
