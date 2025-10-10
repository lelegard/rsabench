# RSA Benchmarks

This project runs RSA tests on various CPU's using the OpenSSL cryptographic library.

Note: equivalent [aesbench](https://github.com/lelegard/aesbench) and
[shabench](https://github.com/lelegard/shabench) projects exist for AES
and SHA hash functions.

The tested key sizes are 2048, 3072, and 4096 bits.

Encryptions use OAEP padding. Signatures use PSS padding.

## Performance results

The performances are displayed and sorted in number of operations: encryption,
decryption, signature generation or verification.

The results are summarized in file [RESULTS.txt](RESULTS.txt).
It is generated using the Python script `analyze.py`.

Two tables are provided:

- Number of operations per second.
- Number of operations per CPU cycle. This metrics is independent of the
  CPU frequency and demonstrates the quality of implementation.

In each table, the ranking of each CPU in the line is added between brackets.

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
