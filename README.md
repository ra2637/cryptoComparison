# cryptoComparison
This is a project that compares cryptography time among JCE, Bouncy Castle, and Crypto++. The project compares

Symmetric key
- DES CBC
- DES OFB
- AES CBC
- AES OFB

Asymmetric key
- RSA
- DH

Hash
- MD5
- SHA512

There are 2 shell scripts and tested in Ubuntu wily: `runDemo` and `runAnlaysis`. Please run `runDemo` first and then `runAnalysis`.

`runDemo $filePath $testTimes`: you can specify the file to run all the alogrithms thorugh filePath and how many times you would like to run for the test.

After `runDemo` is done, uses `runAnalysis`. This will create an `analysis` folder and you can see the results there.
