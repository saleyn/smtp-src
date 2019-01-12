# BarracudaSMTP - smtp server example (C++)
Ssl Smtp Server with c++ openssl sockets and STARTTLS

### Install
<br> apt-get install openssl libssl-dev g++
<br>
### Compile
<br> g++ -o BarsacudaSMTP main.cpp starttls.cpp starttls.h -lssl -lcrypto -L. -I.
<br>
### Create TLS certs (very simple): 
<br> https://www.sslforfree.com/
<br>
### Add certificate to main folder 
<br> (create .pem - copy all certs,keys,ca_bundle to one file)
<br> certificate.pem, private.key - without password

### Send email test
openssl s_client -connect localhost:25 -starttls smtp


