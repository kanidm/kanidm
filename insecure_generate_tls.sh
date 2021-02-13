#!/bin/sh

cat > ./altnames.cnf << DEVEOF
[req]
nsComment = "Certificate"
distinguished_name  = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]

countryName                     = Country Name (2 letter code)
countryName_default             = AU
countryName_min                 = 2
countryName_max                 = 2

stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = Queensland

localityName                    = Locality Name (eg, city)
localityName_default            = Brisbane

0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = INSECURE EXAMPLE

organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default =  KaniDM

commonName                      = Common Name (eg, your name or your server\'s hostname)
commonName_max                  = 64
commonName_default              = localhost

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1

DEVEOF

# Make the ca
openssl req -x509 -new -newkey rsa:4096 -sha256 -keyout cakey.pem -out ca.pem -days 31 -subj "/C=AU/ST=Queensland/L=Brisbane/O=INSECURE/CN=insecure.ca.localhost" -nodes
openssl genrsa -out key.pem 4096
openssl req -sha256 -key key.pem -out cert.csr -days 31 -config altnames.cnf -new -extensions v3_req
openssl x509 -req -days 31 -in cert.csr -CA ca.pem -CAkey cakey.pem -CAcreateserial -out cert.pem -extfile altnames.cnf -extensions v3_req -sha256
# Create the chain
cat cert.pem ca.pem > chain.pem

echo use chain.pem, and key.pem

