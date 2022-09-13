#!/bin/sh

set -e

# you can set the hostname if you want, but it'll default to localhost
if [ -z "$CERT_HOSTNAME" ]; then
    CERT_HOSTNAME="localhost"
fi

# also where the files are stored
if [ -z "$KANI_TMP" ]; then
    KANI_TMP=/tmp/kanidm/
fi

ALTNAME_FILE="${KANI_TMP}altnames.cnf"
CANAME_FILE="${KANI_TMP}ca.cnf"
CACERT="${KANI_TMP}ca.pem"
CAKEY="${KANI_TMP}cakey.pem"
CADB="${KANI_TMP}ca.txt"
CASRL="${KANI_TMP}ca.srl"

KEYFILE="${KANI_TMP}key.pem"
CERTFILE="${KANI_TMP}cert.pem"
CSRFILE="${KANI_TMP}cert.csr"
CHAINFILE="${KANI_TMP}chain.pem"
DHFILE="${KANI_TMP}dh.pem"

if [ ! -d "${KANI_TMP}" ]; then
    echo "Creating temp kanidm dir: ${KANI_TMP}"
    mkdir -p "${KANI_TMP}"
fi

cat > "${CANAME_FILE}" << DEVEOF
[req]
nsComment = "Certificate Authority"
distinguished_name  = req_distinguished_name
req_extensions = v3_ca

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
organizationalUnitName_default =  kanidm

commonName                      = Common Name (eg, your name or your server\'s hostname)
commonName_max                  = 64
commonName_default              = insecure.ca.localhost

[ v3_ca ]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

DEVEOF

cat > "${ALTNAME_FILE}" << DEVEOF

[ca]
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = ${KANI_TMP}
certs             = ${KANI_TMP}
crl_dir           = ${KANI_TMP}
new_certs_dir     = ${KANI_TMP}
database          = ${CADB}
serial            = ${CASRL}

# The root key and root certificate.
private_key       = ${CAKEY}
certificate       = ${CACERT}

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 3650
preserve          = no
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

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
organizationalUnitName_default =  kanidm

commonName                      = Common Name (eg, your name or your server\'s hostname)
commonName_max                  = 64
commonName_default              = ${CERT_HOSTNAME}

[ v3_req ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "Server Certificate"
subjectKeyIdentifier = hash
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1

DEVEOF

touch ${CADB}
echo 1000 > ${CASRL}

echo "Make the ca key..."
openssl ecparam -genkey -name prime256v1 -noout -out "${CAKEY}"

echo "Self sign the CA..."
openssl req -batch -config "${CANAME_FILE}" \
    -key "${CAKEY}" \
    -new -x509 -days +31 \
    -sha256 -extensions v3_ca \
    -out "${CACERT}" \
    -nodes

echo "Generate the server private key..."
openssl ecparam -genkey -name prime256v1 -noout -out "${KEYFILE}"

echo "Generate the certficate signing request..."
openssl req -sha256 -new \
    -batch \
    -config "${ALTNAME_FILE}" -extensions v3_req \
    -key "${KEYFILE}"\
    -nodes \
    -out "${CSRFILE}"

echo "Sign the cert..."
openssl ca -config "${ALTNAME_FILE}" \
    -batch \
    -extensions v3_req \
    -days 31 -notext -md sha256 \
    -in "${CSRFILE}" \
    -out "${CERTFILE}"

# Create the chain
cat "${CERTFILE}" "${CACERT}" > "${CHAINFILE}"

# create the dh file for RADIUS
openssl dhparam -in "${CAFILE}" -out "${DHFILE}" 2048

echo "Certificate chain is at: ${CHAINFILE}"
echo "Private key is at: ${KEYFILE}"
echo ""
echo "**Remember** the default action is to store the files in /tmp/ so they'll be deleted on reboot! Set the KANI_TMP environment variable before running this script if you want to change that. You'll need to update server config elsewhere if you do, however."
