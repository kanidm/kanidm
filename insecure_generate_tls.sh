#!/bin/sh

# you can set the hostname if you want, but it'll default to localhost
if [ -z "$CERT_HOSTNAME" ]; then
    CERT_HOSTNAME="localhost"
fi

# also where the files are stored
if [ -z "$KANI_TMP" ]; then
    KANI_TMP=/tmp/kanidm/
fi

ALTNAME_FILE="${KANI_TMP}altnames.cnf"
CACERT="${KANI_TMP}ca.pem"
CAKEY="${KANI_TMP}cakey.pem"

KEYFILE="${KANI_TMP}key.pem"
CERTFILE="${KANI_TMP}cert.pem"
CSRFILE="${KANI_TMP}cert.csr"
CHAINFILE="${KANI_TMP}chain.pem"
DHFILE="${KANI_TMP}dh.pem"

if [ ! -d "${KANI_TMP}" ]; then
    echo "Creating temp kanidm dir: ${KANI_TMP}"
    mkdir -p "${KANI_TMP}"
fi

cat > "${ALTNAME_FILE}" << DEVEOF
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
openssl req -x509 -new -newkey rsa:4096 -sha256 \
    -keyout "${CAKEY}" \
    -out "${CACERT}" \
    -days +31 \
    -subj "/C=AU/ST=Queensland/L=Brisbane/O=INSECURE/CN=insecure.ca.localhost" -nodes

# generate the ca private key
openssl genrsa -out "${KEYFILE}" 4096

# generate the certficate signing request
openssl req -sha256 \
    -config "${ALTNAME_FILE}" \
    -new -extensions v3_req \
    -key "${KEYFILE}"\
    -subj "/C=AU/ST=Queensland/L=Brisbane/O=INSECURE/CN=${CERT_HOSTNAME}" \
    -nodes \
    -out "${CSRFILE}"

# sign the cert
openssl x509 -req -days 31 \
    -extfile "${ALTNAME_FILE}" \
    -CA "${CACERT}" \
    -CAkey "${CAKEY}" \
    -CAcreateserial \
    -in "${CSRFILE}" \
    -out "${CERTFILE}" \
    -extensions v3_req -sha256
# Create the chain
cat "${CERTFILE}" "${CACERT}" > "${CHAINFILE}"

# create the dh file for RADIUS
openssl dhparam -in "${CAFILE}" -out "${DHFILE}" 2048

echo "Certificate chain is at: ${CHAINFILE}"
echo "Private key is at: ${KEYFILE}"
echo ""
echo "**Remember** the default action is to store the files in /tmp/ so they'll be deleted on reboot! Set the KANI_TMP environment variable before running this script if you want to change that. You'll need to update server config elsewhere if you do, however."