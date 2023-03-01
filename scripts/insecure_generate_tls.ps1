
$ErrorActionPreference = "Stop"

$KANI_TMP="$Env:TEMP\kanidm\"

$ALTNAME_FILE="${KANI_TMP}altnames.cnf"
$CACERT="${KANI_TMP}ca.pem"
$CAKEY="${KANI_TMP}cakey.pem"

$KEYFILE="${KANI_TMP}key.pem"
$CERTFILE="${KANI_TMP}cert.pem"
$CSRFILE="${KANI_TMP}cert.csr"
$CHAINFILE="${KANI_TMP}chain.pem"
# $DHFILE="${KANI_TMP}dh.pem"
$CONFIG_FILE="${KANI_TMP}server.toml"


if (Test-Path -Path "$KANI_TMP" ) {
    Write-Output "Output dir exists at $KANI_TMP"
} else {
    Write-Warning "Output dir missing at $KANI_TMP"
    $result = New-Item -Path "$KANI_TMP" -ItemType Directory
}


if ( $(Test-Path -Path "examples\insecure_server.toml") -eq $false ) {
    Write-Error "You need to run this from the base dir of the repo!"
    exit 1
}
# Building the config file
$CONFIG = Get-Content "examples\insecure_server.toml"
$CONFIG = $CONFIG -replace "/tmp/kanidm/", "$KANI_TMP"
$CONFIG = $CONFIG -replace "\\", "/"

$CONFIG | Set-Content "${CONFIG_FILE}" -Force

$ALTNAME_FILE_CONTENTS = @'
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

commonName                      = Common Name (eg, your name or your servers hostname)
commonName_max                  = 64
commonName_default              = localhost

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
'@

Write-Output "Creating cert template"
$result = New-Item -Path "$ALTNAME_FILE" -ItemType File -Value "$ALTNAME_FILE_CONTENTS" -Force

write-debug $result

Write-Output "Generate the CA"
openssl req -x509 -new -newkey rsa:4096 -sha256 -keyout "${CAKEY}" -out "${CACERT}" -days 31 -subj "/C=AU/ST=Queensland/L=Brisbane/O=INSECURE/CN=insecure.ca.localhost" -nodes
if ( $LastExitCode -ne 0  ){
    exit 1
}

Write-Output "Generating the private key"
openssl genrsa -out "${KEYFILE}" 4096
if ( $LastExitCode -ne 0  ){
    exit 1
}

Write-Output "Generating the certificate signing request"
openssl req -sha256 -config "${ALTNAME_FILE}" -days 31 -new -extensions v3_req -key "${KEYFILE}" -out "${CSRFILE}"
if ( $LastExitCode -ne 0  ){
    exit 1
}
Write-Output "Signing the certificate"
openssl x509 -req -days 31 -extfile "${ALTNAME_FILE}" -CA "${CACERT}" -CAkey "${CAKEY}" -CAcreateserial -in "${CSRFILE}" -out "${CERTFILE}" -extensions v3_req -sha256

Write-Output "Creating the certificate chain"
Get-Content "${CERTFILE}" ,"${CACERT}" | Set-Content "${CHAINFILE}" -Force

Write-Output "Certificate chain is at: ${CHAINFILE}"
Write-Output "Private key is at: ${KEYFILE}"
Write-Output "The configuration file is at: ${CONFIG_FILE}"
