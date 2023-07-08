# Центр сертифікації OpenSSL
```bash
Використовується:
Ubuntu 20.04.1 LTS
OpenSSL 1.1.1f  31 Mar 2020
Використання RAM = 1.2GiB
```

Цей посібник демонструє, як зробити власний центр сертифікації (CA) за допомогою інструментів командного рядка OpenSSL. Це корисно в ряді ситуацій, наприклад, у локальній мережі коли треба видати сертифікати сервера для захисту веб-сайту або видати сертифікати клієнтам, щоб дозволити їм автентифікацію на сервері.
## Вступ
OpenSSL - це безкоштовна криптографічна бібліотека з відкритим кодом, яка надає кілька інструментів командного рядка для обробки цифрових сертифікатів. Деякі з цих інструментів можна використовувати як орган сертифікації.
Центр сертифікації (ЦС) - це організація, яка підписує цифрові сертифікати. Веб-сайти повинні повідомляти своїх клієнтів про те, що з'єднання безпечне, тому вони платять міжнародному довіреному центру сертифікації (наприклад, VeriSign, DigiCert), щоб підписати сертифікат для свого домену.
У деяких випадках може мати більше сенсу виступати як власний ЦС, а не платити ЦС. Поширені випадки включають захист веб-сайту в локальній мережі або видачу сертифікатів клієнтам, щоб дозволити їм автентифікацію на сервері (наприклад, Apache, OpenVPN).
## Створення кореневої пари
Діяти як орган сертифікації (CA) означає мати справу з криптографічними парами приватних ключів та відкритих сертифікатів. Найперша криптографічна пара, яку ми створимо, - це коренева пара. Він складається з кореневого ключа (ca.key.pem) та кореневого сертифіката (ca.cert.pem). Ця пара формує ідентифікацію вашого ЦС.
Зазвичай кореневий ЦС не підписує серверні чи клієнтські сертифікати безпосередньо. Кореневий ЦС завжди використовується лише для створення одного або декількох проміжних ЦС, яким кореневий ЦС довіряє підписувати сертифікати від їх імені. Це найкраща практика. Це дозволяє зберігати кореневий ключ в автономному режимі та використовувати його якомога більше, оскільки будь-який компроміс із кореневим ключем є згубним.
Примітка
Кращою практикою є створення кореневої пари в захищеному середовищі. В ідеалі, це повинно бути на повністю зашифрованому комп’ютері, який постійно ізольований від Інтернету. Вийміть бездротову карту та залийте порт Ethernet клеєм.
Підготовка каталогу

Виберіть каталог (/root/ca) для зберігання всіх ключів та сертифікатів.
```bash
mkdir /root/ca
```
Створіть структуру каталогів. index.txt і serial файли діють як плоский файл бази даних для відстеження підписаних сертифікатів
```bash
cd /root/ca
mkdir certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
```
Підготовка файлу конфігурації

Ви повинні створити файл конфігурації для використання OpenSSL. Скопіюйте кореневий файл конфігурації в /root/ca/openssl.cnf. 
```bash
# Файл конфігурації кореневого ЦС
# Кореневий файл конфігурації CA OpenSSL.
# Скопіювати в /root/ca/openssl.cnf`.

[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = /root/ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
randfile          = $dir/private/.rand

private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem

crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional



[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca
prompt = no


# ТРЕБА ЗМІНІТИ!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[ req_distinguished_name ]
countryName                     = UA
stateOrProvinceName             = Ukraine
localityName                    = Odessa
0.organizationName              =  ЗМІНИТИ (наприклад: Company Name)
organizationalUnitName          = ЗМІНИТИ (наприклад: Root Company Name)
commonName                      = ЗМІНИТИ (наприклад: Company Name Root CA)
emailAddress                    = support@ITdep.com


[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ ocsp ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
```

## Створення кореневого ключа

Створіть кореневий ключ ( ca.key.pem). Кожен, хто володіє кореневим ключем, може видавати надійні сертифікати. Зашифруйте кореневий ключ за допомогою 256-бітного шифрування AES та надійного пароля.
```bash
cd /root/ca
openssl genrsa -aes256 -out private/ca.key.pem 4096
chmod 400 private/ca.key.pem
```
## Створіть кореневий сертифікат

Використовуйте кореневий ключ ( ca.key.pem) для створення кореневого сертифіката ( ca.cert.pem). Дайте кореневому сертифікату тривалий термін дії, наприклад двадцять років. Після закінчення терміну дії кореневого сертифіката всі сертифікати, підписані ЦС, стають недійсними.
```bash
cd /root/ca
openssl req -config openssl.cnf \
   -key private/ca.key.pem \
   -new -x509 -days 7300 -sha256 -extensions v3_ca \
   -out certs/ca.cert.pem
```
```bash
chmod 444 certs/ca.cert.pem
```
## Перевірка кореневого сертифіката
```bash
openssl x509 -noout -text -in certs/ca.cert.pem
```
Результат показує:
•	Використання Signature Algorithm
•	Дату посвідчення Validity
•	Довжину бітів Public-Key
•	Об'єкт, який видав сертифікат Issuer
•	Що відноситься до самого сертифікату Subject
IssuerІ Subject ідентичні , так як сертифікат самопідписний. Зверніть увагу, що всі кореневі сертифікати мають власні підписи.
Signature Algorithm: sha256WithRSAEncryption
  Issuer: C=UA, ST=Ukraine,
      O=Alice Ltd, OU=Alice Ltd Certificate Authority,
      CN=Alice Ltd Root CA
  Validity
    Not Before: Apr 11 12:22:58 2015 GMT
    Not After : Apr 6 12:22:58 2035 GMT
  Subject: C=UA, ST=Ukraine,
       O=Alice Ltd, OU=Alice Ltd Certificate Authority,
       CN=Alice Ltd Root CA
  Subject Public Key Info:
    Public Key Algorithm: rsaEncryption
      Public-Key: (4096 bit)

На виході також показано розширення X509v3. Ми застосували v3_ca розширення, тому параметри від повинні бути відображені у вихідних даних.[ v3_ca ]

X509v3 extensions:
  X509v3 Subject Key Identifier:
    38:58:29:2F:6B:57:79:4F:39:FD:32:35:60:74:92:60:6E:E8:2A:31
  X509v3 Authority Key Identifier:
    keyid:38:58:29:2F:6B:57:79:4F:39:FD:32:35:60:74:92:60:6E:E8:2A:31

  X509v3 Basic Constraints: critical
    CA:TRUE
  X509v3 Key Usage: critical
    Digital Signature, Certificate Sign, CRL Sign


## Створення проміжної пари

Проміжний центр сертифікації (ЦС) - це організація, яка може підписувати сертифікати від імені кореневого ЦС. Кореневий ЦС підписує проміжний сертифікат, утворюючи ланцюжок довіри.
Метою використання проміжного ЦС є в першу чергу для безпеки. Кореневий ключ можна зберігати в автономному режимі та використовувати якомога рідше. Якщо проміжний ключ порушено, кореневий ЦС може відкликати проміжний сертифікат і створити нову проміжну криптографічну пару.
Підготовка каталогу

Кореневі файли CA зберігаються в /root/ca. Виберіть інший каталог ( /root/ca/intermediate) для зберігання проміжних файлів ЦС.
```bash
mkdir /root/ca/intermediate
```
Створіть ту саму структуру каталогів, яка використовується для кореневих файлів ЦС. Зручно також створити csr каталог для зберігання запитів на підпис сертифікатів.
```bash
cd /root/ca/intermediate
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
```
Додайте crlnumber файл до проміжного дерева каталогів ЦС. Crlnumber використовується для відстеження списків відкликаних сертифікатів .
```bash
echo 1000 > /root/ca/intermediate/crlnumber
```
Скопіюйте проміжний файл конфігурації ЦС із додатка Скопіюйте  файл конфігурації в /root/ca/intermediate/openssl.cnf.
```bash
# OpenSSL intermediate CA configuration file.
# Copy to `/root/ca/intermediate/openssl.cnf`.

[ ca ]
# `man ca`
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = /root/ca/intermediate
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

# The root key and root certificate.
private_key       = $dir/private/intermediate.key.pem
certificate       = $dir/certs/intermediate.cert.pem

# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/intermediate.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca
prompt = no
#ЗМІНИТИ!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[ req_distinguished_name ]
countryName                     = UA
stateOrProvinceName             = Ukraine
localityName                    = Odessa
0.organizationName              = ЗМІНИТИ (наприклад: Company Name)
organizationalUnitName          = ЗМІНИТИ (наприклад: Company Name)
commonName                      = ЗМІНИТИ (наприклад: Company Name CA)
emailAddress                    = support@ITdep.com


[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
# Extensions for client certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
# Extensions for server certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
# Extension for CRLs (`man x509v3_config`).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (`man ocsp`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
```
## Створення проміжного ключа

Створіть проміжний ключ (intermediate.key.pem). Зашифруйте проміжний ключ за допомогою 256-бітного шифрування AES та надійного пароля.
```bash
cd /root/ca
openssl genrsa -aes256 \
   -out intermediate/private/intermediate.key.pem 4096
```
Enter pass phrase for intermediate.key.pem: secretpassword
Verifying - Enter pass phrase for intermediate.key.pem: secretpassword
```bash
chmod 400 intermediate/private/intermediate.key.pem
```
## Створення проміжного сертифіката

Використовуйте проміжний ключ для створення запиту на підпис сертифіката (CSR). Деталі, як правило, повинні відповідати кореневому CA. Однак загальна назва повинна бути іншою.
```bash
cd /root/ca
openssl req -config intermediate/openssl.cnf -new -sha256 \
   -key intermediate/private/intermediate.key.pem \
   -out intermediate/csr/intermediate.csr.pem
```
Enter pass phrase for intermediate.key.pem: secretpassword


Щоб створити проміжний сертифікат, використовуйте кореневий ЦС із v3_intermediate_caрозширенням для підписання проміжного CSR. Проміжний сертифікат повинен бути дійсним протягом коротшого періоду, ніж кореневий сертифікат. Десять років було б розумно.
```bash
cd /root/ca
openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
   -days 3650 -notext -md sha256 \
   -in intermediate/csr/intermediate.csr.pem \
   -out intermediate/certs/intermediate.cert.pem
```
Enter pass phrase for ca.key.pem: secretpassword
Sign the certificate? [y/n]: y
```bash
chmod 444 intermediate/certs/intermediate.cert.pem
```
У цьому index.txt файлі  OpenSSL зберігає базу даних сертифікатів. Не видаляйте та не редагуйте цей файл вручну. Тепер він повинен містити рядок, який посилається на проміжний сертифікат.

V 250408122707Z 1000 unknown ... /CN=Alice Ltd Intermediate CA
 
Перевірка проміжного сертифіката

Як і у випадку з кореневим сертифікатом, перевірте правильність даних про проміжний сертифікат.
```bash
 openssl x509 -noout -text \
   -in intermediate/certs/intermediate.cert.pem
```
	Перевірте проміжний сертифікат проти кореневого сертифіката. Значок OK вказує на те, що ланцюг довіри недоторканий.
```bash
openssl verify -CAfile certs/ca.cert.pem \
   intermediate/certs/intermediate.cert.pem
```
intermediate.cert.pem: OK
## Створити файл ланцюжка сертифікатів

Коли програма (наприклад, веб-браузер) намагається перевірити сертифікат, підписаний проміжним ЦС, вона також повинна перевірити проміжний сертифікат щодо кореневого сертифіката. Щоб завершити ланцюжок довіри, створіть ланцюжок сертифікатів ЦС, щоб подати її до програми.
Щоб створити ланцюжок сертифікатів CA, об'єднайте проміжні та кореневі сертифікати разом. Пізніше ми використаємо цей файл для перевірки сертифікатів, підписаних проміжним ЦС.
```bash
cat intermediate/certs/intermediate.cert.pem \
   certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem
```
```bash
chmod 444 intermediate/certs/ca-chain.cert.pem
```

Підпис сертифікатів сервера та клієнта
Ми будемо підписувати сертифікати, використовуючи наш проміжний ЦС. Ви можете використовувати ці підписані сертифікати в різних ситуаціях, наприклад, для захисту з'єднань з веб-сервером або для автентифікації клієнтів, що підключаються до послуги.
Необхідно скопіювати даний скрипт в /root/ca/intermediate з назвою script.py:
```python3
#!/bin/evn python3import

from os import system
import re
prefix = input("Enter your domain: ")
def change(conf_file, index, change):
    with open(conf_file, "r") as ftp:
        position = ftp.readlines()[int(index)].strip()
    data = open(conf_file).read()
    u = open(conf_file, 'w')
    u.write(re.sub(position,change, data))
    u.close()
system("cat all.cnf > " + prefix + ".cnf")
file = prefix + ".cnf"
change(file, 110, "DNS.1 = " + prefix)
change(file, 77, "commonName                      = " + prefix)

system("openssl genrsa -out " + prefix +".key 3072")
system("openssl req -extensions v3_req -config " + prefix + ".cnf -sha256 -new -key " + prefix + ".key -out " + prefix + ".csr")
system("openssl x509 -req -extensions v3_req -days 1825 -sha256 -in " + prefix + ".csr -CA certs/intermediate.cert.pem -CAkey private/intermediate.key.pem -CAcreateserial -out " + prefix + ".crt -extfile " + prefix + ".cnf")

system("openssl x509 -in " + prefix + ".crt -text -noout")
system("mkdir " + prefix)
system("mv " + prefix + ".* " + prefix)
system("cat certs/ca-chain.cert.pem >> " + prefix + "/" + prefix + ".crt")
print("YOUR CREDENTIALS:\n", prefix + "/" + prefix + ".crt\n", prefix + "/" + prefix + ".key")
```
Необхідно скопіювати дану конфігурацію в /root/ca/intermediate і назвати її all.cnf:
```bash
# OpenSSL intermediate CA configuration file.
# Copy to `/root/ca/intermediate/openssl.cnf`.

[ ca ]
# `man ca`
default_ca = CA_default

[ CA_default ]
# Directory and file locations.
dir               = /root/ca/intermediate
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

# The root key and root certificate.
private_key       = $dir/private/intermediate.key.pem
certificate       = $dir/certs/intermediate.cert.pem

# For certificate revocation lists.
crlnumber         = $dir/crlnumber
crl               = $dir/crl/intermediate.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
# See the POLICY FORMAT section of `man ca`.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
# See the POLICY FORMAT section of the `ca` man page.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the `req` tool (`man req`).
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca
prompt = no
req_extensions = v3_req
# ЗМІНИТИ!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[ req_distinguished_name ]
countryName                     = UA
stateOrProvinceName             = Ukraine
localityName                    = Odessa
0.organizationName              = ЗМІНИТИ (наприклад: Company Name)
organizationalUnitName          = ЗМІНИТИ (наприклад: Company Name)
commonName                      = M
emailAddress                    = support@ITdep.com

[ v3_ca ]
# Extensions for a typical CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA (`man x509v3_config`).
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
#extendedKeyUsage=serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = mydomain.com

[ usr_cert ]
# Extensions for client certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
# Extensions for server certificates (`man x509v3_config`).
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ crl_ext ]
# Extension for CRLs (`man x509v3_config`).
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates (`man ocsp`).
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
```
## Створення сертифікати для веб серверів 
```python3
python3 script.py
```
