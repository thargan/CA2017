CREATE MASTER KEY ENCRYPTION BY PASSWORD = 	'4testuse!'
CREATE CERTIFICATE PIN_CERT
   WITH SUBJECT = 'PIN';
CREATE SYMMETRIC KEY PIN_KEY
    WITH ALGORITHM = AES_256
    ENCRYPTION BY CERTIFICATE PIN_CERT;



