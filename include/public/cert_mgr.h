// @@@LICENSE
//
//      Copyright (c) 2008-2013 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// LICENSE@@@

/**
 * @brief  This file contains an API for managing certificates
 * 
 * @defgroup CERTMgrLib The certificate manager library
 * @ingroup CERTMgrLib
 *
 * @file cert_mgr.h
 * <hr>
 * @todo CERT_DEF_CONF_FILE should be placed in a standard location
 **/

#ifndef __CERT_MGR_H__
#define __CERT_MGR_H__

#include <sys/types.h>

#include <openssl/x509v3.h>

#define CERT_DEFAULT_DIRECTORY "./.cert_store"

#define CERT_PROPERTY_DIR     0x00000001

#define CERT_VERSION_NUMBER   "0.1"

/*!
 * The maximum number of files with the same name
 * we make the arbitrary assumption that there can be
 * no more than 100 files with the same hash
 */
#define CERT_MAX_HASHED_FILES  100

typedef enum
  {
    CERT_GENERAL_LOCK,
    CERT_DATABASE_LOCK,
    CERT_MAX_LOCK
  } certLocks;

/*!
 * 
 * @brief Return Values
 * Return function values and error messages
 */
typedef enum
{
  CERT_OK,                       /*!< No Failure                          */
  CERT_GENERAL_FAILURE,          /*!< General Failure, should not occur   */
  CERT_UNSUPPORTED_CERT_TYPE,    /*!< Certificate type not supported      */
  CERT_ILLEGAL_KEY_PACKAGE_TYPE, /*!< Package type not supported.         */
  CERT_NULL_BUFFER,              /*!< Buffer unexpectedly NULL            */
  CERT_BUFFER_LIMIT_EXCEEDED,    /*!< Target string is too long           */
  CERT_OPEN_FILE_FAILED,         /*!< The file could not be opened        */
  CERT_FILE_ACCESS_FAILURE,      /*!< The file could not be accessed      */
  CERT_FILE_READ_FAILURE,        /*!< The file could not be read          */
  CERT_UNDEFINED_ROOT_DIR,       /*!< The configured root not defined     */
  CERT_DUPLICATE,                /*!< The certificate already exists      */
  CERT_MEMORY_ERROR,             /*!< Function dependant memory error     */
  CERT_ITER_EXCEED,              /*!< An iterator has gone beyond bounds  */
  CERT_INVALID_ARG,              /*!< Function dependant argument error   */
  CERT_PASSWD_WRONG,             /*!< bad password for decryption         */
  CERT_LINK_ERR,                 /*!< File (un)link was unsuccessfull     */
  CERT_INSUFFICIENT_BUFFER_SPACE,/*!< User passed in buffer space         */
  CERT_PATH_LIMIT_EXCEEDED,      /*!< The path exceeds system limits      */
  CERT_UNDEFINED_DESTINATION,    /*!< The directory doesn't exist         */
  CERT_TEMP_FILE_CREATION_FAILED,/*!< The temp file can't be created      */
  CERT_CONFIG_UNAVAILABLE,       /*!< The config tag doesn't exist        */
  CERT_UNKNOWN_PROPERTY,         /*!< The property isn't defined          */
  CERT_PROPERTY_NOT_FOUND,       /*!< The property couldn't be resolved      */
  CERT_PROPERTY_STRING_NOT_FOUND,/*!< No string associated with the property */
  CERT_ILLFORMED_CONFIG_FILE,    /*!< Something's broken in the file         */
  CERT_DATE_PENDING,             /*!< The certificate is not yet valid       */
  CERT_DATE_EXPIRED,             /*!< The certificate is no longer valid     */
  CERT_FILE_PARSE_ERROR,         /*!< The input file is illformed            */
  CERT_LOCK_FILE_CREATION_FAILURE,/*!< The lock file could not be created    */
  CERT_LOCK_FILE_LOCKED,         /*!< The lock file is already locked        */
  CERT_BAD_CERTIFICATE,          /*!< The certificate is bad (maybe NULL)    */
  CERT_SERIAL_NUMBER_FILE_UNAVAILABLE,/*!<Can't access the serial number file*/
  CERT_SERIAL_NUMBER_UNAVAILABLE,/*!< Can't resolve the current serial #     */
  CERT_DATABASE_INITIALIZATION_ERROR,/*!< The database couldn't be init'ed   */
  CERT_DATABASE_NOT_AVAILABLE,   /*!< The database is not available          */
  CERT_DATABASE_OUT_OF_BOUNDS,   /*!< A db search has been exhausted         */
  CERT_DATABASE_LOCKED,          /*!< The database is unavailable            */
  CERT_TOO_MANY_HASHED_FILES,    /*!< Too many cert files with the same name */
  CERT_MAX_RETURN_CODE
} CertReturnCode_t;

/*! known certificate types */
typedef enum
  {
    CERTTYPE_PEM,     /*!< Privacy Enhanced Mail wrapper        */
    CERTTYPE_P12,     /*!< PKCS #12 wrapper                     */
    CERTTYPE_DER,     /*!< Distinguished Encoding Rules wrapper */
    CERTTYPE_UNKNOWN
  } CertPkgType_t;


/*! extension types */
typedef enum
  {
    CERT_UNKNOWN_FILE,
    CERT_PEM_FILE,            /*!< extension for PEM     */
    CERT_P12_FILE,            /*!< extension for  pkcs12 */
    CERT_PFX_FILE,            /*!< extension for pkcs12  */
    CERT_DER_FILE,            /*!< extension for der     */
    CERT_CRT_FILE,            /*!< extension for pem     */
    CERT_CER_FILE,            /*!< extension for der     */
    CERT_CRL_FILE,			  /*!< extension for crl 	 */
    CERT_MAX_FILE_EXTENSIONS
  } CertFileExt_t;

/*! Destination directories for various file types */
typedef enum
  {
    CERT_DIR_PRIVATE_KEY,  /*!< Dir where private keys are placed            */
    CERT_DIR_PUBLIC_KEY,   /*!< Dir where public keys are placed             */
    CERT_DIR_CRL,          /*!< Dir where the cert revocation list is placed */
    CERT_DIR_CERTIFICATES, /*!< Dir where X.509 Certs are placed             */
    CERT_DIR_AUTHORIZED,   /*!< Dir where authorized certificates are linked */
    CERT_DIR_PACKAGES      /*!< Dir where containers are placed              */
  } CertDestDir_t;

/*! Objects that we can find in a container */
typedef enum
  {
    CERT_OBJECT_RSA_PRIVATE_KEY, /*!< RSA Private Key */
    CERT_OBJECT_RSA_PUBLIC_KEY,  /*!< RSA Public Key  */
    CERT_OBJECT_DSA_PRIVATE_KEY, /*!< DSA Private Key */
    CERT_OBJECT_DSA_PUBLIC_KEY,  /*!< DSA Public Key  */
    CERT_OBJECT_DH_PARAMETERS,   /*!< Diffie-Hellman parameters      */
    CERT_OBJECT_EC_PRIVATE_KEY,	 /*!< Eliptic Curve */
    CERT_OBJECT_CERTIFICATE,     /*!< X.509 Certificate              */
    CERT_OBJECT_REQUEST,         /*!< Certificate request            */
    CERT_OBJECT_CRL,             /*!< Certificate revocation list    */
    CERT_OBJECT_C_AUTHORIZATION, /*!< Certificate authorization list */
    CERT_OBJECT_MAX_OBJECT
  } CertObject_t;

/*!
 * Status for certificates.  These can be used by the counting functions
 */
typedef enum
  {
    CERT_STATUS_ALL,                /*!< Used for collecting everything     */
    CERT_STATUS_VALID_CA,           /*!< The certificate authority is valid */
    CERT_STATUS_TRUSTED_SERVER_CA,  /*!< Trusted to issue server certs
                                     * implies CERT_STATUS_VALID_CA
                                     */
    CERT_STATUS_EXPIRED,            /*!< The certificate is expired         */
    CERT_STATUS_VALID_PEER,         /*!< The certificate is a valid peer    */
    CERT_STATUS_TRUSTED_PEER,       /*!<
                                     * implies CERT_STATUS_VALID_PEER
                                     */
    CERT_STATUS_REVOKED,            /*!< The certificate has been revoked   */ 
    CERT_STATUS_SUSPENDED,          /*!< The certificate has been suspended */
    CERT_STATUS_TRUSTED_CLIENT_CA,  /*!< Trusted to issue client certs
                                     * implies CERT_STATUS_VALID_CA
                                     */
    CERT_STATUS_VALID_CERT,        /*!< The certificate            is valid */
    CERT_STATUS_USER_CERTIFICATE,
    CERT_STATUS_WARNING,
    CERT_STATUS_UNKNOWN,
    CERT_STATUS_UNDEFINED
  } CertStatus_t;

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_CERT_PATH 256

/* Opaque struct for iterating over installed cert collections */
typedef struct cert_Iterator_t cert_Iterator_t;

/*
 * Separate set of errors mirroring OpenSSL errors, or just use
 *  OpenSSL errors?
 */
typedef enum
  {
    CERT_CM_ALL_OK         = 0,
    CERT_CM_UNREADABLE     = 1,
    CERT_CM_SOMETHING_ELSE = 2,
    CERT_CM_DATE_PENDING   = 4,
    CERT_CM_DATE_EXPIRED   = 8,
    CERT_CM_ALL_BROKEN     = CERT_CM_UNREADABLE |
                             CERT_CM_SOMETHING_ELSE |
                             CERT_CM_DATE_PENDING | CERT_CM_DATE_EXPIRED
  } cert_MgrError_t;

  /*! Information kept in the certificate itself */
typedef enum
  {
    CERT_INFO_ISSUED_TO,
    CERT_INFO_ISSUED_BY,
    CERT_INFO_START_DATE,
    CERT_INFO_EXPIRATION_DATE,
    CERT_INFO_MAX_PROPERTY
  } certMgrField_t;

  
/*!
 * @brief Setup the directory structure necessary for CertMgr to be initialized
 *
 * This function builds the necessary directory and initialized the necessary
 * file that the certmgr need to run properly.
 *
 *
 * @return CERT_OK: The database was successfully read and deciphered
 * @return CERT_CONFIG_UNAVAILABLE: The named configuration file is not
 */
CertReturnCode_t SetupCertMgrEnviroment();

/*!
 * @brief Initialize the instance of the certificate Manager
 *
 * This function initializes a particular instance
 *    of the Certificate Manager based on the configuration file passed in.
 *    The configuration file is structured in the manner of an SSL
 *    configuration.  Setting the paramter to NULL has the effects of 
 *    using default settings.  The default settings checked are the enviroment
 *    variable OPENSSL_CONF and the system default CERT_DEF_CONF_FILE, in
 *    that order.
 *
 * @param[in] configFile the configuration file
 *
 * @return CERT_OK: The database was successfully read and deciphered
 * @return CERT_PATH_LIMIT_EXCEEDED: The path string is too long
 * @return CERT_OPEN_FILE_FAILED: The config file couldn't be opened
 * @return CERT_ILLFORMED_CONFIG_FILE: There was some problem in the config
 * @return CERT_CONFIG_UNAVAILABLE: The named configuration file is not
 *           available
 * @return CERT_UNDEFINED_DESTINATION if the certificate root dir not available
 *
 */
CertReturnCode_t CertInitCertMgr(const char *configFile);


/*!
 * @brief Reset the configuration of the certificate Manager
 *
 * This function re-initializes a particular instance
 *    of the Certificate Manager based on the configuration file passed in.
 *    Any changes made to the configuration file since initialization
 *    will be realized at this time.
 *
 * @param[in] configFile the configuration file
 *
 * @return CERT_OK: The database was successfully read and deciphered
 * @return CERT_INSUFFICIENT_BUFFER_SPACE: The origianal configuration file
 *             string is ill-defined.
 * @return CERT_OPEN_FILE_FAILED: The config file couldn't be opened
 * @return CERT_ILLFORMED_CONFIG_FILE: There was some problem in the config
 * @return CERT_CONFIG_UNAVAILABLE: The named configuration is not
 *           available in the configuration file
 * @return CERT_UNDEFINED_DESTINATION if the certificate root dir not available
 *
 */
CertReturnCode_t CertResetConfig(const char *pConfigFile);


/* Given a filename, stores the file in the authorized certs directory
 * under a name compatible with openssl's load_verify_locations.  (See
 * p. 129 of o'reilly's OpenSSL book.)  Filename will be unique thanks
 * to the above requirement. Will return an error if the file doesn't
 * contain data in a format we can handle, but not if it's
 * unauthorized, expired, etc.
 */
/** 
 * @brief Add a certificate to the list of valid certificates
 * 
 * @param serialNb The certificate ID
 * 
 * @return CERT_OK:
 * @return CERT_UNSUPPORTED_CERT_TYPE: the certificate package is not a
 *     supported package type
 * @return CERT_OPEN_FILE_FAILURE: the certificate file could not be opened
 * @return CERT_FILE_READ_FAILURE: the PEM was not read successfully
 * @return CERT_TOO_MANY_HASH_FILES: We've exceeded the number of files whose
 *      base name is the same.
 */
CertReturnCode_t CertAddAuthorizedCert(const int32_t serialNb);

CertReturnCode_t CertAddTrustedCert(const int32_t serialNb);

/* Return the number of Authorized Certs currently installed.
 */
/** 
 * @brief Retrieve the number of certificates based on status from the
 *        default database
 *
 * Count the number of certificates that match the status. 
 *
 * @param pDatabase The certificate database
 * @param status The filter
 * @param pNCerts The number of certificates that matched the status
 * 
 * @return CERT_OK
 * @return CERT_DATABASE_INITIALIZATION_ERROR: The database was never init'ed
 * @return CERT_FILE_ACCESS_FAILURE: The database file could not be accessed
 * @return CERT_LOCKED_FILE_LOCKED: The database lockfile is unavailable
 * @return CERT_DATABASE_LOCKED: The database is currently in use
 */
CertReturnCode_t CertGetCertificateCount(CertStatus_t status, int *pNCerts);
/** 
 * @brief Retrieve the number of certificates based on status
 *
 * Count the number of certificates that match the status. 
 *
 * @param pDatabase The certificate database
 * @param status The filter
 * @param pNCerts The number of certificates that matched the status
 * 
 * @return CERT_OK
 * @return CERT_DATABASE_INITIALIZATION_ERROR: The database was never init'ed
 * @return CERT_FILE_ACCESS_FAILURE: The database file could not be accessed
 * @return CERT_LOCKED_FILE_LOCKED: The database lockfile is unavailable
 * @return CERT_DATABASE_LOCKED: The database is currently in use
 */
CertReturnCode_t CertGetCertificateCountDirect(char        *pDatabase,
                                               CertStatus_t status,
                                               int32_t     *pNCerts);

/* Returns array of trusted cert filenames. alternatively, use
   GetNextAuthorizedCert iterator function (StartSearch and StopSearch
   search functions may be needed too). */
/* CertReturnCode_t CertGetAuthorizedCertList(); */

/* Create an iterator over authorized certs.  Returns in *hIter a ptr
 * to an opaque structure.  Must call CertGetNextAuthorizedCert to get
 * the first cert.
 */
CertReturnCode_t CertMakeCertIter( cert_Iterator_t** hIter );


/* Delete an opaque cert_Iterator_t struct previously allocated by
 * CertMakeAuthorizedCertIter().  Must be called after all calls to
 * certGetNextAuthorizedCert have been made.
 */
CertReturnCode_t CertDeleteCertIter( cert_Iterator_t* pIter );

/* Given an iterator returned by MakeAuthorizedCertIter, return in
 * pPath the path to the next certificate file, or NULL if the
 * iterator is finished (in which case the return value is
 * cert_ITER_EXCEED, and any memory associated with the pIter is freed.
 * Since the pointer returned in pPath may point into pIter, that
 * pointer is only valid until the next call to
 * GetNextAuthorizedCert() or CertDeleteAuthorizedCertIter().
 */
CertReturnCode_t CertGetNextCert( cert_Iterator_t* pIter, const char** hPath );

/* Given a path to an authorized cert file (which need not be
 * installed), return in *pCMErr error codes indicating if content is
 * in supported format and contains valid data.  We check as much as
 * we can until an actual error is returned from openssl.  If there
 * are multiple problems with the cert, several bits may be set in the
 * result.  If it's perfect in every way, CERT_CM_ALL_OK is returned.
 */
CertReturnCode_t CertValidateCert(const char* pPath, 
                     cert_MgrError_t* pCMErr);

/* Given a path to an authorized cert file (which need not be
 * installed), determine if certificate is currently in valid date
 * window, and return code indicating valid, not yet valid, or
 * expired.
 */
/* CertReturnCode_t CertCheckAuthorizedCertDate( const char* pPath,  */
/*                                     cert_MgrDateError_t* pCMErr ); */

/* Given a path to a cert file (which need not be installed), return
 * information needed by Add Authorized Cert dialog and View Cert
 * dialog in security panel. If value passed into pBufLen is too
 * small, returns error CERT_BUFFER_TOO_SMALL and required size in
 * *pBufLen.  Caller should call again after allocating sufficient
 * storage.
 *
 * The model we're supporting here has info about a cert displayed to
 * a user stuffed into a scrolling text field.  In a later version we
 * may want to support a UI with separate fields by providing separate
 * query methods for all the relevant elements and attributes of a
 * cert.  Or a single method and set of keys to be requested.
 */
CertReturnCode_t CertGetAuthorizedCertInfo(const char* pPath, char* buf,
                                       int* pBufLen );

/* Given the name of an installed authorized cert file, and an enum
 * telling which field of info is wanted, return in buf the value of
 * that field as a string suitable for user display -- IFF *pBufLen is
 * greater than the length of the string.  CERT_OK is returned in this
 * case.  If *pBufLen indicates that insufficient space is available,
 * CERT_BUFFER_TOO_SMALL is returned.
 */
CertReturnCode_t CertGetAuthorizedCertInfoField( const char* pPath, 
                                    certMgrField_t field,
                                    char* buf, int* pBufLen );


/* Given a path to a client cert file, which may be encrypted with a
 * password (e.g. provided by IT), decrypts, re-encrypts using the
 * global password manager, and writes result into a file in the
 * directory used for client certs.  pcbk will be called if the
 * certificat is encrypted; otherwise, it's ignored.  Broadcasts the
 * change to any registered listeners (on what property?).
 *
 * Files are stored on disk 3DES encrypted.  The password needed to
 * decrypt them is also stored encrypted on disk, encrypted with the
 * user's current actual password.  The decrypted password is what's
 * provided.
 */
typedef int (*CertPassCallback)(char *buf, int bufLen, void *ctxt);
CertReturnCode_t CertInstallKeyPackageDirect(const char      *pPkgPath,
                                             const char      *pDestPath,
                                             CertPassCallback pcbk,
                                             void            *pwd_ctxt,
                                             int32_t         *serialNb);

/** 
 * @brief  Resolve a Key Package into its component parts to the default
 *         directory.
 *
 *       1) Packages are assumed to be encoded by their extension
 *       2) The following types are supported
 *          PKCS#12
 *              .pfx
 *              .p12
 *          DER
 *              .der Distinguished Encoding Rules
 *              .cer Canonical Encoding Rules
 *          PEM
 *              .pem Privacy Enhanced Mail
 *              .crt used in at least Debian (Ubuntu) defined pem files
 *       3) The constituent parts of the package are not re-encrypted, but,
 *          rather, rely on the native Linux permission controls with the
 *          following defaults:
 *          certs/   rwxr-x-r-x
 *          private/ rwx------
 *          This presupposes that the destination path has permissions set
 *          correctly
 *       4) The location of the package itself is placed in
 *          directory denoted by CERTCFG_PACKAGE_DIR.
 *
 * 
 * @param[in] pPkgPath The name of the package file.
 * @param[in] pDestPath The path to the package file
 * @param[in] pcbk The callback function for encrypting the package
 * @param[in] pwd_ctxt The passkey in clear text for decrypting the package
 * @param[out] serialNb An identifying number for the certificate
 * 
 * @return CERT_OK
 * @return CERT_SERIAL_NUMBER_FILE_UNAVAILABLE: The Certificate Manager is not
 *              properly initialized
 * @return CERT_SERIAL_NUMBER_UNAVAILABLE: The system was unable to provied a
 *             valid serial number
 * @return CERT_FILE_ACCESS_FAILURE: The system was unable to write the x.509
 *           certificate.
 * @return CERT_DATABASE_LOCKED: The system was unable to access the database
 * @return CERT_DATABASE_NOT_AVAILABLE: The system was unable to access the
 *           the database
 * @return CERT_LOCKFILE_LOCKED: The database is currently used
 * @return CERT_FILE_PARSE_ERROR: The input file is ill-formed
 * @return CERT_FILE_READ_ERROR: The input file cannot be read
 * @return CERT_OPEN_FILE_FAILED: The input file cannot be opened
 * @return CERT_ILLEGAL_KEY_PACKAGE_TYPE: The package is not a supported type
 * @return CERT_OPEN_FILE_FAILED: the requested package could not be opened.
 *           perhaps a password problem
 *
 */
CertReturnCode_t CertInstallKeyPackage(const char      *pPkgPath,
                                       CertPassCallback pcbk,
                                       void            *pwd_ctxt,
                                       int32_t         *serialNb);

CertReturnCode_t CertAddClientCert(const char      *pCertPath,
                                   CertPassCallback pcbk, 
                                   void            *pcbk_ctxt);

/* Given the path to a client cert, delete it.  Broadcast the change
 * to any registered listeners (on what property?).
 */
/** 
 * 
 * @brief Remove a certificate from the default directory
 * 
 * @param[in] serialNb The certificate ID.
 * @param[in] pCertPath The location of the certificate.
 * 
 * @return CERT_OK
 * CERT_UNDEFINED_DESTINATION: The path isn't defined
 * CERT_PATH_LIMIT_EXCEEDED: The combination of path and certificate name
 *     exceeds the pre-defined limits
 * CERT_LINK_ERROR: The certificate removal failed.
 */
CertReturnCode_t CertRemoveCertificate(const int32_t serialNb);

/* returns number of client cert files */
CertReturnCode_t CertGetClientCertCount( int* pNumClientCerts );

/* Create an iterator over client certs.  Returns in *hIter a ptr to
 * an opaque structure.  Must call certGetNextClientCert to get the
 * first cert.
 */
CertReturnCode_t CertMakeClientCertIter( cert_Iterator_t** hIter );

/* Delete an opaque cert_Iterator_t struct previously allocated by
 * CertMakeClientCertIter().  Must be called after all calls to
 * CertGetNextClientCert have been made.
 */
CertReturnCode_t CertDeleteClientCertIter(cert_Iterator_t* pIter);

/* Given an iterator returned by MakeClientCertIter, return in pPath
 * the path to the next certificate file, or NULL if the iterator is
 * finished (in which case the return value is CERT_ITER_EXCEED, and any
 * memory associated with the pIter is freed.  Since the pointer
 * returned in pPath may point into pIter, that pointer is only valid
 * until the next call to GetNextClientCert() or
 * CertDeleteClientCertIter().
 */
CertReturnCode_t CertGetNextClientCert(cert_Iterator_t* pIter, const char** hPath);

/* Writes path to client certs directory into pPath and writes len
 * to *pBufLen.  If value passed into pBufLen is too small, returns
 * error CERT_BUFFER_TOO_SMALL and required size in *pBufLen.  Caller
 * should call again after allocating sufficient storage. 
 */
CertReturnCode_t CertGetClientCertDirectory( char* buf, int* pBufLen );

/* returns unencrypted client cert in a buffer, or full pathname of
 * ccert encrypted with global key (caller would then need to pass the
 * global key to openssl), or full pathname of ccert encrypted with
 * random ccert key. 
 *
 */
/* CertReturnCode_t CertGetClientCert(); */

/* Client certs, i.e. the files whose paths are returned by
 * CertGetNextClientCert() above, are stored encrypted.  OpenSSL needs
 * the password in order to incorporate them into contexts.  This
 * function returns the password.  Note that it is *not* the user's
 * password.  It's some internal-only bits that have been decrypted
 * using the user's password.
 *
 * If value passed into pBufLen is too small, returns error
 * CERT_BUFFER_TOO_SMALL and required size in *pBufLen.  Caller should
 * call again after allocating sufficient storage.
 */
CertReturnCode_t CertGetClientCertKey( char* pBuf, int* pBufLen );

/* Given the name of a client cert file (which must already be
 * installed), return in *pCMErr error codes indicating if content is
 * in supported format and contains valid data.  Dates are ignored.
 */
CertReturnCode_t CertValidateClientCert(const char* pPath,
                                    cert_MgrError_t* pCMErr);

#ifdef HOLLY_EXTENSIONS
/* Given the name of a client cert file (which must already be
 * installed), return information needed by Add Client Cert dialog and
 * View Client Cert dialog in security panel. If value passed into
 * pBufLen is too small, returns error CERT_BUFFER_TOO_SMALL and
 * required size in *pBufLen.  Caller should call again after
 * allocating sufficient storage.
 */
CertReturnCode_t CertGetCertInfo( const char* pPath, char* buf, int* pBufLen );
#endif

/* Given the name of an installed client cert file, and an enum
 * telling which field of info is wanted, return in buf the value of
 * that field as a string suitable for user display -- IFF *pBufLen is
 * greater than the length of the string.  CERT_OK is returned in this
 * case.  If *pBufLen indicates that insufficient space is available,
 * CERT_BUFFER_TOO_SMALL is returned.
 */
CertReturnCode_t CertGetClientCertInfoField(const char* pPath,
                                        certMgrField_t field,
                                        char* buf, int* pBufLen );

int returnFileType (const char *file);

CertReturnCode_t CertPemToX509(const char* pemPath, X509** hCert);
CertReturnCode_t derToX509(const char *derPath, X509 **hCert);
CertReturnCode_t p12ToX509(const char *p12Path, void *pass, X509 **hCert, EVP_PKEY **pKey, STACK_OF(X509) **pCa);
CertReturnCode_t CertGetX509(const char *pPkgPath, void *pass, X509 **hCert);

CertReturnCode_t CertValidateCertPath(const char *path,
                                      int32_t serialNb,
                                      int certType,
                                      cert_MgrError_t *pCMErr);
/** 
 * @brief Read a Key Package into memory
 *
 *       Read a Key Package into memory and gives access to the component
 *       parts to the designated.  Decrypt if necessary.  The password,
 *       passwd  is in clear text.
 *
 * 
 * @param[in] pPkgPath The name of the package file.
 * @param[in] pDestPath The path to the package file
 * @param[in] pcbk The callback function for encrypting the package
 * @param[in] pwd_ctxt The passkey in clear text for decrypting the package
 * @param[out] serialNb An identifying number for the certificate
 * 
 * @return CERT_OK
 * @return CERT_SERIAL_NUMBER_FILE_UNAVAILABLE: The Certificate Manager is not
 *              properly initialized
 * @return CERT_SERIAL_NUMBER_UNAVAILABLE: The system was unable to provied a
 *             valid serial number
 * @return CERT_FILE_ACCESS_FAILURE: The system was unable to write the x.509
 *           certificate.
 * @return CERT_DATABASE_LOCKED: The system was unable to access the database
 * @return CERT_DATABASE_NOT_AVAILABLE: The system was unable to access the
 *           the database
 * @return CERT_LOCKFILE_LOCKED: The database is currently used
 * @return CERT_FILE_PARSE_ERROR: The input file is ill-formed
 * @return CERT_FILE_READ_ERROR: The input file cannot be read
 * @return CERT_OPEN_FILE_FAILED: The input file cannot be opened
 * @return CERT_ILLEGAL_KEY_PACKAGE_TYPE: The package is not a supported type
 * @return CERT_OPEN_FILE_FAILED: the requested package could not be opened.
 *           perhaps a password problem
 *
 */
CertReturnCode_t CertReadKeyPackageDirect(const char *pPkgPath,
                                      const char *pDestPath,
                                      CertPassCallback pcbk, void *pwd_ctxt,
                                      int32_t *serial);
/** 
 * @brief  Resolve a Key Package into its component parts to the designated
 *       destination directory.
 *
 *       1) Packages are assumed to be encoded by their extension
 *       2) The following types are supported
 *          PKCS#12
 *              .pfx
 *              .p12
 *          DER
 *              .der Distinguished Encoding Rules
 *              .cer Canonical Encoding Rules
 *          PEM
 *              .pem Privacy Enhanced Mail
 *              .crt used in at least Debian (Ubuntu) defined pem files
 *       3) The constituent parts of the package are not re-encrypted, but,
 *          rather, rely on the native Linux permission controls with the
 *          following defaults:
 *          certs/   rwxr-x-r-x
 *          private/ rwx------
 *          This presupposes that the destination path has permissions set
 *          correctly
 *       4) The location of the package itself is placed in
 *          directory denoted by CERTCFG_PACKAGE_DIR.
 *
 * 
 * @param[in] pPkgPath The name of the package file.
 * @param[in] pDestPath The path to the package file
 * @param[in] pcbk The callback function for encrypting the package
 * @param[in] pwd_ctxt The passkey in clear text for decrypting the package
 * @param[out] serialNb An identifying number for the certificate
 * 
 * @return CERT_OK
 * @return CERT_SERIAL_NUMBER_FILE_UNAVAILABLE: The Certificate Manager is not
 *              properly initialized
 * @return CERT_SERIAL_NUMBER_UNAVAILABLE: The system was unable to provied a
 *             valid serial number
 * @return CERT_FILE_ACCESS_FAILURE: The system was unable to write the x.509
 *           certificate.
 * @return CERT_DATABASE_LOCKED: The system was unable to access the database
 * @return CERT_DATABASE_NOT_AVAILABLE: The system was unable to access the
 *           the database
 * @return CERT_LOCKFILE_LOCKED: The database is currently used
 * @return CERT_FILE_PARSE_ERROR: The input file is ill-formed
 * @return CERT_FILE_READ_ERROR: The input file cannot be read
 * @return CERT_OPEN_FILE_FAILED: The input file cannot be opened
 * @return CERT_ILLEGAL_KEY_PACKAGE_TYPE: The package is not a supported type
 * @return CERT_OPEN_FILE_FAILED: the requested package could not be opened.
 *           perhaps a password problem
 *
 */
CertReturnCode_t CertInstallPackageDirect(const char *pPkgPath,
                                      const char *pDestPath,
                                      CertPassCallback pcbk, void *pwd_ctxt);
                            
/** 
 * 
 * @brief Check to see if the certificate is valid.
 * 
 * @param serialNb The certificate ID to validate
 * 
 * @return CERT_OPEN_FILE_FAILURE: the file associated with the serialNB could
 *            not be opened
 * @return CERT_BUFFER_LIMIT_EXCEEDED: The path is too long for the default
 *            buffer size.
 * @return CERT_INSUFFICIENT_BUFFER_SPACE: There were problems resolving the
 *            root path.
 * @return CERT_UNSUPPORTED_CERT_TYPE: The certificate type is not supported
 * @return CERT_DATE_EXPIRED: The certificate may be inedible
 * @return CERT_DATE_PENDING: The certificate is premature
 * @return CERT_DATABASE_LOCKED: The database could not be updated
 */
CertReturnCode_t CertValidateCertificate(const int32_t serialNb);
#ifdef __cplusplus
}
#endif


#endif //#define __CERT_MGR_H__
