// @@@LICENSE
//
//      Copyright (c) 2008-2012 Hewlett-Packard Development Company, L.P.
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
 * @file
 *
 * General interface to the Certificate Manager.
 *
 */
/*--************************************************************************-*/
/* cert_mgr.c: General interface to the certificate manager                  */
/*             Maybe change to cert_ui                                       */
/*--************************************************************************-*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <linux/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libgen.h>

//#include <stdint.h>

#include <dirent.h>
#include <assert.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs12.h>
#include <openssl/conf.h>
#include <openssl/ec.h>

#include "cert_mgr.h"
#include "cert_mgr_prv.h"
#include "cert_cfg.h"
#include "cert_utils.h"
#include "cert_db.h"

#include "cert_x509.h"
#include "cert_debug.h"

#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif

#define CERT_UNDEFINED_FILE      CERT_MAX_FILE_EXTENSIONS


const char *ext_a[CERT_MAX_FILE_EXTENSIONS] = { "UNKNOWN", "pem", "p12", "pfx",
		"der", "crt", "cer", "crl" };

	

#define CERT_NULL_PARAMETER_CHECK(A)

typedef struct CertIterPriv {
	DIR* dir;
} _cert_IterPriv;

#ifdef D_DEBUG_ENABLED
static void logSSLErrors( void );
#else
# define logSSLErrors()
#endif

int Mkdir(const char *path)
{
    struct stat statbuf;
    int rc;
    const char *parent = dirname(strdup(path));
    rc = stat(parent,&statbuf);
    if (rc == -1) {
	if (errno == ENOENT && path != NULL) {
	    // parent is missing, make it
	    rc = Mkdir(parent);
	}
	else {
	    return rc; // fail
	}
    }
    // actually make the dir
    rc = mkdir(path,0777);
    if (parent) free((void*)parent);
    return rc;
}

int Touch(const char *path, const char* data)
{
    int fd, rc;

    // make sure the parent dir exists:
    const char *parent = dirname(strdup(path));
    rc = Mkdir(parent);
    if (rc != 0)
	return rc;

    fd = open(path,O_CREAT|O_WRONLY,0777);
    if (fd > 0) {
	if (data) {
	    write(fd,data,strlen(data));
	}
	close(fd);
    }
    if (fd > 0)
	return 0;
    else
	return -1;
}

CertReturnCode_t SetupCertMgrEnviroment() {
	int32_t result = CERT_OK;
	char dbName[MAX_CERT_PATH];
//	FILE *ifp;
//	const char *mode = "r";

	result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE, dbName,
			MAX_CERT_PATH);
	fprintf(stdout, "%s: path %s\n", __FUNCTION__, dbName);

//	if (CERT_OK != result) {
//		result = CERT_DATABASE_NOT_AVAILABLE;
//	} else {
//		ifp = fopen(dbName, mode);
//		if (ifp == NULL) {
			char certPath[64];
			if ((CERT_OK != (result = CertCfgGetObjectStrValue(
					CERTCFG_CERT_DIR, certPath, 64)))
					|| (!strlen(certPath))) {
				perror("CertInitCertMgr unable to read cert path");
				strcpy(certPath, "/var/ssl/certs");
			}

			if (Mkdir(certPath) != 0) {
				fprintf(stderr, "ERROR making dir '%s'\n", certPath);
			}

			if ( Touch(dbName,NULL) != 0) {
				fprintf(stderr, "ERROR touching '%s'\n", dbName);
			}

			if ((CERT_OK != (result = CertCfgGetObjectStrValue(
					CERTCFG_CERT_SERIAL_NAME, certPath, 64)))
					|| (!strlen(certPath))) {
				perror("CertInitCertMgr unable to read cert path");
				strcpy(certPath, "/var/ssl/serial");
			}

			//sprintf(command, "echo \'01\' > %s", certPath);
			//fprintf(stdout, "%s: command=%s\n", __FUNCTION__, command);
			if (Touch(certPath,"01\n")) {
				fprintf(stderr, "ERROR writing '%s'\n", certPath);
			}

			if ((CERT_OK != (result = CertCfgGetObjectStrValue(
					CERTCFG_PRIVATE_KEY_DIR, certPath, 64)))
					|| (!strlen(certPath))) {
				perror("CertInitCertMgr unable to read private key path");
				strcpy(certPath, "/var/ssl/private");
			}

			if (Mkdir(certPath) != 0) {
				fprintf(stderr, "ERROR creating dir '%s'\n", certPath);
			}
			
			result = CERT_OK;
//		} else {
//			fclose(ifp);
//		}
//	}

	return result;
}
/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertInitCertMgr                                                 */
/* INPUT:                                                                    */
/*       configFile the configuration file                                   */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_PATH_LIMIT_EXCEEDED: The path string is too long               */
/*       CERT_OPEN_FILE_FAILED: The config file couldn't be opened           */
/*       CERT_ILLFORMED_CONFIG_FILE: There was some problem in the config    */
/*       CERT_CONFIG_UNAVAILABLE: The named configuration not available      */
/*       CERT_UNDEFINED_DESTINATION: The certificate root dir not available  */
/* NOTES:                                                                    */
/*       1) If configFile == NULL then the set of possible defaults is       */
/*          checked in the following order:                                  */
/*           1. The environment variable OPENSSL_CONF                        */
/*           2. The system default, CERT_DEF_CONF_FILE, in cert_mgr.h        */
/*       2) Put this into a library initialization routine                   */
/*                                                                           */
/*--***********************************************************************--*/

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

CertReturnCode_t CertInitCertMgr(const char *configFile) 
{
    static int32_t sInited = 0;
    int32_t result = CERT_OK;
    char *configName = 0; //= (char *)configFile;

    if (!sInited) {
	sInited = 1;

	if (NULL == configName) {
	    configName = getenv("OPENSSL_CONFIG_NAME");
	}
	result = CertCfgOpenConfigFile(configFile, configName);

	if(result == CERT_UNDEFINED_ROOT_DIR) {
	    SetupCertMgrEnviroment();
	    result = CERT_OK;
	}

	if (CERT_OK == result) {
	    char rootPath[64];
	    if ((CERT_OK != (result = CertCfgGetObjectStrValue(
				CERTCFG_ROOT_DIR, rootPath, 64))) || (!strlen(rootPath))) {
		strcpy(rootPath, ".");
	    }
	    if (CERT_OK != (result = CertInitLockFiles(rootPath))) {
		perror("CertInitCertMgr");
		result = CERT_LOCK_FILE_CREATION_FAILURE;
		sInited = 0;
	    } else {
		char dbName[MAX_CERT_PATH];

		result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE,
			dbName, MAX_CERT_PATH);
		if (CERT_OK != result) {
		    result = CERT_DATABASE_NOT_AVAILABLE;
		} else if (CERT_OK != (result = CertInitDatabase(dbName))) {
		    result = CERT_DATABASE_NOT_AVAILABLE;
		}
		ERR_load_crypto_strings();
		ERR_load_PKCS12_strings();
		OpenSSL_add_all_algorithms();

		seed_prng();
	    }
	}
    }
    return result;
}



/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertResetConfig                                                 */
/*       Reset the configuration of the certificate Manager                  */
/* INPUT:                                                                    */
/*       configFile: The configuration file                                  */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK: The database was successfully read and deciphered          */
/*       CERT_INSUFFICIENT_BUFFER_SPACE: The origianal configuration file    */
/*           string is ill-defined.                                          */
/*       CERT_OPEN_FILE_FAILED: The config file couldn't be opened           */
/*       CERT_ILLFORMED_CONFIG_FILE: There was some problem in the config    */
/*       CERT_CONFIG_UNAVAILABLE: The named configuration is not             */
/*           available in the configuration file                             */
/*       CERT_UNDEFINED_DESTINATION if the certificate root dir not available*/
/*                                                                           */
/* NOTES:                                                                    */
/*       1) Pick up any changes made to the configuration file               */
/*                                                                           */
/*--***********************************************************************--*/

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
CertReturnCode_t CertResetConfig(const char *pConfigFile) {
	char configName[MAX_CERT_PATH];
	CertReturnCode_t rValue;

	// check to see if it's already set
	rValue = CertCfgGetObjectStrValue(CERTCFG_CONFIG_NAME, configName,
			MAX_CERT_PATH);

	if (CERT_OK == rValue) {
		rValue = CertCfgOpenConfigFile(pConfigFile, configName);
	} else {
		char *name;

		// check if it's set in the environment
		if (NULL == (name = getenv("OPENSSL_CONFIG_NAME")))
			rValue = CertCfgOpenConfigFile(pConfigFile, name);
		else
			rValue = CertCfgOpenConfigFile(pConfigFile, NULL);
	}
	return rValue;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertReadKeyPackageDirect                                        */
/*       Read a Key Package into memory and gives access to the component    */
/*       parts to the designated.  Decrypt if necessary.  The password,      */
/*       passwd  is in clear text.                                           */
/* INPUT:                                                                    */
/*       pPkgPath: The name of the package file                              */
/*       pDestPath: The path to the package file                             */
/*       pcbk: The callback function for encrypting the package              */
/*       pwd_ctxt: The passkey in clear text for decrypting the package      */
/* OUTPUT:                                                                   */
/*       serialNb: An identifying number for the certificate                 */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_SERIAL_NUMBER_FILE_UNAVAILABLE: The Certificate Manager is not */
/*           properly initialized                                            */
/*       CERT_SERIAL_NUMBER_UNAVAILABLE: The system was unable to provied a  */
/*           valid serial number                                             */
/*       CERT_FILE_ACCESS_FAILURE: The system was unable to write the x.509  */
/*           certificate.                                                    */
/*       CERT_DATABASE_LOCKED: The system was unable to access the database  */
/*       CERT_DATABASE_NOT_AVAILABLE: The system was unable to access the    */
/*           the database                                                    */
/*       CERT_LOCKFILE_LOCKED: The database is currently used                */
/*       CERT_FILE_PARSE_ERROR: The input file is ill-formed                 */
/*       CERT_FILE_READ_ERROR: The input file cannot be read                 */
/*       CERT_OPEN_FILE_FAILED: The input file cannot be opened              */
/*       CERT_ILLEGAL_KEY_PACKAGE_TYPE: The package is not a supported type  */
/*       CERT_OPEN_FILE_FAILED: the requested package could not be opened.   */
/*           perhaps a password problem                                      */
/* NOTES:                                                                    */
/*       1) Packages are assumed to be encoded by their extension            */
/*       2) The following types are supported                                */
/*          PKCS#12                                                          */
/*              .pfx                                                         */
/*              .p12                                                         */
/*          DER                                                              */
/*              .der Distinguished Encoding Rules                            */
/*              .cer Canonical Encoding Rules                                */
/*          PEM                                                              */
/*              .pem Privacy Enhanced Mail                                   */
/*              .crt used in at least Debian (Ubuntu) defined pem files      */
/*       4) The location of the package itself is placed in                  */
/*          directory denoted by CERTCFG_PACKAGE_DIR.                        */
/*       5) This is not currently exported to applications                   */
/*                                                                           */
/*--***********************************************************************--*/

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
		const char *pDestPath, CertPassCallback pcbk, void *pwd_ctxt,
		int32_t *serialNb) 
{
    CertReturnCode_t result = CERT_GENERAL_FAILURE;
    int32_t ctype __attribute__((unused));

    switch (returnFileType(pPkgPath)) {
	case CERT_PFX_FILE:
	case CERT_P12_FILE:
	    fprintf(stdout, "%s crt p12 file \n", __FUNCTION__);
	    result = p12ToFile(pPkgPath, pDestPath, pcbk, pwd_ctxt, serialNb);
	    ctype = CERTTYPE_P12;
	    break;

	case CERT_DER_FILE:
	case CERT_CER_FILE:		
	case CERT_CRT_FILE:
	case CERT_PEM_FILE:
	case CERT_CRL_FILE:
	    if((result = pemToFile(pPkgPath, pDestPath, pcbk, pwd_ctxt, serialNb)) == CERT_OK) {
		fprintf(stdout, "%s crt pem file \n", __FUNCTION__);
		ctype = CERTTYPE_PEM;			
	    } else {			
		if((result = derToFile(pPkgPath, pDestPath, serialNb)) == CERT_OK) {
		    fprintf(stdout, "%s crt der file \n", __FUNCTION__);
		    ctype = CERTTYPE_DER;				 
		}
	    }		
	    break;

	default:
	    result = CERT_ILLEGAL_KEY_PACKAGE_TYPE;
	    break;
    }

    return result;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertInstallKeyPackageDirect                                     */
/*       Resolve a Key Package into its component parts to the designated    */
/*       destination directory.  Decrypt if necessary.  The password, passwd */
/*       is in clear text.                                                   */
/* INPUT:                                                                    */
/*       pPkgPath: The location of the package file                          */
/*       pDestPath: The root directory for the resolved, decrypted data      */
/*       pcbk: The callback function for decrypting the package              */
/*       pwd_ctxt: The passkey in clear text for decrypting the package      */
/* OUTPUT:                                                                   */
/*       serialNb: The certificate ID number                                 */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_ILLEGAL_PACKAGE_TYPE: The package is not a supported type      */
/*       CERT_OPEN_FILE_FAILED: the requested package could not be opened.   */
/*           perhaps a password problem                                      */
/*       CERT_UNDEFINED_DESTINATION: the destination directory could not be  */
/*           resolved.                                                       */
/* NOTES:                                                                    */
/*       1) Packages are assumed to be encoded by their extension            */
/*       2) The following types are supported                                */
/*          PKCS#12                                                          */
/*              .pfx                                                         */
/*              .p12                                                         */
/*          DER                                                              */
/*              .der Distinguished Encoding Rules                            */
/*              .cer Canonical Encoding Rules                                */
/*          PEM                                                              */
/*              .pem Privacy Enhanced Mail                                   */
/*              .crt used in at least Debian (Ubuntu) defined pem files      */
/*       3) The constituent parts of the package are not re-encrypted, but,  */
/*          rather, rely on the native Linux permission controls with the    */
/*          following defaults:                                              */
/*          certs/   rwxr-x-r-x                                              */
/*          private/ rwx------                                               */
/*          This presupposes that the destination path has permissions set   */
/*          correctly                                                        */
/*       4) The location of the package itself is placed in                  */
/*          directory denoted by CERTCFG_PACKAGE_DIR.                        */
/*                                                                           */
/*--***********************************************************************--*/

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

CertReturnCode_t CertInstallKeyPackageDirect(const char *pPkgPath,
		const char *pDestPath, CertPassCallback pcbk, void *pwd_ctxt,
		int32_t *serialNb) 
{
    CertReturnCode_t result = CERT_GENERAL_FAILURE;
    int32_t ctype __attribute__((unused));

    switch (returnFileType(pPkgPath)) {
	case CERT_PFX_FILE:
	case CERT_P12_FILE:
	    fprintf(stdout, "%s p12 pfx file\n", __FUNCTION__);
	    result = p12ToFile(pPkgPath, pDestPath, pcbk, pwd_ctxt, serialNb);
	    ctype = CERTTYPE_P12;
	    break;

	case CERT_DER_FILE:
	case CERT_CER_FILE:		
	case CERT_CRT_FILE:
	case CERT_PEM_FILE:
	case CERT_CRL_FILE:
	    if((result = pemToFile(pPkgPath, pDestPath, pcbk, pwd_ctxt, serialNb)) == CERT_OK) {
		fprintf(stdout, "%s crt pem file \n", __FUNCTION__);
		ctype = CERTTYPE_PEM;			
	    } else {			
		if((result = derToFile(pPkgPath, pDestPath, serialNb)) == CERT_OK) {
		    fprintf(stdout, "%s crt der file \n", __FUNCTION__);
		    ctype = CERTTYPE_DER;				 
		}
	    }		
	    break;

	default:
	    result = CERT_ILLEGAL_KEY_PACKAGE_TYPE;
	    break;
    }

    return result;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertInstallKeyPackage                                           */
/*       Resolve a Key Package into its component parts to the default       */
/*       destination directories.  Decrypt if necessary.  The password,      */
/*       passwd, is in clear text.                                           */
/* INPUT:                                                                    */
/*       pPkgPath: The location of the package file                          */
/*       pcbk: The callback function for decrypting the package              */
/*       pwd_ctxt: The passkey in clear text for decrypting the package      */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_ILLEGAL_PACKAGE_TYPE: The package is not a supported type      */
/*       CERT_OPEN_FILE_FAILED: the requested package could not be opened.   */
/*           perhaps a password problem                                      */
/*       CERT_UNDEFINED_DESTINATION: the destination directory could not be  */
/*           resolved.                                                       */
/* NOTES:                                                                    */
/*       1) Packages are encoded by their extension                          */
/*       2) The following types are supported                                */
/*          PKCS#12                                                          */
/*              .pfx                                                         */
/*              .p12                                                         */
/*          DER                                                              */
/*              .der Distinguished Encoding Rules                            */
/*              .cer Canonical Encoding Rules                                */
/*          PEM                                                              */
/*              .pem Privacy Enhanced Mail                                   */
/*              .crt used in at least Debian definition of pem               */
/*       3) The constituent parts of the package are not re-encrypted, but,  */
/*          rather, rely on the native Linux permission controls.            */
/*          This presupposes that the destination path has permissions set   */
/*          correctly                                                        */
/*       4) The destination directory is resolved at initialization time from*/
/*          the rules defined in the configuration file                      */
/*                                                                           */
/*--***********************************************************************--*/

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

CertReturnCode_t CertInstallKeyPackage(const char *pPkgPath,
		CertPassCallback pcbk, void *pwd_ctxt, int32_t *serialNb) 
{
    char pDestPath[MAX_CERT_PATH];
    CertReturnCode_t result;

    result = CertCfgGetObjectStrValue(CERTCFG_ROOT_DIR, pDestPath,
	    MAX_CERT_PATH);

    if (CERT_OK != result)
	return result;

    if (NULL == pDestPath)
	return CERT_UNDEFINED_DESTINATION;
    else
	return CertInstallKeyPackageDirect(pPkgPath, pDestPath, pcbk, pwd_ctxt,
		serialNb);
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertRemoveCertificateDirect                                     */
/*       Remove a certificate from the designated directory                  */
/* INPUT:                                                                    */
/*       serialNb: The certificate ID.                                       */
/*       pCertPath The location of the certificate.                          */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/*       CERT_OK                                                             */
/*       CERT_UNDEFINED_DESTINATION: The path isn't defined                  */
/*       CERT_PATH_LIMIT_EXCEEDED: The combination of path and certificate   */
/*           name exceeds the pre-defined limits                             */
/*       CERT_LINK_ERROR: The certificate removal failed.                    */
/* NOTES:                                                                    */
/*       1) removeFromPath will do the error checking on both pCertName and  */
/*          *CertPath                                                        */
/*                                                                           */
/*--***********************************************************************--*/

/** 
 * 
 * @brief Remove a certificate from the designated directory
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
CertReturnCode_t CertRemoveCertificateDirect(int32_t serialNb,
		const char *pCertPath) 
{
    int errorNb;
    CertReturnCode_t result = 0;

    result = removeFromPath(serialNb, pCertPath, "", "pem", &errorNb);

    return result;
} /*--** CertRemoveCertificate **--*/


CertReturnCode_t removeLinkFiles() {
	CertReturnCode_t result = 0;
	char command[255] = {'\0'};
	char certPath[64] = {'\0'};
	
	if ((CERT_OK != (result = CertCfgGetObjectStrValue(
			CERTCFG_CERT_DIR, certPath, 64)))
			|| (!strlen(certPath))) {
		perror("CertInitCertMgr unable to read cert path");
		strcpy(certPath, "/var/ssl/certs");
	}

	sprintf(command, "rm -f `for f in $(find %s -type l); do if [ ! -e \"$f\" ]; then echo $f; fi; done`", certPath);
	fprintf(stdout, "%s: command=%s\n", __FUNCTION__, command);
	if (-1 == system(command)) {
		fprintf(stderr, "ERROR removing links\n");
	}
	
	// XXX also remove links from cache dir

	return result;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertRemoveCertificate                                           */
/*       Remove a certificate from the default directory                     */
/* INPUT:                                                                    */
/*       serialNb: the certificate to be removed                             */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/*       CERT_OK                                                             */
/*       CERT_UNDEFINED_DESTINATION: The path isn't defined                  */
/*       CERT_PATH_LIMIT_EXCEEDED: The combination of path and certificate   */
/*           name exceeds the pre-defined limits                             */
/*       CERT_LINK_ERROR: The certificate removal failed.                    */
/* NOTES:                                                                    */
/*       1) All files installed with the certificate will be removed         */
/*                                                                           */
/*--***********************************************************************--*/

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
CertReturnCode_t CertRemoveCertificate(int32_t serialNb) {
	char pPath[MAX_CERT_PATH];
	int errorNb;
	CertReturnCode_t result = CERT_GENERAL_FAILURE;

	/* Get one after another */

	if (CERT_OK == CertCfgGetObjectStrValue(CERTCFG_CERT_DIR, pPath,
			MAX_CERT_PATH))
		result = removeFromPath(serialNb, pPath, "", "pem", &errorNb);

	if (CERT_OK == CertCfgGetObjectStrValue(CERTCFG_CERT_DIR, pPath,
			MAX_CERT_PATH))
		result = removeFromPath(serialNb, pPath, "ca", "pem", &errorNb);

	if (CERT_OK == CertCfgGetObjectStrValue(CERTCFG_PRIVATE_KEY_DIR, pPath,
			MAX_CERT_PATH))
		result = removeFromPath(serialNb, pPath, "rsa", "pem", &errorNb);

	if (CERT_OK == CertCfgGetObjectStrValue(CERTCFG_PRIVATE_KEY_DIR, pPath,
			MAX_CERT_PATH))
		result = removeFromPath(serialNb, pPath, "dsa", "pem", &errorNb);

	if (CERT_OK == CertCfgGetObjectStrValue(CERTCFG_AUTH_CERT_DIR, pPath,
			MAX_CERT_PATH))
		result = removeFromPath(serialNb, pPath, "", "pem", &errorNb);

	if (CERT_OK == CertCfgGetObjectStrValue(CERTCFG_PUBLIC_KEY_DIR, pPath,
			MAX_CERT_PATH))
		result = removeFromPath(serialNb, pPath, "rsa", "pem", &errorNb);

	if (CERT_OK == CertCfgGetObjectStrValue(CERTCFG_PUBLIC_KEY_DIR, pPath,
			MAX_CERT_PATH))
		result = removeFromPath(serialNb, pPath, "dsa", "pem", &errorNb);

	if (CERT_OK == CertCfgGetObjectStrValue(CERTCFG_CRL_DIR, pPath,
			MAX_CERT_PATH))
		result = removeFromPath(serialNb, pPath, "crl", "pem.gz", &errorNb);

	/* result = removeLinkFiles(); */
	/* whether or not things went well  */

	result = CertUpdateDatabaseItem((char *)"ksa", serialNb,
			CERT_DATABASE_ITEM_STATUS, "x");

	return result;
}
/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertGetCertificateCountDirect                                   */
/*       Retrieve the number of certificates based on status                 */
/* INPUT:                                                                    */
/*       pDatabase: The certificate database                                 */
/*       status: The filter                                                  */
/* OUTPUT:                                                                   */
/*       pNCerts: The number of certificates that matched the status         */
/* RETURN:                                                                   */
/*       CERT_OPEN_FILE_FAILED: The certificate directory couldn't be opened */
/* NOTES:                                                                    */
/*       1) There are no checks for database consistency                     */
/*                                                                           */
/*--***********************************************************************--*/
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
CertReturnCode_t CertGetCertificateCountDirect(char *pDatabase,
		CertStatus_t status, int32_t *pNCerts) {
	CertReturnCode_t result;

	result = CertDatabaseCountCertsDirect(pDatabase, status, pNCerts);

	return result;
} /*--** CertGetCertificateCountDirect **--*/

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertGetCertificateCount                                         */
/*       Resolve the current certificate directory and count its contents    */
/* INPUT:                                                                    */
/*       status: The filter                                                  */
/* OUTPUT:                                                                   */
/*       pNCerts: The number of certificates that matched the status         */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) There are no checks for database consistency                     */
/*                                                                           */
/*--***********************************************************************--*/

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
CertReturnCode_t CertGetCertificateCount(CertStatus_t status, int32_t *pNCerts) {
	char path[MAX_CERT_PATH];
	CertReturnCode_t result = CERT_GENERAL_FAILURE;

	if (CERT_OK == CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE, path,
			MAX_CERT_PATH)) {
		result = CertGetCertificateCountDirect(path, status, pNCerts);
	}

	return result;
} /*--** CertGetCertificateCount **--*/

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: certAddAuthorizedCertificate                                    */
/*       Set a certificate to authorized                                     */
/* INPUT:                                                                    */
/*       serialNB: the serial number of the certificate file to be authorized*/
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_UNSUPPORTED_CERT_TYPE: the certificate package is not a        */
/*          supported package type                                           */
/*       CERT_OPEN_FILE_FAILURE: the certificate file could not be opened    */
/*       CERT_FILE_READ_FAILURE: the PEM was not read successfully           */
/*       CERT_TOO_MANY_HASH_FILES: We've exceeded the number of files whose  */
/*           base name is the same.                                          */
/* NOTES:                                                                    */
/*       1) The expectation is that the file is named after the first 4 bytes*/
/*          of the hash to be an Authoritative certificate.  Validation has  */
/*          not yet been achieved.                                           */
/*       2) Authorized certificates will be held in a database similar to    */
/*          index.txt for issued certificates                                */
/*       3) The output is placed in the defaults defined by the configuration*/
/*          file along with a copy of the certificate.  the actual files are */
/*          links rather than copies.  The convention followed on Ubuntu is  */
/*          the original container is in an arbitrary location with the      */
/*          suffix .crt.   The destination files are .pem for the straight   */
/*          copy and .# for the copy with the hash as the name.              */
/*       4) This treats the package as if it were in the correct format.  It */
/*          does not break it down into its constituent parts.               */
/*       5) No checks are made to the certificate.  It is assumed that the   */
/*          checks will be made at the time of the certificate's use.  This  */
/*          is as it should be.                                              */
/*                                                                           */
/*--***********************************************************************--*/

CertReturnCode_t CertUpdateDatabase(void);

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
CertReturnCode_t CertAddAuthorizedCert(const int32_t serialNb) 
{
    CertReturnCode_t result = CERT_GENERAL_FAILURE;
    X509* cert = NULL;
    char certPath[MAX_CERT_PATH];
    char filename[MAX_CERT_PATH];
    unsigned long hash;

#if 0
    result = CertGetNameFromSerialNumber(serialNb, certPath, MAX_CERT_PATH);
#else
    result = makePathToCert(serialNb, certPath, MAX_CERT_PATH);
#endif

    if (CERT_OK != result)
    {
	return result;
    }

    result = CertPemToX509(certPath, &cert);
    if (CERT_OK != result) 
    {
	return result;
    }

    hash = X509_subject_name_hash(cert);
    result = mkFileNameFromHash(filename, sizeof(filename), hash, certPath,			CERTCFG_AUTH_CERT_DIR);
    if (CERT_OK == result) {
	char dbPath[MAX_CERT_PATH];

	if (-1 == symlink(certPath, filename)) {
	    fprintf(stderr, "ERROR %d creating symlink '%s' -> '%s'\n",
		    errno, filename, certPath);
	}
	fprintf(stdout, "%s - %s - %s\n", __FUNCTION__, certPath, filename);
	result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE, dbPath,
		MAX_CERT_PATH);

	if (CERT_OK != result) {
	    PRINT_RETURN_CODE(result);
	    fprintf(stdout, "Need to unwind this %s\n", __FUNCTION__);
	} else {
	    result = CertUpdateDatabaseItem(dbPath, serialNb,
		    CERT_DATABASE_ITEM_STATUS,
		    statusNames[CERT_STATUS_VALID_CA]);
	}
    }

    // ericm: also make a link in trusted cache dir that points to this cert
    result = mkFileNameFromHash(filename, sizeof(filename), hash, certPath,			CERTCFG_TRUSTED_CA_DIR);
    if (CERT_OK == result) {

	if (-1 == symlink(certPath, filename)) {
	    fprintf(stderr, "ERROR %d creating symlink '%s' -> '%s'\n",
		    errno, filename, certPath);
	}
	fprintf(stdout, "%s - %s - %s\n", __FUNCTION__, certPath, filename);
	/* don't update db, it was done above */
    }


    if (cert)
	X509_free(cert);

    return result;
} /* CertAddAuthorizedCert */

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: certAddTrustedCertificate                                    */
/*       Set a certificate to trusted                                     */
/* INPUT:                                                                    */
/*       serialNB: the serial number of the certificate file to be authorized*/
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_UNSUPPORTED_CERT_TYPE: the certificate package is not a        */
/*          supported package type                                           */
/*       CERT_OPEN_FILE_FAILURE: the certificate file could not be opened    */
/*       CERT_FILE_READ_FAILURE: the PEM was not read successfully           */
/*       CERT_TOO_MANY_HASH_FILES: We've exceeded the number of files whose  */
/*           base name is the same.                                          */
/* NOTES:                                                                    */
/*                                                                           */
/*--***********************************************************************--*/

/** 
 * @brief Add a certificate to the list of trusted certificates
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

CertReturnCode_t CertAddTrustedCert(const int32_t serialNb) {
	CertReturnCode_t result = CERT_GENERAL_FAILURE;
#if 0
	X509* cert = NULL;
	char certPath[MAX_CERT_PATH];
	char filename[MAX_CERT_PATH];
	unsigned long hash;

#if 0
	result = CertGetNameFromSerialNumber(serialNb, certPath, MAX_CERT_PATH);
#else
	result = makePathToCert(serialNb, certPath, MAX_CERT_PATH);
#endif

	if (CERT_OK != result)
		return result;

	result = CertPemToX509(certPath, &cert);
	if (CERT_OK != result)
		return result;

	hash = X509_subject_name_hash(cert);
	result = mkFileNameFromHash(filename, sizeof(filename), hash, 
		certPath, CERTCFG_AUTH_CERT_DIR);
	if (CERT_OK == result) {
		char dbPath[MAX_CERT_PATH];

		symlink(certPath, filename);
#endif
		char dbPath[MAX_CERT_PATH];
		result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE, dbPath,
				MAX_CERT_PATH);

		if (CERT_OK != result) {
			PRINT_RETURN_CODE(result);
			fprintf(stdout, "Need to unwind this %s\n", __FUNCTION__);
		} else {
			result = CertUpdateDatabaseItem(dbPath, serialNb,
					CERT_DATABASE_ITEM_STATUS,
					statusNames[CERT_STATUS_TRUSTED_PEER]);
		}
#if 0
	}

	X509_free(cert);
#endif

	return result;
} /* CertAddTrustedCert */


/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertValidateCertificate                                         */
/*       Check to see if the certificate is valid.                           */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/*       CERT_OPEN_FILE_FAILURE: the file associated with the serialNB could */
/*            not be opened                                                  */
/*       CERT_BUFFER_LIMIT_EXCEEDED: The path is too long for the default    */
/*            buffer size.                                                   */
/*       CERT_INSUFFICIENT_BUFFER_SPACE: There were problems resolving the   */
/*            root path                                                      */
/*       CERT_UNSUPPORTED_CERT_TYPE: The certificate type is not supported   */
/*       CERT_DATE_EXPIRED: The certificate may be inedible                  */
/*       CERT_DATE_PENDING: The certificate is premature                     */
/*       CERT_DATABASE_LOCKED: The database could not be updated             */
/* NOTES:                                                                    */
/*       1) CERT_DATABASE_LOCKED will obscure whether or not the certificate */
/*          is valid                                                         */
/*                                                                           */
/*--***********************************************************************--*/
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
CertReturnCode_t CertValidateCertificate(const int32_t serialNb) {
	CertReturnCode_t result = CERT_GENERAL_FAILURE;

	char dir[MAX_CERT_PATH];
	int32_t cmErr;

	if (CERT_OK == (result = makePathToCert(serialNb, dir, MAX_CERT_PATH))) {
		if (exists(dir)) {
			int32_t i;

			/* File formats are mutually exclusive in interpretation */
			for (i = CERTTYPE_PEM; i < CERTTYPE_UNKNOWN; i++) {
				result = validateCertPath(dir, serialNb, i, &cmErr);
				/*
				 * This test fails if the file is the wrong CERTTYPE
				 * So go on the the next one
				 */
				if (CERT_FILE_READ_FAILURE != result)
					break;
			}
		} else {
			result = CERT_OPEN_FILE_FAILED;
		}
	}

	return result;
}

/*--***********************************************************************--*/
/*--**** FILE TO MEMORY                                            ********--*/
/*--***********************************************************************--*/

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: CertPemToX509                                                       */
/*       Read a PEM encoded certificate into memory                          */
/* INPUT:                                                                    */
/*       pemPath: the path to the PEM encoded file                           */
/* OUTPUT:                                                                   */
/*       hCert: the X.509 certificate for use                                */
/* RETURN:                                                                   */
/*       CERT_OK: the certificate had been read successfully                 */
/*       CERT_OPEN_FILE_FAILURE: the bio file could not be opened            */
/*       CERT_FILE_READ_FAILURE: the PEM was not read successfully           */
/* NOTES:                                                                    */
/*                                                                           */
/*--***********************************************************************--*/

CertReturnCode_t CertPemToX509(const char* pemPath, X509** hCert) {
	CertReturnCode_t result = CERT_GENERAL_FAILURE;
	X509* cert = NULL;

	BIO* bio;

	if ((bio = BIO_new_file(pemPath, "r")) == NULL) {
		result = CERT_OPEN_FILE_FAILED;
		PRINT_RETURN_CODE(result);
	} else {
		char buffer[] = "    ";

		cert = PEM_read_bio_X509(bio, NULL, NULL, buffer);
		BIO_free(bio);
		if (NULL != cert) {
			result = CERT_OK;
		} else {
			result = CERT_FILE_READ_FAILURE;
			PRINT_RETURN_CODE(result);logSSLErrors();
		}
	}

	*hCert = cert;

	return result;
} /* CertPemToX509 */

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: derToX509                                                       */
/*       Read a DER encoded X.509 information into memory                    */
/* INPUT:                                                                    */
/*       derPath: the path to the DER encoded file                           */
/* OUTPUT:                                                                   */
/*       hCert: the X.509 certificate for use                                */
/* RETURN:                                                                   */
/*       CERT_OK: the certificate had been read successfully                 */
/*       CERT_FILE_ACCESS_FAILURE: the bio file opening failed               */
/*       CERT_FILE_READ_FAILURE: the PEM was not read successfully           */
/* NOTES:                                                                    */
/*                                                                           */
/*--***********************************************************************--*/

CertReturnCode_t derToX509(const char *derPath, X509 **hCert) {
	CertReturnCode_t result = CERT_GENERAL_FAILURE;
	X509 *cert = NULL;

	FILE *file = fopen(derPath, "r");

	if (NULL != file) {
		cert = d2i_X509_fp(file, NULL);

		if (NULL == cert) {
			cert = X509_new();
			rewind(file);

			if (NULL == PEM_read_X509(file, &cert, NULL, NULL)) {
				X509_free(cert);
				cert = NULL;
			}
		}

		fclose(file);

		if (NULL != cert) {
			*hCert = cert;
			result = CERT_OK;
		} else {
			result = CERT_FILE_READ_FAILURE;
			PRINT_RETURN_CODE(result);logSSLErrors();
		}
	} else {
		result = CERT_FILE_ACCESS_FAILURE;
		PRINT_RETURN_CODE(result);
	}
	return result;
}

CertReturnCode_t p12ToX509(const char *p12Path, void *pass, X509 **hCert, 
EVP_PKEY **pKey, STACK_OF(X509) **pCa) 
{

    CertReturnCode_t result = CERT_OK;
    FILE *fp = fopen(p12Path, "r");

    if (NULL != fp) {
	PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);


	if (NULL != p12) {
	    EVP_PKEY *pkey = NULL;
	    X509 *cert = NULL;
	    STACK_OF(X509) *ca = NULL;

	    if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0)) {
		fprintf(stdout, "%s no password \n", __FUNCTION__);
	    } else {
		fprintf(stdout, "%s password required \n", __FUNCTION__);
		if (PKCS12_verify_mac(p12, pass, strlen(pass))) {
		    fprintf(stdout, "%s password correct \n", __FUNCTION__);
		} else {
		    fprintf(stdout, "%s password incorrect %s\n", __FUNCTION__,
			    (char*)pass);
		    result = CERT_PASSWD_WRONG;
		}
	    }

	    if (result == CERT_OK) {
		if ( 0 != PKCS12_parse(p12, pass, &pkey, &cert, &ca)) {
		    if (NULL != cert) {
			//						if(**hCert != NULL)
			*hCert = cert;
			//						if(**hKey != NULL)
			*pKey = pkey;
			//						if(**hCa != NULL)
			*pCa = ca;
		    } else {
			result = CERT_FILE_READ_FAILURE;
			PRINT_RETURN_CODE(result);
			logSSLErrors();
		    }
		} else {
		    result = CERT_FILE_READ_FAILURE;
		    PRINT_RETURN_CODE(result);
		    logSSLErrors();
		}
	    }
	} else {
	    result = CERT_FILE_READ_FAILURE;
	    PRINT_RETURN_CODE(result);
	}
    } else {
	result = CERT_FILE_READ_FAILURE;
	PRINT_RETURN_CODE(result);
    }
    return result;
}

CertReturnCode_t CertGetX509(const char *pPkgPath, void *pass, X509 **hCert) {

	CertReturnCode_t result = CERT_GENERAL_FAILURE;

	switch (returnFileType(pPkgPath)) {
	case CERT_PFX_FILE:
	case CERT_P12_FILE:
	{
		EVP_PKEY *pkey = NULL;
		STACK_OF(X509) *ca = NULL;

		fprintf(stdout, "%s p12 pfx file\n", __FUNCTION__);
		result = p12ToX509(pPkgPath, pass, hCert, &pkey, &ca);

		if (pkey)
			EVP_PKEY_free(pkey);
		
		if (ca)
			sk_X509_free(ca);

		break;
	}
	case CERT_DER_FILE:
	case CERT_CER_FILE:		
	case CERT_CRT_FILE:
	case CERT_PEM_FILE:
		if((result = CertPemToX509(pPkgPath, hCert)) == CERT_OK) {
			fprintf(stdout, "%s crt pem file \n", __FUNCTION__);
		} else {			
			if((result = derToX509(pPkgPath, hCert)) == CERT_OK) {
				fprintf(stdout, "%s crt der file \n", __FUNCTION__);
			}
		}		
		break;

//	case CERT_DER_FILE:
//	case CERT_CER_FILE:
//		result = derToX509(pPkgPath, hCert);
//		break;
//
//	case CERT_CRT_FILE:
//	case CERT_PEM_FILE:
//		fprintf(stdout, "%s crt pem file \n", __FUNCTION__);
//		result = CertPemToX509(pPkgPath, hCert);
//		break;

	default:
		PRINT_ERROR4("Path", pPkgPath, "FileType", (int)returnFileType(pPkgPath));
		result = CERT_ILLEGAL_KEY_PACKAGE_TYPE;
		break;
	}

	return result;
}

/*--***********************************************************************--*/
/*--**** FILE TO FILE                                              ********--*/
/*--***********************************************************************--*/
static CertReturnCode_t getNextSerialNumber(int32_t *serial) {
	CertReturnCode_t rValue = CERT_GENERAL_FAILURE;
	char serialFile[MAX_CERT_PATH] = {'\0'};
	int32_t serialNb = 0;
	
	/* lock the database              */
	if (0 != (rValue = CertLockFile(CERT_FILELOCK_DATABASE))) {
		return rValue;
	}
	/* Get the current serial number  */
	if (CERT_OK == (rValue = CertCfgGetObjectStrValue(CERTCFG_CERT_SERIAL_NAME,
			serialFile, MAX_CERT_PATH))) {
		if (0 == (serialNb = CertGetSerialNumberInc(serialFile, 1))) {
			rValue = CERT_SERIAL_NUMBER_UNAVAILABLE;
		} else {
			*serial = serialNb;
		}
	}
	CertUnlockFile(CERT_FILELOCK_DATABASE);
	
	return rValue;	
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: p12ToFile                                                       */
/*       Decrypt the PKCS#12 package and populate the given directory with   */
/*       the results                                                         */
/* INPUT:                                                                    */
/*       pPkgPath: The location of the package file                          */
/*       pcbk: a callback function for optional re-encrypting                */
/*       pDestPath: The root location for the resolved, decrypted data       */
/*       pass: The passkey in clear text for decrypting the package          */
/* OUTPUT:                                                                   */
/*       serial: an identifying number for the associated files              */
/* RETURN:                                                                   */
/*       CERT_OK: No absolute errors were found                              */
/*       CERT_FILE_PARSE_ERROR: the PKCS#12 file was not parsed properly     */
/*       CERT_FILE_READ_FAILURE: the PKCS#12 file could not be read          */
/*       CERT_OPEN_FILE_FAILED: the PKCS#12 file could not be opened         */
/* NOTES:                                                                    */
/*      1) From the documentation on openssl PKCS12_parse throws away most   */
/*         attributes keeping only:                                          */
/*             friendlyName                                                  */
/*             localKeyID                                                    */
/*      2) Similarly, attributes cannot be stored in the private key EVP_PKEY*/
/*      3) default locations are as follows:                                 */
/*             certificates:  pDestPath/new_certs/    rwxr-x---              */
/*             private key:   pDestPath/private/      rwx------              */
/*             public key:    pDestPath/public/       rwxr-xr-x              */
/*      4) The passkey must be a NULL terminated string                      */
/*                                                                           */
/*--***********************************************************************--*/

CertReturnCode_t p12ToFile(const char *pPkgPath, const char *pDestPath,
		CertPassCallback pcbk, void *pass, int32_t *serial) 
{
    CertReturnCode_t result = CERT_OK;

    fprintf(stdout, "%s %s \n", __FUNCTION__, pPkgPath);

    char *baseName = fileBaseName(pPkgPath);
    int certInstalled = 0;

    EVP_PKEY *pkey;
    X509 *cert;
    STACK_OF(X509) *ca;
    int32_t serialNb = 0;
    int32_t duplicateSerial = 0;


    if ((result = getNextSerialNumber(&serialNb)) != CERT_OK) {
	return result;
    } else {
	*serial = serialNb;
    }


    if ((result = p12ToX509(pPkgPath, pass, &cert, &pkey, &ca)) == CERT_OK) {
	//		char dbPath[MAX_CERT_PATH] = {'\0'};

	/*
	 * We've gotten everything,
	 * now let's write it out the the dest
	 */

	if (NULL != cert) {
	    char *certPath;
	    FILE *fp;

	    if ((duplicateSerial = findSSLCertInLocalStore(cert)) != 0) {
		*serial = serialNb = duplicateSerial;
		fprintf(stdout, "%s duplicate cert found %d\n", __FUNCTION__, duplicateSerial);
	    }

	    certPath = serialPathName(baseName, CERT_DIR_CERTIFICATES,
		    CERT_OBJECT_CERTIFICATE, serialNb);

	    if (NULL != (fp = fopen(certPath, "w"))) {

		PEM_write_X509(fp, cert);
		fclose(fp);
	    }
	    certInstalled++;

	    free(certPath);
	}

	if (NULL != pkey) {
	    int32_t keyType;
	    char *pkeyPath;
	    char *destPath;
	    FILE *fp;

	    
	    /* find out what type of key it is */
	    keyType = getPrivKeyType(pkey);
	    if (keyType >= CERT_OBJECT_MAX_OBJECT) {
		fprintf(stdout, "unknown keyType %d\n",keyType);
		/* not sure what else to do here */
	    }
	    else {
		pkeyPath = serialPathName(baseName, CERT_DIR_PRIVATE_KEY, keyType,
			serialNb);
		fp = fopen(pkeyPath, "w");
		switch (keyType) {
		    case CERT_OBJECT_RSA_PRIVATE_KEY:
			PEM_write_RSAPrivateKey(fp, (RSA *)pkey->pkey.rsa,
				(const EVP_CIPHER *)pcbk, NULL, 0, 0, pass);				
			certInstalled++;
			break;
		    case CERT_OBJECT_EC_PRIVATE_KEY:
			/* ECDSA */
			/* NOTE: we append the private key to the cert because
			 ** WAPI expects that.  The real (secure) way to do this
			 ** is to store the key in keymanager
			 */
			destPath = serialPathName(baseName, 
				CERT_DIR_CERTIFICATES,
				    CERT_OBJECT_CERTIFICATE, serialNb);

			FILE *pfp;
			if (NULL != (pfp = fopen(destPath, "a"))) {
			    PEM_write_ECPrivateKey(pfp, 
				(EC_KEY *)pkey->pkey.ec,
				    NULL, NULL, 0, 0, NULL);
			    fclose(pfp);
			} else {
			    fprintf(stdout, 
				    "%s unable to write ECDSA private key\n", 
				    __FUNCTION__);
			}

			free(destPath);

			certInstalled++;
			break;
		    default:
			fprintf(stdout, "%s keyType %d\n", __FUNCTION__, keyType);
			break;
		}

		fclose(fp);
		free(pkeyPath);
		EVP_PKEY_free(pkey);
	    }
	}

	if (NULL != ca) {
	    int count = 1;
	    char *caPath = 0;
	    unsigned long hash = 0;
	    X509 *x509;
	    FILE *fp;

	    if (cert) {
		hash = X509_subject_name_hash(cert);
		fprintf(stdout, "%s hash 0x%lx\n", __FUNCTION__, hash);
	    }

	    /* this is the list of CA certs for verification */
	    /* the file is the hased name of the certificate subject */
	    while ((ca != NULL) && ((x509 = sk_X509_pop(ca)) != NULL)) {
		caPath = serialPathNameCount(baseName, CERT_DIR_CERTIFICATES,
			CERT_OBJECT_C_AUTHORIZATION, serialNb, count++);				
		if (NULL != (fp = fopen(caPath, "w"))) {
		    char filename[MAX_CERT_PATH];
		    memset(filename, 0, sizeof(filename));
		    fprintf(stdout, "%s ca install %s\n", __FUNCTION__, caPath);
		    PEM_write_X509(fp, x509);
		    fprintf(stdout, "%s ca hash 0x%lx\n", __FUNCTION__,
			    X509_subject_name_hash(x509));
		    if (CERT_OK == mkFileNameFromHash(filename,
				sizeof(filename), X509_subject_name_hash(x509),
				caPath, CERTCFG_TRUSTED_CA_DIR)) {
			if (-1 == symlink(caPath, filename)) {
			    fprintf(stderr, "ERROR %d creating symlink '%s' -> '%s'\n",
				    errno, caPath, filename);
			}
		    }
		    fclose(fp);
		    certInstalled++;
		} else {
		    perror("cert_mgr");
		    result = CERT_FILE_ACCESS_FAILURE;
		}

	    }

	    if(0 < certInstalled && duplicateSerial == 0) {
		result = CertCreateDatabaseItem(cert, baseName, serialNb, "X");
		fprintf(stdout, "%s item created in db \n", __FUNCTION__);
	    } else {
		result = CERT_OK;
	    }

	    //			if (CERT_OK == result) {
	    //				CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE, dbPath,
	    //						MAX_CERT_PATH);
	    //				result = CertWriteDatabase(dbPath);
	    //			}

	    free(caPath);
	    if (ca)
		sk_X509_free(ca);
	}
    }

    if (baseName)
	free(baseName);

    return result;
} /* p12ToFile */

CertReturnCode_t isDup(const char* path1, const char* path2) {
	CertReturnCode_t result = CERT_OK;
	X509 *cert1 = NULL;
	X509 *cert2 = NULL;
	FILE* fpIn1 = fopen(path1, "r");
	FILE* fpIn2 = fopen(path2, "r");

	if (NULL != fpIn1) {
		cert1 = PEM_read_X509(fpIn1, NULL, NULL,
				NULL);
	} else {
		fprintf(stdout, "%s file1 null \n", __FUNCTION__);
	}

	if (NULL != fpIn2) {
		cert2 = PEM_read_X509(fpIn2, NULL, NULL,
				NULL);
	} else {
		fprintf(stdout, "%s file2 null \n", __FUNCTION__);
	}

	fprintf(stdout, "%s look for dup %s %s\n", __FUNCTION__, path1, path2);
	if(cert1 != NULL && cert2 != NULL) {
		if (X509_cmp(cert1, cert2) == 0) {
			result = CERT_DUPLICATE;
			fprintf(stdout, "%s duplicate found \n", __FUNCTION__);
		}
		X509_free(cert1);
		X509_free(cert2);
	} else {
		fprintf(stdout, "%s cert null \n", __FUNCTION__);
	}
	
	fclose(fpIn1);
	fclose(fpIn2);
	return result;
} /* isDup */

CertReturnCode_t isCertFile(const char* pName) {
	int32_t len = strlen(pName);
	return len > 2 /* not . or .. */
	|| (len == 1 && pName[0] != '.') || (len == 2 && pName[0] != '.'
			&& pName[1] != '.' );
} /* isCertFile */


/*
* ericm: remove a single link to a cert
*/
CertReturnCode_t removeLink(unsigned long hash, const char *fullpath,
	certcfg_Property_t basedir)
{
    CertReturnCode_t result = CERT_GENERAL_FAILURE;

    char filename[MAX_CERT_PATH];
    char dir[MAX_CERT_PATH];
    char linkpath[MAX_CERT_PATH];

    if (CERT_OK == (result = CertCfgGetObjectStrValue(basedir,
		    dir, MAX_CERT_PATH))) {
	int32_t pos;
	int32_t extCounter;


	snprintf(filename, sizeof(filename), "%s/%08lx.", dir, hash);
	pos = strlen(filename);

	result = CERT_GENERAL_FAILURE;
	/* Look for the link to the cert */
	/* stop after the first one we find as there should be only one */
	for (extCounter = 0; 
		result != CERT_OK && extCounter < CERT_MAX_HASHED_FILES; 
		++extCounter) 
	{
	    struct stat statbuf;
	    snprintf(filename + pos, sizeof(filename)-pos, "%d", extCounter);
	    if (lstat(filename,&statbuf) == 0) {
		if (S_ISLNK(statbuf.st_mode)) {
		    /* check that the link points to our cert */
		    int len = readlink(filename,linkpath,sizeof(linkpath)-1);
		    if (len > 0) {
			linkpath[len] = '\0'; // null terminate
			if (strncmp(fullpath,linkpath,MAX_CERT_PATH) == 0) {
			    if (unlink(filename) == 0)
				result = CERT_OK;
			}
		    }
		}
	    }
	}
    }
    return result;
}


/*
* ericm: remove the links to a cert
*/
CertReturnCode_t removeLinks(const char *fullpath)
{

    CertReturnCode_t result = CERT_GENERAL_FAILURE;

    X509* cert = NULL;
    unsigned long hash;

    result = CertPemToX509(fullpath, &cert);
    if (CERT_OK != result) 
    {
	return result;
    }

    hash = X509_subject_name_hash(cert);

    /* delete links in both dirs */
    result = removeLink(hash, fullpath, CERTCFG_AUTH_CERT_DIR);

    /* try to delete the other link even if the first failed */
    result = removeLink(hash, fullpath, CERTCFG_TRUSTED_CA_DIR);

    if (cert)
	X509_free(cert);
    return result;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: removeFromPath                                                  */
/*       Remove a certificate and its hash links from a certificate store    */
/* INPUT:                                                                    */
/*       cert: the name of the certificate                                   */
/*       dirDefType: the default type of certificate which can be            */
/*                   CERT_SYSTEM_DEFAULT_DIR: the system-wide set of defaults*/
/*                   CERT_USER_DEFAULT_DIR: User level set of defaults       */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK: the certificate was successfully removed                   */
/*       CERT_PATH_LIMIT_EXCEEDED: not enough buffer allocated for the       */
/*                directory path                                             */
/*       CERT_LINK_ERR: Linking itself was not successfull (check errno)     */
/* NOTES:                                                                    */
/*                                                                           */
/*--***********************************************************************--*/

CertReturnCode_t removeFromPath(const int32_t certID, const char *path,
		const char *prefix, const char *ext, int32_t *err) 
{
    char certStr[MAX_CERT_PATH];
    char fullPath[MAX_CERT_PATH];

    int32_t len;
    CertReturnCode_t result;

    syslog(LOG_INFO,"func: %s, prefix: %s", __FUNCTION__,prefix);

    if (NULL == path) {
	return CERT_UNDEFINED_DESTINATION;
    }

    sprintf(certStr, "%X", certID);

    len = strlen(path) + 1;
    len += strlen(certStr) + 1;
    len += strlen(ext) + 2; /* don't forget the dot  */

    /* check to see if we have enough space */
    // add 1 for the intervening '/'

    if (MAX_CERT_PATH < len) {
	result = CERT_PATH_LIMIT_EXCEEDED;
    } else {
	int counter = 0;
	snprintf(fullPath, sizeof(fullPath), "%s/%s%s.%s", path, prefix,
		certStr, ext);

	if(!strcmp(prefix,""))prefix="ca"; // for pfx certs(eg: E.pfx) delete files of the form caE_0.pem, caE_1.pem 

	for (counter = 0; counter < CERT_MAX_HASHED_FILES; ++counter) {
	    if (exists(fullPath)) {
		    /* don't pass along return code from removeLinks
		    ** since not all "certs" we remove here will have links
		    */
		    removeLinks(fullPath);
		if (0 == unlink(fullPath)) {
		    result = CERT_OK;
		} else {
		    fprintf(stdout, "unlink failed - %s - %s\n", __FUNCTION__, fullPath);
		    result = CERT_LINK_ERR;
		    *err = errno;
		    PRINT_ERROR2(strerror(errno), errno);
		}				
		snprintf(fullPath, sizeof(fullPath), "%s/%s%s_%d.%s", path, prefix,
			certStr, counter, ext);
	    } else {
		fprintf(stdout, "file not found - %s - %s\n", __FUNCTION__, fullPath);
		result = CERT_LINK_ERR;
		break;
	    }
	}

    }

    return result;
} /* removeFromPath */

#if 0
_cert_IterPriv * mkCertIter(const char *dir)
{
	_cert_IterPriv *piter = calloc(1, sizeof(*piter));

	if (NULL != piter)
	{
		piter->dir = opendir(dir);
	}

	return piter;
}

void freeCertIter( cert_Iterator_t* iter )
{
	_cert_IterPriv* piter = (_cert_IterPriv*)iter;

	closedir( piter->dir );

	free( piter );
	/*     return CERT_OK; */
}

CertReturnCode_t getNextCert( cert_Iterator_t* pIter, const char** hPath )
{
	CertReturnCode_t result = CERT_GENERAL_FAILURE;

	CERT_NULL_PARAMETER_CHECK( pIter );
	CERT_NULL_PARAMETER_CHECK( hPath );

	_cert_IterPriv* piter = (_cert_IterPriv*)pIter;
	do
	{
		struct dirent* dent = readdir( piter->dir );
		if ( dent == NULL )
		{
			result = CERT_ITER_EXCEED;
		}
		else if ( isCertFile( dent->d_name ) )
		{
			*hPath = dent->d_name;
			result = CERT_OK;
		}
	}while ( result == CERT_GENERAL_FAILURE );

	return result;
} /* getNextCert */

CertReturnCode_t makeCertIter(cert_Iterator_t **hIter, int32_t isSystem)
{
	char dir[MAX_CERT_PATH];
	int32_t len = sizeof(dir);
	CertReturnCode_t result;
	result = isSystem ?
	getSystemCertDir(dir, &len) : getUserCertDir(dir, &len);
	if (CERT_OK == result)
	{
		_cert_IterPriv* piter = mkCertIter(dir);
		if (piter != NULL)
		{
			*hIter = (cert_Iterator_t*)piter;
			result = CERT_OK;
		}
	}
	return result;
}
#endif

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: mkFileNameFromHash                                              */
/*       Make a file name from the first 4 bytes of the file's hash          */
/* INPUT:                                                                    */
/*       buf: */
/*       bufSize: the size of the buffer                                     */
/*       hash: Really just an arbitrary number that happens to be the hash of*/
/*             the file of interest                                          */
/*       infile: The file of interest                                        */
/*       basedir: The base location                                          */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/*       CERT_TOO_MANY_HASH_FILES: We've exceeded the number of files whose  */
/*           base name is the same.                                          */
/* NOTES:                                                                    */
/*       1) The file includes the default directory path for authorized certs*/
/*       2) The same hash means that the file has the same subject name.     */
/*          This happens with different certificates with the same subject or*/
/*          a duplicate certificate.                                         */
/*                                                                           */
/*--***********************************************************************--*/

CertReturnCode_t mkFileNameFromHash(char *buf, int32_t bufSize,
		unsigned long hash, const char *infile,
		certcfg_Property_t basedir) 
{
    CertReturnCode_t result = CERT_GENERAL_FAILURE;
    char filename[MAX_CERT_PATH];
    char dir[MAX_CERT_PATH];

    /* CERTCFG_AUTH_CERT_DIR, */
    if (CERT_OK == (result = CertCfgGetObjectStrValue(basedir,
		    dir, MAX_CERT_PATH))) {
	int32_t extCounter;
	int32_t pos;

	snprintf(filename, sizeof(filename), "%s/%08lx.", dir, hash);

	pos = strlen(filename);

	/* Let's check to see if we've already installed this certificate */
	for (extCounter = 0; extCounter < CERT_MAX_HASHED_FILES; ++extCounter) {
	    snprintf(filename + pos, sizeof(filename)-pos, "%d", extCounter);
	    if (exists(filename)) {
		/* the same name, is it the same inside ? */
		if (isDup(filename, infile) != CERT_OK) {
		    result = CERT_DUPLICATE;
		    break;
		}
	    } else {
		snprintf(buf, bufSize, "%s", filename);
		result = CERT_OK;
		break;
	    }
	}
	if (CERT_MAX_HASHED_FILES <= extCounter)
	    result = CERT_TOO_MANY_HASHED_FILES;
    }

    return result;
} /* mkFileNameFromHash */

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: returnFileType                                                  */
/* INPUT:                                                                    */
/*       file: the file name                                                 */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       The file type based on its extension                                */
/* NOTES:                                                                    */
/*       1) The list of supported file extensions is kept in cert_mgr.h      */
/*                                                                           */
/*--***********************************************************************--*/

int returnFileType(const char *file) {
	int32_t i;
	char *extn = strrchr(file, '.');

	if (NULL == extn)
		return 0;

	/* start from 1 because 0 is "UNKNOWN"  */
	for (i = 1; i < CERT_MAX_FILE_EXTENSIONS; i++) {
		if (!strcasecmp(ext_a[i], extn + 1)) {
			break;
		}
	}
	return ((i >= CERT_MAX_FILE_EXTENSIONS) ? 0 : i);
}



CertReturnCode_t derToFile(const char* pCertPath, const char *pDestPath, int32_t *serial) 
{
    int32_t serialNb = 0;
    int32_t duplicateSerial = 0;
    CertReturnCode_t rValue = CERT_GENERAL_FAILURE;
    BIO *bio;
    X509 *cert;


    if ((rValue = getNextSerialNumber(&serialNb)) != CERT_OK) {
	return rValue;
    } else {
	*serial = serialNb;
    }

    bio = BIO_new(BIO_s_mem());
    if (NULL != bio) {

	FILE* fpIn = fopen(pCertPath, "r");

	if (NULL != fpIn) {
	    char *baseName;
	    char *destPath;
	    DSA *dsa = NULL;
	    RSA *rsa = NULL;
	    EC_KEY *ec_key = NULL;
	    X509_CRL *crl = NULL;
	    FILE *fp;

	    baseName = fileBaseName(pCertPath);
	    cert = d2i_X509_fp(fpIn, NULL);

	    if (NULL != cert) {
		fprintf(stdout, "%s cert found \n", __FUNCTION__);
		char *certPath;
		FILE *fp;

		if ((duplicateSerial = findSSLCertInLocalStore(cert)) != 0) {
		    *serial = serialNb = duplicateSerial;
		    fprintf(stdout, "%s duplicate cert found %d\n", __FUNCTION__, duplicateSerial);
		}

		certPath = serialPathName(baseName, CERT_DIR_CERTIFICATES,
			CERT_OBJECT_CERTIFICATE, serialNb);
		if (NULL != (fp = fopen(certPath, "w"))) {

		    PEM_write_X509(fp, cert);
		    fclose(fp);
		}
		if(duplicateSerial == 0) {
		    rValue = CertCreateDatabaseItem(cert, baseName, serialNb, "X");
		    fprintf(stdout, "%s item created in db \n", __FUNCTION__);
		} else {
		    rValue = CERT_OK;
		}

		free(certPath);

	    }else {
		fprintf(stdout, "%s no cert \n", __FUNCTION__);
		rValue = CERT_BAD_CERTIFICATE;
	    }

	    if (NULL != cert) {
		dsa = d2i_DSAPrivateKey_fp(fpIn, NULL);
		if (NULL != dsa) {
		    fprintf(stdout, "%s DSA private key read \n", __FUNCTION__);
		    destPath = serialPathName(baseName, CERT_DIR_PRIVATE_KEY,
			    CERT_OBJECT_DSA_PRIVATE_KEY, serialNb);
		    if (NULL != (fp = fopen(destPath, "w"))) {
			PEM_write_DSAPrivateKey(fp, dsa, NULL, NULL, 0, 0, NULL);
			fclose(fp);
		    } else {
			fprintf(stdout, "%s unable to write DSA private key\n", __FUNCTION__);
		    }

		    DSA_free(dsa);
		    free(destPath);
		    rValue = CERT_OK;
		}

		rewind(fpIn);
		dsa = d2i_DSA_PUBKEY_fp(fpIn, NULL);
		if (NULL != dsa) {
		    fprintf(stdout, "%s DSA pubkey read\n", __FUNCTION__);
		    destPath = serialPathName(baseName, CERT_DIR_PUBLIC_KEY,
			    CERT_OBJECT_DSA_PUBLIC_KEY, serialNb);
		    if (NULL != (fp = fopen(destPath, "w"))) {
			PEM_write_DSA_PUBKEY(fp, dsa);
			fclose(fp);
		    } else {
			fprintf(stdout, "%s unable to write DSA pub key\n", __FUNCTION__);
		    }
		    DSA_free(dsa);
		    free(destPath);
		    rValue = CERT_OK;
		}

		rewind(fpIn);
		rsa = d2i_RSAPrivateKey_fp(fpIn, NULL);
		if (NULL != rsa) {
		    fprintf(stdout, "%s RSA private key read \n", __FUNCTION__);
		    destPath = serialPathName(baseName, CERT_DIR_PRIVATE_KEY,
			    CERT_OBJECT_RSA_PRIVATE_KEY, serialNb);
		    if (NULL != (fp = fopen(destPath, "w"))) {
			PEM_write_RSAPrivateKey(fp, rsa, NULL,
				NULL, 0, 0, NULL);
			fclose(fp);
		    } else {
			fprintf(stdout, "%s unable to write RSA private key\n", __FUNCTION__);
		    }

		    RSA_free(rsa);
		    free(destPath);
		    rValue = CERT_OK;
		}

		rewind(fpIn);
		rsa = d2i_RSA_PUBKEY_fp(fpIn, NULL);
		if (NULL != rsa) {
		    fprintf(stdout, "%s RSA public key read \n", __FUNCTION__);
		    destPath = serialPathName(baseName, CERT_DIR_PUBLIC_KEY,
			    CERT_OBJECT_RSA_PUBLIC_KEY, serialNb);
		    if (NULL != (fp = fopen(destPath, "w"))) {
			PEM_write_RSAPublicKey(fp, rsa);
			fclose(fp);
		    } else {
			fprintf(stdout, "%s unable to write RSA pub key\n", __FUNCTION__);
		    }

		    RSA_free(rsa);
		    free(destPath);
		    rValue = CERT_OK;
		}

		/* ECDSA */
		/* NOTE: we append the private key to the cert because
		** WAPI expects that.  The real (secure) way to do this
		** is to store the key in keymanager
		*/
		rewind(fpIn);
		ec_key = d2i_ECPrivateKey_fp(fpIn, NULL);
		if (NULL != ec_key) {
		    fprintf(stdout, 
			"%s ECDSA private key read \n", __FUNCTION__);

		    destPath = serialPathName(baseName, CERT_DIR_CERTIFICATES,
			CERT_OBJECT_CERTIFICATE, serialNb);

		    if (NULL != (fp = fopen(destPath, "a"))) {
			PEM_write_ECPrivateKey(fp, ec_key, 
				NULL, NULL, 0, 0, NULL);
			fclose(fp);
		    } else {
			fprintf(stdout, 
				"%s unable to write ECDSA private key\n", 
				__FUNCTION__);
		    }

		    EC_KEY_free(ec_key);
		    free(destPath);
		    rValue = CERT_OK;
		}

		/* 
		don't need to write EC pub key, just cert
		*/

		rewind(fpIn);
		crl = d2i_X509_CRL_fp(fpIn, NULL);
		if (NULL != crl) {
		    fprintf(stdout, "%s crl read 0x%lX\n", __FUNCTION__, X509_NAME_hash(X509_CRL_get_issuer(crl)));

		    char *certPath;
		    FILE *fp;

		    certPath = serialPathName(baseName, CERT_DIR_CRL,
			    CERT_OBJECT_CRL, serialNb);
		    if (NULL != (fp = fopen(certPath, "w"))) {
			PEM_write_X509_CRL(fp, crl);
			fclose(fp);
			char command[255] = {'\0'};
			sprintf(command, "gzip %s", certPath);
			fprintf(stdout, "%s: command=%s\n", __FUNCTION__, command);
			if (-1 == system(command)) {
			    fprintf(stderr, "ERROR compressing cert file '%s'\n", certPath);
			}
		    }
		    free(certPath);
		    X509_CRL_free(crl);
		    rValue = CERT_OK;
		} else {
		    fprintf(stdout, "%s no crl \n", __FUNCTION__);
		}
	    }
	    free(baseName);
	    fclose(fpIn);
	} else {
	    fprintf(stdout, "%s file access failure \n", __FUNCTION__);
	    rValue = CERT_FILE_ACCESS_FAILURE;
	}

	BIO_free(bio);
    }
    return rValue;	
}
typedef struct PrvPemCallbackStruct {
	CertPassCallback cb;
	void* ctxt;
	char pwdCache[64];
	int32_t haveCache;
} PrvPemCallbackStruct;

int pem_callback(char* buf, int32_t len, int32_t rwflag, void* cb_arg) {
	/* Appears this is supposed to return pwd length */
	PrvPemCallbackStruct* pcs = (PrvPemCallbackStruct*)cb_arg;
	CertReturnCode_t result;

	if (pcs->haveCache) {
		fprintf(stdout, "%s have cache %s \n", __FUNCTION__, pcs->pwdCache);
		snprintf(buf, len, "%s", pcs->pwdCache);
		result = CERT_OK;
	} else if (NULL == pcs->cb) {
		fprintf(stdout, "%s invalid\n", __FUNCTION__);
		result = CERT_INVALID_ARG;
	} else {		
		result = (*pcs->cb)(buf, len, pcs->ctxt);
		fprintf(stdout, "%s password %s %d \n", __FUNCTION__, (char*)pcs->ctxt, result);
	}

	int32_t res = (CERT_OK == result) ? strlen(buf) : 0;

	if (res && !pcs->haveCache) {
		snprintf(pcs->pwdCache, sizeof(pcs->pwdCache), "%s", buf);
		pcs->haveCache = true;
	}

	return res;
}

CertReturnCode_t pemToFile(const char* pCertPath, const char *pDestPath,
		CertPassCallback pcbk, void* pwd_ctxt, int32_t *serial) 
{
    int32_t serialNb = 0;
    int32_t duplicateSerial = 0;
    CertReturnCode_t rValue = CERT_GENERAL_FAILURE;
    BIO *bio;
    X509 *cert;

    if ((rValue = getNextSerialNumber(&serialNb)) != CERT_OK) {
	return rValue;
    } else {
	*serial = serialNb;
    }

    bio = BIO_new(BIO_s_mem());
    if (NULL != bio) {

	PrvPemCallbackStruct pcs;
	pcs.cb = pcbk;
	pcs.ctxt = pwd_ctxt;
	pcs.haveCache = false;

	FILE* fpIn = fopen(pCertPath, "r");

	if (NULL != fpIn) {
	    char *baseName;
	    char *destPath;
	    DSA *dsa = NULL;
	    RSA *rsa = NULL;
	    EC_KEY *ec_key = NULL;
	    X509_CRL *crl = NULL;

	    FILE *fp;

	    baseName = fileBaseName(pCertPath);
	    cert = PEM_read_X509(fpIn, NULL, (pem_password_cb *)pem_callback,
		    NULL);

	    if (NULL != cert) {
		fprintf(stdout, "%s cert found \n", __FUNCTION__);
		char *certPath;
		FILE *fp;

		// see if this is a duplicate.
		if ((duplicateSerial = findSSLCertInLocalStore(cert)) != 0) {
		    *serial = serialNb = duplicateSerial;
		    fprintf(stdout, "%s duplicate cert found %d\n", __FUNCTION__, duplicateSerial);
		}

		certPath = serialPathName(baseName, CERT_DIR_CERTIFICATES,
			CERT_OBJECT_CERTIFICATE, serialNb);
		if (!certPath) {
			fprintf(stdout, "cert path too long in %s:%d\n",
			 __FUNCTION__,__LINE__);
			rValue = CERT_PATH_LIMIT_EXCEEDED;
		}

		else {
		    // success
		    if (NULL != (fp = fopen(certPath, "w"))) {

			PEM_write_X509(fp, cert);
			fclose(fp);
		    }
		    if (duplicateSerial == 0) {
			rValue = CertCreateDatabaseItem(cert, baseName, serialNb, "X");
			fprintf(stdout, "%s item created in db \n", __FUNCTION__);
		    } else {
			rValue = CERT_OK;
		    }
#if 0
		    if (CERT_OK == rValue)
		    {
			char dbPath[MAX_CERT_PATH];

			CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE,
				dbPath, MAX_CERT_PATH);
			rValue = CertWriteDatabase(dbPath);
		    }
#endif
		}
		free(certPath);

	    } else {
		fprintf(stdout, "%s no cert \n", __FUNCTION__);
		rValue = CERT_BAD_CERTIFICATE;
	    }

	    if (NULL != cert) {
		dsa = PEM_read_DSAPrivateKey(fpIn, NULL, pem_callback, &pcs);
		if (NULL != dsa) {
		    fprintf(stdout, "%s DSA private key read \n", __FUNCTION__);
		    destPath = serialPathName(baseName, CERT_DIR_PRIVATE_KEY,
			    CERT_OBJECT_DSA_PRIVATE_KEY, serialNb);
		    if (NULL != (fp = fopen(destPath, "w"))) {
			PEM_write_DSAPrivateKey(fp, dsa, (const EVP_CIPHER *)pcbk,
				NULL, 0, 0, pwd_ctxt);
			fclose(fp);
		    } else {
			fprintf(stdout, "%s unable to write DSA private key\n", __FUNCTION__);
		    }

		    DSA_free(dsa);
		    free(destPath);
		    rValue = CERT_OK;
		}

		rewind(fpIn);
		dsa = PEM_read_DSA_PUBKEY(fpIn, NULL, pem_callback, &pcs);
		if (NULL != dsa) {
		    fprintf(stdout, "%s DSA pubkey read\n", __FUNCTION__);
		    destPath = serialPathName(baseName, CERT_DIR_PUBLIC_KEY,
			    CERT_OBJECT_DSA_PUBLIC_KEY, serialNb);
		    if (NULL != (fp = fopen(destPath, "w"))) {
			PEM_write_DSA_PUBKEY(fp, dsa);
			fclose(fp);
		    } else {
			fprintf(stdout, "%s unable to write DSA pub key\n", __FUNCTION__);
		    }
		    DSA_free(dsa);
		    free(destPath);
		    rValue = CERT_OK;
		}

		rewind(fpIn);
		rsa = PEM_read_RSAPrivateKey(fpIn, NULL, pem_callback, &pcs);
		if (NULL != rsa) {
		    fprintf(stdout, "%s RSA private key read \n", __FUNCTION__);
		    destPath = serialPathName(baseName, CERT_DIR_PRIVATE_KEY,
			    CERT_OBJECT_RSA_PRIVATE_KEY, serialNb);
		    if (NULL != (fp = fopen(destPath, "w"))) {
			int ret = PEM_write_RSAPrivateKey(fp, rsa, (const EVP_CIPHER *)pcbk,
				NULL, 0, 0, pwd_ctxt);
			fprintf(stdout, "%s RSA private key write return = %d\n", __FUNCTION__, ret);
			fclose(fp);
		    } else {
			fprintf(stdout, "%s unable to write RSA private key\n", __FUNCTION__);
		    }

		    RSA_free(rsa);
		    free(destPath);
		    rValue = CERT_OK;
		}

		rewind(fpIn);
		rsa = PEM_read_RSA_PUBKEY(fpIn, NULL, pem_callback, &pcs);
		if (NULL != rsa) {
		    fprintf(stdout, "%s RSA public key read \n", __FUNCTION__);
		    destPath = serialPathName(baseName, CERT_DIR_PUBLIC_KEY,
			    CERT_OBJECT_RSA_PUBLIC_KEY, serialNb);
		    if (NULL != (fp = fopen(destPath, "w"))) {
			PEM_write_RSAPublicKey(fp, rsa);
			fclose(fp);
		    } else {
			fprintf(stdout, "%s unable to write RSA pub key\n", __FUNCTION__);
		    }

		    RSA_free(rsa);
		    free(destPath);
		    rValue = CERT_OK;
		}

		/* ECDSA */
		/* NOTE: we append the private key to the cert because
		 ** WAPI expects that.  The real (secure) way to do this
		 ** is to store the key in keymanager
		 */
		rewind(fpIn);
		ec_key = PEM_read_ECPrivateKey(fpIn, NULL, pem_callback, &pcs);
		if (NULL != ec_key) {
		    fprintf(stdout, 
			    "%s ECDSA private key read \n", __FUNCTION__);
		    /*
		       destPath = serialPathName(baseName, CERT_DIR_PRIVATE_KEY,
		       CERT_OBJECT_DSA_PRIVATE_KEY, serialNb);
		     */

		    destPath = serialPathName(baseName, CERT_DIR_CERTIFICATES,
			    CERT_OBJECT_CERTIFICATE, serialNb);

		    if (NULL != (fp = fopen(destPath, "a"))) {
			PEM_write_ECPrivateKey(fp, ec_key, 
				(const EVP_CIPHER *)pcbk,
				NULL, 0, 0, pwd_ctxt);
			fclose(fp);
		    } else {
			fprintf(stdout, 
				"%s unable to write ECDSA private key\n", 
				__FUNCTION__);
		    }

		    EC_KEY_free(ec_key);
		    free(destPath);
		    rValue = CERT_OK;
		}

		/* 
		   don't need to write EC pub key, just cert
		 */


		rewind(fpIn);
		crl = PEM_read_X509_CRL(fpIn, NULL, NULL, NULL);
		if (NULL != crl) {
		    fprintf(stdout, "%s crl read 0x%lX\n", __FUNCTION__, X509_NAME_hash(X509_CRL_get_issuer(crl)));

		    char *certPath;
		    FILE *fp;

		    certPath = serialPathName(baseName, CERT_DIR_CRL,
			    CERT_OBJECT_CRL, serialNb);

		    fprintf(stdout, "%s certPath %s\n", __FUNCTION__, certPath);

		    if (NULL != (fp = fopen(certPath, "w"))) {
			PEM_write_X509_CRL(fp, crl);
			fclose(fp);
			char command[255] = {'\0'};
			sprintf(command, "gzip %s", certPath);
			fprintf(stdout, "%s: command=%s\n", __FUNCTION__, command);
			if (-1 == system(command)) {
			    fprintf(stderr, "ERROR compressing cert file '%s'\n", certPath);
			}
		    } else {
			fprintf(stdout, "%s failed writing file.\n", __FUNCTION__);
		    }

		    free(certPath);
		    X509_CRL_free(crl);
		    rValue = CERT_OK;
		} else {
		    fprintf(stdout, "%s no crl \n", __FUNCTION__);
		}
	    }
	    free(baseName);
	    fclose(fpIn);
	} else {
	    fprintf(stdout, "%s file access failure \n", __FUNCTION__);
	    rValue = CERT_FILE_ACCESS_FAILURE;
	}

	BIO_free(bio);
    }
    return rValue;
} /* x509ToFile */

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: makePathToCert                                                  */
/* INPUT:                                                                    */
/*       serialNb: the ID of the certificate                                 */
/*       len:  the length of the input buffer                                */
/* OUTPUT:                                                                   */
/*       path: The path for the certificate based on the configuration       */
/* RETURN:                                                                   */
/*       CERT_OK                                                             */
/*       CERT_BUFFER_LIMIT_EXCEEDED: the input buffer is insufficient for the*/
/*           full path                                                       */
/* NOTES:                                                                    */
/*       1) The list of supported file extensions is kept in cert_mgr.h      */
/*                                                                           */
/*--***********************************************************************--*/

CertReturnCode_t makePathToCert(int32_t serialNb, char *path, int32_t len) {
    char dir[MAX_CERT_PATH];
    CertReturnCode_t result;

    result = CertCfgGetObjectStrValue(CERTCFG_CERT_DIR, dir, MAX_CERT_PATH);

    if (CERT_OK == result) {
	char serialStr[16];

	sprintf(serialStr, "%X", serialNb);
	if (len <= (strlen(dir) + strlen(serialStr) + 5)) {
	    result = CERT_BUFFER_LIMIT_EXCEEDED;
	} else {
	    sprintf(path, "%s/%s.pem", dir, serialStr);
	}
    }
    return result;
}

CertReturnCode_t getPEMCertInfoPath(const char *pPath, certMgrField_t field,
	char* buf, int32_t* pBufLen) {
    CertReturnCode_t result = CERT_GENERAL_FAILURE;

    X509* cert = NULL;
    result = CertPemToX509(pPath, &cert);

    if (CERT_OK == result) {
	result = certInfoToBuffer(cert, field, buf, pBufLen);
    }

    if (NULL != cert) {
	X509_free(cert);
    }

    return result;
}

int checkCert(X509 *cert, char *CAFile, char *CAPath);
CertReturnCode_t validateCertPath(const char *path, int32_t serialNb,
	int32_t certType, int32_t *pCMErr) {
    CertReturnCode_t result;
    X509* cert = NULL;

    switch (certType) {
	case CERTTYPE_PEM:
	    result = CertPemToX509(path, &cert);
	    break;

	case CERTTYPE_DER:
	    result = derToX509(path, &cert);
	    break;

	default:
	    result = CERT_UNSUPPORTED_CERT_TYPE;
	    break;
    }

    if (CERT_OK == result) {
	/*
	 * If we get here then we know that the type has been found
	 * we use result to signal that the type has been found, so
	 * use a local result to carry forward errors within the 
	 * certificate
	 */
	CertReturnCode_t lResult;
	char caPath[MAX_CERT_PATH];
	int32_t status = 0;
	//      X509_STORE      *cert_ctx = NULL;

	lResult = CertGetDatabaseInfo(CERT_DATABASE_ITEM_STATUS, &status);
	if (status != (int32_t)statusNames[CERT_STATUS_TRUSTED_PEER]) { /* We trust the certificate per user's blessing, do not invalidate.*/
	    /* TODO: return that the cert is valid. */
	    lResult = checkCertDates(cert);

	    if (lResult != CERT_OK) {
		char dbPath[MAX_CERT_PATH];

		*pCMErr = CERT_CM_ALL_OK;

		if (lResult == CERT_DATE_EXPIRED) {
		    *pCMErr |= CERT_CM_DATE_EXPIRED;
		    result = CertUpdateDatabaseItem(dbPath, serialNb,
			    CERT_DATABASE_ITEM_STATUS,
			    statusNames[CERT_STATUS_EXPIRED]);

		} else if (lResult == CERT_DATE_PENDING) {
		    *pCMErr |= CERT_CM_DATE_PENDING;
		    result = CertUpdateDatabaseItem(dbPath, serialNb,
			    CERT_DATABASE_ITEM_STATUS,
			    statusNames[CERT_STATUS_SUSPENDED]);
		}
	    }
	}

	//      cert_ctx = X509_STORE_new();


	result = CertCfgGetObjectStrValue(CERTCFG_AUTH_CERT_DIR, caPath,
		MAX_CERT_PATH);
	result = checkCert(cert, NULL, caPath);

	// X509_free(cert);
    }

    return result;
}

/* Need to decrypt the damned things and compare them since the same
 * thing encrypted twice will not always be the same. 
 */
int get_key_cb(char *buf, int32_t size, int32_t rwflag, void *userdata) {
    /* userdata is a ptr to the key */
    int32_t wantsSize = snprintf(buf, size, "%s", (const char *)userdata);

    if (wantsSize >= size) {
	wantsSize = 0;
    }

    return wantsSize;
}

#define NUM_KEYS 5
typedef struct PrvCertCmpStruct {
    char *keys[NUM_KEYS];
    long dataLen;
} PrvCertCmpStruct;

CertReturnCode_t readEVPKeys(EVP_PKEY *pkey, PrvCertCmpStruct *cs) {
    DSA* dsa = EVP_PKEY_get1_DSA(pkey);
    if (NULL != dsa) {
	unsigned char* c = NULL;

	if (i2d_DSAPrivateKey(dsa, &c)) {
	    cs->keys[4] = (char *)c;
	}
	DSA_free(dsa);
    }

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (NULL != rsa) {
	unsigned char* c = NULL;

	if (i2d_RSAPrivateKey(rsa, &c)) {
	    cs->keys[1] = (char *)c;
	}
	RSA_free(rsa);
    }

    return true;
} /* readEVPKeys */

CertReturnCode_t readPemKeys(const char *path, PrvCertCmpStruct *cs,
	char *encKey) {
    CertReturnCode_t success= false;
    FILE* fp = fopen(path, "r");

    if (NULL != fp) {
	char *name = NULL;
	char *header = NULL;
	unsigned char *data = NULL;
	long len = 0;

	if (0 != PEM_read(fp, &name, &header, &data, &len)) {
	    OPENSSL_free(name);
	    OPENSSL_free(header);
	    cs->keys[0] = (char *)data;
	    cs->dataLen = len;
	}

	EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, get_key_cb, encKey);

	if (NULL != pkey) {
	    success = readEVPKeys(pkey, cs);
	    EVP_PKEY_free(pkey);
	}

	rewind(fp);
	RSA* rsa = PEM_read_RSA_PUBKEY(fp, NULL, get_key_cb, encKey);
	if (NULL != rsa) {
	    unsigned char* c = NULL;

	    if (i2d_RSAPublicKey(rsa, &c) ) {
		cs->keys[2] = (char *)c;
	    }

	    RSA_free(rsa);
	}

	rewind(fp);
	DSA* dsa = PEM_read_DSA_PUBKEY(fp, NULL, get_key_cb, encKey);
	if (NULL != dsa) {
	    unsigned char* c = NULL;
	    if (i2d_DSAPublicKey(dsa, &c) ) {
		cs->keys[4] = (char *)c;
	    }

	    DSA_free(dsa);
	}

	success = true;
	fclose(fp);
    }
    return success;
} /* readPemKeys */

CertReturnCode_t precompP12Keys(const char* path1, const char* path2,
	PrvCertCmpStruct* cs, char* encKey) {
    CertReturnCode_t success= false;
    FILE* fp1 = fopen(path1, "r");

    if (NULL != fp1) {
	FILE* fp2 = fopen(path2, "r");

	if (NULL != fp2) {
	    PKCS12 *p12_1 = d2i_PKCS12_fp(fp1, NULL);

	    if (NULL != p12_1) {
		PKCS12 *p12_2 = d2i_PKCS12_fp(fp2, NULL);

		if (NULL != p12_2) {
		    EVP_PKEY *pkey1;
		    X509* cert1;

		    if (1 == PKCS12_parse(p12_1, encKey, &pkey1, &cert1, NULL)) {
			EVP_PKEY *pkey2;
			X509* cert2;
			if (1 == PKCS12_parse(p12_2, encKey, &pkey2, &cert2,
				    NULL)) {
			    int32_t same = (0 == X509_cmp(cert1, cert2));

			    if (same) {
				success = readEVPKeys(pkey1, &cs[0])
				    && readEVPKeys(pkey2, &cs[1]);
			    }
			    X509_free(cert2);
			    EVP_PKEY_free(pkey2);
			}
			X509_free(cert1);
			EVP_PKEY_free(pkey1);
		    }

		    PKCS12_free(p12_2);
		}
		PKCS12_free(p12_1);
	    }

	    fclose(fp2);
	}
	fclose(fp1);
    }
    return success;
}

CertReturnCode_t areSameCertFile(const char *path1, const char *path2,
	CertPkgType_t ctype) {
    CertReturnCode_t same= false;
    CertReturnCode_t success;
    int32_t i, j;

    char key[64];

    PrvCertCmpStruct cs[2];
    memset( &cs, 0, sizeof(cs));

    switch (ctype) {
	case CERTTYPE_PEM:
	    success = readPemKeys(path1, &cs[0], key) && readPemKeys(path2, &cs[1],
		    key);
	    break;

	case CERTTYPE_P12:
	    success = precompP12Keys(path1, path2, &cs[0], key);
	    break;
	default:
	    success = false;
    }

    if (success) {
	same = true;

	for (i = 0; same && i < NUM_KEYS; ++i) {
	    if (NULL != cs[0].keys[i] && NULL != cs[1].keys[i]) {
		if (i == 0) { /* not null-terminated */
		    if ( (cs[0].dataLen != cs[1].dataLen) || 0 != memcmp(
				cs[0].keys[0], cs[1].keys[0], cs[0].dataLen) ) {
			same = false;
		    }
		} else {
		    if ( 0 != strcmp(cs[0].keys[i], cs[1].keys[i]) ) {
			same = false;
		    }
		}
	    } else if (cs[0].keys[i] != cs[1].keys[i]) {
		same = false;
	    }
	}

	for (j = 0; j < 2; ++j) {
	    for (i = 0; i < NUM_KEYS; ++i) {
		char* s = cs[j].keys[i];
		if (NULL != s) {
		    OPENSSL_free(s);
		}
	    }
	}
    }

    return same;
} /* areSameCertFile */

/* turn foo.ext into foo_00.ext, and foo_00.ext into foo_01.ext.  This
 * is a hack, but I don't see any utilities doing it for me. 
 */
void makeUnique(char *path) {
    while (exists(path)) {
	char buf[MAX_CERT_PATH];
	int32_t count = 0;

	snprintf(buf, sizeof(buf), "%s", path);

	char* ubar = strrchr(buf, '_');
	char* dot = strrchr(buf, '.');
	if (NULL == dot) {
	    dot = buf + strlen(buf);
	}
	if ( (NULL == ubar) || (ubar + 3 != dot)) {
	    /* Not our pattern.  Append the _nn */
	    ubar = dot;
	} else {
	    count = 1 + atoi(ubar+1);
	}

	snprintf(ubar, sizeof(buf) - (ubar - buf), "_%.2d%s", count, strrchr(
		    path, '.') );
	strcpy(path, buf);
    }
} /* makeUnique */

#if D_DEBUG_ENABLED
    static void
logSSLErrors()
{
    // we'll get this error if bad passwd: PEM_F_PEM_DO_HEADER ???
    for (;; )
    {
	unsigned long sslerr = ERR_get_error();
	if ( 0 == sslerr )
	{
	    break;
	}
	else
	{
	    /* Ok to call these multiple times: they're only loaded once
	       internally. */
	    ERR_load_CRYPTO_strings();
	    ERR_load_SSL_strings();

	    char buf[512];
	    ERR_error_string_n( sslerr, buf, sizeof(buf) );

	}
    }
} /* logSSLErrors */
#endif
/*--**************************************************************************
 * helper functions
 **************************************************************************--*/

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: seed_prng                                                       */
/*       Seed the pseudo-random number generator                             */
/* INPUT:                                                                    */
/*       file: the file name                                                 */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*                                                                           */
/* NOTES:                                                                    */
/*                                                                           */
/*--***********************************************************************--*/

int32_t seed_prng(void) {
    /* Warning: /dev/random blocks if not enough entropy is available
       (which is almost always the case).  If this is happening, try
       /dev/urandom, or save seeds across boots. */
    int32_t result = RAND_load_file("/dev/urandom", 1024);
    assert(result);

    return result;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: exists                                                          */
/*       Check to see if the given file exists                               */
/* INPUT:                                                                    */
/*       file: the file name                                                 */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       false (== 0): the file does not exist                               */
/*                                                                           */
/* NOTES:                                                                    */
/*                                                                           */
/*--***********************************************************************--*/

int exists(const char *file) {
    struct stat buf;
    int32_t err = stat(file, &buf);
    return err == 0;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: existsIn                                                        */
/*       Check to see if the given file exists in the given directory        */
/* INPUT:                                                                    */
/*       file: the given file name                                           */
/*       dir:  the directory to check                                        */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       false (== 0): the file does not exist in the directory              */
/* NOTES:                                                                    */
/*                                                                           */
/*--***********************************************************************--*/

int32_t existsIn(const char *file, const char *dir) {
    struct stat buf;
    int32_t err;

    err = stat(file, &buf);
    return err == 0;
}

/*--***********************************************************************--*/
/*                                                                           */
/* FUNCTION: certInfoToBuffer DEPRECATED for CertX509ReadStrProperty         */
/*        Copy the requested information to a user allocated buffer          */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*--***********************************************************************--*/

CertReturnCode_t certInfoToBuffer(X509 *cert, certMgrField_t field, char *pBuf,
	int32_t *pBufLen) {

    int result = CERT_OK;
    switch(field) {	
	case CERT_INFO_ISSUED_TO:
	    result = CertX509ReadStrProperty(cert, CERTX509_SUBJECT_ORGANIZATION_NAME, pBuf, *pBufLen);
	    break;
	case CERT_INFO_ISSUED_BY:
	    result = CertX509ReadStrProperty(cert, CERTX509_ISSUER_ORGANIZATION_NAME, pBuf, *pBufLen);
	    break;
	case CERT_INFO_START_DATE:
	    result = CertX509ReadTimeProperty(cert, CERTX509_START_DATE, pBuf, *pBufLen);
	    break;
	case CERT_INFO_EXPIRATION_DATE:
	    result = CertX509ReadTimeProperty(cert, CERTX509_EXPIRATION_DATE, pBuf, *pBufLen);
	    break;
	case CERT_INFO_MAX_PROPERTY:
	    *pBufLen = 0;
	    break;
    }

    return result;
} /* certInfoToBuffer */

int findSSLCertInLocalStore(X509 * cert)
{
    if (cert == NULL)
	return 0;

    int items=0;
    //	SSL_library_init();
    //	SSL_load_error_strings();
    CertReturnCode_t result = CertGetDatabaseInfo(CERT_DATABASE_SIZE, &items);
    if (result == CERT_OK) {
	int i = 0;
	for (i = 0; i < items; i++) {
	    char serialStr[128] = { '\0' };
	    result = CertGetDatabaseStrValue(i, CERT_DATABASE_ITEM_SERIAL,
		    serialStr, 128);
	    if (CERT_OK == result) {
		char dir[MAX_CERT_PATH];
		char * endPtr = NULL;
		int serial = strtol(serialStr, &endPtr, 16);
		result = makePathToCert(serial, dir, MAX_CERT_PATH);
		if (CERT_OK == result) {
		    X509 *candidate_cert = NULL;
		    result = CertPemToX509(dir, &candidate_cert);
		    if (candidate_cert == NULL)
			continue;
		    if (result == CERT_OK) {
			//DO COMPARISON
			if (X509_cmp(candidate_cert,cert) == 0) {
			    return serial;
			}
		    }
		}
	    }
	}
    }
    return 0;
}




