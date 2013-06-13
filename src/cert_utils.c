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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <errno.h>
#include <libgen.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>

#include "cert_mgr.h"
#include "cert_utils.h"
#include "cert_cfg.h"

#include "cert_mgr_prv.h"
#include "cert_debug.h"

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: gettimeString                                                   */
/*       */
/* INPUT:                                                                    */
/*       */
/* OUTPUT:                                                                   */
/*       */
/*       */
/*       */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

int getTimeString(ASN1_TIME *time_data, char *buf, int buflen)
{
  int result;
  BIO* bio = BIO_new(BIO_s_mem());
  
  if (NULL == bio)
    {
      result = CERT_MEMORY_ERROR;
    }
  else
    {
      BUF_MEM *bufmem;
      
      ASN1_TIME_print(bio, time_data);
      BIO_get_mem_ptr(bio, &bufmem); /* is this allocating? */
      
      if (NULL == buf)
        {
          result = CERT_NULL_BUFFER;
        }
      else if (bufmem->length >= buflen)
        {
          
          result = CERT_BUFFER_LIMIT_EXCEEDED;
        }
      else
        {
          memcpy(buf, bufmem->data, bufmem->length);
          buf[bufmem->length] = 0;
          result = CERT_OK;
        }
      BIO_free( bio );
    }
  return result;
} /* getTimeString */

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: checkCertDates                                                  */
/*       Check whether or not the certificate in its valid period of time    */
/* INPUT:                                                                    */
/*       cert: the X.509 certificate in question in memory                   */
/* OUTPUT:                                                                   */
/*       CERT_OK: The certificate is within the valid range of dates         */
/*       CERT_DATE_PENDING: It's too early for the certificate's use         */
/*       CERT_DATE_EXPIRED: It's too late for the certificate's use          */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

int checkCertDates(X509 *cert)
{
  time_t now = time(NULL);
  ASN1_STRING *date;

  date = X509_get_notBefore(cert);

  if (X509_cmp_time(date, &now) > 0)
    {
      return CERT_DATE_PENDING;
    }
    
  date = X509_get_notAfter(cert);

  if (X509_cmp_time (date, &now) < 0)
    {
      return CERT_DATE_EXPIRED;
    }

  return CERT_OK;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION*: CertGetSerialNumber                                            */
/*       Read the current serial number from the file                        */
/* INPUT:                                                                    */
/*       path: The serial number file                                        */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       The value in the serial number file                                 */
/* NOTES:                                                                    */
/*       1) The serial number file is resolved through the configuration file*/
/*          There may be several serial number files depending on what is    */
/*          kept track of.  The default for SSL is serial in the default dir.*/
/*          That file keeps track of the certificates issued from that       */
/*          location.                                                        */
/*       2) The algorithm is quite simple and should be forgiving when open- */
/*          ing the wrong file.  0 is considered an error                    */
/*       3) The serial number file must be protected around this call        */
/*                                                                           */
/*****************************************************************************/

int CertGetSerialNumber(char *path)
{
  int fd;
  char inBuf[MAX_CERT_PATH];
  int rValue;
  
  if (0 > (fd = open(path, O_RDONLY)))
    return CERT_FILE_ACCESS_FAILURE;

  rValue = read(fd, inBuf, MAX_CERT_PATH);
  inBuf[rValue] = '\0';

  sscanf(inBuf, "%x", &rValue);
  return rValue;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION*: CertGetSerialNumberInc                                         */
/*       Read the current serial number from the file and change the number  */
/*       by the given amount.                                                */
/* INPUT:                                                                    */
/*       path: The serial number file                                        */
/*       increment: added to the serial number and stored into the file      */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) The serial number file is resolved through the configuration file*/
/*          There may be several serial number files depending on what is    */
/*          kept track of.  The default for SSL is serial in the default dir.*/
/*          That file keeps track of the certificates issued from that       */
/*          location.                                                        */
/*       2) The algorithm is quite simple and should be forgiving when open- */
/*          ing the wrong file.  0 is considered an error                    */
/*       3) The increment value may be negative to allow for resetting the   */
/*          serial number file in case of an error                           */
/*       4) The serial number file must be protected around this call        */
/*                                                                           */
/*****************************************************************************/

int CertGetSerialNumberInc(char *path, int increment)
{
  int fd;
  char inBuf[MAX_CERT_PATH];
  int rValue, serial;

  fd = open(path, O_RDWR);

  rValue = read(fd, inBuf, sizeof(inBuf));
  if (rValue < 0)
    fprintf(stderr, "Error %d reading certificate serial number\n", errno);
  sscanf(inBuf, "%x", &serial);

  if (serial)
    {
      printf("Serial is currently %d\n", serial);
      lseek(fd, 0, SEEK_SET);
      sprintf(inBuf, "%X ", serial + increment);
	  if (ftruncate(fd, 0)) {
		  fprintf(stderr, "Error %d truncating %s\n", errno, path);
	  }
	  if (4 != write(fd, inBuf, 4)) {
		fprintf(stderr, "Error %d writing to %s\n", errno, path);
	  }
    }
  close(fd);

  return serial;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertInitLockFiles                                              */
/*       Initialize the lock file for serializing data access.  It's crude,  */
/*       but should be sufficient                                            */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) Initialization must be done after the configuration file is read */
/*       2) I could have harmonized the certificate error codes with those   */
/*          passed by lock, but it's too much work.                          */
/*       3) TODO: Make the lock file a variable so we can change it          */
/*       4) TODO: The lock file name and its descriptor should be part of the*/
/*          configuration object                                             */
/*                                                                           */
/*****************************************************************************/


int cert_LockFile_d;

int CertInitLockFiles(char *rootPath)
{
  int result;
  int fd;
  char lockfile[64];

  /* we may need finer grain than one, but for now */
  sprintf(lockfile, "%s/.lock", rootPath);
  
  if (-1 == (fd = open(lockfile, O_CREAT | O_WRONLY | O_TRUNC, 0700)))
    {
#ifdef D_DEBUG_ENABLED
      int errorNb = errno;
#endif
      PRINT_ERROR2("Can't open lockfile", errorNb);
      PRINT_ERROR2(lockfile, 0);
      result = CERT_UNDEFINED_DESTINATION;
      PRINT_RETURN_CODE(result);
    }
  else
    {
      cert_LockFile_d = fd;
      result = CERT_OK;
    }

  /* This won't work if the process closed stdin */
  return result;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertLockFile                                                   */
/*       Lock access to the database                                         */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) This is an internal function, but should it be needed at some    */
/*          future point we can add a finer tuned locking mechanism.         */
/*                                                                           */
/*****************************************************************************/

int CertLockFile(int fileType)
{
  int rValue = 0;
  int lockstate;

  if (-1 == (lockstate = lockf(cert_LockFile_d, F_TLOCK, 0)))
    {
      rValue = errno;
      perror("cert_LockFile");
    }

  return rValue;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertUnlockFile                                                  */
/*       Unlock access to the files                                          */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) This is an internal function, but should it be needed at some    */
/*          future point we can add a finer tuned locking mechanism.         */
/*                                                                           */
/*****************************************************************************/

int CertUnlockFile(int fileType)
{
  int rValue = 0;
  int lockstate;

  if (-1 == (lockstate = lockf(cert_LockFile_d, F_ULOCK, 0)))
    {
      rValue = errno;
      perror("cert_LockFile");
    }

  return rValue;
}

const char *objectFileName[] =
{
  "rsa",   // CERT_OBJECT_RSA_PRIVATE
  "rsa",   // CERT_OBJECT_RSA_PUBLIC
  "dsa",   // CERT_OBJECT_DSA_PRIVATE
  "dsa",   // CERT_OBJECT_DSA_PUBLIC
  "dh",    // CERT_OBJECT_DH_PARAMETERS
  "ec",	   // CERT_OBJECT_EC_PRIVATE_KEY
  "",      // CERT_OBJECT_CERTIFICATE
  "req",   // CERT_OBJECT_REQUEST
  "crl",   // CERT_OBJECT_CRL
  "ca"     // CERT_OBJECT_C_AUTHORIZATION
};

const char *objectFileExt[] =
{
  "pem",
  "pem",
  "pem",
  "pem",
  "pem",
  "pem",
  "pem",
  "pem",
  "pem",
  "pem"
};

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: buildPath                                                       */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) objectFileName must be kept coordinated with CertObject_t as     */
/*          defined in cert_mgr.h                                            */
/*       2) objectFileExt must be kept coordinated with CertObject_t as      */
/*          defined in cert_mgr.h                                            */
/*                                                                           */
/*****************************************************************************/

char *buildPath(int destDirType, int objectType)
{
  char *result = 0;
  
  switch (destDirType)
    {
#if 0
      if (CERT_OK ==
          (rValue = CertCfgGetObjectStrValue(CERTCFG_CERT_SERIAL_NAME,
                                              serialFile,
                                              MAX_CERT_PATH)))
        {}
#endif
    }
      return result;
}
/*****************************************************************************/
/*                                                                           */
/* FUNCTION: serialPathName                                                  */
/*       Create a proper path and file name for the object type              */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) objectFileName must be kept coordinated with CertObject_t as     */
/*          defined in cert_mgr.h                                            */
/*       2) objectFileExt must be kept coordinated with CertObject_t as      */
/*          defined in cert_mgr.h                                            */
/*       3) The extension for the hashed CA file is hardcoded                */
/*                                                                           */
/*****************************************************************************/
char *serialPathName(char *baseName, int destDirType, CertObject_t objectType,
		int serial) {
	return serialPathNameCount(baseName, destDirType, objectType, serial, 0);
}

char *serialPathNameCount(char *baseName, int destDirType, 
	CertObject_t objectType, int serial, int count) 
{
	char fullPath[64];
	char dir[64];
	char serialStr[64];
	char *rDest = NULL;
	int rValue;
	int cfgTag = CERTCFG_MAX_PROPERTY;

	/* Do this so that we can calculate the entire length */
	sprintf(serialStr, "%X", serial);
	switch (destDirType) {
	case CERT_DIR_PRIVATE_KEY:
		cfgTag = CERTCFG_PRIVATE_KEY_DIR;
		break;

	case CERT_DIR_PUBLIC_KEY:
		cfgTag = CERTCFG_PUBLIC_KEY_DIR;
		break;

	case CERT_DIR_CRL:
		cfgTag = CERTCFG_CRL_DIR;
		break;

	case CERT_DIR_CERTIFICATES:
		cfgTag = CERTCFG_CERT_DIR;
		break;

	case CERT_DIR_PACKAGES:
		cfgTag = CERTCFG_PACKAGE_DIR;
		break;

	case CERT_DIR_AUTHORIZED:
	default:
		cfgTag = CERTCFG_MAX_PROPERTY;
		break;

	}

	if (CERT_OK == (rValue = CertCfgGetObjectStrValue(cfgTag, dir,
			MAX_CERT_PATH))) {
		if (MAX_CERT_PATH >= (strlen(baseName) + 1 + 
				strlen(dir) + 1	+ 
				strlen(objectFileName[objectType]) + 1 + 
				strlen(serialStr) + 1 + 
				strlen(objectFileExt[objectType]) + 1)) {
			
			if(count == 0) {
				sprintf(fullPath, "%s/%s%s.%s", dir, objectFileName[objectType],
					serialStr, objectFileExt[objectType]);
			} else {
				sprintf(fullPath, "%s/%s%s_%d.%s", dir, objectFileName[objectType],
								serialStr, count-1, objectFileExt[objectType]);
			}

			/* Let's check to see if we've already installed this certificate */
//			if(CERT_OBJECT_C_AUTHORIZATION == objectType) {
//				int32_t counter = 0;
//				for (counter = 0; counter < CERT_MAX_HASHED_FILES; ++counter) {
//					if (exists(fullPath)) {
//						memset(fullPath, 0, sizeof(fullPath));
//						sprintf(fullPath, "%s/%s%s_%d.%s", dir, objectFileName[objectType],
//											serialStr, counter, objectFileExt[objectType]);
//					} else {
//						break;
//					}
//				}
//			}

			rDest = (char *)malloc(strlen(fullPath) + 1);

			// only do copy if path was short enough:
			strcpy(rDest, fullPath);
		}
	}
	return rDest;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: fileBaseName                                                    */
/*       Given a path name return the final file without an extension        */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) We chop off the extension first to allow for "." and "..".       */
/*          basename() should take care of the rest                          */
/*                                                                           */
/*****************************************************************************/

char *fileBaseName(const char *pPath)
{
	char * name;
  char *basePtr;
  char *base = (char *)malloc(strlen(pPath) + 1);

  strcpy(base, pPath);
  
  if (0 != (basePtr = strrchr((const char *)base, '.')))
    basePtr[0] = 0;
  
  name = basename(base);
  strcpy(base, name);
  
  return base;
  
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: getPrivKeyType                                                  */
/*       Check the key type and translate it into a type that the certificate*/
/*       manager understands                                                 */
/* INPUT:                                                                    */
/*       pkey: a pointer to an EVP private key structure                     */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_RSA_PRIVATE_KEY:                                               */
/* NOTES:                                                                    */
/*       1) I can't believe that SSL didn't have an interegator for this,    */
/*          everything seems so OO.  But according to                        */
/*          _Network_Security_with_OpenSSL_, 1st ed. pg 282 para 4, derefer- */
/*          rencing the structure itself must be done.                       */
/*                                                                           */
/*****************************************************************************/

int getPrivKeyType(EVP_PKEY *pkey)
{
  int rValue = CERT_OBJECT_MAX_OBJECT;
  
  switch (EVP_PKEY_type(pkey->type))
    {
    case EVP_PKEY_RSA:
      rValue = CERT_OBJECT_RSA_PRIVATE_KEY;
      break;
      
    case EVP_PKEY_DSA:
      rValue = CERT_OBJECT_DSA_PRIVATE_KEY;
      break;
    case EVP_PKEY_EC:
      rValue = CERT_OBJECT_EC_PRIVATE_KEY;
      break;
    }
  
  return rValue;
}



CertReturnCode_t makePath(char *file,
                          certcfg_Property_t fileType,
                          char* path, int32_t len)
{
  char rootPath[MAX_CERT_PATH];
  char targPath[MAX_CERT_PATH];
  int target;
  int targetLen = 0;
  int fileLen   = 0;
  int rootLen   = 0;
  CertReturnCode_t result;

  fileLen = strlen(file);
  result = CertCfgGetObjectStrValue(CERTCFG_ROOT_DIR, rootPath, MAX_CERT_PATH);
  if (CERT_OK != result)
    return result;

  rootLen = strlen(rootPath);

  switch (fileType)
    {
    case CERTCFG_CONFIG_FILE:
    case CERTCFG_CERT_DATABASE:
    case CERTCFG_CERT_SERIAL_NAME:
      target = 0;
      break;

    case CERTCFG_CERTIFICATE:
      target = CERTCFG_CERT_DIR;
      break;

    case CERTCFG_PRIVATE_KEY:
      target = CERTCFG_PRIVATE_KEY_DIR;
      break;

    case CERTCFG_CRL_DIR:
    	target = CERTCFG_CRL_DIR;
    	break;
    	
    case CERTCFG_CONFIG_NAME:
    case CERTCFG_ROOT_DIR:
    case CERTCFG_CERT_DIR:
    case CERTCFG_PRIVATE_KEY_DIR:
    case CERTCFG_CERT_SERIAL:
    case CERTCFG_PUBLIC_KEY_DIR:
    case CERTCFG_PACKAGE_DIR:
    case CERTCFG_AUTH_CERT_DIR:
      target = 0;
      result = CERT_PROPERTY_NOT_FOUND;
      break;

    default:
      target = 0;
      result = CERT_UNKNOWN_PROPERTY;
    }
  /* 
   * Currently this is a redundant test,
   * but it is left for as a prophylactic
   * should the code within the switch change
   */
  if (CERT_OK == result)
    {
      if (0 != target)
        {
          result = CertCfgGetObjectStrValue(target, targPath, MAX_CERT_PATH);
          if (CERT_OK == result)
            {
              targetLen = strlen(targPath);
              if (MAX_CERT_PATH >= (targetLen + fileLen + rootLen + 1))
                return CERT_BUFFER_LIMIT_EXCEEDED;
              
              sprintf(path, "%s/%s/%s", rootPath, targPath, file);
            }
        }
      else
        {
          if (MAX_CERT_PATH >= (fileLen + rootLen + 1))
            return CERT_BUFFER_LIMIT_EXCEEDED;
          
          sprintf(path, "%s/%s", rootPath, file);
        }
    }

  return result;
}

CertReturnCode_t certSerialNumberToFileName(const int32_t serialNb,
                                            char *buf,
                                            int32_t bufLen)
{
  CertReturnCode_t result;
  char certDir[MAX_CERT_PATH];
  

  result = CertCfgGetObjectStrValue(CERTCFG_AUTH_CERT_DIR,
                                    certDir, MAX_CERT_PATH);
  if (result != CERT_OK)
    fprintf(stderr, "Error %d getting certificate value\n", errno);

  sprintf(buf, "%s/%X.pem", certDir, serialNb);

  return CERT_OK;
}
