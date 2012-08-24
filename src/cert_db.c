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

/* cert_db.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/txt_db.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>



#include "cert_mgr.h"
#include "cert_cfg.h"

#include "cert_utils.h"
#include "cert_db.h"
#include "cert_debug.h"

/* workaround for missing OPENSSL_PSTRING type in openssl-0.9.8k
 * TODO: remove when support for openssl-0.9.8k not needed (>openssl-1.0.0i used) 
 */
#ifndef sk_OPENSSL_PSTRING_num
#  define sk_OPENSSL_PSTRING_num sk_num
#endif
#ifndef sk_OPENSSL_PSTRING_value
#  define sk_OPENSSL_PSTRING_value sk_value
#endif

int CertLockFile(int fileType);
int CertUnlockFile(int fileType);

#ifndef W_OK
#  define F_OK 0
#  define X_OK 1
#  define W_OK 2
#  define R_OK 4
#endif

#undef PROG
#define PROG ca_main

#define BASE_SECTION  "ca"
#define CONFIG_FILE "openssl.cnf"
#define ENV_DEFAULT_CA		"default_ca"

#define STRING_MASK	"string_mask"
#define UTF8_IN			"utf8"


/* Additional revocation information types */

#define REV_NONE            0   /* No addditional information        */
#define REV_CRL_REASON      1   /* Value is CRL reason code          */
#define REV_HOLD            2   /* Value is hold instruction         */
#define REV_KEY_COMPROMISE  3   /* Value is cert key compromise time */
#define REV_CA_COMPROMISE   4   /* Value is CA key compromise time   */

const char *statusNames[] = 
  {
    "x", "c", "C", "E", "p", "P", "R",
    "S", "T", "V", "u", "w", "X"
  };

char statusValues[] = 
  {
    'x', 'c', 'C', 'E', 'p', 'P', 'R', 'S', 'T', 'V', 'u', 'w', 'X'
  };

/*****************************************************************************/
/*                                                                           */
/* FUNCTION:                                                                 */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/


CertReturnCode_t CertUpdateDatabase(void);


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertLockDatabase                                                */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CA_DB *clocaldb = NULL;
DB_ATTR db_attr;
int32_t __DbLocked = 1;  /* the database is initially locked */
int32_t __DbInitialized = 0;
static int32_t userID;

CA_DB *CertLockDatabase(int32_t user)
{
  if (__DbLocked++ || (clocaldb == NULL))
    {
      __DbLocked--;
      return (CA_DB *)0;
    }

  userID = user;
  return clocaldb;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertUnlockDatabase                                              */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

int32_t CertUnlockDatabase(void)
{
  return --__DbLocked;
}



/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertInitDatabase                                                */
/*       Initial reading of the database                                     */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode_t CertInitDatabase(char *dbName)
{
  CA_DB *db;
  struct stat statBuf;
  CertReturnCode_t result = CERT_OK;

  if (0 != __DbInitialized)
    {
      return CERT_DATABASE_LOCKED;
    }
  if (-1 == stat(dbName, &statBuf))
    {
      return CERT_FILE_ACCESS_FAILURE;
    }
  if (0 == __DbLocked)
    {
      return CERT_DATABASE_NOT_AVAILABLE;
    }
  
  if (0 == (CertLockFile(CERT_DATABASE_LOCK)))
    {
      db = load_index(dbName, &db_attr);
      if (db == NULL)
        {
          result = CERT_FILE_ACCESS_FAILURE;
        }
      else
        {
          clocaldb = db;
        }
      CertUnlockFile(CERT_DATABASE_LOCK);
    }
  else
    {
      result = CERT_LOCK_FILE_LOCKED;
      PRINT_RETURN_CODE(result);
    }
  
  /* Unlock the database in the grossest manner */
  __DbInitialized = 1;
  __DbLocked      = 0;
  
  PRINT_RETURN_CODE(result);
  return result;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertReadDatabase                                                */
/*       Initial reading of the database                                     */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/*      CERT_OK                                                              */
/*      CERT_DATABASE_INITIALIZATION_ERROR: The database was never init'ed   */
/*      CERT_FILE_ACCESS_FAILURE: The database file could not be accessed    */
/*      CERT_LOCKED_FILE_LOCKED: The database lockfile is unavailable        */
/* NOTES:                                                                    */
/*      1) Check to see if load_index() doesn't create a memory leak         */
/*                                                                           */
/*****************************************************************************/

CertReturnCode_t CertReadDatabase(char *dbName)
{
  CA_DB *db;
  struct stat statBuf;
  CertReturnCode_t result = CERT_OK;

  if (0 == __DbInitialized)
    {
      return CERT_DATABASE_INITIALIZATION_ERROR;
    }
  if (-1 == stat(dbName, &statBuf))
    {
      return CERT_FILE_ACCESS_FAILURE;
    }
  
  if (0 == (CertLockFile(CERT_DATABASE_LOCK)))
    {
      db = load_index(dbName, &db_attr);
      if (db == NULL)
        {
          result = CERT_FILE_ACCESS_FAILURE;
        }
      else
        {
          clocaldb = db;
        }
      CertUnlockFile(CERT_DATABASE_LOCK);
    }
  else
    {
      result = CERT_LOCK_FILE_LOCKED;
      PRINT_RETURN_CODE(result);
    }
  
  PRINT_RETURN_CODE(result);
  return result;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertWriteDatabase                                               */
/* INPUT:                                                                    */
/*       dbName: The database file itself                                    */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_DATABASE_NOT_AVAILABLE: The database could not be opened       */
/*       CERT_LOCK_FILE_LOCKED: The database lock could not be aquired       */
/*       CERT_NULL_BUFFER: Trying to save a database without a name          */
/* NOTES:                                                                    */
/*       1) The rather arcane splitting off of the extension is needed       */
/*          because there is an attribute file saved along with the database */
/*                                                                           */
/*****************************************************************************/

CertReturnCode_t CertWriteDatabase(char *dbName)
{
  CA_DB *db;
  CertReturnCode_t result = CERT_OK;
  
  if (NULL == dbName)
    {
      return CERT_NULL_BUFFER;
    }
  
  if (0 == (CertLockFile(CERT_DATABASE_LOCK)))
    {
      char basename[MAX_CERT_PATH];
      char suffix[64];
      char *suffixp;
        
      if (NULL != (suffixp = strrchr(dbName, '.')))
        {
          suffixp++;
          strcpy(suffix, suffixp);
        }
      if (suffixp && ((suffixp - dbName) < strlen(dbName)))
        {
          strncpy(basename, dbName, (suffixp - dbName) - 1);
          basename[(suffixp - dbName) - 1] = '\0';
        }
      if (NULL != (db = CertLockDatabase(2)))
        {
          save_index(basename, suffix, db);
          CertUnlockDatabase();
        }
      else
        {
          result = CERT_DATABASE_NOT_AVAILABLE;
        }
      CertUnlockFile(CERT_DATABASE_LOCK);
    }
  else
    {
      result = CERT_LOCK_FILE_LOCKED;
    }
  return result;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertGetDatabaseInfo                                             */
/*       Get information on the database itself                              */
/* INPUT:                                                                    */
/*       dbName: The property of interest                                    */
/* OUTPUT:                                                                   */
/*       value: The value of the property expressed as a 32 bit int          */
/* RETURN:                                                                   */
/*       CERT_PROPERTY_NOT_FOUND: the property exists, but isn't available   */
/*       CERT_UNKNOWN_PROPERTY: the property itself doesn't exist            */
/*       CERT_DATABASE_NOT_AVAILABLE: the database could not be locked       */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode_t CertGetDatabaseInfo(int32_t property, int32_t *value)
{
  CertReturnCode_t result = CERT_OK;
  CA_DB *db;

  if (NULL != (db = CertLockDatabase(3)))
    {
      switch (property)
        {
        case CERT_DATABASE_SIZE:
           *value = sk_OPENSSL_PSTRING_num(db->db->data);
           if (0 > *value)
             result = CERT_PROPERTY_NOT_FOUND;
           break;

        default:
          result = CERT_UNKNOWN_PROPERTY;
          break;
        }
      CertUnlockDatabase();
    }
  else
    {
      result = CERT_DATABASE_NOT_AVAILABLE;
    }
  return result;     
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertGetDatabaseStrValue                                         */
/*       Return information stored in the database in a string               */
/* INPUT:                                                                    */
/*       index: the key for the desired certificate                          */
/*       property: the name of the information requested                     */
/*       len:  the length of the buffer passed into the function             */
/* OUTPUT:                                                                   */
/*       propertyStr: the value of the property                              */
/* RETURN:                                                                   */
/*       CERT_DATABASE_LOCKED: The database is currently being used elsewhere*/
/*       CERT_DATABASE_OUT_OF_BOUNDS: Attempting to look outside of the      */
/*          database's range.                                                */
/*       CERT_BUFFER_LIMIT_EXCEEDED: the requested property doesn't fit the  */
/*          buffer passed in                                                 */
/*       CERT_UNKNOWN_PROPERTY: The property passed in is not supported      */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode_t CertGetDatabaseStrValue(int32_t index,
                            CertDbItemProperty_t property,
                            char *propertyStr, int32_t len)
{
  const char **pp;
  CertReturnCode_t result = CERT_OK;
  CA_DB *db;


  if (NULL != (db = CertLockDatabase(4)))
    {
      if ((int32_t)sk_OPENSSL_PSTRING_num(db->db->data) < index)
        {
          result = CERT_DATABASE_OUT_OF_BOUNDS;
        }
      else
        {
          pp = (const char **)sk_OPENSSL_PSTRING_value(db->db->data, index);
          switch (property)
            {
            case CERT_DATABASE_ITEM_STATUS:
            case CERT_DATABASE_ITEM_EXPIRATION:
            case CERT_DATABASE_ITEM_START:
            case CERT_DATABASE_ITEM_SERIAL:
            case CERT_DATABASE_ITEM_FILE:
            case CERT_DATABASE_ITEM_NAME:
              if (len < strlen(pp[property]))
                {
                  result = CERT_BUFFER_LIMIT_EXCEEDED;
                }
              else
                {
                  if (!strlen(pp[property]))
                    {
                      propertyStr[0] = '\0';
                    }
                  else
                    {
                      strncpy(propertyStr,
                              pp[property],
                              strlen(pp[property]) + 1);
                    }
                }
              break;

            default:
              result = CERT_UNKNOWN_PROPERTY;
              break;
            }
        }
      CertUnlockDatabase();
    }
  else
    {
      result = CERT_DATABASE_LOCKED;
    }
  return result;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION:CertCreateDatabaseItem                                           */
/*       Something wicked this way comes                                     */
/*       Put a new item into the database                                    */
/* INPUT:                                                                    */
/*       x509: The database revolves around certificates                     */
/*       name: The name of the database file                                 */
/*       serial: The serial number for the certificate                       */
/*       value:  The status value                                            */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*       1) Lots of allocations here, so we rely on a common error area to   */
/*          free what's needed to be freed                                   */
/*       2) Check to make sure there's no memory leak here                   */
/*       3) Move the status strings to an enum                               */
/*       4) I think that the error recovery is a bit baroque.  Look into an  */
/*          alternative one.                                                 */
/*                                                                           */
/*****************************************************************************/
char *newMem(const void *data, int32_t len)
{
  char *nBuf;
  
  nBuf = (void *)malloc(len + 1);
  if (NULL == nBuf)
    return 0;

  memcpy(nBuf, data, len);
  nBuf[len] = 0;
  return nBuf;
}

CertReturnCode_t CertCreateDatabaseItem(X509 *x509, char *name, int32_t serial, const char *value)
{
  CertReturnCode_t result;
  int32_t i;
  char *row[CERT_DATABASE_ITEM_MAX];
  char **rrow;
  char **irow;
  ASN1_UTCTIME *Ansitm = NULL;
  CA_DB *db;
  char serialStr[64];
  char dbPath[MAX_CERT_PATH];
  
  if (NULL == value)
    return CERT_NULL_BUFFER;

  result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE,
                                    dbPath, MAX_CERT_PATH);
  if (CERT_OK != result)
    return result;

  result = CertReadDatabase(dbPath);
  if (CERT_OK != result)
    return result;

  for (i = 0; i < CERT_DATABASE_ITEM_MAX; i++)
    row[i] = NULL;

  if (NULL != (db = CertLockDatabase(5)))
    {
      /* Look for to see if the corresponding serial number exists */
      
      rrow = TXT_DB_get_by_index(db->db,
                                 CERT_DATABASE_ITEM_SERIAL,
                                 row);
      
      /* here we're looking at something brand new, so we can add it  */
      if (rrow == NULL)
        {
          fprintf(stderr, "Adding Entry with serial number %d to DB for %s\n",
                  serial, name);
          
          /* We now just add it to the database */
          
          /* Find the expiration date           */
          Ansitm = X509_get_notAfter(x509);
          
          row[CERT_DATABASE_ITEM_EXPIRATION] = 
            (char *)newMem(Ansitm->data, 
                           Ansitm->length + 1);
          if (NULL == row[CERT_DATABASE_ITEM_EXPIRATION])
            {
              result = CERT_MEMORY_ERROR;
              goto err;
            }
          
          row[CERT_DATABASE_ITEM_FILE] = (char *)newMem(name,
                                                        strlen(name) + 1);
          if (NULL == row[CERT_DATABASE_ITEM_FILE])
            {
              result = CERT_MEMORY_ERROR;
              goto err;
            }
          
          
          row[CERT_DATABASE_ITEM_STATUS] = (char *)newMem(value,
                                                          strlen(value) + 1);
          if (NULL == row[CERT_DATABASE_ITEM_STATUS])
            
            {
              result = CERT_MEMORY_ERROR;
              goto err;
            }
          
          sprintf(serialStr, "%04x", serial);
          row[CERT_DATABASE_ITEM_SERIAL] = (char *)newMem(serialStr,
                                                          strlen(serialStr)+1);
          if (NULL == row[CERT_DATABASE_ITEM_SERIAL])
            {
              result = CERT_MEMORY_ERROR;
              goto err;
            }
          
          row[CERT_DATABASE_ITEM_NAME] = 
            X509_NAME_oneline(X509_get_subject_name(x509), NULL, 0);
          
          if (NULL == row[CERT_DATABASE_ITEM_NAME])
            {
              result = CERT_MEMORY_ERROR;
              goto err;
            }
          
          Ansitm = X509_get_notBefore(x509);
          
          row[CERT_DATABASE_ITEM_START] = 
            (char *)newMem(Ansitm->data, 
                           Ansitm->length + 1);
          if (NULL == row[CERT_DATABASE_ITEM_START])
            {
              result = CERT_MEMORY_ERROR;
              goto err;
            }
          


          if ((irow =
               (char **)malloc(sizeof(char *) *
                               (CERT_DATABASE_ITEM_MAX + 1))) ==
              NULL)
            {
              result = CERT_MEMORY_ERROR;
              goto err;
            }
          
          for (i = 0; i < CERT_DATABASE_ITEM_MAX; i++)
            {
              irow[i] = row[i];
              row[i]  = NULL;
            }
          irow[CERT_DATABASE_ITEM_MAX] = NULL;
          
          if (!TXT_DB_insert(db->db, irow))
            {
              fprintf(stderr,"failed to update database\n");
              fprintf(stderr,"TXT_DB error number %ld\n",db->db->error);
            }
        }
      CertUnlockDatabase();
    }
  else
    {
      result = CERT_DATABASE_LOCKED;
    }

  if (CERT_OK == result)
    {
      result = CertWriteDatabase(dbPath);
    }

 err:
  for (i = 0; i < CERT_DATABASE_ITEM_MAX; i++)
    if (NULL != row[i])
      free(row[i]);
  
  return result;
}



/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertUpdateDatabaseItem                                          */
/*       Change a certificate property in the database                       */
/* INPUT:                                                                    */
/*       dbName: The database name                                           */
/*       serialNb: The serial number of the certificate                      */
/*       property: the property that you wish to change.                     */
/*       value: The new value for the certificate property                   */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode_t CertUpdateDatabaseItem(char *dbName,
                                        int32_t serialNb, 
                                        CertDbItemProperty_t property,
                                        const char *value)
{
  CA_DB *db;
  char dbPath[MAX_CERT_PATH];
  int32_t update = 0;
  CertReturnCode_t result; 

  result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE,
                                    dbPath, MAX_CERT_PATH);
  if (CERT_OK != result)
    return result;

  result = CertReadDatabase(dbPath);
  if (CERT_OK != result)
    return result;

  if (NULL != (db = CertLockDatabase(6)))
    {
      char **pp = NULL;
      int32_t i;

      for (i = 0; i < sk_OPENSSL_PSTRING_num(db->db->data); i++)
		{
          int32_t dbSerialNb;

          pp = (char **)sk_OPENSSL_PSTRING_value(db->db->data, i);
          
          sscanf(pp[CERT_DATABASE_ITEM_SERIAL], "%x", &dbSerialNb);
          if (dbSerialNb == serialNb)
            {
              break;
            }
          else
            {
              pp = NULL;
            }
        }
      
      if (NULL != pp)
        {
          switch (property)
            {
            case CERT_DATABASE_ITEM_STATUS:
              strncpy(pp[CERT_DATABASE_ITEM_STATUS],
                      value, 1);
              pp[CERT_DATABASE_ITEM_STATUS][1] = '\0';
              update = 1;
              break;
              
            case CERT_DATABASE_ITEM_EXPIRATION:
            case CERT_DATABASE_ITEM_START:
            case CERT_DATABASE_ITEM_NAME:
              fprintf(stdout,
                      "%s:This property probably shouldn't be changed %d\n",
                      __FUNCTION__, property);
              
            case CERT_DATABASE_ITEM_SERIAL:
            case CERT_DATABASE_ITEM_FILE:
              fprintf(stdout, "UNIMPLEMENTED property in %s\n", __FUNCTION__);
              result = CERT_PROPERTY_STRING_NOT_FOUND;
              break;
              
            default:
              result = CERT_UNKNOWN_PROPERTY;
              break;
            }
        }
      CertUnlockDatabase();
    }
  else
    {
      result = CERT_DATABASE_LOCKED;
    }
  
  if ((CERT_OK == result) && update)
    {
      result = CertWriteDatabase(dbPath);
    }
  return result;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertDatabaseCountCertsDirect                                    */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/*      CERT_OK                                                              */
/*      CERT_DATABASE_INITIALIZATION_ERROR: The database was never init'ed   */
/*      CERT_FILE_ACCESS_FAILURE: The database file could not be accessed    */
/*      CERT_LOCKED_FILE_LOCKED: The database lockfile is unavailable        */
/*      CERT_DATABASE_LOCKED: The database is currently in use               */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode_t CertDatabaseCountCertsDirect(char        *dbName,
                                              CertStatus_t certStatus,
                                              int32_t     *certNb)
{
  int32_t size = 0;
  int32_t i;
  CA_DB *db;
  CertReturnCode_t result;

  if (CERT_STATUS_UNDEFINED <= certStatus)
    return CERT_UNKNOWN_PROPERTY;

  result = CertReadDatabase(dbName);
  if (CERT_OK != result)
    return result;

  if (CERT_OK != result)
    return CERT_DATABASE_NOT_AVAILABLE;

  if (NULL != (db = CertLockDatabase(7)))
    {
      int nCertsTotal = sk_OPENSSL_PSTRING_num(db->db->data);
      for (i = 0, size = 0; i < nCertsTotal; i++)
		{
          const char **pp;
          
          pp = (const char **)sk_OPENSSL_PSTRING_value(db->db->data, i);
          if ((CERT_STATUS_ALL == certStatus)  ||
              (pp[CERT_DATABASE_ITEM_STATUS][0] == statusValues[certStatus]))
            {
              size++;
            }
        }
    }
  else
    {
      result = CERT_DATABASE_LOCKED;
    }
  CertUnlockDatabase();
  *certNb = size;
  return result;
}





/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertListDatabaseCertsByStatusDirect                             */
/*      Return a list of certificates filtered by status                     */
/* INPUT:                                                                    */
/*      dbName: the file containing the desired database                     */
/*      certStatus: the filter for listing                                   */
/*      certNb: the number of certificates possible in the array             */
/* OUTPUT:                                                                   */
/*      certList: an array of certificate serial numbers that match          */
/* RETURN:                                                                   */
/*      CERT_OK if the database was successfully read and deciphered         */
/*      CERT_UNKNOWN_PROPERTY if the status filter is undefined              */
/*      CERT_INSUFFICIENT_BUFFER_SPACE if there are too many certificates    */
/*         that match the filter for the array                               */
/*      CERT_DATABASE_LOCKED if the lock file has been aquired by another    */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode_t CertListDatabaseCertsByStatusDirect(char *dbName,
                                                     CertStatus_t certStatus,
                                                     int32_t *certList,
                                                     int32_t *certNb)
{
  int32_t size = 0;
  int32_t i;
  CA_DB *db;
  CertReturnCode_t result;

  if (CERT_STATUS_UNDEFINED <= certStatus)
    return CERT_UNKNOWN_PROPERTY;

  result = CertReadDatabase(dbName);
  if (CERT_OK != result)
    return result;
  /* ####DF is this redundant? */
  if (CERT_OK != result)
    return CERT_DATABASE_NOT_AVAILABLE;

  if (NULL != (db = CertLockDatabase(7)))
    {
      int nCertsTotal = sk_OPENSSL_PSTRING_num(db->db->data);
      for (i = 0, size = 0; i < nCertsTotal; i++)
		{
          const char **pp;
          
          pp = (const char **)sk_OPENSSL_PSTRING_value(db->db->data, i);
          if ((CERT_STATUS_ALL == certStatus)  ||
              (pp[CERT_DATABASE_ITEM_STATUS][0] == statusValues[certStatus]))
            {
              //              fprintf(stdout, "captured serial #%s\n", 
              //      pp[CERT_DATABASE_ITEM_SERIAL]);
              sscanf(pp[CERT_DATABASE_ITEM_SERIAL], "%x", &(certList[i]));
              
              if (size == *certNb)
                {
                  result = CERT_INSUFFICIENT_BUFFER_SPACE;
                  break;
                }
              size++;
            }
        }
    }
  else
    {
      result = CERT_DATABASE_LOCKED;
    }
  CertUnlockDatabase();
  *certNb = size;
  return result;
}




/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertListDatabaseCertsByStatusDirect                             */
/*      Return a list of certificates filtered by status from the default    */
/*           database                                                        */
/* INPUT:                                                                    */
/*      dbName: the file containing the desired database                     */
/*      certStatus: the filter for listing                                   */
/*      certNb: the number of certificates possible in the array             */
/* OUTPUT:                                                                   */
/*      certList: an array of certificate serial numbers that match          */
/* RETURN:                                                                   */
/*      CERT_OK if the database was successfully read and deciphered         */
/*      CERT_UNKNOWN_PROPERTY if the status filter is undefined              */
/*      CERT_INSUFFICIENT_BUFFER_SPACE if there are too many certificates    */
/*         that match the filter for the array                               */
/*      CERT_DATABASE_LOCKED if the lock file has been aquired by another    */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode_t CertListDatabaseCertsByStatus(CertStatus_t certStatus,
                                               int32_t *certList,
                                               int32_t *certNb)
{
  CertReturnCode_t result;
  char dbName[MAX_CERT_PATH];
  
  result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE,
                                    dbName, MAX_CERT_PATH);
  if (CERT_OK == result)
    {
      result = CertListDatabaseCertsByStatusDirect(dbName,
                                                   certStatus,
                                                   certList,
                                                   certNb);
    }

  return result;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertGetNameFromSerialNumberDirect                               */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode_t CertGetNameFromSerialNumberDirect(char *dbName,
                                                   int32_t serialNb,
                                                   char   *buf,
                                                   int     bufLen)
{
  int32_t size;
  int32_t i;
  CA_DB *db;
  CertReturnCode_t result;
  result = CertReadDatabase(dbName);
  if (CERT_OK != result)
    return result;

  if (NULL != (db = CertLockDatabase(7)))
    {
      int nCertsTotal = sk_OPENSSL_PSTRING_num(db->db->data);

      for (i = 0, size = 0; i < nCertsTotal; i++)
		{
          int dbSerialNb;
          const char **pp;
          
          pp = (const char **)sk_OPENSSL_PSTRING_value(db->db->data, i);
          sscanf(pp[CERT_DATABASE_ITEM_SERIAL], "%x", &dbSerialNb);

          if (dbSerialNb == serialNb)
            {
              int len;
              //              fprintf(stdout, "captured serial #%s\n", 
              //      pp[CERT_DATABASE_ITEM_SERIAL]);

              if ((len = strlen(pp[CERT_DATABASE_ITEM_FILE])) >= bufLen)
                {
                  result = CERT_INSUFFICIENT_BUFFER_SPACE;
                }
              else
                {
                  memcpy(buf, pp[CERT_DATABASE_ITEM_FILE], len + 1);
                  break;
                }
            }
        }
      CertUnlockDatabase();
    }
  else
    {
      result = CERT_DATABASE_LOCKED;
    }
  return result;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertGetNameFromSerialNumber                                     */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

CertReturnCode_t CertGetNameFromSerialNumber(int32_t serialNb,
                                             char   *buf,
                                             int     bufLen)
{
  CertReturnCode_t result;
  char filename[MAX_CERT_PATH];

  result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE,
                                    filename, MAX_CERT_PATH);
  if (CERT_OK != result)
    return result;

#if 0
  result = makePath(filename, CERTCFG_CERT_DATABASE, database, MAX_CERT_PATH);
  if (CERT_OK != result)
    return result;
#endif

  result = CertGetNameFromSerialNumberDirect(filename, serialNb, buf, bufLen);

  return result;
}


long MY_TXT_DB_write(BIO *out, TXT_DB *db)
{
  long i, j, n, nn, l, tot=0;
  char *p, **pp, *f;
  BUF_MEM *buf = NULL;
  long ret = -1;
  
  if ((buf = BUF_MEM_new()) == NULL)
    goto err;
 
  n = sk_OPENSSL_PSTRING_num(db->data);
  nn = db->num_fields;
  for (i = 0; i < n; i++)
    {
      pp=(char **)sk_OPENSSL_PSTRING_value(db->data, i);
      
      l = 0;
      for (j = 0; j < nn; j++)
        {
          if (pp[j] != NULL)
            l += strlen(pp[j]);
        }
      if (!BUF_MEM_grow_clean(buf,(int)(l * 2 + nn)))
        goto err;
      
      p = buf->data;
      for (j = 0; j < nn; j++)
        {
          f = pp[j];
          if (f != NULL)
            for (;;) 
              {
                if (*f == '\0') break;
                if (*f == '\t') *(p++)='\\';
                *(p++)= *(f++);
              }
          *(p++) = '\t';
        }
      p[-1] = '\n';
      j = p-buf->data;
      if (BIO_write(out, buf->data, (int)j) != j)
        goto err;
      tot += j;
    }
  ret = tot;
 err:
  if (buf != NULL)
    BUF_MEM_free(buf);

  return(ret);
}

CA_DB *load_index(char *dbfile, DB_ATTR *db_attr)
{
  CA_DB *retdb = NULL;
  TXT_DB *tmpdb = NULL;
  BIO *in = BIO_new(BIO_s_file());
  CONF *dbattr_conf = NULL;
  char buf[1][MAX_CERT_PATH];
  long errorline= -1;
  
  if (in == NULL)
    {
      goto err;
    }
  if (BIO_read_filename(in, dbfile) <= 0)
    {
      perror(dbfile);
      goto err;
    }
  if ((tmpdb = TXT_DB_read(in, DB_NUMBER)) == NULL)
    {
      goto err;
    }
  
  BIO_snprintf(buf[0], sizeof buf[0], "%s.attr", dbfile);
  dbattr_conf = NCONF_new(NULL);

  if (0 >= NCONF_load(dbattr_conf,buf[0], &errorline))
    {
      if (errorline > 0)
        {
          goto err;
        }
      else
        {
          NCONF_free(dbattr_conf);
          dbattr_conf = NULL;
        }
    }
  
  if ((retdb = OPENSSL_malloc(sizeof(CA_DB))) == NULL)
    {
      fprintf(stderr, "Out of memory\n");
      goto err;
    }
  
  retdb->db = tmpdb;
  tmpdb = NULL;
  if (db_attr)
    retdb->attributes = *db_attr;
  else
    {
      retdb->attributes.unique_subject = 1;
    }
  
  if (dbattr_conf)
    {
      char *p = NCONF_get_string(dbattr_conf,NULL,"unique_subject");
      if (p)
        {
          retdb->attributes.unique_subject = parse_yesno(p,1);
        }
    }
  
 err:
  if (dbattr_conf)
    NCONF_free(dbattr_conf);
  if (tmpdb)
    TXT_DB_free(tmpdb);
  if (in)
    BIO_free_all(in);

  return retdb;
}

int save_index(const char *dbfile, const char *suffix, CA_DB *db)
	{
	char buf[3][MAX_CERT_PATH];
	BIO *out = BIO_new(BIO_s_file());
	int j;

	if (out == NULL)
		{

		goto err;
		}

	j = strlen(dbfile) + strlen(suffix);
	if (j + 6 >= MAX_CERT_PATH)
		{
		fprintf(stderr,"file name too long\n");
		goto err;
		}

	j = BIO_snprintf(buf[2], sizeof buf[2], "%s.attr", dbfile);
	j = BIO_snprintf(buf[1], sizeof buf[1], "%s.attr.%s", dbfile, suffix);
	j = BIO_snprintf(buf[0], sizeof buf[0], "%s.%s", dbfile, suffix);

	fprintf(stderr, "DEBUG: writing \"%s\"\n", buf[0]);

	if (BIO_write_filename(out,buf[0]) <= 0)
		{
		perror(dbfile);
		fprintf(stderr,"unable to open '%s'\n", dbfile);
		goto err;
		}
	j=MY_TXT_DB_write(out,db->db);
	if (j <= 0) goto err;
			
	BIO_free(out);

	out = BIO_new(BIO_s_file());

	fprintf(stderr, "DEBUG: writing \"%s\"\n", buf[1]);

	if (BIO_write_filename(out,buf[1]) <= 0)
		{
		perror(buf[2]);
		fprintf(stderr,"unable to open '%s'\n", buf[2]);
		goto err;
		}
	BIO_printf(out,"unique_subject = %s\n",
		db->attributes.unique_subject ? "yes" : "no");
	BIO_free(out);

	return 1;
 err:
	return 0;
	}



int rotate_index(const char *dbfile, const char *new_suffix, const char *old_suffix)
{
  char buf[5][MAX_CERT_PATH];
  int i,j;
  struct stat sb;
  
  i = strlen(dbfile) + strlen(old_suffix);
  j = strlen(dbfile) + strlen(new_suffix);
  if (i > j)
    j = i;
  if (j + 6 >= MAX_CERT_PATH)
    {
      fprintf(stderr,"file name too long\n");
      goto err;
    }
  
  j = BIO_snprintf(buf[4], sizeof buf[4], "%s.attr", dbfile);
  j = BIO_snprintf(buf[2], sizeof buf[2], "%s.attr.%s",
                   dbfile, new_suffix);
  j = BIO_snprintf(buf[0], sizeof buf[0], "%s.%s",
                   dbfile, new_suffix);
  j = BIO_snprintf(buf[1], sizeof buf[1], "%s.%s",
                   dbfile, old_suffix);
  j = BIO_snprintf(buf[3], sizeof buf[3], "%s.attr.%s",
                   dbfile, old_suffix);
  if (stat(dbfile,&sb) < 0)
    {
      if (errno != ENOENT 
#ifdef ENOTDIR
          && errno != ENOTDIR
#endif
          )
        goto err;
    }
  else
    {
      fprintf(stderr, "DEBUG: renaming \"%s\" to \"%s\"\n",
              dbfile, buf[1]);
      if (rename(dbfile,buf[1]) < 0)
        {
          fprintf(stderr,
                  "unable to rename %s to %s\n",
                  dbfile, buf[1]);
          perror("reason");
          goto err;
        }
    }
  fprintf(stderr, "DEBUG: renaming \"%s\" to \"%s\"\n",
          buf[0],dbfile);
  if (rename(buf[0],dbfile) < 0)
    {
      fprintf(stderr,
              "unable to rename %s to %s\n",
              buf[0],dbfile);
      perror("reason");
      rename(buf[1],dbfile);
      goto err;
    }
  if (stat(buf[4],&sb) < 0)
    {
      if (errno != ENOENT 
#ifdef ENOTDIR
          && errno != ENOTDIR
#endif
          )
        goto err;
    }
  else
    {
      fprintf(stderr, "DEBUG: renaming \"%s\" to \"%s\"\n",
              buf[4],buf[3]);
      if (rename(buf[4],buf[3]) < 0)
        {
          fprintf(stderr,
                  "unable to rename %s to %s\n",
                  buf[4], buf[3]);
          perror("reason");
          rename(dbfile,buf[0]);
          rename(buf[1],dbfile);
          goto err;
        }
    }
#ifdef RL_DEBUG
  fprintf(stderr, "DEBUG: renaming \"%s\" to \"%s\"\n",
          buf[2],buf[4]);
#endif
  if (rename(buf[2],buf[4]) < 0)
    {
      fprintf(stderr,
              "unable to rename %s to %s\n",
              buf[2],buf[4]);
      perror("reason");
      rename(buf[3],buf[4]);
      rename(dbfile,buf[0]);
      rename(buf[1],dbfile);
      goto err;
    }
  return 1;
 err:
  return 0;
}

void free_index(CA_DB *db)
	{
	if (db)
		{
		if (db->db) TXT_DB_free(db->db);
		OPENSSL_free(db);
		}
	}

int parse_yesno(const char *str, int def)
	{
	int ret = def;
	if (str)
		{
		switch (*str)
			{
		case 'f': /* false */
		case 'F': /* FALSE */
		case 'n': /* no */
		case 'N': /* NO */
		case '0': /* 0 */
			ret = 0;
			break;
		case 't': /* true */
		case 'T': /* TRUE */
		case 'y': /* yes */
		case 'Y': /* YES */
		case '1': /* 1 */
			ret = 0;
			break;
		default:
			ret = def;
			break;
			}
		}
	return ret;
	}
