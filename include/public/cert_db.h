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
 * @file cert_db.h
 *
 * @brief Certificate Manager database routines
 *
 * @ingroup CERTMgrLib
 *
 */

#ifndef __CERT_DB_H__
#define __CERT_DB_H__

#include <openssl/txt_db.h>

/*! Properties of the data base itself    */
typedef enum
  {
    CERT_DATABASE_SIZE,  /*!< The number of items in the database */
    CERT_DATABASE_MAX    /*!< A fencepost value                   */
  } CertDbProperty_t;
  
  /*! Properties of items in the database */
typedef enum 
  {
    CERT_DATABASE_ITEM_STATUS,     /*!< The status of the certificate   */
    CERT_DATABASE_ITEM_EXPIRATION, /*!< The certificate expiration date */
    CERT_DATABASE_ITEM_START,      /*!< The certificate start date      */
    CERT_DATABASE_ITEM_SERIAL,     /*!< The certificate serial number   */ 
    CERT_DATABASE_ITEM_FILE,       /*!< The certificate file name       */
    CERT_DATABASE_ITEM_NAME,       /*!< The certificate name            */
    CERT_DATABASE_ITEM_MAX         /*!< */
  } CertDbItemProperty_t;

/*!
 * Characters taken from <citation> used to designate the status of a 
 * given certificate in the database
 */
extern const char *statusNames[];

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Read the database into memory
 *
 * @param[in] dbName the file containing the desired database
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_DATABASE_INITIALIZATION_ERROR the database wasn't initialized
 * @return CERT_FILE_ACCESS_FAILURE if the file could not be found or loaded
 * @return CERT_LOCK_FILE_LOCKED if the lock file has been aquired by another
 *
 */
CertReturnCode_t CertReadDatabase(char *dbName);


/*!
 * Initialize the database system
 *
 * @param[in] dbName the file containing the desired database
 *
 * @return CERT_OK if the database was successfully initialized.
 * @return CERT_DATABASE_LOCKED if the database has already been initialized.
 * @return CERT_FILE_ACCESS_FAILURE if the file could not be found or loaded.
 * @return CERT_DATABASE_NOT_AVAILABLE if the couldn't get the protective lock.
 * @return CERT_DATABASE_INITIALIZATION_ERROR the database wasn't initialized.
 * @return CERT_LOCK_FILE_LOCKED if the lock file has been aquired by another.
 *
 */
CertReturnCode_t CertInitDatabase(char *dbName);


/*!
 * Get information on the database itself
 *
 * @param[in]  dbName the property of interest
 * @param[out] value the value of the property
 *
 * @return CERT_OK The value of the property has been passed back
 * @return CERT_PROPERTY_NOT_FOUND if the property exists, but isn't available
 * @return CERT_UNKNOWN_PROPERTY if the property itself doesn't exist
 * @return CERT_DATABASE_NOT_AVAILABLE if the database could not be locked
 *
 * @todo set property to enumeration type.
 *
 */
CertReturnCode_t CertGetDatabaseInfo(int32_t property, int32_t *value);


/*!
 * Information stored in the database in a string
 *
 * @param[in] index the key for the desired certificate
 * @param[in] property is the name of the information requested
 * @param[in] len is the length of the buffer passed into the function
 *
 * @param[out] propertyStr is the value of the property
 *
 * @return CERT_OK if the database successfully divulged the information
 * @return CERT_DATABASE_OUT_OF_BOUNDS if the index exceeded the database
 * @return CERT_BUFFER_LIMIT_EXCEEDED if the requested property doesn't fit
 * @return CERT_UNKNOWN_PROPERTY if the requested property doesn't exist
 * @return CERT_DATABASE_LOCKED if the database is locked by another
 *
 */
CertReturnCode_t CertGetDatabaseStrValue(int index,
                                         CertDbItemProperty_t property,
                                         char *propertyStr, int len);


/*!
 * Read the database into memory
 *
 * @param[in] dbName the file containing the desired database
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_DATABASE_INITIALIZATION_ERROR the database wasn't initialized
 * @return CERT_FILE_ACCESS_FAILURE if the file could not be found or loaded
 * @return CERT_LOCK_FILE_LOCKED if the lock file has been aquired by another
 *
 */
CertReturnCode_t CertCreateDatabaseItem(X509   *x509,
                                        char   *name,
                                        int32_t serial,
                                        const char   *value);
/*!
 * Put a new item into the database
 *
 * @param[in] x509 The database revolves around certificates
 * @param[in] name The name of the database file.
 * @param[in] serial The serial number for the certificate
 * @param[in] value  The status value.
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_DATABASE_INITIALIZATION_ERROR the database wasn't initialized
 * @return CERT_FILE_ACCESS_FAILURE if the file could not be found or loaded
 * @return CERT_LOCK_FILE_LOCKED if the lock file has been aquired by another
 *
 */
CertReturnCode_t CertUpdateDatabaseItem(char *dbName, int32_t serialNb,
                                        CertDbItemProperty_t property,
                                        const char *value);
/*!
 * Write the database to file
 *
 * @param[in] dbName the file for the desired database
 *
 * @return CERT_OK if the database was successfully written
 * @return CERT_DATABASE_NOT_AVAILABLE if The database could not be opened
 * @return CERT_NULL_BUFFER if trying to save a database without a name
 * @return CERT_LOCK_FILE_LOCKED if the lock file has been aquired by another
 *
 */
CertReturnCode_t CertWriteDatabase(char *dbName);


/*!
 * Count the certificates registered in the given database
 *
 * @param[in] dbName the file containing the desired database.
 * @param[in] certStatus the filter for counting
 * @param[out] certNb the number of certificates that match the filter
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_UNKNOWN_PROPERTY if the status filter is unknown.
 * @return CERT_DATABASE_NOT_AVAILABLE if the database couldn't be read.
 * @return CERT_DATABASE_LOCKED if the lock file has been aquired by another
 *
 */
CertReturnCode_t CertDatabaseCountCertsDirect(char *dbName,
                                              CertStatus_t certStatus,
                                              int32_t *certNb);


/*!
 * Return a list of certificates filtered by status
 *
 * @param[in] dbName the file containing the desired database
 * @param[in] certStatus the filter for listing
 * @param[out] certList an array of certificate serial numbers that match
 * @param[in] certNb the number of certificates in the array
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_UNKNOWN_PROPERTY if the status filter is undefined
 * @return CERT_INSUFFICIENT_BUFFER_SPACE if there are too many certificates
 *           that match the filter for the array
 * @return CERT_DATABASE_LOCKED if the lock file has been aquired by another
 *
 */
CertReturnCode_t CertListDatabaseCertsByStatusDirect(char *dbName,
                                                     CertStatus_t certStatus,
                                                     int32_t *certList,
                                                     int32_t *certNb);


/*!
 * Return a list of certificates filtered by status from the default database
 *
 * @param[in] dbName the file containing the desired database
 * @param[in] certStatus the filter for listing
 * @param[out] certList an array of certificate serial numbers that match
 * @param[in] certNb the number of certificates in the array
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_UNKNOWN_PROPERTY if the status filter is undefined
 * @return CERT_INSUFFICIENT_BUFFER_SPACE if there are too many certificates
 *           that match the filter for the array
 * @return CERT_DATABASE_LOCKED if the lock file has been aquired by another
 *
 */
CertReturnCode_t CertListDatabaseCertsByStatus(CertStatus_t certStatus,
                                               int32_t *certList,
                                               int32_t *certNb);
/*!
 * Read the database into memory
 *
 * @param[in] dbName the file containing the desired database
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_DATABASE_INITIALIZATION_ERROR the database wasn't initialized
 * @return CERT_FILE_ACCESS_FAILURE if the file could not be found or loaded
 * @return CERT_LOCK_FILE_LOCKED if the lock file has been aquired by another
 *
 */
CertReturnCode_t CertGetNameFromSerialNumberDirect(char *dbName,
                                                   int32_t serialNb,
                                                   char   *buf,
                                                   int     bufLen);

/*!
 * Read the database into memory
 *
 * @param[in] dbName the file containing the desired database
 *
 * @return CERT_OK if the database was successfully read and deciphered
 * @return CERT_DATABASE_INITIALIZATION_ERROR the database wasn't initialized
 * @return CERT_FILE_ACCESS_FAILURE if the file could not be found or loaded
 * @return CERT_LOCK_FILE_LOCKED if the lock file has been aquired by another
 *
 */
CertReturnCode_t CertGetNameFromSerialNumber(int32_t serialNb,
                                             char   *buf,
                                             int     bufLen);

#define DB_type         0
#define DB_exp_date     1
#define DB_rev_date     2
#define DB_serial       3       /* index - unique */
#define DB_file         4       
#define DB_name         5       /* index - unique when active & not disabled */
#define DB_NUMBER       6

#define DB_TYPE_REV	'R'
#define DB_TYPE_EXP	'E'
#define DB_TYPE_VAL	'V'

typedef struct db_attr_st
{
  int unique_subject;
} DB_ATTR;

typedef struct ca_db_st
{
  DB_ATTR attributes;
  TXT_DB *db;
} CA_DB;


BIGNUM *load_serial(char *serialfile, int create, ASN1_INTEGER **retai);
int save_serial(char *serialfile, char *suffix,
                BIGNUM *serial, ASN1_INTEGER **retai);
int rotate_serial(char *serialfile, char *new_suffix, char *old_suffix);
int rand_serial(BIGNUM *b, ASN1_INTEGER *ai);
CA_DB *load_index(char *dbfile, DB_ATTR *dbattr);
int index_index(CA_DB *db);
int save_index(const char *dbfile, const char *suffix, CA_DB *db);
int rotate_index(const char *dbfile,
                 const char *new_suffix, const char *old_suffix);
void free_index(CA_DB *db);
int index_name_cmp(const char **a, const char **b);
int parse_yesno(const char *str, int def);

X509_NAME *parse_name(char *str, long chtype, int multirdn);

#ifdef __cplusplus
}
#endif

#endif // __CERT_DB_H__
