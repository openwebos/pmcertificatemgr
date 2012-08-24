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
 * @file cert_cfg.h
 *
 * @brief Certificate Manager configuration file routines
 *
 * @ingroup CERTMgrLib
 *
 */

#ifndef __CERT_CFG_H__
#define __CERT_CFG_H__
#include <stdio.h>

/*!
 * The various labels of interest within the configuration file.
 * cert_cfg.c has the definitive values for them in propertyNameList[]
 */
typedef enum
  {
    CERTCFG_CONFIG_FILE,      /*!< File with the ssl configuration           */
    CERTCFG_CONFIG_NAME,      /*!< Configuration with the config file        */
    CERTCFG_ROOT_DIR,         /*!< directory root for the cert info          */
    CERTCFG_CERT_DIR,         /*!< Where certificates are kept               */
    CERTCFG_CERTIFICATE,      /*!< A personal ceritificate [optional]        */
    CERTCFG_PRIVATE_KEY_DIR,  /*!< The location for private keys             
                               *   [def == private]                          */
    CERTCFG_PRIVATE_KEY,      /*!< A personal private key [optional]         */
    CERTCFG_CERT_DATABASE,    /*!< lists the certificates [def == index.txt] */
    CERTCFG_CERT_SERIAL_NAME, /*!< serial number file                        */
    CERTCFG_AUTH_CERT_DIR,    /*!< location for certificates that have been
                               *   authourized                               */
    CERTCFG_PUBLIC_KEY_DIR,   /*!< directory for public keys                 */
    CERTCFG_CRL_DIR,          /*!< directory for Certificate Revocation Lists*/
    CERTCFG_PACKAGE_DIR,      /*!< location for uninstalled packages         
                               *   (pem, der, pk12)                          */
    CERTCFG_CERT_SERIAL,      /*!< serial number for certificate creation    */
    CERTCFG_TRUSTED_CA_DIR,   /*!< trusted CA directory                      */
    CERTCFG_MAX_PROPERTY
  } certcfg_Property_t;

#define PROPERTY_MAX CERTCFG_MAX_PROPERTY

#ifdef __cplusplus
extern "C" {
#endif

/** 
 * @brief Open a configuration file
 *
 * The named configuration file is opened and the named configuration
 * is used to set the system up.
 * If the value of configFile == NULL, the following are checked in order:
 *   OPENSSL_CONF environmental variable or CERT_DEF_CONF_FILE
 *   defined in cert_mgr.h.
 * We expect the repository directory to be labeled "dir" in the
 *          config file
 * 
 * @param[in] configFile The name of the configuration file
 * @param[in] configName The name of the configuration
 * 
 * @return CERT_OK:
 * @return CERT_PATH_LIMIT_EXCEEDED: The path string is too long
 * @return CERT_OPEN_FILE_FAILED: The config file couldn't be opened
 * @return CERT_ILLFORMED_CONFIG_FILE: There was some problem in the config
 * @return CERT_CONFIG_UNAVAILABLE: The named configuration not available
 * @return CERT_UNDEFINED_DESTINATION: The certificate root dir not available
 */
int   CertCfgOpenConfigFile(const char *configFile, const char *configName);

int   CertCfgSetObjectValue(certcfg_Property_t certObjStrProperty, int value);
/** 
 * @brief Get the value of a property in the configuration.
 * 
 * Properties, if they can be expressed as an integer, can be checked here.
 * Currently only CERTCFG_CERT_SERIAL is the only property available.
 *
 * @param[in] certObjStrProperty The property in question.
 * @param[out] value the value associated with the property.
 *             <serial number\> when the property is CERTCFG_CERT_SERIAL.
 * 
 * @return CERT_OK
 * @return CERT_SERIAL_NUMBER_UNAVAILABLE: The serial number is not available.
 * @return CERT_UNKNOWN_PROPERTY: The property is not supported.
 */
int   CertCfgGetObjectValue(certcfg_Property_t certObjStrProperty, int *value);

int   CertCfgSetObjectStrValue(certcfg_Property_t certObjStrProperty, const char *value);
/** 
 * @brief Get the value of a property in the configuration.
 * 
 * Most properties can be checked here. The caller supplies the buffer 
 * and sends the length.
 *
 * @param[in] certObjStrProperty The property
 * @param[out] value the value associated with the property.
 * @param[in] len The length of the user supplied buffer
 * 
 * @return CERT_OK
 * @return CERT_PATH_LIMIT_EXCEEDED The size of the user supplied buffer is
 *             too small
 * @return CERT_UNKNOWN_PROPERTY The property is not supported.
 * 
 * @return 
 */
int   CertCfgGetObjectStrValue(certcfg_Property_t certObjStrProperty, char *buf, int bufLen);
char *CertCfgResolveConfigValue(FILE *fp, char *configName,  char *configValue);

#ifdef __cplusplus
}
#endif

#endif  /*  __CERT_CFG_H__ */
