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

/*****************************************************************************/
/* cert_cfg.c: functions for dealing directly with configuration files       */
/*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/conf.h>

#include "cert_mgr.h"
#include "cert_cfg.h"
#include "cert_utils.h"

/* #define D_DEBUG_ENABLED */
#include "cert_debug.h"


/*
 * Currently just hold this stuff in globals.  This is not something we
 * want to continue into the future.
 * Wouldn't an actual object be nice!
 */
typedef struct ConfigObject_t
{
  CONF *conf;
  char *descStr[PROPERTY_MAX+2];
} configObject_t;

configObject_t configObject;
static int populateConfig(void);




/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertCfgOpenConfigFile                                          */
/*       Open the configuration file                                         */
/* INPUT:                                                                    */
/*       configFile: a fully qualified path to the ssl configuration file    */
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
/*       1) Not thread safe                                                  */
/*       2) If the value of configFile == NULL, the following are checked in */
/*          order:                                                           */
/*            OPENSSL_CONF environmental variable                            */
/*            CERT_DEF_CONF_FILE defined in cert_mgr.h                       */
/*       3) We expect the repository directory to be labeled "dir" in the    */
/*          config file                                                      */
/*       4) NCONF_load seems to indescriminatly open arbitrary files         */
/*                                                                           */
/*****************************************************************************/
 
int CertCfgOpenConfigFile(const char *configFile, const char *configName)
{
  const char *pConfigFile = configFile;
  char *dirName;
  long err = 0;
  int len;
  CONF *conf;
  
  if (NULL == pConfigFile)
    {
      // first check the environment
      pConfigFile = getenv("OPENSSL_CONF");
      
      // if it didn't find it we'll use the default
      if (NULL == pConfigFile)
        pConfigFile = CERT_DEF_CONF_FILE;
    }
  
  // keep a copy in case of error
  CertCfgSetObjectStrValue(CERTCFG_CONFIG_FILE, pConfigFile);
  
  // make sure it's reasonable
  
  if (MAX_CERT_PATH <= (len = strlen(pConfigFile)))
    {
      return CERT_PATH_LIMIT_EXCEEDED;
    }
  conf = NCONF_new(NCONF_default());
  if (!NCONF_load(conf, pConfigFile, &err))
    {
      if (err == 0)
        {
          PRINT_RETURN_CODE(CERT_OPEN_FILE_FAILED);
          return CERT_OPEN_FILE_FAILED;
        }
      else
        {
          PRINT_RETURN_CODE(CERT_ILLFORMED_CONFIG_FILE);
          return CERT_ILLFORMED_CONFIG_FILE;
        }
    }
  
  /* Figure out the configuration inside the designate file that we want 
   * to use
   */
  if (NULL == configName)
    {
      if (!(configName = NCONF_get_string (conf, "ca", "default_ca")))
        return CERT_CONFIG_UNAVAILABLE;
    }
  
  
  /*
   * Let's find out if there is anything reasonable
   */
  if (!(dirName = NCONF_get_string (conf, configName, "dir")))
    {
      PRINT_RETURN_CODE(CERT_ILLFORMED_CONFIG_FILE);
      err = CERT_ILLFORMED_CONFIG_FILE;
    }
  else
    {
      struct stat statBuf;
      if (0 != stat(dirName, &statBuf))
        {
          fprintf(stdout, "Can't find %s\n", dirName);
          err = CERT_UNDEFINED_ROOT_DIR;
        }
    }
  
  // Cache it away
  CertCfgSetObjectStrValue(CERTCFG_CONFIG_NAME, (const char *)configName);
  configObject.conf = conf;
	
  // Now resolve the rest of the defaults from the config file
  // We are asuming that the file is well formed or this might have problems.
  // if we can't resolve the directory then fail.
  // if we can't resolve the subdirectories, don't fail put them under dir.
	
  populateConfig();

  return err;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertCfgSetObjectValue                                          */
/*       Figure out the proper configuration file                            */
/* INPUT:                                                                    */
/*       certObjProperty: deontes a property that is stored as an integer    */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/**/
/* NOTES:                                                                    */
/*       1) Not thread safe                                                  */
/*                                                                           */
/*****************************************************************************/
int CertCfgSetObjectValue(certcfg_Property_t certObjProperty, int value)
{
  int result = CERT_GENERAL_FAILURE;

#ifdef D_DEBUG_ENABLED
  result =  CERT_OK;
#endif

  PRINT_ERROR2("UNIMPLEMENTED", 0);
  return result;
}
  
/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertCfgGetObjectValue                                           */
/*       Get the value of a property in the configuration.                   */
/* INPUT:                                                                    */
/*       certObjProperty: denotes a property that is stored as an integer    */
/* OUTPUT:                                                                   */
/*       value: The value the value associated with the property.            */
/* RETURN:                                                                   */
/*       CERT_OK                                                             */
/*       CERT_SERIAL_NUMBER_UNAVAILABLE: The serial number is not available. */
/*       CERT_UNKNOWN_PROPERTY: The property is not supported.               */
/* NOTES:                                                                    */
/*       1) Not thread safe                                                  */
/*                                                                           */
/*****************************************************************************/
int CertCfgGetObjectValue(certcfg_Property_t certObjProperty, int *propertyValue)
{
  int rValue = CERT_UNKNOWN_PROPERTY;
  char filePath[MAX_CERT_PATH];

  switch (certObjProperty)
    {
    case CERTCFG_CERT_SERIAL:
      if (CERT_OK ==
          (rValue =
           CertCfgGetObjectStrValue(CERTCFG_CERT_SERIAL_NAME,
                                     filePath, MAX_CERT_PATH)))
        {
          int serialNb = CertGetSerialNumber(filePath);
          if (0 == serialNb)
            rValue = CERT_SERIAL_NUMBER_UNAVAILABLE;
          else 
            *propertyValue = serialNb;
        }
      break;

    default:
      break;
    }

  return rValue;
}
  
/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertCfgSetObjectStrValue                                       */
/*       Figure out the proper configuration file                            */
/* INPUT:                                                                    */
/*       certObjectStrProperty: denotes a property that is stored as a string*/
/* OUTPUT:                                                                   */
/*        value: the value associated with the property.                     */
/* RETURN:                                                                   */
/**/
/* NOTES:                                                                    */
/*       1) Not thread safe                                                  */
/*                                                                           */
/*****************************************************************************/
int CertCfgSetObjectStrValue(certcfg_Property_t certObjStrProperty,
			      const char *value)
{
  int result = CERT_OK;
  int len;
  
  // check for correctness:
  if (certObjStrProperty >= CERTCFG_MAX_PROPERTY || certObjStrProperty < 0)
	return CERT_PROPERTY_NOT_FOUND;

  // check for reasonable size
  if (!value)
    {
      if (configObject.descStr[certObjStrProperty])
		free(configObject.descStr[certObjStrProperty]);
      configObject.descStr[certObjStrProperty] =  NULL;
    }
  else
    {  
      if (MAX_CERT_PATH <= (len = strlen(value)) + 1)
        {
          result = CERT_PATH_LIMIT_EXCEEDED;
        }
      else if (certObjStrProperty >= CERTCFG_MAX_PROPERTY)
        {
          result = CERT_PROPERTY_NOT_FOUND;
        }
      else
        {
          configObject.descStr[certObjStrProperty] = strdup(value);
        }
    }
  PRINT_CFG_STR_PROPS(certObjStrProperty, value);
  return result;
}
  
/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertCfgGetObjectStrValue                                        */
/*       Figure out the proper configuration file                            */
/* INPUT:                                                                    */
/*       certObjStrProperty: denotes a property that is stored as a string   */
/*       buf: A user supplied buffer                                         */
/*       bufLen; the length of the supplied buffer                           */
/* OUTPUT:                                                                   */
/*       void                                                                */
/* RETURN:                                                                   */
/*       CERT_OK:                                                            */
/*       CERT_INSUFFICIENT_BUFFER_SPACE: The user memory is not sufficiently */
/*           large to hold the data                                          */
/*       CERT_UNKNOWN_PROPERTY: The requested prperty is not supported       */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/
int CertCfgGetObjectStrValue(certcfg_Property_t certObjStrProperty, char *buf, int bufLen)
{
  int rValue = 0;
  int sLen;


  if (certObjStrProperty >= CERTCFG_MAX_PROPERTY)
    {

      PRINT_ERROR2("Unknown string property", certObjStrProperty);
      PRINT_RETURN_CODE(CERT_UNKNOWN_PROPERTY);

      rValue = CERT_UNKNOWN_PROPERTY;
    }
  else {
      if (configObject.descStr[certObjStrProperty])  {
	  if (bufLen <= (sLen = strlen(configObject.descStr[certObjStrProperty])))
	  {
	      PRINT_ERROR2("Insufficient buffor for the string property", sLen);
	      rValue = CERT_INSUFFICIENT_BUFFER_SPACE;
	  }
	  else
	  {
	      strncpy(buf, configObject.descStr[certObjStrProperty], sLen);
	      buf[sLen] = '\0';
	      PRINT_CFG_STR_PROPS(certObjStrProperty, buf);
	  }
      }
  }

  return rValue;
}
  
/* keep in sync with CertCfgProperty_t in cert_cfg.h */

const char *propertyNameList[] =
  {
    CERT_DEF_CONF_FILE,  /* CERTCFG_CONFIG_FILE */
    "default_ca",	/* CERTCFG_CONFIG_NAME */
    "dir",		/* CERTCFG_ROOT_DIR */
    "certs",		/* CERTCFG_CERT_DIR */
    "certificate",	/* CERTCFG_CERTIFICATE */
    "private_dir",	/* CERTCFG_PRIVATE_KEY_DIR */
    "private_key",	/* CERTCFG_PRIVATE_KEY */
    "database",		/* CERTCFG_CERT_DATABASE */
    "serial",		/* CERTCFG_CERT_SERIAL_NAME */
    "authorized",	/* CERTCFG_AUTH_CERT_DIR */
    "public_dir",	/* CERTCFG_PUBLIC_KEY_DIR */
    "crl_dir", 		/* CERTCFG_CRL_DIR */
    "package_dir",	/* CERTCFG_PACKAGE_DIR */
    "authorized",	/* CERTCFG_CERT_SERIAL */
    "trusted_ca_dir"	/* CERTCFG_TRUSTED_CA_DIR */
			/* CERTCFG_MAX_PROPERTY */
  };
    
/*****************************************************************************/
/*                                                                           */
/* FUNCTION: populateConfig                                                  */
/*       Convenience function for populating the configuration structure from*/
/*       its configuration file                                              */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/
static int populateConfig(void)
{
  certcfg_Property_t i;

  for (i = CERTCFG_ROOT_DIR; i < CERTCFG_MAX_PROPERTY ; i++)
    {
      char *str;
      /* zero all pointers so if there's no conf we dont' have
      ** bogus info */
      configObject.descStr[i] = '\0';

      str = NCONF_get_string(configObject.conf,
			     configObject.descStr[CERTCFG_CONFIG_NAME],
			     propertyNameList[i]);

      PRINT_CFG_STR_PROPS(i, str);
      CertCfgSetObjectStrValue(i, str);
      
      // no need to free as NCONF_get_string doesn't return a copy.
    }
  return 0;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION:                                                                 */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

