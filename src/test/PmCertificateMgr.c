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
/* PmCertificateMgr.c: Main program for testing the Certificate Manager             */
/*                                                                           */
/* the test is divided into various file type                                */
/* Mostly file type reside in their particular directories as specified in   */
/* the configuration file.                                                   */
/*****************************************************************************/
#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <openssl/x509.h>

#include "cert_mgr.h"
#include "cert_cfg.h"

#include "cert_pkcs.h"
#include "cert_x509.h"
#include "cert_utils.h"

#include "cert_db.h"

#define D_DEBUG_ENABLED
#include "cert_debug.h"


void tcert_PrintConfigInfo(unsigned int min, unsigned int max);
void tcert_printDatabase(void);
void tcert_ListDirExt(char *dir, char *ext, int level);
void tcert_DumpPKCS12(char *name);
void tcert_InstallPackage(char *opt, char *param1, char *param2);
void tcert_PrivatekeyInfo(char *pKeyOption, char *pKeyName, char *param3p);
void tcert_X509PackageInfo(char *certOpt, char *explodeProp, char *certFile);
void tcert_RawPackageInfo(char *rawOpt, char *pkgName, char *param3p);
int tcert_TestDatabase(char *param1, char *param2, char *param3);
int displayConfigDetail(char *configOption, char *configUpdate);
int testAPI(char *ApiName, char *param1, char* param2, char *param3);

void printUsage(char *usageList[], int number);

#define MAIN_TEST_LIST_SIZE 9
char *mainTestList[MAIN_TEST_LIST_SIZE] =
  {
    "a: Direct API manipulation",
    "c: Configuration information...",
    "d: Database manipulation",
    "h: Print this list",
    "i: Insert an object",
    "p: Private Key data...",
    "q: quit",
    "r: Raw package information",
    "x: X.509 information",
  };          

void usage() {
	fprintf(stderr,"usage: PmCertificateMgr [-v] [/path/to/openssl.cnf]\n");
	exit(1);
}


int main(int argc, char **argv)
{
  //  char *outstring;
  //int i;
  int cmdNum = 0;
  int verbose = 0;
  int rValue;
  int argcnt = 1;
  char *confpath = "/etc/ssl/openssl.cnf";
      // Needs to be configured to wherever @WEBOS_INSTALL_SYSCONFDIR@
      // points.  Pass as run-time parameter to override.
  
  while(argcnt < argc) {
      switch(argv[argcnt][0]) {
	  case '-':
	      switch(argv[argcnt][1]) {
		  case 'v':
		      verbose++;
		      break;
		  default:
		      usage();
		      break;
	      }
	      break;
	  default:
	      confpath = argv[argcnt];
	      break;
      }
      argcnt++;
  }
		
	
    if (0 != (rValue = (CertInitCertMgr(confpath))))
    {
      fprintf(stderr,
	"ERROR: Couldn't initialize the manager using conf file %s\n",confpath);
      PRINT_RETURN_CODE(rValue);
    }
  
  while (1)
    {
      char cmdBuf[1024];
      char nOpts;
      char cmd[64];
      char param1[64], *param1p;
      char param2[64], *param2p;
      char param3[64], *param3p;
      int result;
      
      printf("%08d> ", cmdNum++);
      
      memset((void *)cmdBuf, 0, MAX_CERT_PATH);
      
      gets(cmdBuf);
      cmd[0] = 0;
      nOpts = sscanf(cmdBuf, "%s %s %s %s", cmd, param1, param2, param3);
      
      if (verbose)
        printf("%s\n", cmdBuf);
      result = CERT_OK;
      
      param1p = param2p = param3p = NULL;
      if (1 <  nOpts)
        {
          param1p = param1;
          if (2 < nOpts)
          {
            param2p = param2;
            if (3 < nOpts)
              {
                param3p = param3;
              }
          }
        }                

      if (!nOpts)
        {
          printUsage(mainTestList, MAIN_TEST_LIST_SIZE);
          break;
        }
      switch (cmd[0])
        {
        case 'a': // test API directly
          result = testAPI(param1p, param2p, param3p, cmdBuf);
          printf("API %s: %s (%d)\n", param1p, 
                 (result < CERT_MAX_RETURN_CODE) ?
                 strErrorNames[result] : "UNKNOWN",
                 result);
          break;

        case 'c': // configuration details
          displayConfigDetail(param1p, param2p);
          break;   // configuration details
          
        case 'd':  // Database manipulation
          result = tcert_TestDatabase(param1p, param2p, param3p);
          break;

        case 'h':  // h[elp]
          printUsage(mainTestList, MAIN_TEST_LIST_SIZE);
          break;   // help
          
          /* installation goes from default package dir
           * to default destination dirs
           */
        case 'i':  // install
          tcert_InstallPackage(param1p, param2p, param3p);
          break;

        case 'p':  // private keys
          tcert_PrivatekeyInfo(param1p, param2p, param3p);
          break;
          
        case 'q':
          exit(0);
          break;
          
        case 'r': // raw package information
          tcert_RawPackageInfo(param1p, param2p, param3p);
          break; // raw package information
          
        case 'x': // x[509 certificate information]
          tcert_X509PackageInfo(param1p, param2p, param3p);
          break; // x[509 certificate information]
          
        default:
          cmdNum--;
          break;
        }  // switch(cmdBuf[0])
      PRINT_RETURN_CODE(result);
      
    }
  return 0;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: tcert_PrintConfigInfo                                           */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

void tcert_PrintConfigInfo(unsigned int min, unsigned int max)
{
  int i;
  char str[MAX_CERT_PATH];
  
  if (max > CERTCFG_MAX_PROPERTY)
    max = CERTCFG_MAX_PROPERTY;
  
  for (i = min; i < max; i++)
    {
      int rValue;
      
      if (CERT_OK == (rValue = CertCfgGetObjectStrValue(i, str,
                                                         MAX_CERT_PATH)))
        printf("%s = %s\n", strPropNames[i], str);
      else
        printf("%s = %s (%d)\n", strPropNames[i], "UNKNOWN", rValue);
    }
}
void cert_printError(int errno);

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: tcert_printDatabase                                             */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

void tcert_printDatabase(void)
{
  int i;
  char database[MAX_CERT_PATH];
  
  if (CERT_OK == 
      (i = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE,
                                     database, MAX_CERT_PATH)))
    {
      char dbItem[MAX_CERT_PATH];
      
      FILE *fp = fopen(database, "r");
      
      if (fp)
        {
          while (fgets(dbItem, MAX_CERT_PATH, fp))
            printf("<%s>\n", dbItem);
        }
      else
        printf("ERROR: can't open database %s\n", database);
    }
  else
    {
      cert_printError(i);
    }
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

void tcert_DumpPKCS12(char *name)
{
  char pkcsDir[MAX_CERT_PATH];
  int i;
  if (CERT_OK == 
      (i = CertCfgGetObjectStrValue(CERTCFG_PACKAGE_DIR,
                                     pkcsDir, MAX_CERT_PATH)))
    {
      char pkgPath[MAX_CERT_PATH];
      //      FILE *fp;
      
      sprintf(pkgPath, "%s/%s", pkcsDir, name);
      tcert_DumpPKCS12(pkgPath);
    }
  else
    printf("ERROR: Package directory is not set\n");
}

#include <dirent.h>

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: tcert_ListDirExt                                                */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

void tcert_ListDirExt(char *dir, char *ext, int level)
{
    struct dirent **namelist;
    int n;

    n = scandir(dir, &namelist, 0, alphasort);

    if (0 > n)
    {
	;// perror("tcert_ListDirExt");
    }
    else
    {
	while (n--)
	{
	    char *val;

	    if (strcmp(namelist[n]->d_name, ".") &&
		    strcmp(namelist[n]->d_name, "..")) {
		if (0 != (val = strpbrk((const char *)namelist[n]->d_name, ".")))
		{
		    if (!strcmp(++val, ext))
		    {
			int i;
			for (i = 0; i < level; i++)
			    printf("\t");

			printf("%s\n", namelist[n]->d_name);
		    }
		}
		else  {
		    printf("**%s %s (%p)\n", namelist[n]->d_name, ext, val);
		}
	    }
	    free(namelist[n]);
	}
	free(namelist);
    }
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: cert_printError                                                 */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

/* 
 * Name strings are found in cert_debug.h
 */

void cert_printError(int errCode)
{
  int errIdx = errCode;

  if (errCode > CERT_MAX_RETURN_CODE)
    errIdx = CERT_MAX_RETURN_CODE;

  printf("ERROR %d: %s\n", errCode, strErrorNames[errIdx]);
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: printUsage                                                      */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

void printUsage(char *usageList[], int number)
{
  int i;

  for (i = 0; i < number; i++)
    {
      printf("%s\n", usageList[i]);
    }
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: testAPI                                                         */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

enum CertApiList
  {
    CERT_API_INIT_CERT_MGR,
    CERT_API_RESET_CONFIG,
    CERT_READ_KEY_PACKAGE_DIRECT,
    CERT_INSTALL_KEY_PACKAGE_DIRECT,
    CERT_INSTALL_KEY_PACKAGE,
    CERT_GET_CERTIFICATE_COUNT,
    CERT_REMOVE_CERTIFICATE,
    CERT_API_MAX_VALUE
  };

#define API_NAME_LIST_SIZE (CERT_API_MAX_VALUE+1)
char *APINameList[API_NAME_LIST_SIZE] =
  {
    "CertInitCertMgr",
    "CertResetConfig",
    "CertReadKeyPackageDirect",
    "CertInstallKeyPackageDirect",
    "CertInstallKeyPackage",
    "CertGetCertificateCount",
    "CertRemoveCertificate",
    "UNKNOWN"
  };

char *APICommandList[API_NAME_LIST_SIZE] =
  {
    "Available configuration info:",
    "\tCertInitCertMgr [config]: Initialize the system",
    "\tCertResetConfig  [config]: Initialize the system",
    "\tCertReadPackageDirect <package> <dir>: Initialize the system",
    "\tCertInstallKeyPackageDirect <package> <dir> <passphrase>: Install a package",
    "\tCertInstallKeyPackage <package> <passphrase>: Install a package, default location",
    "\tCertGetCertificateCount",
    "\tCertRemoveCertificate <certificateID>",
  };
int tcert_resolveStatusSwitch(int value);

int TCertResolveApi(char *ApiName)
{
  int i;

  if (NULL == ApiName)
    return CERT_API_MAX_VALUE;

  for (i = 0; i < CERT_API_MAX_VALUE; i++)
    {
      if (0 == strcmp(APINameList[i], ApiName))
        break;
    }
  return i;
}

int testAPI(char *ApiName, char *param1, char* param2, char *param3)
{
  int result = CERT_OK;
  int apiValue = TCertResolveApi(ApiName);
  int passPhraseLen;
  char passPhrase[64];
  int serial;

  memset (passPhrase,0,sizeof(passPhrase));
  switch (apiValue)
    {
    case CERT_API_INIT_CERT_MGR:
      result = CertInitCertMgr(param1);
      break;

    case CERT_API_RESET_CONFIG:
      break;

    case CERT_READ_KEY_PACKAGE_DIRECT:
      result = CertReadKeyPackageDirect(param1, param2, NULL, NULL, &serial);
      break;

    case CERT_INSTALL_KEY_PACKAGE_DIRECT:
      if ('H' == param3[0]) // I just don't feel like doing the right thing
        {
          strcpy(passPhrase, "Help Im a Rock");
        }
      else
        {
          passPhraseLen = strlen(param3) - 1;
          strncpy(passPhrase, &param3[1], passPhraseLen);
        }
      result = CertInstallKeyPackageDirect(param1, param2, NULL, passPhrase,
                                           &serial);
      break;

    case CERT_INSTALL_KEY_PACKAGE:
      if (param2) {
	if ('H' == param2[0]) // I just don't feel like doing the right thing
        {
          strcpy(passPhrase, "Help Im a Rock");
        }
      else
        {
          passPhraseLen = strlen(param2);
          strncpy(passPhrase, param2, passPhraseLen);
        }
	}
      result = CertInstallKeyPackage(param1, NULL, passPhrase, &serial);
      break;

    case CERT_GET_CERTIFICATE_COUNT:
      {
        int status, count;

        if (NULL == param1)
          {
            status = CERT_STATUS_ALL;
          }
        else
          {
            status = tcert_resolveStatusSwitch(param1[0]);
          }
        result = CertGetCertificateCount(status, &count);

        if (CERT_OK == result)
          printf("%d certificates\n", count);
      }
      break;

    case CERT_REMOVE_CERTIFICATE:
      {
        int certID;
        
        if (NULL != param1)
          {
            sscanf(param1, "%X", &certID);
            result = CertRemoveCertificate(certID);
          }
        else
          {
            printf("Missing certificate ID\n");
            printf("%s\n", APICommandList[CERT_REMOVE_CERTIFICATE + 1]);
          }
      }
      break;

    default:
      printUsage(APICommandList, API_NAME_LIST_SIZE);
      result = CERT_OK;
      break;
    }
  return result;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: displayConfigDetail                                             */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

#define CONFIG_DETAIL_LIST_SIZE 9
char *configDetailList[CONFIG_DETAIL_LIST_SIZE] =
  {
    "Available configuration info:",
    "\tc a[ll]: all configuration data",
    "\tc f[ile] <new>: configuration file name",
    "\tc l[ist] <dir> <: Directory listing",
    "\tc n[ame] <new>: The configuration name",
    "\tc p[rivate]: The private key directory",
    "\tc r[oot]: The root directory",
    "\tc s[erial]: the serial number file",
    "\tc x: reread the configuration",
  };

int displayConfigDetail(char *configOption, char *configUpdate)
{
  int result;

  if (NULL == configOption)
    {
      printUsage(configDetailList, CONFIG_DETAIL_LIST_SIZE);
      return 0;
    }

  switch (configOption[0])
    {
      //      char str[MAX_CERT_PATH];
      //int rValue;
      
    case 'a': /* "\tc a[ll]: all configuration data", */
      tcert_PrintConfigInfo(0, CERTCFG_MAX_PROPERTY);
      break;
      
    case 'f': /* "\tc f[ile] <new>: configuration file name", */
      tcert_PrintConfigInfo(CERTCFG_CONFIG_FILE,
                            CERTCFG_CONFIG_FILE + 1);
      if (NULL != configUpdate)
        {
          CertCfgSetObjectStrValue(CERTCFG_CONFIG_FILE,
                                    configUpdate); 
          printf("\tChanged to\n");
          tcert_PrintConfigInfo(CERTCFG_CONFIG_FILE,
                                CERTCFG_CONFIG_FILE + 1);
        }
      break;
      
    case 'n': /* "\tc n[ame] <new>: The configuration name", */
      tcert_PrintConfigInfo(CERTCFG_CONFIG_NAME,
                            CERTCFG_CONFIG_NAME + 1);
      if (NULL != configUpdate)
        {
          CertCfgSetObjectStrValue(CERTCFG_CONFIG_NAME,
                                    configUpdate); 
          printf("\tChanged to\n");
          tcert_PrintConfigInfo(CERTCFG_CONFIG_NAME,
                                CERTCFG_CONFIG_NAME + 1);
        }
      break;
      
    case 'p': /* "\tc p[rivate]: The private key directory", */
      tcert_PrintConfigInfo(CERTCFG_PRIVATE_KEY_DIR,
                            CERTCFG_PRIVATE_KEY_DIR + 1);
      break;
      
    case 'r': /* "\tc r[oot]: The root directory", */
      tcert_PrintConfigInfo(CERTCFG_ROOT_DIR,
                            CERTCFG_ROOT_DIR + 1);
      break;
      
    case 's': /* "\tc s[erial]: the serial number file", */
      tcert_PrintConfigInfo(CERTCFG_CERT_SERIAL,
                            CERTCFG_CERT_SERIAL + 1);
      break;
    case 't': /* "\tc t[rust]: the trusted CA cert dir", */
      tcert_PrintConfigInfo(CERTCFG_TRUSTED_CA_DIR,
                            CERTCFG_TRUSTED_CA_DIR + 1);
      break;
      
      
    case 'x': /* "\tc x: reread the configuration", */
      // purposefully don't check the parameter
      // to allow bogus values
      if (CERT_OK != (result = CertResetConfig(configUpdate)))
        {
          printf("ERROR[%d]: could not reset with %s\n",
                 result, configUpdate);
          PRINT_RETURN_CODE(result);
        }
      break;
      
    default:
      printUsage(configDetailList, CONFIG_DETAIL_LIST_SIZE);
    } return 0;
}


/*****************************************************************************/
/*                                                                           */
/* FUNCTION: tcert_TestDatabase                                              */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

#define  DATABASE_DETAIL_LIST_SIZE 5
char *databaseDetailList[DATABASE_DETAIL_LIST_SIZE] = 
  {
      "Available install functions:",
      "\tdb c[ertificate] <status> [file]: list the certificates by status",
      "\tdb l[ist] [long | help]: list the certificates in the database",
      "\tdb r[ead] [database]: Read the database",
      "\tdb w[rite] [database]: Write out the database",
  };

int CertUpdateDatabase(void);

int tcert_TestDatabase(char *dbCmd, char *param1, char *param2)
{
  int result = CERT_OK;


  if (NULL == dbCmd)
    {
      printUsage(databaseDetailList, DATABASE_DETAIL_LIST_SIZE);
      return CERT_OK;
    }

  switch(dbCmd[0])
    {
    case 'c':
      {
        int statusSwitch = 0;
        int certList[100];
        int certNb = 100;
        int i;
        
        if (NULL != param1)
          statusSwitch = tcert_resolveStatusSwitch(param1[0]);

        if (NULL != param2)
          {
            result = CertListDatabaseCertsByStatusDirect(param2, statusSwitch,
                                                         certList, &certNb);
          }
        else
          {
            result = CertListDatabaseCertsByStatus(statusSwitch,
                                                   certList, &certNb);
            
          }

        if (CERT_OK == result)
          for (i = 0; i < certNb; i++)
            printf("%X found\n", certList[i]);
      }
      break;

    case 'l':  // list the certificates in the database
      {
        int i;
        int items;
        
        result = CertGetDatabaseInfo(CERT_DATABASE_SIZE, &items);
        for (i = 0; i < items; i++)
          {
            char fileStr[128];
            char propStr[128];
            char serlStr[128];
            char nameStr[128];
            char startStr[128];
            char endStr[128];
            char installStr[128];
            
            result = CertGetDatabaseStrValue(i, CERT_DATABASE_ITEM_STATUS,
                                      propStr, 128);
            result = CertGetDatabaseStrValue(i, CERT_DATABASE_ITEM_FILE,
                                      fileStr, 128);
            result = CertGetDatabaseStrValue(i, CERT_DATABASE_ITEM_SERIAL,
                                      serlStr, 128);
            result = CertGetDatabaseStrValue(i, CERT_DATABASE_ITEM_EXPIRATION,
                                      endStr, 128);
            result = CertGetDatabaseStrValue(i, CERT_DATABASE_ITEM_START,
                                      startStr, 128);
            result = CertGetDatabaseStrValue(i, CERT_DATABASE_ITEM_NAME,
                                      nameStr, 128);
            if (param1)
              {
                if (param1[0] == 'l')
                  {
                    fprintf(stdout,
                       "Certificate %s:\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n",
                            serlStr, propStr, fileStr,
                            startStr, endStr, nameStr, installStr);
                  }
              }
            else
              {
                fprintf(stdout, 
                        "Certificate %s: <%s><%s>\n",
                        serlStr, propStr, fileStr);
              }
          }
      }
      break;
    case 'r':  // Read in the database
      {

        if (NULL == param1)
          {
            char dbfile[MAX_CERT_PATH];
            
            result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE,
                                              dbfile, MAX_CERT_PATH);
            if (CERT_OK != result)
              {
                PRINT_RETURN_CODE(result);
              }
            else
              result = CertReadDatabase(dbfile);
          }
        else
          {
            result = CertReadDatabase(param1);
          }
      }
      break;

    case 'w':  // write out the database
      {

        if (NULL == param1)
          {
            char dbfile[MAX_CERT_PATH];
            
            result = CertCfgGetObjectStrValue(CERTCFG_CERT_DATABASE,
                                              dbfile, MAX_CERT_PATH);
            if (CERT_OK != result)
              {
                PRINT_RETURN_CODE(result);
              }
            else
              result = CertWriteDatabase(dbfile);
          }
        else
          {
            result = CertWriteDatabase(param1);
          }
      }
      break;

    default:
      break;
    }
  return result;
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: tcert_InstallPackage                                            */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

#define  INSTALL_DETAIL_LIST_SIZE 5
char *installDetailList[INSTALL_DETAIL_LIST_SIZE] = 
  {
      "Available install functions:",
      "\ti d[elete] <pkg_serial#>: delete the given package",
      "\ti i[nstall] <pkg>: Install the components of <pkg>",
      "\ti r[aw] type <pkg>: insert a raw package into its directory",
      "\ti s[erial] [i]: current serial number [increment]",
  };

/*****************************************************************************/

#define  INSTALL_RAW_DETAIL_LIST_SIZE 5
char *installRawDetailList[INSTALL_RAW_DETAIL_LIST_SIZE] = 
  {
    "*\t\ti r a <pkg>: insert a authorized certificate",
    "*\t\ti r c <pkg>: insert a certificate",
    "*\t\ti r p <pkg>: insert a public key",
    "\t\ti r r <pkg>: insert a raw package",
    "*\t\ti r s <pkg>: insert a private (secret) key"
  };

void tcert_InstallPackage(char *opt, char *param1, char *param2)
{
  char pkgName[MAX_CERT_PATH];
  //  char serialFile[MAX_CERT_PATH];
  int rValue; //, nOpts;
  int serialNb;
  
  if (NULL == opt)
    {
      printf("Install option not named\n");
      printUsage(installDetailList, INSTALL_DETAIL_LIST_SIZE);
      return;
    }
  if (NULL == param1)
    {
      printf("Install file type not named\n");
      printUsage(installDetailList, INSTALL_DETAIL_LIST_SIZE);
      return;
    }
  
  switch(opt[0])
    {
    case 'd':  // delete an installed package
	if (NULL == param1) {
		printf("Cert not named\n");
	}
	else {
		serialNb = atoi(param1);
	}
		
	printf("deleting #%d\n",serialNb);
	rValue = CertRemoveCertificate(serialNb);
	PRINT_RETURN_CODE(rValue);
	
      break;
      
    case 'i':  // install the package
      
      if (CERT_OK ==
          (rValue = CertCfgGetObjectValue(CERTCFG_CERT_SERIAL,
                                           &serialNb)))
        {
          printf("installing %s (#%d)\n", param1, serialNb);
          rValue = CertInstallKeyPackage(param1,
                                          NULL,
                                          "Help Im a Rock", &serialNb);
          PRINT_RETURN_CODE(rValue);

	  printf("Authorizing %s (#%d)\n", param1, serialNb);
	  rValue = CertAddAuthorizedCert(serialNb);
          PRINT_RETURN_CODE(rValue);
	  
        }
      else
        {
          printf("Unavailable serial number file (%d)\n", rValue);
          PRINT_RETURN_CODE(rValue);
        }
      break;
      
    case 'r': // insert unexploded file (raw) into its default dir
      if (NULL == param2)
        {
          printf("Package not named\n");
          printUsage(installRawDetailList, INSTALL_RAW_DETAIL_LIST_SIZE);
          return;
        }
      switch (param2[0])
        {
        case 'r':  // raw (container p12 usually)
          { char rawDir[64];
            //            char rawFile[64];
            struct stat statBuf;
            
            rValue = CertCfgGetObjectStrValue(CERTCFG_PACKAGE_DIR,
                                               rawDir,
                                               MAX_CERT_PATH);
            if (rValue != CERT_OK)
              {
                printf("ERROR: unable to get the raw directory\n");
                PRINT_RETURN_CODE(rValue);
              }
            else if (!strlen(rawDir))
              {
                printf("ERROR: Degenerate string for the raw directory\n");
              }
            else if (0 != (rValue = stat(param2, &statBuf)))
              {
                perror("testprog");
                printf("ERROR: File <%s> is not good\n", param2);
              }
            else
              {
                char rawFile[64];
                
                sprintf(rawFile, "%s/%s", rawDir, basename(param2));
                if (-1 == rename(param2, rawFile))
                  {
                    perror("raw grab");
                  }
              }
          }
          break;
          
        case 'a':
        case 'c':
        case 'p':
        case 's':
          printf("UNIMPLEMENTED\n");
          break;
          
        default:
          printUsage(installRawDetailList, INSTALL_RAW_DETAIL_LIST_SIZE);
          break;
        }
      break;
      
    case 's':  // check the serial number possibly increment
      if (CERT_OK ==
          (rValue = CertCfgGetObjectStrValue(CERTCFG_CERT_SERIAL,
                                              pkgName,
                                              MAX_CERT_PATH)))
        {
          //          printf("Lock file == %d\n", CertLockFile(0));
          
          if ('i' == param1[0])
            {
              fprintf(stdout, "CALL 4\n");
              
              rValue = CertGetSerialNumberInc(pkgName, 1);
            }
          else
            rValue = CertGetSerialNumber(pkgName);
          printf("Unlock file == %d\n", CertUnlockFile(0));
          printf("Serial Number = %d\n", rValue);
        }
      else
        printf("Unavailable serial number file (%d)\n", rValue);
      break;
      
    default:
      printUsage(installDetailList, INSTALL_DETAIL_LIST_SIZE);
      break;
    }
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: tcert_PrivatekeyInfo                                            */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

#define PKEY_INFO_LIST_SIZE 3
char *pKeyInfoList[PKEY_INFO_LIST_SIZE] = 
  {
    "Available private key information:",
    "\tp d[nfo] <key>: dump information on the given key",
    "\tp l[ist]: list the private keys"
  };

void tcert_PrivatekeyInfo(char *pKeyOption,
                          char *pKeyName,
                          char *param3p)
{
  //  char privOpt[MAX_CERT_PATH];
  char privDir[MAX_CERT_PATH];
  //char privKeyName[MAX_CERT_PATH];
  int rValue;
  
  if (NULL == pKeyOption)
    {
      printUsage(pKeyInfoList, PKEY_INFO_LIST_SIZE);
    }
  switch(pKeyOption[0])
    {
    case 'd':
      if (NULL == pKeyName)
        {
          printf("ERROR: Key not named\n");
        }
      else
        printf("UNIMPLEMENTED\n");
      break;
      
    case 'l':  // list private keys
      if (CERT_OK ==
          (rValue = CertCfgGetObjectStrValue(CERTCFG_PRIVATE_KEY_DIR,
                                              privDir, MAX_CERT_PATH)))
        tcert_ListDirExt(privDir, "pem", 1);
      else
        printf("Unavailable private key dir\n");
      break;
      
    default:
      printUsage(pKeyInfoList, PKEY_INFO_LIST_SIZE);
      break;
    }
}



/*****************************************************************************/
/*                                                                           */
/* FUNCTION: tcert_RawPackageInfo                                            */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

#define RAW_FILE_INFO_LIST_SIZE 3
char *rawFileInfoList[RAW_FILE_INFO_LIST_SIZE] = 
  {
    "Available raw package (r) queries:",
    "\tr l[ist]: list all packages (pem, p12, pfx, der)",
    "\tr d[ump] <pkg>: dump the package information"
  };

void tcert_RawPackageInfo(char *rawOpt, char *pkgName, char *param3p)
{
  char rawDir[MAX_CERT_PATH];
  int rValue; //, nOpts;
  
  if (NULL == rawOpt)
    {
      printf("ERROR: Raw file option not set\n");
      printUsage(rawFileInfoList, RAW_FILE_INFO_LIST_SIZE);
      return;
    }
  
  switch(rawOpt[0])
    {
    case 'd':
      {
        int fType = returnFileType(pkgName);
        
        switch(fType)
          {
          case CERT_P12_FILE:
            tcert_DumpPKCS12(pkgName);
            break;
          default:
            printf("Unimplemented type for %s (%d)\n",
                   pkgName, fType);
            break;
          }
      }
      break;
      
    case 'l':  // l[ist raw packages]
      if (CERT_OK ==
          (rValue = CertCfgGetObjectStrValue(CERTCFG_PACKAGE_DIR,
                                              rawDir, MAX_CERT_PATH)))
        {
          //printf("\tPEM files (.pem):\n");
          tcert_ListDirExt(rawDir, "pem", 2);
          //printf("\tPKCS files (.p12):\n");
          tcert_ListDirExt(rawDir, "p12", 2);
          //printf("\tPKCS files (.pfx):\n");
          tcert_ListDirExt(rawDir, "pfx", 2);
          //printf("\tDER files (.der):\n");
          tcert_ListDirExt(rawDir, "der", 2);
        }
      else
        printf("ERROR: Unavailable package dir (errno == %d)\n", rValue);
      break;
      
    default:
      printUsage(rawFileInfoList, RAW_FILE_INFO_LIST_SIZE);
    }
}

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: tcert_X509PackageInfo                                           */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/
#define X509_INFO_LIST_SIZE 6
char *x509InfoList[] =
  {
    "Available certificate (X.509) queries:",
    "\tx d[atabase dump]",
    "\tx i[nstall] <pkg>: verify and install a certificate",
    "\tx s[erial number]",
    "\tx x[plode] <prop> <pkg>",
    "\tx v[alidate] <serial#>: validate the certificate"
  };

#define X509_EXPLODE_LIST_SIZE 2
char *x509ExplodeList[X509_EXPLODE_LIST_SIZE] = 
  {
    "\t\tx x a <pkg>: dump everything",
    "\t\tx x i <pkg>: issuer"
  };

#define X509_EXPLODE_PROPERTY_LIST_SIZE 9
char *x509ExplodePropertyList[X509_EXPLODE_PROPERTY_LIST_SIZE] =
{
  "\t\tx x b <pkg>: begin date for certificate",
  "\t\tx x e <pkg>: end date for the certificate",
  "\t\tx x i <pkg>: issuer",
  "\t\tx x o <pkg>: subject organization",
  "\t\tx x O <pkg>: issuer organization",
  "\t\tx x s <pkg>: subject",
  "\t\tx x S <pkg>: subject surname",
  "\t\tx x u <pkg>: subject organizational unit",
  "\t\tx x U <pkg>: issuer organizational unit"
};

#define X509_PROPERTY_NAME_LIST_SIZE 10

char *x509PropertyNameList[X509_PROPERTY_NAME_LIST_SIZE] = 
{
  "CERTX509_ISSUER_ORGANIZATION_NAME",
  "CERTX509_ISSUER_COMMON_NAME",
  "CERTX509_ISSUER_ORGANIZATION_UNIT_NAME",
  "CERTX509_ISSUER_SURNAME",
  "CERTX509_SUBJECT_ORGANIZATION_NAME",
  "CERTX509_SUBJECT_COMMON_NAME",
  "CERTX509_SUBJECT_ORGANIZATION_UNIT_NAME",
  "CERTX509_SUBJECT_SURNAME",
  "CERTX509_START_DATE",
  "CERTX509_EXPIRATION_DATE"
};

//int CertPemToX509(const char* pemPath, X509** hCert);
void tcert_X509PackageInfo(char *certOpt, char *explodeProp, char *certFile)
{
  //  char param1[MAX_CERT_PATH];
  //char param2[MAX_CERT_PATH];
  
  if (NULL == certOpt)
    {
      printUsage(x509InfoList, X509_INFO_LIST_SIZE);
      return;
    }
  
  switch (certOpt[0])
    {
    case 'd':  // d[atabase of current certificates]
      tcert_printDatabase();
      break;
      
    case 'i':  // i[nstall] and validate a certificate
      if (NULL == explodeProp)
        {
          printf("ERROR: undefined explode option\n");
          printUsage(x509InfoList, X509_INFO_LIST_SIZE);
          break;
        }
      else
        {
          int serial = 0;

          sscanf(explodeProp, "%x", &serial);

          if (0 != serial)
            CertAddAuthorizedCert(serial);
          
        }
      break;
      
    case 's':  // s[erial number]
      printf("UNIMPLEMENTED\n");
      break;

    case 'v':
      if (NULL == explodeProp)
        {
          printf("ERROR: undefined certificate serial number\n");
          printUsage(x509InfoList, X509_INFO_LIST_SIZE);
          break;
        }
      else
        {
          int serial = 0;

          sscanf(explodeProp, "%x", &serial);

          if (0 != serial)
            CertValidateCertificate(serial);
          
        }
      break;
      
    case 'x': // x[plode] the given certificate
      if (NULL == explodeProp)
        {
          printf("ERROR: undefined explode option\n");
          printUsage(x509ExplodePropertyList, X509_EXPLODE_PROPERTY_LIST_SIZE);
          break;
        }
      else if (NULL == certFile)
        {
          printf("ERROR: undefined certificate name\n");
          break;
        }
      else
        {
          X509 *cert;
          int fileType;
          unsigned int result;
          int property = CERTX509_UNKNOWN_PROPERTY;
          char propertyStr[64];
          
          fileType = returnFileType(certFile);
          switch (fileType)
            {
            case CERT_PEM_FILE:
              result = CertPemToX509(certFile, &cert);
              break;
              
            default:
              printf("ERROR: Illegal file type for %s (%d)\n",
                     certFile, fileType);
              result = CERT_UNSUPPORTED_CERT_TYPE;
            }
          if (CERT_OK != result)
            {
              PRINT_RETURN_CODE(result);
              break;;
            }
          switch(explodeProp[0])
            {
            case 'b': // Begining of certificate period
              property = CERTX509_START_DATE;
              break;
              
            case 'e': // End of certificate period
              property = CERTX509_EXPIRATION_DATE;
              break;
              
            case 'i': // issuer
              property = CERTX509_ISSUER_COMMON_NAME;
              break;
              
            case 'o': // subject Org
              property = CERTX509_SUBJECT_ORGANIZATION_NAME;
              break;
              
            case 'O': // issuer Org
              property = CERTX509_ISSUER_ORGANIZATION_NAME;
              break;
              
            case 's': // subject common name
              property = CERTX509_SUBJECT_COMMON_NAME;
              break;
              
            case 'S': // subject Surname
              property = CERTX509_SUBJECT_SURNAME;
              break;
              
            case 'u': // subject organization unit
              property = CERTX509_SUBJECT_ORGANIZATION_UNIT_NAME;
              break;

            case 'U': // issuer organization unit
              property = CERTX509_ISSUER_ORGANIZATION_UNIT_NAME;
              break;
            }
          
          if (property == CERTX509_UNKNOWN_PROPERTY)
            {
              printf("ERROR: Unknown property %s\n", explodeProp);
              printUsage(x509ExplodePropertyList, X509_EXPLODE_PROPERTY_LIST_SIZE);
              result = CERT_UNKNOWN_PROPERTY;
           }
          else if ((CERTX509_START_DATE == property) ||
                   (CERTX509_EXPIRATION_DATE == property))
            {
              result = CertX509ReadTimeProperty(cert,
                                                property,
                                                propertyStr, 64);
            }
          else
            {
              result = CertX509ReadStrProperty(cert,
                                               property,
                                               propertyStr, 64);
            }
          if (CERT_OK == result)
            {
              printf("%s::%s\n",
                     x509PropertyNameList[property],
                     propertyStr);
            }
          else
            PRINT_RETURN_CODE(result);
        }
      break;
      
    default:
      printUsage(x509InfoList, X509_INFO_LIST_SIZE);
      break;
    }
}



int tcert_resolveStatusSwitch(int value)
{
  int rValue;

  switch(value)
    {
    case 'x':
      rValue = CERT_STATUS_ALL;
      break;
    case 'c':
      rValue = CERT_STATUS_TRUSTED_SERVER_CA;
      break;
    case 'C':
      rValue = CERT_STATUS_VALID_CA;
      break;
    case 'E':
      rValue = CERT_STATUS_EXPIRED;
      break;
    case 'p':
      rValue = CERT_STATUS_VALID_PEER;
      break;
    case 'P':
      rValue = CERT_STATUS_TRUSTED_PEER;
      break;
    case 'R':
      rValue = CERT_STATUS_REVOKED;
      break;
    case 'S':
      rValue = CERT_STATUS_SUSPENDED;
      break;
    case 'T':
      rValue = CERT_STATUS_TRUSTED_CLIENT_CA;
      break;
    case 'V':
      rValue = CERT_STATUS_VALID_CERT;
      break;
    case 'u':
      rValue = CERT_STATUS_USER_CERTIFICATE;
      break;
    case 'w':
      rValue = CERT_STATUS_WARNING;
      break;
    case 'X':
      rValue = CERT_STATUS_UNKNOWN;
      break;
    default:
      rValue = CERT_STATUS_UNDEFINED;
      break;
    }

  return rValue;
}

