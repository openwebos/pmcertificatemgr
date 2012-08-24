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
/* cert_pkcs.c: interaction with PCKS package files                          */
/*****************************************************************************/
#include <stdio.h>

#include <openssl/pkcs12.h>

#include "cert_mgr.h"
#include "cert_cfg.h"
#include "cert_x509.h"

/* taken from openssl/crypto/objects/objects.h */
#define ENCRYPT_NAME_MAX 25
const char *encryptNames[ENCRYPT_NAME_MAX] = 
  {
    "undefined",
    "rsadsi",
    "pkcs",
    "md2",
    "md5",
    "rc4",
    "rsaEncryption",
    "m2dWithRSAEncryption",
    "md5WithRSAEncryption",
    "pbeWithMD2AndDES-CBC",
    "pbeWithMD5AndDES-CBC",
    "X500",
    "X509",
    "CommonName",
    "CountryName",
    "locality",
    "State",
    "Organization",
    "OrganizationUnitName",
    "RSA",
    "pkcs7",
    "pkcs7-data",
    "pkcs7-signedData",
    "pkcs7-envelopeData",
    "pkcs7-signedAndEnvelopedData",
  };

/*****************************************************************************/
/*                                                                           */
/* FUNCTION: CertPKCS12Dump                                                  */
/* INPUT:                                                                    */
/* OUTPUT:                                                                   */
/* RETURN:                                                                   */
/* NOTES:                                                                    */
/*                                                                           */
/*****************************************************************************/

int CertPKCS12Dump(char *pPkgPath)
{
  int result = CERT_GENERAL_FAILURE;
  FILE *fp = fopen(pPkgPath, "r");

  if (NULL != fp)
    {
      PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
      
      fclose( fp );
      
      if (NULL != p12)
        {
#if 0
          const char *pass = passForP12(p12, pwdbuf, sizeof(pwdbuf), 
                                        pcbk, pwd_ctxt);
#else
          const char *pass = "Help Im a Rock";
#endif
          if (NULL != pass)
            {
              EVP_PKEY *pkey;
              X509 *cert;
              STACK_OF(X509) *ca = NULL;
              
              if (0 != PKCS12_parse(p12, pass, &pkey, &cert, &ca))
                {
                  char destPath[MAX_CERT_PATH];
                  
                  if (NULL != pkey)
                    {
                	  result = CertCfgGetObjectStrValue(CERTCFG_PRIVATE_KEY_DIR,
                                               destPath, MAX_CERT_PATH);
                      printf("PKEY->type = %s (%d)\n",
                             encryptNames[pkey->type], pkey->type);
                      printf("PKEY->save_type = 0x%x\n", pkey->save_type);
                      EVP_PKEY_free(pkey );
                    }
                  if (NULL != cert)
                    {
                	  result = CertCfgGetObjectStrValue(CERTCFG_CERT_DIR,
                                               destPath, MAX_CERT_PATH);
                      CertX509Dump(cert);
                      X509_free(cert);
                    }
                  if (NULL != ca)
                    {
                	  result = CertCfgGetObjectStrValue(CERTCFG_PRIVATE_KEY_DIR,
                                               destPath, MAX_CERT_PATH);
                      sk_X509_free(ca);
                    }
                }
              else
                {
                  /* PKCS 12 parse error */
                }
            }
          else
            {
              /* Password failure */
            }
          PKCS12_free( p12 );
        }
    }
  return result;
  
}
