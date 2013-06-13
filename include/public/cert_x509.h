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

/*****************************************************************************/
/* cert_x509.h: interaction with X.509 package files                         */
/*****************************************************************************/

#ifndef __CERT_X509_H__
#define __CERT_X509_H__

#include <sys/types.h>

#include <openssl/x509.h>

typedef enum
  {
    CERTX509_ISSUER_ORGANIZATION_NAME,
    CERTX509_ISSUER_COMMON_NAME,
    CERTX509_ISSUER_ORGANIZATION_UNIT_NAME,
    CERTX509_ISSUER_SURNAME,
    CERTX509_ISSUER_COUNTRY,
    CERTX509_ISSUER_STATE,
    CERTX509_ISSUER_LOCATION,
    
    CERTX509_SUBJECT_ORGANIZATION_NAME,
    CERTX509_SUBJECT_COMMON_NAME,
    CERTX509_SUBJECT_ALT_NAME, //ALT NAME
    CERTX509_SUBJECT_ORGANIZATION_UNIT_NAME,
    CERTX509_SUBJECT_SURNAME,
    CERTX509_SUBJECT_COUNTRY,
    CERTX509_SUBJECT_STATE,
    CERTX509_SUBJECT_LOCATION,

    CERTX509_START_DATE,
    CERTX509_EXPIRATION_DATE,
    CERTX509_UNKNOWN_PROPERTY
  } X509Properties;

#ifdef __cplusplus
extern "C"
{
#endif

int CertX509ReadStrProperty(X509 *cert, int property, char *pBuf, int len);
int checkCert(X509 *cert, char *CAFile, char *CAPath);
int CertX509ReadTimeProperty(X509 *cert, int property, char *pBuf, int len);

void CertX509Dump(X509 *cert);

#ifdef __cplusplus
}
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#endif //  __CERT_X509_H__
