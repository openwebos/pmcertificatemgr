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

#ifndef __CERT_MGR_PRIV__
#define __CERT_MGR_PRIV__




#ifdef __cplusplus
extern "C"
{
#endif

int findSSLCertInLocalStore(X509 * cert);
int exists(const char* file);

CertReturnCode_t derToX509(const char *derPath, X509 **hCert);
CertReturnCode_t certInfoToBuffer(X509 *cert, certMgrField_t field,
                                  char *pBuf, int *pBufLen);
CertReturnCode_t removeFromPath(const int32_t,
                                const char *pCertDir,
                                const char *prefix, const char *ext,
                                int32_t *errorNb);

CertReturnCode_t mkFileNameFromHash(char *buf, int bufSize,
                                unsigned long hash, const char *infile,
				unsigned int basedir);
//CertReturnCode_t makeCertIter(cert_Iterator_t **hIter, int isSystem);
CertReturnCode_t derToFile(const char* pCertPath, const char *pDestPath, int32_t *serial);

CertReturnCode_t pemToFile(const char *pCertPath, const char *pDestPath,
                           CertPassCallback pcbk, void *pwd_ctxt, int32_t *serialNb);

CertReturnCode_t p12ToFile(const char *outfile, const char *pCertPath,
                           CertPassCallback pcbk, void* pwd_ctxt,
                           int32_t *serialNb);
CertReturnCode_t getPEMCertInfoPath(const char     *pPath,
                                    certMgrField_t  field,
                                    char *buf, int *pBufLen); 

CertReturnCode_t areSameCertFile(const char * path1, const char * path2,
                                 CertPkgType_t ctype );
CertReturnCode_t validateCertPath(const char *path,
                                  int32_t serialNb,
                                  int32_t certType,
                                  int32_t *pCMErr);
void makeUnique    (char *path);




CertReturnCode_t makePathToCert(int32_t serialNb, char *path, int len);
int seed_prng(void);

#ifdef __cplusplus
}
#endif

#endif  /* __CERT_MGR_PRIV__ */
