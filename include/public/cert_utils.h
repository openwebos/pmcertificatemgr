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

/****************/
/* cert_utils.h */
/****************/

#ifndef __CERT_UTILS_H__
#define __CERT_UTILS_H__

#include <openssl/pkcs12.h>
#include "cert_mgr.h"
#include "cert_cfg.h"

typedef enum
  {
    CERT_FILELOCK_SERIAL,
    CERT_FILELOCK_DATABASE,
  } CertFileLock_t;

#ifdef __cplusplus
extern "C" {
#endif

int getTimeString(ASN1_TIME* time_data, char* buf, int buflen);
int CertGetSerialNumber(char *path);
int CertGetSerialNumberInc(char *path, int increment);
int CertLockFile(int fileType);
int CertUnlockFile(int fileType);
int CertInitLockFiles(char *rootDir);
char *buildPath(int destDirType, int objectType);
char *serialPathName(char *baseName, int destDirType, CertObject_t objectType, int serial);
char *serialPathNameCount(char *baseName, int destDirType, CertObject_t objectType, int serial, int count);
int checkCertDates(X509* cert);
int getPrivKeyType(EVP_PKEY *pkey);
char *fileBaseName(const char *pPath);
CertReturnCode_t makePath(char *file,
                          certcfg_Property_t fileType,
                          char* path, int32_t len);
CertReturnCode_t certSerialNumberToFileName(const int32_t serialNb,
                                            char *buf,
                                            int32_t bufLen);

#ifdef __cplusplus
}
#endif

#endif  // __CERT_UTILS_H__
