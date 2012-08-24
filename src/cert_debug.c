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
/* cert_debug.c                                                              */
/*****************************************************************************/

const char *strProps[] = 
  {
    "CERTCFG_CONFIG_FILE",
    "CERTCFG_CONFIG_NAME",
    "CERTCFG_ROOT_DIR",
    "CERTCFG_CERT_DIR",
    "CERTCFG_CERTIFICATE",
    "CERTCFG_PRIVATE_KEY_DIR",
    "CERTCFG_PRIVATE_KEY",
    "CERTCFG_CERT_DATABASE",
    "CERTCFG_CERT_SERIAL",
    "CERTCFG_PUBLIC_KEY_DIR",
    "CERTCFG_CRL_DIR",
    "CERTCFG_PACKAGE_DIR",
    "CERTCFG_AUTH_CERT_DIR",
    "CERTCFG_MAX_PROPERTY"
  };

const char *strPropNames[] = 
  {
    "Configuration file",
    "Configuration name",
    "Root directory",
    "Certificate directory",
    "Certificate",
    "Private Key directory",
    "Private Key",
    "Certificate Database",
    "Certificate Serial Number file",
    "Public Key directory",
    "Certificate Revocation List directory",
    "Raw package directory",
    "Authorized Certificate directory",
    "UNKNOWN PROPERTY"
  };

const char *strErrorNames[] =
  {
  "CERT_OK",
  "CERT_GENERAL_FAILURE",
  "CERT_UNSUPPORTED_CERT_TYPE",
  "CERT_ILLEGAL_KEY_PACKAGE_TYPE",
  "CERT_NULL_BUFFER",
  "CERT_BUFFER_LIMIT_EXCEEDED",
  "CERT_OPEN_FILE_FAILED",
  "CERT_FILE_ACCESS_FAILURE",
  "CERT_FILE_READ_FAILURE",
  "CERT_UNDEFINED_ROOT_DIR",
  "CERT_DUPLICATE",
  "CERT_MEMORY_ERROR",
  "CERT_ITER_EXCEED",
  "CERT_INVALID_ARG",
  "CERT_PASSWD_WRONG",
  "CERT_LINK_ERR",                  // File (un)link was unsuccessfull
  "CERT_INSUFFICIENT_BUFFER_SPACE", // User passed in buffer space 
  "CERT_PATH_LIMIT_EXCEEDED",       // The path is too long
  "CERT_UNDEFINED_DESTINATION",    // The directory doesn't exist
  "CERT_TEMP_FILE_CREATION_FAILED",
  "CERT_CONFIG_UNAVAILABLE",        // config doesn't exist in the file
  "CERT_UNKNOWN_PROPERTY",          // the property doesn't exist
  "CERT_PROPERTY_NOT_FOUND",        // The property couldn't be resolved
  "CERT_PROPERTY_STRING_NOT_FOUND", // No string associated with the property
  "CERT_ILLFORMED_CONFIG_FILE",     // Something's broken in the file
  "CERT_DATE_PENDING",
  "CERT_DATE_EXPIRED",
  "CERT_FILE_PARSE_ERROR",
  "CERT_LOCK_FILE_CREATION_FAILURE",
  "CERT_BAD_CERTIFICATE",
  "CERT_SERIAL_NUMBER_FILE_UNAVAILABLE",
  "CERT_SERIAL_NUMBER_UNAVAILABLE",
  "CERT_DATABASE_INITIALIZATION_ERROR",
  "CERT_DATABASE_NOT_AVAILABLE",
  "CERT_DATABASE_OUT_OF_BOUNDS",
  "CERT_DATABASE_LOCKED",
  "CERT_TOO_MANY_HASHED_FILES",
  "UNKNOWN ERROR"
  };
