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
/* cert_x509.c: interaction with X.509 package files                         */
/*****************************************************************************/
#include <stdio.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "cert_mgr.h"
#include "cert_cfg.h"

#include "cert_utils.h"

#include "cert_x509.h"

#include <syslog.h>

#define CERT_X509_STORE_FLAGS  0

#ifdef D_DEBUG_ENABLED
void CertX509Dump(X509 *cert);
#endif

#if 0 /* FUTURE EXPANSION OF CAPABILITIES  1 */
static int check(X509_STORE *ctx,
                 X509 *cert,
                 STACK_OF(X509) *uchain,
                 STACK_OF(X509) *tchain, int purpose);
static STACK_OF(X509) *load_untrusted(char *certfile);
#endif

int make_property_ssl_equiv(int);
X509_NAME* get_cname(int, X509*);
int get_subjectaltname(X509*, char*, int);
int copy_csv_to_buffer(char*, char*, const int, int);
int ip_to_string(char*,int, GENERAL_NAME*);

int CertX509ReadStrProperty(X509 *cert, int property, char *pBuf, int len)
{
  int result = CERT_OK;
  int dataIdx = 0;
  X509_NAME *cName;
  //  ASN1_STRING *data;
  int lproperty;

  if (NULL == cert)
    {
      result = CERT_BAD_CERTIFICATE;
      return result;
    }

  lproperty=  make_property_ssl_equiv(property);
  cName= get_cname(property,cert);
  
  if(lproperty==NID_subject_alt_name){  // if 1
  
	  dataIdx= get_subjectaltname(cert,pBuf, len);
}  //end 1
 else{
      //### dataIdx = X509_NAME_get_text_by_NID(cName, lproperty, pBuf, len);

		char *sub_str = pBuf;
		int space_taken = 0;
		int space_left = len;

		//int loc;
		X509_NAME_ENTRY *e;
		//loc = -1;
		int lastpos = -1;
		int atleast_one_entry = 0;
		for (;;)
		{
			lastpos = X509_NAME_get_index_by_NID(cName, lproperty, lastpos);                       //(nm, NID_commonName, lastpos);
			if (lastpos == -1){
				if(atleast_one_entry)
					dataIdx = 1;
				else 
					dataIdx = -1;
				break;
			}
			atleast_one_entry = 1;
			e = X509_NAME_get_entry(cName, lastpos);
			/* Do something with e */
			ASN1_IA5STRING *data;
			data = X509_NAME_ENTRY_get_data(e);
			syslog(LOG_INFO,"all common name: %s", (char *) data->data);
			if(0 < space_left)
				space_taken= copy_csv_to_buffer(sub_str, (char *)data->data, len, space_left);
			space_left= space_left - space_taken;
		}

 }
  if (0 >  dataIdx) {
    return CERT_PROPERTY_NOT_FOUND;
  } else {
	  // trim trailing ','
	  int len = strlen(pBuf);
	  if (pBuf[len-1] == ',')
		pBuf[len-1] = '\0';
	  return CERT_OK;
  }
//
  return CERT_PROPERTY_STRING_NOT_FOUND;
}

int get_subjectaltname(X509* cert, char* buf, int buf_len){

/*
    Copy "," separated dNSName values 
    of the subjectAltName extension, to pBuf
*/

  GENERAL_NAMES *gens;
  GENERAL_NAME  *gen;
  int i;
  char *sub_str= buf;
  int space_taken=0;
  int space_left= buf_len;

  gens = X509_get_ext_d2i(cert , NID_subject_alt_name, NULL, NULL);

  for(i = 0; i < sk_GENERAL_NAME_num(gens); i++){
      gen = sk_GENERAL_NAME_value(gens, i);
      syslog(LOG_INFO,"1sub_str");

      if((gen->type == GEN_DNS)||(gen->type == GEN_URI)){
	if(0 < space_left)
	  space_taken= copy_csv_to_buffer(sub_str, (char*)gen->d.ia5->data, buf_len, space_left);
	  space_left= space_left -space_taken;
      }

      if(gen->type == GEN_IPADD){
	if(0 < space_left){
          const int oline_len = 40;
	  char oline[oline_len];
	  oline[0]='\0';
	  ip_to_string(oline, oline_len, gen);
	  space_taken= copy_csv_to_buffer(sub_str,  oline, buf_len, space_left);
	  space_left= space_left - space_taken;
	}
      }

      syslog(LOG_INFO,"2 sub_str: %s space_taken:%d space_left:%d",sub_str, space_taken, space_left);
  }

  sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
  return CERT_OK;

}


int ip_to_string(char* oline, int oline_len, GENERAL_NAME* gen)
{
  int i;
  unsigned char *p;
  char htmp[5];

  p = gen->d.ip->data;

  if(gen->d.ip->length == 4)
    BIO_snprintf(oline, oline_len,"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);  //sizeof oline replaced by 40

  else if(gen->d.ip->length == 16){
    oline[0] = 0;
    for (i = 0; i < 8; i++){
      BIO_snprintf(htmp, sizeof htmp,"%X", p[0] << 8 | p[1]);
      p += 2;
      strcat(oline, htmp);
      if (i != 7) strcat(oline, ":");
    }
  }

  else{
    BIO_snprintf(oline, sizeof oline, "IP Address <invalid>");
  }

  syslog(LOG_INFO,"IP is: %s",oline);

  return 0;

}


int copy_csv_to_buffer(char* sub_str, char* oline, const int buf_len, int space_left)
{

  // copies the string into buffer
  // and returns the number of chararacters copied

  //ASN1_STRING_to_UTF8((unsigned char**)&pBuf,gen->d.ia5);
  
  int req_len, space_taken;

  req_len= strlen((char*)oline);


  if( (req_len+1) <= space_left ){
    strncat(sub_str, (char*)oline,(req_len+1)); 
    space_taken=req_len+1;
  }
  else{
    strncat(sub_str, (char*)oline, space_left);  
    sub_str[buf_len]='\0';
    return 0;
  }

  if((1+space_taken) <= space_left){  
    strcat(sub_str,",");
    space_taken = space_taken +1; // '\0' is allready taken for in (req_len+1) 
  }

  return space_taken; 
}


X509_NAME* get_cname (int property,X509 *cert)
{
  X509_NAME *cName;

  switch (property){
    case CERTX509_ISSUER_ORGANIZATION_NAME:
    case CERTX509_ISSUER_ORGANIZATION_UNIT_NAME:
    case CERTX509_ISSUER_COMMON_NAME:
    case CERTX509_ISSUER_COUNTRY:
    case CERTX509_ISSUER_STATE:
    case CERTX509_ISSUER_LOCATION:
      cName = X509_get_issuer_name(cert);
      break;

    case CERTX509_SUBJECT_ORGANIZATION_NAME:
    case CERTX509_SUBJECT_ORGANIZATION_UNIT_NAME:
    case CERTX509_SUBJECT_COMMON_NAME:
    case CERTX509_SUBJECT_ALT_NAME:   //ALT NAME
    case CERTX509_SUBJECT_COUNTRY:
    case CERTX509_SUBJECT_STATE:
    case CERTX509_SUBJECT_LOCATION:
      cName = X509_get_subject_name(cert);
      break;

    default:
      cName = NULL;
    }

  return cName;
}


int make_property_ssl_equiv(int property)
{

  int lProperty;

  /* make the property comensurate with SSL  */
  switch(property)
    {
    case CERTX509_ISSUER_ORGANIZATION_NAME:
    case CERTX509_SUBJECT_ORGANIZATION_NAME:
      lProperty = NID_organizationName;
      break;
    case CERTX509_ISSUER_ORGANIZATION_UNIT_NAME:
    case CERTX509_SUBJECT_ORGANIZATION_UNIT_NAME:
      lProperty = NID_organizationalUnitName;
      break;
    case CERTX509_ISSUER_COMMON_NAME:
    case CERTX509_SUBJECT_COMMON_NAME:
      lProperty = NID_commonName;
      break;
    case CERTX509_SUBJECT_ALT_NAME:  // ALT NAME
      lProperty = NID_subject_alt_name;
      break;
    case CERTX509_ISSUER_SURNAME:
    case CERTX509_SUBJECT_SURNAME:
      lProperty = NID_surname;
      break;
    case CERTX509_ISSUER_COUNTRY:
    case CERTX509_SUBJECT_COUNTRY:
	  lProperty = NID_countryName;
	  break;      
    case CERTX509_ISSUER_STATE:
    case CERTX509_SUBJECT_STATE:
	  lProperty = NID_stateOrProvinceName;
	  break;            
    case CERTX509_ISSUER_LOCATION:      
    case CERTX509_SUBJECT_LOCATION:
	  lProperty = NID_localityName;
	  break;
    

    default:
      lProperty = 0;
    }

return lProperty;

}



int CertX509ReadTimeProperty(X509 *cert, int property, char *pBuf, int len)
{
  int rValue;
  char buf[64];
  ASN1_TIME *cTime;
  
  switch (property)
    {
    case CERTX509_START_DATE:
      cTime = X509_get_notBefore(cert);
      if (CERT_OK == 
          (rValue = getTimeString(cTime, buf, sizeof(buf))))
        {
          strcpy(pBuf, buf);
        }
      break;
      
    case CERTX509_EXPIRATION_DATE:
      cTime = X509_get_notAfter(cert);
      if (CERT_OK == 
          (rValue = getTimeString(cTime, buf, sizeof(buf))))
        {
          strcpy(pBuf, buf);
        }
      break;
      
    default:
      rValue = CERT_UNKNOWN_PROPERTY;
    }
  return rValue;
}

void CertX509Dump(X509 *cert)
{
#ifdef D_DEBUG_ENABLED
  char outputStr[64];
  int rVal;
  
  printf("Certificate:\n");
  if (CERT_OK == 
      (rVal = CertX509ReadStrProperty(cert,
				       CERTX509_ISSUER_COMMON_NAME,
				       outputStr, 64)))
    printf("\tIssuer Common name = %s\n", outputStr);
  else
    printf("Issuer Common Name not found (%d)\n", rVal);

  if (CERT_OK ==
      (rVal = CertX509ReadStrProperty(cert,
				       CERTX509_SUBJECT_COMMON_NAME,
				       outputStr, 64)))
    printf("\tSubject Common name = %s\n", outputStr);
  else
    printf("Subject Common Name not found (%d)\n", rVal);


 if (CERT_OK ==
      (rVal = CertX509ReadStrProperty(cert,
                                       CERTX509_SUBJECT_ALT_NAME, //ALT NAME
                                       outputStr, 64)))
    printf("\tSubject Alt name = %s\n", outputStr);
  else
    printf("Subject Alt name not found (%d)\n", rVal);


  if (CERT_OK ==
      (rVal = CertX509ReadStrProperty(cert,
				       CERTX509_ISSUER_ORGANIZATION_NAME,
				       outputStr, 64)))
    printf("\tIssuer Org name = %s\n", outputStr);
  else
    printf("Issuer Org Name not found (%d)\n", rVal);

  if (CERT_OK == 
      (rVal = CertX509ReadStrProperty(cert,
				       CERTX509_SUBJECT_ORGANIZATION_NAME,
				       outputStr, 64)))
    printf("\tSubject Org name = %s\n", outputStr);
  else
    printf("Subject Org Name not found (%d)\n", rVal);


  /* Check to see if we have a valid certificate by date */
  rVal = checkCertDates(cert);

  switch (rVal)
    {
    case CERT_OK:
      printf("Certificate is VALID\n");
      break;

    case CERT_DATE_PENDING:
      printf("Certificate is not yet valid\n");
      break;

    case CERT_DATE_EXPIRED:
      printf("Certificate is expired\n");
      break;

    }
  if (CERT_OK == 
      (rVal = CertX509ReadTimeProperty(cert,
					CERTX509_START_DATE,
				       outputStr, 64)))
    printf("\tStart data = %s\n", outputStr);
  else
    printf("Start date not found (%d)\n", rVal);

  if (CERT_OK == 
      (rVal = CertX509ReadTimeProperty(cert,
					CERTX509_EXPIRATION_DATE,
				       outputStr, 64)))
    printf("\tExpiration date = %s\n", outputStr);
  else
    printf("Expiration date not found (%d)\n", rVal);

#endif
}


int checkCert(X509 *cert, char *CAfile, char *CApath)
{
  X509_STORE *cert_ctx   = NULL;

  int i;
#if 0 /* FUTURE EXPANSION OF CAPABILITIES  1 */
  int purpose = -1;
  char *untfile   = NULL;
  char *trustfile = NULL;
  STACK_OF(X509) *untrusted = NULL;
  STACK_OF(X509) *trusted   = NULL;
#endif
  X509_LOOKUP *lookup    = NULL;
  
  cert_ctx = X509_STORE_new();

  if (cert_ctx == NULL)
    goto end;

  lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());

  if (lookup == NULL)
    return 123456;

  if (CAfile)
    {
      i = X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM);
      if (!i)
        {
          fprintf(stderr, "Error loading file %s\n", CAfile);
          goto end;
        }
    }
  else
    {
      X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
    }
  
  lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());

  if (lookup == NULL)
    return 123456;

  if (CApath)
    {
      i = X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM);
      if (!i)
        {
          fprintf(stderr, "Error loading directory %s\n", CApath);
          goto end;
		}
	}
  else
    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
  
#if 0 /* FUTURE EXPANSION OF CAPABILITIES  1 */
  if (untfile)
    {
      if (!(untrusted = load_untrusted(untfile)))
        {
          fprintf(stderr, "Error loading untrusted file %s\n", untfile);
          goto end;
        }
	}

	if (trustfile)
      {
		if (!(trusted = load_untrusted(trustfile)))
          {
			fprintf(stderr, "Error loading untrusted file %s\n", trustfile);
			goto end;
          }
      }
    
    check(cert_ctx, cert, untrusted, trusted, purpose);
#endif    
    
 end:
    
	if (cert_ctx != NULL)
      X509_STORE_free(cert_ctx);

#if 0 /* FUTURE EXPANSION OF CAPABILITIES  1 */
	sk_X509_pop_free(untrusted, X509_free);
	sk_X509_pop_free(trusted, X509_free);
#endif

    return 0;
}

#if 0 /* FUTURE EXPANSION OF CAPABILITIES  1 */
static int check(X509_STORE *ctx,
                 X509 *x,
                 STACK_OF(X509) *untrustedChain,
                 STACK_OF(X509) *trustedChain,
                 int purpose)
{
  int i = 0, ret = 0;
  X509_STORE_CTX *csc;

  //  fprintf(stdout, "%s: ", (file == NULL) ? "stdin" : file);
  
  csc = X509_STORE_CTX_new();
  if (csc == NULL)
    {
      goto end;
    }
  
  X509_STORE_set_flags(ctx, CERT_X509_STORE_FLAGS);
  if (!X509_STORE_CTX_init(csc, ctx, x, untrustedChain))
    {
      goto end;
    }

  if (trustedChain)
    X509_STORE_CTX_trusted_stack(csc, trustedChain);

  if (purpose >= 0)
    X509_STORE_CTX_set_purpose(csc, purpose);

  i = X509_verify_cert(csc);
  X509_STORE_CTX_free(csc);
  
  ret = 0;
 end:
  if (i)
    {
      fprintf(stdout,"OK\n");
      ret = 1;
    }


  if (x != NULL)
    X509_free(x);
  
  return(ret);
}

static STACK_OF(X509) *load_untrusted(char *certfile)
{
	STACK_OF(X509_INFO) *sk    = NULL;
	STACK_OF(X509)      *stack = NULL;
    STACK_OF(X509)      *ret   = NULL;
	BIO                 *in    = NULL;
	X509_INFO           *xi;

	if(!(stack = sk_X509_new_null()))
      {
        fprintf(stderr,"memory allocation failure\n");
		goto end;
      } 
    
	if(!(in = BIO_new_file(certfile, "r")))
      {
		fprintf(stderr, "error opening the file, %s\n", certfile);
		goto end;
      }
    
	/* This loads from a file, a stack of x509/crl/pkey sets */
	if (!(sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL)))
      {
		fprintf(stderr,"error reading the file, %s\n",certfile);
		goto end;
      }

	/* scan over it and pull out the certs */
	while (sk_X509_INFO_num(sk))
      {
		xi = sk_X509_INFO_shift(sk);
		if (xi->x509 != NULL)
          {
			sk_X509_push(stack, xi->x509);
			xi->x509 = NULL;
          }
		X509_INFO_free(xi);
      }
	if (!sk_X509_num(stack))
      {
        fprintf(stderr, "no certificates in file, %s\n", certfile);
        sk_X509_free(stack);
		goto end;
      }
	ret = stack;
 end:
	BIO_free(in);
	sk_X509_INFO_free(sk);
	return(ret);
}

#endif
