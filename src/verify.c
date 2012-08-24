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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apps.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#undef PROG
#define PROG	verify_main

/*##1## DO WE NEED TO SET THE VERIFY FUNCTION? **/
static int  cb(int ok, X509_STORE_CTX *ctx);

static int check(X509_STORE *ctx, X509 *cert,
                 STACK_OF(X509) *uchain, STACK_OF(X509) *tchain, int purpose);
static STACK_OF(X509) *load_untrusted(char *file);
static int vflags = 0;

int checkCert(X509 *cert, char *CAFile, char *CAPath);

int checkCert(X509 *cert, char *CAfile, char *CApath)
{
  X509_STORE *cert_ctx   = NULL;

  int i, ret = 0;
  int purpose = -1;
  char *untfile   = NULL;
  char *trustfile = NULL;
  STACK_OF(X509) *untrusted = NULL;
  STACK_OF(X509) *trusted   = NULL;
  X509_LOOKUP *lookup    = NULL;
  
  cert_ctx = X509_STORE_new();

  if (cert_ctx == NULL)
    goto end;

  /*##1##*/
  //  X509_STORE_set_verify_cb_func(cert_ctx, cb);
  
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
    
    
 end:
    
	if (cert_ctx != NULL)
      X509_STORE_free(cert_ctx);

	sk_X509_pop_free(untrusted, X509_free);
	sk_X509_pop_free(trusted, X509_free);


}

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
  
  X509_STORE_set_flags(ctx, vflags);
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
	if (!(sk = PEM_X509_INFO_read_bio(in,NULL,NULL,NULL)))
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

static int  cb(int ok, X509_STORE_CTX *ctx)
{
  char buf[256];
  
  if (!ok)
    {
      if (ctx->current_cert)
        {
          X509_NAME_oneline(X509_get_subject_name(ctx->current_cert),buf,
                            sizeof buf);
          printf("%s\n",buf);
        }
      printf("error %d at %d depth lookup:%s\n",ctx->error,
             ctx->error_depth,
             X509_verify_cert_error_string(ctx->error));
      if (ctx->error == X509_V_ERR_CERT_HAS_EXPIRED)
        ok = 1;

      /* since we are just checking the certificates, it is
       * ok if they are self signed. But we should still warn
       * the user.
       */
      if (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
        ok = 1;
      /* Continue after extension errors too */
      if (ctx->error == X509_V_ERR_INVALID_CA)
        ok = 1;
      if (ctx->error == X509_V_ERR_INVALID_NON_CA)
        ok = 1;
      if (ctx->error == X509_V_ERR_PATH_LENGTH_EXCEEDED)
        ok = 1;
      if (ctx->error == X509_V_ERR_INVALID_PURPOSE)
        ok = 1;
      if (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
        ok = 1;
      if (ctx->error == X509_V_ERR_CRL_HAS_EXPIRED)
        ok = 1;
      if (ctx->error == X509_V_ERR_CRL_NOT_YET_VALID)
        ok = 1;
      if (ctx->error == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION)
        ok = 1;
      
      return ok;
      
    }

  return(ok);
}

