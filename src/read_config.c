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

#include <stdio.h>
#include <stdlib.h>
#include <openssl/conf.h>

void
handle_error (const char *file, int lineno, const char *msg)
{
  fprintf (stderr, "** %s:%i %s\n", file, lineno, msg);
  ERR_print_errors_fp (stderr);
  exit (-1);
}

#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

#define GLOB_VAR "default_ca"
#define GLOB_NUM "GlobalNum"
#define PARAMS "Params"
#define SEC_NAME "SectionName"
#define CONFFILE "/home/fleming/.CA/local.conf"

int
main (int argc, char *argv[])
{
  int i;
  long i_val, err = 0;
  char *key, *s_val;
  STACK_OF (CONF_VALUE) * sec;
  CONF_VALUE *item;
  CONF *conf;

  conf = NCONF_new (NCONF_default ());
  if (!NCONF_load (conf, CONFFILE, &err))
    {
      if (err == 0)
	int_error ("Error opening configuration file");
      else
	{
	  fprintf (stderr, "Error in %s on line %li\n", CONFFILE, err);
	  int_error ("Errors parsing configuration file");
	}
    }
  if (!(s_val = NCONF_get_string (conf, "ca", GLOB_VAR)))
    {
      fprintf (stderr, "Error finding \"%s\" in [%s]\n", GLOB_VAR, "ca");
      int_error ("Error finding string");
    }
  printf ("Sec: %s, Key: %s, Val: %s\n", "ca", GLOB_VAR, s_val);
#if 0
#if (OPENSSL_VERSION_NUMBER > 0x00907000L)
  if (!(err = NCONF_get_number_e (conf, NULL, GLOB_NUM, &i_val)))
    {
      fprintf (stderr, "Error finding \"%s\" in [%s]\n", GLOB_NUM, NULL);
      int_error ("Error finding number");
    }
#else
  if (!(s_val = NCONF_get_string (conf, NULL, GLOB_NUM)))
    {
      fprintf (stderr, "Error finding \"%s\" in [%s]\n", GLOB_VAR, NULL);
      int_error ("Error finding number");
    }
  i_val = atoi (s_val);
#endif
  printf ("Sec: %s, Key: %s, Val: %i\n", NULL, GLOB_VAR, i_val);
  if (!(key = NCONF_get_string (conf, PARAMS, SEC_NAME)))
    {
      fprintf (stderr, "Error finding \"%s\" in [%s]\n", SEC_NAME, PARAMS);
      int_error ("Error finding string");
    }
  fprintf (stdout, "Sec: %s, Key: %s, Val: %s\n", PARAMS, SEC_NAME, key);
  if (!(sec = NCONF_get_section (conf, key)))
    {
      fprintf (stderr, "Error finding [%s]\n", key);
      int_error ("Error finding string");
    }
  for (i = 0; i < sk_CONF_VALUE_num (sec); i++)
    {
      item = sk_CONF_VALUE_value (sec, i);
      printf ("Sec: %s, Key: %s, Val: %s\n",
	      item->section, item->name, item->value);
    }
#endif

  NCONF_free (conf);
  return 0;
}
