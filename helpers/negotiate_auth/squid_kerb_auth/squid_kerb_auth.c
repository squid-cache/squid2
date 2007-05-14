/*
 * -----------------------------------------------------------------------------
 *
 * Author: Markus Moeller (markus_moeller at compuserve.com)
 *
 * Copyright (C) 2007 Markus Moeller. All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * -----------------------------------------------------------------------------
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <unistd.h>

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN HOST_NAME_MAX
#endif

#ifdef HEIMDAL
#include <gssapi.h>
#define gss_nt_service_name GSS_C_NT_HOSTBASED_SERVICE
#else
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_generic.h>
#endif

#include <krb5.h>

#include "base64.h"
#include "spnegohelp.h"

static const unsigned char ntlmProtocol [] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0};

#if UNUSED_CODE
static const char *
get_gss_error(OM_uint32 error_status )
{
  OM_uint32 maj_stat, min_stat;
  OM_uint32 msg_ctx = 0;
  gss_buffer_desc status_string;
  char buf[1024];
  size_t len;

  len = 0;
  do {
    maj_stat = gss_display_status (&min_stat,
				   error_status,
				   GSS_C_MECH_CODE,
				   GSS_C_NO_OID,
				   &msg_ctx,
				   &status_string);
    if (sizeof(buf) > len + status_string.length + 1) {
      /*
	sprintf(buf, "%s:", (char*) status_string.value);
      */
      sprintf(buf+len, "%s:", (char*) status_string.value);
      len += status_string.length;
    }
    gss_release_buffer(&min_stat, &status_string);
  } while (!GSS_ERROR(maj_stat) && msg_ctx != 0);

  return(strdup(buf));
}
#endif

char *gethost_name() {
  char      hostname[MAXHOSTNAMELEN];
  struct addrinfo *hres=NULL, *hres_list;
  int rc,count;

  rc = gethostname(hostname,MAXHOSTNAMELEN);
  if (rc)
    {
      fprintf(stderr, "error while resolving hostname '%s'\n", hostname);
      return NULL;
    }
  rc = getaddrinfo(hostname,NULL,NULL,&hres);
  if (rc != 0) {
    fprintf(stderr, "error while resolving hostname with getaddrinfo: %s\n",gai_strerror(rc));
    return NULL;
  }
  hres_list=hres;
  count=0;
  while (hres_list) {
    count++;
    hres_list=hres_list->ai_next;
  }
  rc = getnameinfo (hres->ai_addr, hres->ai_addrlen,hostname, sizeof (hostname), NULL, 0, 0);
  if (rc != 0) {
    fprintf(stderr, "error while resolving ip address with getnameinfo: %s\n",gai_strerror(rc));
    freeaddrinfo(hres);
    return NULL ;
  }

  freeaddrinfo(hres);
  hostname[MAXHOSTNAMELEN]='\0';
  return(strdup(hostname));
}

int check_gss_err(OM_uint32 major_status, OM_uint32 minor_status, char* function, int debug) {
  if (GSS_ERROR(major_status)) {
    OM_uint32 maj_stat,min_stat;
    OM_uint32 msg_ctx = 0;
    gss_buffer_desc status_string;
    char buf[1024];
    size_t len;

    len = 0;
    msg_ctx = 0;
    while (!msg_ctx) {
      /* convert major status code (GSS-API error) to text */
      maj_stat = gss_display_status(&min_stat, major_status,
				    GSS_C_GSS_CODE,
				    GSS_C_NULL_OID,
				    &msg_ctx, &status_string);
      if (maj_stat == GSS_S_COMPLETE) {
	if (sizeof(buf) > len + status_string.length + 1) {
	  sprintf(buf+len, "%s:", (char*) status_string.value);
	  len += status_string.length;
	}
	gss_release_buffer(&min_stat, &status_string);
	break;
      }
      gss_release_buffer(&min_stat, &status_string);
    }
    if (sizeof(buf) > len + 2) {
      sprintf(buf+len, "%s", ". ");
      len += 2;
    }
    msg_ctx = 0;
    while (!msg_ctx) {
      /* convert minor status code (underlying routine error) to text */
      maj_stat = gss_display_status(&min_stat, minor_status,
				    GSS_C_MECH_CODE,
				    GSS_C_NULL_OID,
				    &msg_ctx, &status_string);
      if (maj_stat == GSS_S_COMPLETE) {
	if (sizeof(buf) > len + status_string.length ) {
	  sprintf(buf+len, "%s", (char*) status_string.value);
	  len += status_string.length;
	}
	gss_release_buffer(&min_stat, &status_string);
	break;
      }
      gss_release_buffer(&min_stat, &status_string);
    }
    if (debug)
      fprintf(stderr, "%s failed: %s\n", function, buf);
    fprintf(stdout, "NA %s failed: %s\n",function, buf);
    return(1);
  }
  return(0);
}



int main(int argc, char * const argv[])
{
  char buf[6400];
  char *c;
  int length;
  static int err=0;
  int opt, rc, debug=0;
  OM_uint32 ret_flags=0, spnego_flag=0;
  char *service_name="HTTP",*host_name;
  char *token = NULL;
  char *service_principal = NULL;
  OM_uint32 major_status, minor_status;
  gss_name_t 		my_gss_name = GSS_C_NO_NAME;
  gss_cred_id_t 	my_gss_creds = GSS_C_NO_CREDENTIAL;
  gss_ctx_id_t 	gss_context = GSS_C_NO_CONTEXT;
  gss_cred_id_t 	delegated_cred = GSS_C_NO_CREDENTIAL;
  gss_name_t 		client_name = GSS_C_NO_NAME;
  gss_buffer_desc 	service = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc 	input_token = GSS_C_EMPTY_BUFFER;
  gss_buffer_desc 	output_token = GSS_C_EMPTY_BUFFER;
  const unsigned char	*kerberosToken       = NULL;
  size_t		kerberosTokenLength = 0;
  const unsigned char	*spnegoToken         = NULL ;
  size_t		spnegoTokenLength   = 0;

  setbuf(stdout,NULL);
  setbuf(stdin,NULL);

  while (-1 != (opt = getopt(argc, argv, "ds:h"))) {
    switch (opt) {
    case 'd':
      debug = 1;
      break;              
    case 's':
      service_principal = strdup(optarg);
      break;
    case 'h':
      fprintf(stdout, "Usage: \n");
      fprintf(stdout, "squid_kerb_auth -d [-s SPN]\n");
      fprintf(stdout, "SPN = service principal name\n");
      fprintf(stdout, "Can be set to GSS_C_NO_NAME to allow any entry from keytab\n");
      fprintf(stdout, "default SPN is HTTP/fqdn@DEFAULT_REALM\n");
      break;
    default:
      fprintf(stderr, "%s: unknown option: -%c.\n", argv[0], opt);
    }
  }

  if (service_principal && strcasecmp(service_principal,"GSS_C_NO_NAME") ) {
    service.value = service_principal;
    service.length = strlen((char *)service.value);
  } else {
    host_name=gethost_name();
    if ( !host_name ) {
      fprintf(stderr, "%s: Local hostname could not be determined. Please specify the principal\n", argv[0]);
      exit(-1);
    }
    service.value = malloc(strlen(service_name)+strlen(host_name)+2);
    snprintf(service.value,strlen(service_name)+strlen(host_name)+2,"%s@%s",service_name,host_name);
    service.length = strlen((char *)service.value);
  }

  while (1) {
    if (fgets(buf, sizeof(buf)-1, stdin) == NULL) {
      if (ferror(stdin)) {
	if (debug)
	  fprintf(stderr, "%s: fgets() failed! dying..... errno=%d (%s)\n", argv[0], ferror(stdin),
		 strerror(ferror(stdin)));

	exit(1);    /* BIIG buffer */
      }
      exit(0);
    }

    c=memchr(buf,'\n',sizeof(buf)-1);
    if (c) {
      *c = '\0';
      length = c-buf;
    } else {
      err = 1;
    }
    if (err) {
      if (debug)
	fprintf(stderr, "Oversized message\n");
      fprintf(stderr, "NA Oversized message\n");
      err = 0;
      continue;
    }

    if (debug)
      fprintf(stderr, "Got '%s' from squid (length: %d).\n",buf?buf:"NULL",length);

    if (buf[0] == '\0') {
      if (debug)
	fprintf(stderr, "Invalid request\n");
      fprintf(stdout, "NA Invalid request\n");
      continue;
    }

    if (strlen(buf) < 2) {
      if (debug)
	fprintf(stderr, "Invalid request [%s]\n", buf);
      fprintf(stdout, "NA Invalid request\n");
      continue;
    }

    if ( !strncmp(buf, "QQ", 2) ) {
      if (input_token.value)
        gss_release_buffer(&minor_status, &input_token);
      if (output_token.value)
        gss_release_buffer(&minor_status, &output_token);
      if (my_gss_creds)
        gss_release_cred(&minor_status, &my_gss_creds);
      if (delegated_cred)
        gss_release_cred(&minor_status, &delegated_cred);
      if (my_gss_name)
        gss_release_name(&minor_status, &my_gss_name);
      if (client_name)
        gss_release_name(&minor_status, &client_name);
      if (kerberosToken) {
	/* Allocated by parseNegTokenInit, but no matching free function exists.. */
        free((char *)kerberosToken);
        kerberosToken=NULL;
      }
      if (spnegoToken) {
	/* Allocated by makeNegTokenTarg, but no matching free function exists.. */
        if (spnego_flag)
	  free((char *)spnegoToken);
        spnegoToken=NULL;
      }
      if (token) {
        free(token);
        token=NULL;
      }
      exit(0);
    }

    if ( !strncmp(buf, "YR", 2) && !strncmp(buf, "KK", 2) ) {
      if (debug)
	fprintf(stderr, "Invalid request [%s]\n", buf);
      fprintf(stdout, "NA Invalid request\n");
      continue;
    }
    if ( !strncmp(buf, "YR", 2) )
      gss_context = GSS_C_NO_CONTEXT;

    if (strlen(buf) <= 3) {
      if (debug)
	fprintf(stderr, "Invalid negotiate request [%s]\n", buf);
      fprintf(stdout, "NA Invalid negotiate request\n");
      continue;
    }
        
    input_token.length = base64decode_len(buf+3);
    input_token.value = malloc(input_token.length);

    input_token.length = base64decode(input_token.value, buf+3);
 
#ifndef HAVE_SPNEGO
    if (( rc=parseNegTokenInit (input_token.value,
				input_token.length,
				&kerberosToken,
				&kerberosTokenLength))!=0 ){
      if (debug)
	fprintf(stderr, "parseNegTokenInit failed with rc=%d\n",rc);
        
      /* if between 100 and 200 it might be a GSSAPI token and not a SPNEGO token */    
      if ( rc < 100 || rc > 199 ) {
	if (debug)
	  fprintf(stderr, "Invalid GSS-SPNEGO query [%s]\n", buf);
	fprintf(stdout, "NA Invalid GSS-SPNEGO query\n");
	goto cleanup;
      } 
      if ((input_token.length >= sizeof ntlmProtocol + 1) &&
	  (!memcmp (input_token.value, ntlmProtocol, sizeof ntlmProtocol))) {
	if (debug)
	  fprintf(stderr, "received type %d NTLM token\n", (int) *((unsigned char *)input_token.value + sizeof ntlmProtocol));
	fprintf(stdout, "NA received type %d NTLM token\n",(int) *((unsigned char *)input_token.value + sizeof ntlmProtocol));
	goto cleanup;
      } 
      spnego_flag=0;
    } else {
      gss_release_buffer(&minor_status, &input_token);
      input_token.length=kerberosTokenLength;
      input_token.value = malloc(input_token.length);
      if (input_token.value == NULL) {
	if (debug)
	  fprintf(stderr, "Not enough memory\n");
	fprintf(stdout, "NA Not enough memory\n");
	goto cleanup;
      }
      memcpy(input_token.value,kerberosToken,input_token.length);
      spnego_flag=1;
    }
#else
    if ((input_token.length >= sizeof ntlmProtocol + 1) &&
	(!memcmp (input_token.value, ntlmProtocol, sizeof ntlmProtocol))) {
      if (debug)
	fprintf(stderr, "received type %d NTLM token\n", (int) *((unsigned char *)input_token.value + sizeof ntlmProtocol));
      fprintf(stdout, "NA received type %d NTLM token\n",(int) *((unsigned char *)input_token.value + sizeof ntlmProtocol));
      goto cleanup;
    } 
#endif
     
    if ( service_principal ) {
      if ( strcasecmp(service_principal,"GSS_C_NO_NAME") ){
        major_status = gss_import_name(&minor_status, &service,
  				       (gss_OID) GSS_C_NULL_OID, &my_gss_name);
       
      } else {
        my_gss_name = GSS_C_NO_NAME;
        major_status = GSS_S_COMPLETE;
      }
    } else {
      major_status = gss_import_name(&minor_status, &service,
  				     gss_nt_service_name, &my_gss_name);
    }

    if ( check_gss_err(major_status,minor_status,"gss_import_name()",debug) )
      goto cleanup;

    major_status = gss_acquire_cred(&minor_status, my_gss_name, GSS_C_INDEFINITE,
				    GSS_C_NO_OID_SET, GSS_C_ACCEPT, &my_gss_creds,
				    NULL, NULL);
    if (check_gss_err(major_status,minor_status,"gss_acquire_cred()",debug) )
      goto cleanup;

    major_status = gss_accept_sec_context(&minor_status,
					  &gss_context,
					  my_gss_creds,
					  &input_token,
					  GSS_C_NO_CHANNEL_BINDINGS,
					  &client_name,
					  NULL,
					  &output_token,
					  &ret_flags,
					  NULL,
					  &delegated_cred);


    if (output_token.length) {
#ifndef HAVE_SPNEGO
      if (spnego_flag) {
	if ((rc=makeNegTokenTarg (output_token.value,
				  output_token.length,
				  &spnegoToken,
				  &spnegoTokenLength))!=0 ) {
	  if (debug)
	    fprintf(stderr, "makeNegTokenTarg failed with rc=%d\n",rc);
	  fprintf(stdout, "NA makeNegTokenTarg failed with rc=%d\n",rc);
	  goto cleanup;
	}
      } else {
	spnegoToken = output_token.value;
	spnegoTokenLength = output_token.length;
      }
#else
      spnegoToken = output_token.value;
      spnegoTokenLength = output_token.length;
#endif
      token = malloc(base64encode_len(spnegoTokenLength));
      if (token == NULL) {
	if (debug)
	  fprintf(stderr, "Not enough memory\n");
	fprintf(stdout, "NA Not enough memory\n");
        goto cleanup;
      }

      base64encode(token, (const char *)spnegoToken, spnegoTokenLength);

      if (check_gss_err(major_status,minor_status,"gss_accept_sec_context()",debug) )
	goto cleanup;
      if (major_status & GSS_S_CONTINUE_NEEDED) {
	if (debug)
	  fprintf(stderr, "continuation needed\n");
	fprintf(stdout, "TT %s\n",token);
        goto cleanup;
      }
      major_status = gss_display_name(&minor_status, client_name, &output_token,
				      NULL);

      if (check_gss_err(major_status,minor_status,"gss_display_name()",debug) )
	goto cleanup;
      fprintf(stdout, "AF %s %s\n",token,(char *)output_token.value);
      if (debug)
	fprintf(stderr, "AF %s %s\n",token,(char *)output_token.value); 
      goto cleanup;
    } else {
      if (check_gss_err(major_status,minor_status,"gss_accept_sec_context()",debug) )
	goto cleanup;
      if (major_status & GSS_S_CONTINUE_NEEDED) {
	if (debug)
	  fprintf(stderr, "continuation needed\n");
	fprintf(stdout, "NA No token to return to continue\n");
	goto cleanup;
      }
      major_status = gss_display_name(&minor_status, client_name, &output_token,
				      NULL);

      if (check_gss_err(major_status,minor_status,"gss_display_name()",debug) )
	goto cleanup;
      /* 
       *  Return dummy token AA. May need an extra return tag then AF
       */
      fprintf(stdout, "AF %s %s\n","AA",(char *)output_token.value);
      if (debug)
	fprintf(stderr, "AF %s %s\n","AA",(char *)output_token.value);
    cleanup:
      if (input_token.value) 
	gss_release_buffer(&minor_status, &input_token);
      if (output_token.value) 
	gss_release_buffer(&minor_status, &output_token);
      if (my_gss_creds) 
	gss_release_cred(&minor_status, &my_gss_creds);
      if (delegated_cred) 
	gss_release_cred(&minor_status, &delegated_cred);
      if (my_gss_name) 
	gss_release_name(&minor_status, &my_gss_name);
      if (client_name) 
	gss_release_name(&minor_status, &client_name);
      if (kerberosToken) {
	/* Allocated by parseNegTokenInit, but no matching free function exists.. */
        free((char *)kerberosToken);
      	kerberosToken=NULL;
      }
      if (spnegoToken) {
	/* Allocated by makeNegTokenTarg, but no matching free function exists.. */
	if (spnego_flag)
	    free((char *)spnegoToken);
      	spnegoToken=NULL;
      }
      if (token) {
        free(token);
      	token=NULL;
      }
      continue;            
    }
  }
}
