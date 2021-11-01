// search.cpp : Defines the exported functions for the DLL application.
//
#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define BUFSIZE 3072					// Ѕуфер строки дл€ отправки клиенту
#define ATTRS_LIST_SEPARATOR ','
//#define DEBUG
//#define NUMBERING

#define skip_white(s) while (*s == ' ') {s++;}

// Windows Header Files:
#include "targetver.h"
#include <windows.h>
#include <HttpExt.h>
#include <Winldap.h>
#include <WinInet.h>
#include <Winber.h>
#include <stdio.h>
#include <stdlib.h>
#include <Shlwapi.h>
#include <tchar.h>

LPTSTR host;
LPTSTR basedn;
LPTSTR filter;
LPTSTR attrs;
ULONG scope;
PWCHAR *attrsList = NULL;

DWORD max_host_len = 32;
DWORD max_basedn_len = 64;
DWORD max_filter_len = 32;
DWORD max_attrs_len = 32;

#ifdef DEBUG
TCHAR user[128] = L"macho";
TCHAR pass[128] = L"1234QWer";
#endif

void myInvalidParameterHandler(const wchar_t* expression,
   const wchar_t* function, 
   const wchar_t* file, 
   unsigned int line, 
   uintptr_t pReserved)
{
  // DWORD dummy = 0;
}

BOOL isEmpty(LPCTSTR var)
{
  return !(var && var[0]);					// возвращает true если строка var пуста€
}

BOOL isNumber(LPCTSTR val)
{
  return !_wcsspnp(val, L"012");		// возвращает true если строка val целиком состоит из цифр 0, 1, 2
}

BOOL extract(TCHAR *line, LPCTSTR name, LPTSTR value, DWORD *buflen)
{
  DWORD count;
  TCHAR *n, *p = wcsstr(line, name);
  if (p == NULL)
    return false;

  p += wcslen(name);
  skip_white(p);
  if (*p++ != '=')
    return false;
  skip_white(p);

  n = wcschr(p, '&');
  if ( n == NULL )
    count = wcslen(p);
  else
    count = n-p;

  if ( count > 2 && ((p[0] == '\'' && p[count-1] == '\'') || (p[0] == '\"' && p[count-1] == '\"'))) {
    p++;
    count -= 2;
  };
  
  if (count + 1 > *buflen) {
    *buflen = count + 1;
	value = (LPTSTR) LocalReAlloc(value, *buflen, LMEM_FIXED);
	if (!value)
      return false;
  };

  wcsncpy_s(value, *buflen, p, count);

  return true;
}

void parse_query_string(const LPSTR qstr, LPTSTR _host, LPTSTR _basedn, LPTSTR _filter, LPTSTR _attrs, ULONG* scop)
{
  TCHAR buff[INTERNET_MAX_PATH_LENGTH];
  TCHAR value[2];
  DWORD save_buflen = 2;

  // мен€ем + на пробел
  if ( char *p = qstr ) {
    do {
      if ( *p == '+' ) *p = ' ';
    } while ( *++p );
  };

  MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, qstr, -1, buff, sizeof buff);
  UrlUnescapeInPlace(buff, 0);
  
  // преобразуем кракоз€бры в русский €зык
  for (DWORD i = 0; i < wcslen(buff); i++) {
    if (buff[i] > 128 && buff[i] < 256)
	  buff[i] += 848;
  };

  _wcslwr_s(buff, INTERNET_MAX_PATH_LENGTH);
  
  extract(buff, L"host", _host, &max_host_len);
  extract(buff, L"basedn", _basedn, &max_basedn_len);
  extract(buff, L"filter", _filter, &max_filter_len);
  extract(buff, L"attrs", _attrs, &max_attrs_len);
  if (extract(buff, L"scope", value, &save_buflen) && isNumber(value)) {
    *scop = (ULONG) _wtof(value);
	if (*scop > 2) *scop = 0;
  };

  return;
}

void destroy_attrs(PWCHAR attrs_list[])
{
  if (attrs_list == NULL)
    return;

  DWORD i = 0;
  while (attrs_list[i] != NULL) {
    LocalFree(attrs_list[i++]);
  };

  delete attrs_list;
}

DWORD attrs_count(LPCTSTR list)
{
  if (isEmpty(list))
    return 0;

  DWORD j = 1;
  for (DWORD i = 0; i < wcslen(list); i++) {
    if (list[i] == ATTRS_LIST_SEPARATOR) j++;
  }

  return j;
}

DWORD next_attr_len(const LPTSTR a)
{
  DWORD len = 0;
  while (a[len] != ATTRS_LIST_SEPARATOR && a[len] != 0) 
    len++;

  return len;
}

PWCHAR *reload_attrs(const LPTSTR attrs)
{
  DWORD dim = attrs_count(attrs);
  if (dim == 0)
    return NULL;

  PWCHAR *attrs_list = new PWCHAR[dim];
  LPTSTR s = attrs;
  DWORD len;

  for (DWORD i = 0; i < dim; i++) {
    len = next_attr_len(s);
    attrs_list[i] = (PWCHAR) LocalAlloc(LMEM_FIXED, 2*(len + 1));
	wcsncpy_s(attrs_list[i], len+1, s, len);
	++s += len;
  };

  attrs_list[dim] = NULL;

  return attrs_list;
}

LPTSTR getAttributes(TCHAR *buff, LDAP* ld, LDAPMessage *pMes)
{
  BerElement *pBer = NULL;
  PWCHAR *ppValue = NULL;
  ULONG iValue = 0;

  _invalid_parameter_handler oldHandler = _set_invalid_parameter_handler(myInvalidParameterHandler);

  // Get the first attribute name.
  PWCHAR pAttribute = ldap_first_attribute(ld, pMes, &pBer);
  // Get the distinguished name.
  PWCHAR pDN = ldap_get_dn(ld, pMes);
  wsprintf(buff, L"Dn:%s;", pDN);
  ldap_memfree(pDN);

  try {

    while(pAttribute != NULL) {

	  if (0 != wcsncat_s(buff, BUFSIZE-2, pAttribute, _TRUNCATE)) throw 1;
      if (0 != wcsncat_s(buff, BUFSIZE-2, L":", _TRUNCATE)) throw 1;

      ppValue = ldap_get_valuesW(ld, pMes, pAttribute);

      if (ppValue != NULL) {
        iValue = ldap_count_values(ppValue);
        if (iValue) {
          for(ULONG z=0; z < iValue-1; z++) {
            if (0 != wcsncat_s(buff, BUFSIZE-2, ppValue[z], _TRUNCATE)) throw 1;
            if (0 != wcsncat_s(buff, BUFSIZE-2, L",", _TRUNCATE)) throw 1;
          };
          if (0 != wcsncat_s(buff, BUFSIZE-2, ppValue[iValue-1], _TRUNCATE)) throw 1;
          if (0 != wcsncat_s(buff, BUFSIZE-2, L";", _TRUNCATE)) throw 1;
        };
        ldap_value_free(ppValue);
        ppValue = NULL;
      };

	  ldap_memfree(pAttribute);        
      // Get next attribute name.
      pAttribute = ldap_next_attribute(ld, pMes, pBer);
    };
 
    if( pBer != NULL )
      ber_free(pBer, 0);

  }
  catch (int ) {
    if (ppValue)
      ldap_value_free(ppValue);
	if (pAttribute)
      ldap_memfree(pAttribute);
  }

  wcscat_s(buff, BUFSIZE, L"\r\n");
  _set_invalid_parameter_handler(oldHandler);

  return buff;
}

void send2browser(LPEXTENSION_CONTROL_BLOCK ecb, const LPTSTR text)
{
  DWORD	dwWritten = wcslen(text) * sizeof TCHAR;
  if (dwWritten > BUFSIZE * sizeof TCHAR)
    dwWritten = BUFSIZE * sizeof TCHAR;

  ecb->WriteClient(ecb->ConnID, text, (LPDWORD) &dwWritten, 0 );
}

/* This function is called when the extension is loaded by the web server */
BOOL WINAPI GetExtensionVersion( HSE_VERSION_INFO *pVer )
{
  pVer->dwExtensionVersion = HSE_VERSION;
  strncpy_s( pVer->lpszExtensionDesc, HSE_MAX_EXT_DLL_NAME_LEN, "LDAP Search ISAPI Extension", _TRUNCATE);
  
  host = (LPTSTR) LocalAlloc(LMEM_FIXED, max_host_len * sizeof TCHAR);
  basedn = (LPTSTR) LocalAlloc(LMEM_FIXED, max_basedn_len * sizeof TCHAR);
  filter = (LPTSTR) LocalAlloc(LMEM_FIXED, max_filter_len * sizeof TCHAR);
  attrs = (LPTSTR) LocalAlloc(LMEM_FIXED, max_attrs_len * sizeof TCHAR);

  return TRUE;
}

/* This function is called when the extension is accessed */
DWORD WINAPI HttpExtensionProc( LPEXTENSION_CONTROL_BLOCK ecb )
{
  LDAP* pLdapConnection;
  HSE_SEND_HEADER_EX_INFO header;
  TCHAR szBuff[BUFSIZE] = L"";
#ifdef NUMBERING
  DWORD i = 0;
#endif

  header.pszStatus = "200 OK";
  header.pszHeader = "Content-Type: text/plain; charset=utf-16\r\n\r\n";
  header.cchStatus = strlen(header.pszStatus);
  header.cchHeader = strlen(header.pszHeader);
  header.fKeepConn = FALSE;
  /* Use a server support function to write out a header with our additional header information */
  ecb->ServerSupportFunction( ecb->ConnID, HSE_REQ_SEND_RESPONSE_HEADER_EX, &header, 0, 0 );

  try {

    host[0] = 0;
    basedn[0] = 0;
	  attrs[0] = 0;
	  filter[0] = 0;
    scope = LDAP_SCOPE_BASE;				//LDAP_SCOPE_BASE         0x00, LDAP_SCOPE_ONELEVEL     0x01, LDAP_SCOPE_SUBTREE      0x02

    parse_query_string(ecb->lpszQueryString, host, basedn, filter, attrs, &scope);

    if (isEmpty(host))
      wcscpy_s(host, max_host_len, L"localhost");
    if (isEmpty(basedn)) 
	  throw L"Variable basedn can not be empty.";
	if (isEmpty(filter))
      wcscpy_s(filter, max_filter_len, L"(objectclass=*)");

    destroy_attrs(attrsList);
    attrsList = reload_attrs(attrs);

    pLdapConnection = ldap_init(host, LDAP_PORT);
    if (pLdapConnection == NULL) {
      wsprintf(szBuff, L"ldap_init failed with 0x%x.", LdapGetLastError());
      throw szBuff;
    };
  
    ULONG lRtn = LDAP_NO_LIMIT;
    ldap_set_option(pLdapConnection, LDAP_OPT_SIZELIMIT, &lRtn);
    lRtn = LDAP_VERSION3;
    ldap_set_option(pLdapConnection, LDAP_OPT_VERSION, &lRtn);

    lRtn = ldap_connect(pLdapConnection, NULL);
    if (lRtn != LDAP_SUCCESS) {
      wsprintf(szBuff, L"ldap_connect failed with 0x%x.", LdapGetLastError());
      throw szBuff;
    };

#ifdef DEBUG
    INT iRtn = ldap_bind_s(pLdapConnection, user, pass, LDAP_AUTH_SIMPLE);
#else
	INT iRtn = ldap_bind_s(pLdapConnection, NULL, NULL, LDAP_AUTH_NEGOTIATE);
#endif

    if (iRtn == -1) {
      wsprintf(szBuff, L"ldap_bind failed with 0x%x.", LdapGetLastError());
      throw szBuff;
    };

    LDAPMessage *ldapRes = NULL, *pEntry = NULL;
    ldap_search_s(pLdapConnection, basedn, scope, filter, attrsList, 0, &ldapRes);

    if (ldapRes != NULL) {
      ULONG numberOfEntries = ldap_count_entries(pLdapConnection, ldapRes);
	
	  for( ULONG iCnt = 0; iCnt < numberOfEntries; iCnt++ )
      {
	    szBuff[0] = 0;
        // Get the first/next entry.
        if( !iCnt )
          pEntry = ldap_first_entry(pLdapConnection, ldapRes);
        else
          pEntry = ldap_next_entry(pLdapConnection, pEntry);
#ifdef NUMBERING
		wsprintf(szBuff, L"%u ", ++i);
#endif
        send2browser(ecb, getAttributes(szBuff, pLdapConnection, pEntry));
      };

      ldap_msgfree(ldapRes);

    } else {
      wsprintf(szBuff, L"ldap_search failed with 0x%x.", LdapGetLastError());
	  throw szBuff;
    };

  }
  catch (LPTSTR err) {
    send2browser(ecb, err);
  }

  ldap_unbind(pLdapConnection);

  return HSE_STATUS_SUCCESS;
}

BOOL WINAPI TerminateExtension(DWORD dwFlags)
{

  destroy_attrs(attrsList);

  LocalFree(attrs);
  LocalFree(filter);
  LocalFree(basedn);
  LocalFree(host);

  return TRUE;
}