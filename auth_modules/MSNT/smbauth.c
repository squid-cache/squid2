
/*
  msntauth

  Modified to act as a Squid authenticator
  Removed all Pike stuff.
  Returns OK for a successful authentication, or ERR upon error.

  Antonino Iannella, Camtech SA Pty Ltd
  Thu Sep 16 15:25:28 CST 1999

  Uses code from -
    Andrew Tridgell 1997
    Richard Sharpe 1996
    Bill Welliver 1999

  Released under GNU Public License

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <stdio.h>

/* You must specifiy these for your site! */

#define PRIMARY_DC "my_pdc"
#define BACKUP_DC  "my_bdc"
#define NTDOMAIN   "my_domain"

/* Main program for simple authentication.
   This code could probably be better, might be
   susceptible to buffer overflows. */

int main()
{
  char username[256];
  char password[256];
  char wstr[256];

  while (1)
  {
    // Read whole line from standard input. Terminate on break.
    if (fgets(wstr, 255, stdin) == NULL)    
       break;

    // Clear any current settings
    username[0] = '\0';
    password[0] = '\0';
    sscanf(wstr, "%s %s", username, password);          // Extract parameters

    // Check for invalid or blank entries
    if ((username[0] == '\0') || (password[0] == '\0'))
    {
       puts("ERR");
       fflush(stdout);
       continue;
    }

    if (Valid_User(username, password, PRIMARY_DC, BACKUP_DC, NTDOMAIN) == 0)
       puts("OK");
    else
       puts("ERR");
       
    fflush(stdout);
  }
  
  return 0;
}

/* Valid_User return codes -

   0 - User authenticated successfully.
   1 - Server error.
   2 - Protocol error.
   3 - Logon error; Incorrect password or username given.
*/

