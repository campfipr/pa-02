/*-------------------------------------------------------------------------------
Written By: 
     1- Mohamed Aboutabl
Submitted on: 
-------------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>


pid_t    Fork(void) ;
int      Pipe( int fdArr[2] ) ;


