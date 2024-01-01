/*-------------------------------------------------------------------------------

FILE:   dispatcher.c

Written By: 
     1- Dr. Mohamed Aboutabl
     2- Zoe Zinn
     3- Josh Kuesters
Submitted on: 12/04/2023
-------------------------------------------------------------------------------*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>

#include "wrappers.h"

#define   READ_END	0
#define   WRITE_END	1
#define   STDIN  0
#define   STDOUT 1
//--------------------------------------------------------------------------
int main( int argc , char *argv[] )
{
    printf("\nDispatcher started ... ");
    char myUserName[30];
    getlogin_r (myUserName, 30);
    time_t  now;
    time(&now) ;
    fprintf(stdout, "Logged in as user '%s' on %s\n\n", myUserName, ctime(&now));

    pid_t  amalPID , basimPID , KDCPid ; 
    int    AtoB[2] , BtoA[2] ;      // Amal and Basim pipes
    int    AtoK[2] , KtoA[2] ;      // KDC and Amal pipes
    char   arg1[20], arg2[20] ;
    
    Pipe( AtoK ) ;  // create pipe for KDC-to-Amal control 
    Pipe( KtoA ) ;  // create pipe for KDC-to-Amal data
    Pipe( AtoB ) ;  // create pipe for Amal-to-Basim control
    Pipe( BtoA ) ;  // create pipe for Amal-to-Basim data

    printf("\nDispatcher created these pipes\n") ;
    printf("1) Amal-to-KDC   protocol pipe: read=%d  write=%d\n", AtoK[ READ_END ], AtoK[ WRITE_END ]);
    printf("2) KDC-to-Amal   protocol pipe: read=%d  write=%d\n", KtoA[ READ_END ], KtoA[ WRITE_END ]);
    printf("3) Amal-to-Basim protocol pipe: read=%d  write=%d\n", AtoB[ READ_END ] , AtoB[ WRITE_END ] ) ;
    printf("4) Basim-to-Amal protocol pipe: read=%d  write=%d\n", BtoA[ READ_END ] , BtoA[ WRITE_END ] ) ;


    // Create both child processes:
    amalPID = Fork() ;
    if ( amalPID == 0 )
    {    
        // This is the Amal process.
        // Amal will not use these ends of the pipes, decrement their 'Ref Count'
        close( AtoB[ READ_END  ] ) ;
        close( BtoA[ WRITE_END ] ) ;

        // Close unused KDC pipe ends
        close( AtoK[ READ_END  ] ) ;
        close( KtoA[ WRITE_END ] ) ;

        // Create 2 new arguments for the Amal process
        char arg3[20], arg4[20] ;
        
        // Prepare the file descriptors as args to Amal
        snprintf( arg1 , 20 , "%d" , KtoA[ READ_END  ] ) ;
        snprintf( arg2 , 20 , "%d" , AtoK[ WRITE_END ] ) ;
        snprintf( arg3 , 20 , "%d" , BtoA[ READ_END  ] ) ;
        snprintf( arg4 , 20 , "%d" , AtoB[ WRITE_END ] ) ;
        
        // Now, Start Amal
        char * cmnd = "./amal/amal" ;
        execlp( cmnd , "Amal" , arg1 , arg2, arg3, arg4, NULL );

        // the above execlp() only returns if an error occurs
        perror("ERROR starting Amal" );
        exit(-1) ;      
    } 
    else
    {    // This is still the Dispatcher process 
        basimPID = Fork() ;
        if ( basimPID == 0 )
        {  
            // This is the Basim process
            // Basim will not use these ends of the pipes, decrement their 'count'
            close( AtoB[ WRITE_END ] ) ;
            close( BtoA[ READ_END  ] ) ;
            
            // Prepare the file descriptors as args to Basim
            snprintf( arg1 , 20 , "%d" , AtoB[ READ_END  ] ) ;
            snprintf( arg2 , 20 , "%d" , BtoA[ WRITE_END ] ) ;

            char * cmnd = "./basim/basim" ;
            execlp( cmnd , "Basim" , arg1 , arg2 , NULL );

            // the above execlp() only returns if an error occurs
            perror("ERROR starting Basim" ) ;
            exit(-1) ;
        }
        else
        {   // This is still the parent Dispatcher process
            KDCPid = Fork() ;
            if ( KDCPid == 0 )
            {
                // This is the KDC process
                // close the unused ends of the pipe for the KDC
                close( AtoK[ WRITE_END ] ) ;
                close( KtoA[ READ_END  ] ) ;
                
                // Prepare the file descriptors as args to Basim
                snprintf( arg1 , 20 , "%d" , AtoK[ READ_END  ] ) ;
                snprintf( arg2 , 20 , "%d" , KtoA[ WRITE_END ] ) ;

                char * cmnd = "./kdc/kdc" ;
                execlp( cmnd , "KDC" , arg1 , arg2 , NULL );

                // the above execlp() only returns if an error occurs
                perror("ERROR starting KDC" ) ;
                exit(-1) ;
            }
            else
            {
                // This is still the parent Dispatcher process
                // close all ends of the pipes so that their 'count' is decremented
                close( AtoB[ WRITE_END ] ); 
                close( AtoB[ READ_END  ]  ); 

                close( BtoA[ WRITE_END ] ); 
                close( BtoA[ READ_END  ]  );

                close( KtoA[ WRITE_END ] ); 
                close( KtoA[ READ_END  ]  ); 

                close( AtoK[ WRITE_END ] ); 
                close( AtoK[ READ_END  ]  );      

                printf("\nDispatcher is now waiting for Amal to terminate\n") ;
                int  exitStatus ;
                waitpid( amalPID , &exitStatus , 0 ) ;
                // printf("\nAmal terminated ... "  ) ;
                // if (  WIFEXITED( exitStatus ) )
                //         printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;

                printf("\nDispatcher is now waiting for Basim to terminate\n") ;
                waitpid( basimPID , &exitStatus , 0 ) ;
                // printf("\nBasim terminated ... " ) ;
                // if (  WIFEXITED( exitStatus ) )
                //         printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;
                
                printf("\nDispatcher is now waiting for KDC to terminate\n") ;
                waitpid( KDCPid , &exitStatus , 0 ) ;
                // printf("\nKDC terminated ... " ) ;
                // if (  WIFEXITED( exitStatus ) )
                //         printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;

                printf("\nThe Dispatcher process has terminated\n\n");
            }
        }
    }  
}

