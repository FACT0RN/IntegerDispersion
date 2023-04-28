#include <iostream>
#include <gmpxx.h>
#include <chrono>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <cstdlib>

using namespace std;

int main( int argc, char *argv[] )
{
    
    if ( argc == 1 ){
        std::cout << "Usage:  sieverb <level>\nOne argument is required.\n";
        return 1;
    }

    int bits = atoi(argv[1]);
   
    if (bits == 0){
        std::cout << "Usage:  sieverb <level>\nWhere level is an integer greater than 0.\n";
        return -1;
    }

    //Prepare structure to store the primorials
    mpz_t primorial_level[40];
    for( int k =0; k < 40; k++){
      mpz_init(   primorial_level[k] );
      mpz_set_ui( primorial_level[k],  1);
    }
    
    //Initialize re-usable structure to compute primorials
    mpz_t n[2]; mpz_t m;
    mpz_init(n[0]); mpz_init(n[1]); mpz_init(m);
    mpz_set_ui(n[0],1); mpz_set_ui(n[1],1); mpz_set_ui(m,1);

    //Compute primorials with primes of a fixed bitsize
    uint32_t bitsize = 2; 
    
    //Timings
    using std::chrono::high_resolution_clock;
    using std::chrono::duration_cast;
    using std::chrono::duration;
    using std::chrono::milliseconds;

    for ( ; bitsize < bits; bitsize++ ){

        //redirect stdout to file
        string filename =  string("primorial_level_") +  std::to_string(bitsize - 1) + string(".txt");
        freopen( filename.c_str() , "w", stdout );

        //Compute primorial
        auto t1 = high_resolution_clock::now();
        mpz_primorial_ui( n[bitsize&1] , 1ULL << bitsize);
        auto t2 = high_resolution_clock::now();
        duration<double, std::milli> ms_double = t2 - t1;
  
        //Level this primorial by only keepking primes of the same bitsize
        mpz_divexact(m, n[bitsize&1], n[ (bitsize&1)^1 ] );

        //Store primorial
        mpz_out_str(stdout, 16, m  );
        
        //Close the file
        fclose(stdout);

        //Print stats
        //std::cout << "Bitsize: "<< bitsize << "  Run time: " << ms_double.count() <<  " ms   Bitsize in kilobytes: " << (double)mpz_sizeinbase(m, 2)/(8.0f*1024.0)  << std::endl;
    }

  return 0;
}
