//============================================================================
// Name        : rsa.cpp
// Author      : Jairus Maritn
// Version     :
//============================================================================
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <string>
using namespace std;


class RSACipher {
	BIGNUM *p; // secret prime factor
	BIGNUM *q; // secret prime factor
	BIGNUM *n; // public modulus
	BIGNUM *e; // public exponent
	BIGNUM *d; // private exponent
	BIGNUM *totient;
	BN_CTX *ctx; // BN context
	int loadkey(string file,bool is_pub);
public:
	int init();
	int genkeys(string pubkey, string prikey);
	int encrypt(string pubkey, string msgfile, string outfile);
	int decrypt(string prikey, string msgfile, string outfile);
};

int RSACipher::init() {
	ctx = BN_CTX_new();
	p = BN_new();
	q = BN_new();
	n = BN_new();
	e = BN_new();
	d = BN_new();
	totient = BN_new();
	return 0;
}

/**
 * Does d = e^-1modn
 * using the extended euclid's algorithm
 *
 */
int do_mod_inverse(BIGNUM *d,const BIGNUM *e,const BIGNUM *n, BN_CTX *ctx) {
	BIGNUM *t = BN_new();
	BIGNUM *tn = BN_new();
	BIGNUM *r = BN_new();
	BIGNUM *rn = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *tmp = BN_new();
	BIGNUM *tmp2 = BN_new();
	BIGNUM *one = BN_new();
	BN_one(one);
	BIGNUM *zero = BN_new();
	BN_zero(zero);

	BN_copy(t,zero);
	BN_copy(tn,one);
	BN_copy(r,n);
	BN_copy(rn,e);

	while (!BN_is_zero(rn)) {
		BN_div(q,NULL,r,rn,ctx); // q = r/rn

		// n = q*e + r
		BN_copy(tmp2,tn);
		BN_mul(tmp,q,tn,ctx);
		BN_sub(tn,t,tmp);
		BN_copy(t,tmp2);

		BN_copy(tmp2,rn);
		BN_mul(tmp,q,rn,ctx);
		BN_sub(rn,r,tmp);
		BN_copy(r,tmp2);
	}

	if (BN_cmp(r,one)>0) {
		printf("Not invertable\n");
		return -1; // not invertible
	}

	// Make sure we're using positive numbers
	if (BN_cmp(t,zero)<0) {
		BN_add(tmp,t,n);
		BN_copy(t,tmp);
	}
	BN_copy(d,t);
	return 0;
}

/**
 * 1. Select p, q
 * 2. Calculate n=p*q
 * 3. Calculate f(n)=(p-1)(q-1)
 * 4. Select integer e where gcd(f(n),e) = 1 and 1 < e < f(n)
 * 5. Calculate d = e^-1(modf(n))
 * 6. Public key PU = {e, n}
 * 7. Private key PR = {d, n}
 *
 *
 * Notes from: https://www.openssl.org/docs/crypto/BN_generate_prime.html
 * int BN_generate_prime_ex(BIGNUM *ret,int bits,int safe, const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb);
 * BN_generate_prime_ex() generates a pseudo-random prime number of bit length bits. If ret is not NULL, it will be used to store the number.
 * If add is not NULL, the prime will fulfill the condition p % add == rem (p % add == 1 if rem == NULL) in order to suit a given generator.
 * If safe is true, it will be a safe prime (i.e. a prime p so that (p-1)/2 is also prime).
 *
 *
 */
int RSACipher::genkeys(string pub_file,string pri_file) {
	FILE *f;
	int bits = 1024;
	int safe = 0;

	// Select p, q
	printf("Generating p:\n");
	BN_generate_prime_ex(p,bits,safe,NULL,NULL,NULL);
	printf("%s\n\n",BN_bn2dec(p));

	printf("Generating q:\n");
	BN_generate_prime_ex(q,bits,safe,NULL,NULL,NULL); // ensure p and q are not equal
	printf("%s\n\n",BN_bn2dec(q));

	// Calculate n=p*q
	printf("Common modulus:\n");
	BN_mul(n,p,q,ctx); // TODO: Print
	printf("%s\n\n",BN_bn2dec(n));

	// Calculate f(n)=(p-1)(q-1)
	BIGNUM *BN1 = BN_new();
	BN_one(BN1);
	BIGNUM *tmpp = BN_new();
	BIGNUM *tmpq = BN_new();
	BN_sub(tmpq,q,BN1); // (q-1)
	BN_sub(tmpp,p,BN1); // (p-1)
	BN_mul(totient,tmpq,tmpp,ctx); // (q-1)(p-1)
	BN_clear_free(BN1);
	BN_clear_free(tmpq);
	BN_clear_free(tmpp);

	// Select integer e where gcd(f(n),e) = 1 and 1 < e < f(n)
	printf("Public Key:\n");
	BN_set_word(e,65537);
	printf("%s\n\n",BN_bn2dec(e));

	// Calculate d = e^-1(modf(n))
	printf("Private Key:\n");

	// Debug
	BIGNUM *tmp = BN_new();
	//BN_mod_inverse(tmp,e,totient,ctx);
	do_mod_inverse(d,e,totient,ctx);
	//	if (BN_cmp(tmp,d)==0) {
	//		printf("They match!\n");
	//	} else {
	//		printf("Not equal!\n");
	//	}
	printf("%s\n\n",BN_bn2dec(d));


	// Public key PU = {e, n}
	f = fopen(pub_file.c_str(), "w");
	if (f == NULL){
	    printf("Error opening %s!\n",pub_file.c_str());
	    return -1;
	} else {
		fprintf(f, "PU:\n%s\n%s\n", BN_bn2dec(e),BN_bn2dec(n));
	}
	fclose(f);


	// Private key PR = {d, n}
	f = fopen(pri_file.c_str(), "w");
	if (f == NULL){
		printf("Error opening %s!\n",pri_file.c_str());
		return -1;
	} else {
		fprintf(f, "PR:\n%s\n%s\n", BN_bn2dec(d),BN_bn2dec(n));
	}
	fclose(f);

	return 0; // OK :)
}

/**
 * Read the key from key file
 * @param: is_pub: if true: Load e and n
 * 				   if false: Load d and n
 */
int RSACipher::loadkey(string key_file,bool is_pub) {
	printf("Loading key...\n");
	string line;
	ifstream f(key_file.c_str());
	if (!f.is_open()){
		printf("Error: Unable to open %s!\n",key_file.c_str());
		return -1;
	}
	int i = 0;
	while(getline(f,line)) {
		switch(i) {
			case 1:
				if (is_pub) {
					BN_dec2bn(&e,line.c_str());
				} else {
					BN_dec2bn(&d,line.c_str());
				}
				break;
			case 2:
				BN_dec2bn(&n,line.c_str());
				break;
			default:
				break;
		}
		i++;
	}
	f.close();
	if (is_pub) {
		printf("PU = {%s, %s}!\n",BN_bn2dec(e),BN_bn2dec(n));
	} else {
		printf("PR = {%s, %s}!\n",BN_bn2dec(d),BN_bn2dec(n));
	}
	return 0;
}

/**
 * 1. Read the public key from pub_file
 * 2. Encrypt the msg_file using the key
 * 3. Write it to out_file
 */
int RSACipher::encrypt(string pub_file,string msg_file, string out_file) {
	printf("Encrypting...\n");
	string line;
	BIGNUM *msg = BN_new();
	BIGNUM *ciphertext = BN_new();

	ifstream f1(msg_file.c_str());
	if (!f1.is_open()){
		printf("Error: Unable to open %s",msg_file.c_str());
		return -1;
	}

	// Read the msg
	printf("Message:\n");
	getline(f1,line);
	BN_dec2bn(&msg,line.c_str());
	printf("%s\n\n",BN_bn2dec(msg));
	f1.close();

	// Load the key
	if (loadkey(pub_file,true)!=0) {
		printf("Error: Unable to load key from %s",pub_file.c_str());
		return -1;
	}

	// Encrypt the message
	// BN_mod_exp() computes a to the p-th power modulo m (r=a^p % m). This function uses less time and space than BN_exp().
	printf("Ciphertext:\n");
	BN_mod_exp(ciphertext,msg,e,n,ctx);
	printf("%s\n\n",BN_bn2dec(ciphertext));

	// Write it
	ofstream f2(out_file.c_str());
	if (!f2.is_open()){
		printf("Error: Unable to open %s",out_file.c_str());
		return -1;
	}
	f2 << BN_bn2dec(ciphertext);
	f2.close();
	printf("Done!\n");
	return 0;
}

/**
 * 1. Read the private key from pri_file
 * 2. Decrypt the msg_file using the key
 * 3. Write it to out_file
 */
int RSACipher::decrypt(string pri_file,string msg_file, string out_file) {
	printf("Decrypting...\n");
	string line;
	BIGNUM *msg = BN_new();
	BIGNUM *ciphertext = BN_new();

	ifstream f1(msg_file.c_str());
	if (!f1.is_open()){
		printf("Error: Unable to open %s",msg_file.c_str());
		return -1;
	}

	// Read the msg
	printf("Ciphertext:\n");
	getline(f1,line);
	BN_dec2bn(&msg,line.c_str());
	printf("%s\n\n",BN_bn2dec(msg));
	f1.close();

	// Load the key
	if (loadkey(pri_file,false)!=0) {
		printf("Error: Unable to load key from %s",pri_file.c_str());
		return -1;
	}

	// Encrypt the message
	// BN_mod_exp() computes a to the p-th power modulo m (r=a^p % m). This function uses less time and space than BN_exp().
	printf("Message:\n");
	BN_mod_exp(ciphertext,msg,d,n,ctx);
	printf("%s\n\n",BN_bn2dec(ciphertext));

	// Write it
	ofstream f2(out_file.c_str());
	if (!f2.is_open()){
		printf("Error: Unable to open %s",out_file.c_str());
		return -1;
	}
	f2 << BN_bn2dec(ciphertext);
	f2.close();
	printf("Done!\n");
	return 0;
}

void print_usage() {
	printf("Usage: rsa -g -pu <public_key_file> -pr <private_key_file>\n");
	printf("       rsa -e -pu <public_key_file> -in <plaintext_file> -out <ciphertext_file>\n");
	printf("       rsa -d -pr <private_key_file> -in rsa<file>\n");
	printf("Examples\n");
	printf("       rsa -g -pu \"id_rsa.pub\" -pr \"id_rsa.pri\"\n");
	printf("       rsa -e -pu \"id_rsa.pub\" -in \"plaintext.txt\" -out \"ciphertext.txt\"\n");
	printf("       rsa -d -pr \"id_rsa.pri\" -in \"ciphertext.txt\" -out \"plaintext.txt\"\n");
}


/**
 * Parses args and calls genrsa, encrsa, or decrsa.
 */
int main(int argc, char *argv[]) {
	string mode;
	RSACipher rsa;
	rsa.init();

	if (!(argc==6 ||argc==8)) {
		print_usage();
		return 1;
	}

	mode = argv[1];
	if (mode.compare("-g")==0) {
		// file to output public key
		if (((string) argv[2]).compare("-pu")!=0) {print_usage(); return 1;}
		string pub_file = argv[3];

		// file to output private key
		if (((string) argv[4]).compare("-pr")!=0) {print_usage(); return 1;}
		string pri_file = argv[5];

		return rsa.genkeys(pub_file,pri_file);

	} else if  (mode.compare("-e")==0) {
		// file to read for public key
		if (((string) argv[2]).compare("-pu")!=0) {print_usage(); return 1;}
		string pub_file = argv[3];

		// file to read for input message
		if (((string)argv[4]).compare("-in")!=0) {print_usage(); return 1;}
		string msg_file = argv[5];

		// file to read for output text
		if (((string)argv[6]).compare("-out")!=0) {print_usage(); return 1;}
		string out_file = argv[7];

		return rsa.encrypt(pub_file,msg_file,out_file);
		//rsa.decrypt("id_rsa.pri",out_file,"decrypt.txt");

	} else if  (mode.compare("-d")==0) {
		// file to read for private key
		if (((string) argv[2]).compare("-pr")!=0) {print_usage(); return 1;}
		string pri_file = argv[3];

		// file to read for input message
		if (((string)argv[4]).compare("-in")!=0) {print_usage(); return 1;}
		string msg_file = argv[5];

		// file to read for output text
		if (((string)argv[6]).compare("-out")!=0) {print_usage(); return 1;}
		string out_file = argv[7];

		return rsa.decrypt(pri_file,msg_file,out_file);
	} else {
		print_usage();
		return 1;
	}
}
