#include <iostream>
#include <cctype>
#include <cstdlib>
#include <random>
#include <cstring>
#include <chrono>

#include <bitset>
#include <filesystem>
#include <fstream>

#include "ref10.c"
#include "sha3256.c"

char hexv(uint8_t v){
	switch(v){
		case 0: return '0';
		case 1: return '1';
		case 2: return '2';
		case 3: return '3';
		case 4: return '4';
		case 5: return '5';
		case 6: return '6';
		case 7: return '7';
		case 8: return '8';
		case 9: return '9';
		case 10: return 'a';
		case 11: return 'b';
		case 12: return 'c';
		case 13: return 'd';
		case 14: return 'e';
		case 15: return 'f';
	}
	return 0;
}
void hexprint(std::string name, uint8_t *buf, int size){
	std::cout << name << ": ";
	for(int i = 0; i < size; i++){
		std::cout << hexv( ( buf[i] >> 4) % 16 ) << hexv( buf[i] % 16 );
	}
	std::cout << std::endl;
}
/*
void printfe(const char* name, fe f){
	printf("%s: ",name);
	for(auto i = 0; i < 10; i++){
		printf("%i, ",f[i]);
	}
	printf("\n");
}
*/
char crock32(uint8_t v){
	switch(v){
		case 0: return 'a';
		case 1: return 'b';
		case 2: return 'c';
		case 3: return 'd';
		case 4: return 'e';
		case 5: return 'f';
		case 6: return 'g';
		case 7: return 'h';
		case 8: return 'i';
		case 9: return 'j';
		case 10: return 'k';
		case 11: return 'l';
		case 12: return 'm';
		case 13: return 'n';
		case 14: return 'o';
		case 15: return 'p';
		case 16: return 'q';
		case 17: return 'r';
		case 18: return 's';
		case 19: return 't';
		case 20: return 'u';
		case 21: return 'v';
		case 22: return 'w';
		case 23: return 'x';
		case 24: return 'y';
		case 25: return 'z';
		case 26: return '2';
		case 27: return '3';
		case 28: return '4';
		case 29: return '5';
		case 30: return '6';
		case 31: return '7';
	}
	return 0;
}

uint8_t crocke32(char v){
	switch(v){
		case 'a': return 0;
		case 'b': return 1;
		case 'c': return 2;
		case 'd': return 3;
		case 'e': return 4;
		case 'f': return 5;
		case 'g': return 6;
		case 'h': return 7;
		case 'i': return 8;
		case 'j': return 9;
		case 'k': return 10;
		case 'l': return 11;
		case 'm': return 12;
		case 'n': return 13;
		case 'o': return 14;
		case 'p': return 15;
		case 'q': return 16;
		case 'r': return 17;
		case 's': return 18;
		case 't': return 19;
		case 'u': return 20;
		case 'v': return 21;
		case 'w': return 22;
		case 'x': return 23;
		case 'y': return 24;
		case 'z': return 25;
		case '2': return 26;
		case '3': return 27;
		case '4': return 28;
		case '5': return 29;
		case '6': return 30;
		case '7': return 31;
		default: return 255;
	}
}

std::string docrock32(uint8_t input[35]){
	std::string ret;
	uint8_t bucket = 0;
	int64_t i = 0;
	bucket += ( ( ((input[i/8])>>(7- (i%8))) & 0b1) << (4 - i%5));
	//std::cout << ( ( ((input[i/8])>>(7- (i%8))) & 0b1) << (4 - i%5)) << std::endl;
	i++;
	do{
		
		if( i%5 == 0 ){
			//std::cout << "\t" << int(bucket) << ":" << crock32(bucket) << std::endl;
			ret += crock32(bucket);
			bucket = 0;
		}
		bucket += ( ( ((input[i/8])>>(7- (i%8))) & 0b1) << (4 - i%5));
		//std::cout << ( ( ((input[i/8])>>(7- (i%8))) & 0b1) << (4 - i%5)) << std::endl;
		i++;
	}while(i < 35*8);
	ret += crock32(bucket);
	
	return ret;
}


std::string make_onion(uint8_t *pubkey){
	uint8_t checksum[32];
	int8_t version = 0x03;
	
	const char* checksum_prefix = ".onion checksum";
	uint8_t checksum_input[15 + 32 + 1];
	for(auto i = 0; i < 15; i++){
		checksum_input[i] = checksum_prefix[i];
	}
	for(auto i = 0; i < 32; i++){
		checksum_input[i+15] = pubkey[i];
	}
	checksum_input[15 + 32] = version;
	
	sha3256_hash(checksum,32,checksum_input,sizeof(checksum_input));

	//CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
	//onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
	
	uint8_t crap[35];
	for(auto i = 0; i < 32; i++){
		crap[i] = pubkey[i];
	}
	crap[32] = checksum[0];
	crap[33] = checksum[1];
	crap[34] = version;

	//c0wswmsbpwdrkwz5wsjbnsewhwt3pt7xm2106r0za9gs4ts77qnh788
	//cow7ozp4yafyohpyjgzh4gjn6wvpzqim3hp3kfza2l3fnnqthl2chli
	//cowsznkyp35fzlf4k7najiy2lr73cofuzs7sc7i2zvzw4hfumakygxid
	
	return docrock32(crap) + ".onion";
}

/*
void decroc32(std::string input){
	uint8_t output[35];
	for(auto i = 0; i < input.length(); i++){
		output[(5*i)/8] += ( crocke32(input[i]) << 8- 5 - ((5*i)%8) );
		//round up mod, down
	}
	
	for(auto i = 0; i < 35; i++){
		std::cout << int(output[i]) << " ";
	}
	std::cout << std::endl;
}

*/

void decroc32(std::string input,uint8_t *rum, uint8_t *mask){

	uint64_t len = 5*input.length();
	if(len > 60){
		//error
	}
	input.resize(12,'a');
	for(uint64_t i = 0; i < len/8; i++){
		mask[i] = 0xFF;
	}
	mask[len/8] = ( 0b11111111 << 8 - len%8 );
	for(auto i = 0; i < 8; i++){
		std::cout << int(mask[i]) << " ";
	}
	std::cout << std::endl;
	
	rum[0] = (crocke32(input[0]) << 3) + (crocke32(input[1]) >> 2);
	rum[1] = (crocke32(input[1]) << 6) + (crocke32(input[2]) << 1) + (crocke32(input[3]) >> 4);
	rum[2] = (crocke32(input[3]) << 4) + (crocke32(input[4]) >> 1);
	rum[3] = (crocke32(input[4]) << 7) + (crocke32(input[5]) << 2) + (crocke32(input[6]) >> 3);
	rum[4] = (crocke32(input[6]) << 5) + crocke32(input[7]);

	rum[5] = (crocke32(input[8]) << 3) + (crocke32(input[9]) >> 2);
	rum[6] = (crocke32(input[9]) << 6) + (crocke32(input[10]) << 1) + (crocke32(input[11]) >> 4);
	rum[7] = (crocke32(input[11]) << 4);
	
	for(auto i = 0; i < 8; i++){
		std::cout << int(rum[i]) << " ";
	}
	std::cout << std::endl;
	
}

//opencl

//onion_prefix=

//make onion w/ proper directory structure

//encroc
//decroc

//enxmr52
//dexmr52

//monero_prefix

//make mask and demask field

//64 bit should be enough mask

//0's mask and 1's mask

//make monero_seed


int main(int argc, char** argv){
	
	uint8_t sk[] = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};

	
	uint8_t pk[] = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};

	uint8_t az[] = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};

	/*
	uint8_t sk2[] = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};

	uint8_t pk2[] = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};

	std::ifstream r1;
	r1.open("cow2/hs_ed25519_public_key");
		std::string sa;
		while(r1.good()){
			char a;
			r1.get(a);
			sa += a;
			if(sa == "== ed25519v1-public: type0 =="){
				r1.get(a);
				r1.get(a);
				r1.get(a);
				r1.get((char*)pk2,33);
				hexprint("pk2",pk2,32);
				break;
			}
		}
	r1.close();

	std::ifstream r2;
	r2.open("cow2/hs_ed25519_secret_key");
		std::string ba;
		while(r2.good()){
			char a;
			r2.get(a);
			ba += a;
			if(ba == "== ed25519v1-secret: type0 =="){
				r2.get(a);
				r2.get(a);
				r2.get(a);
				for(auto i = 0; i < 64; i++){
					r2.get(a);
					sk2[i] = a;
				}
				hexprint("sk2",sk2,64);
				break;
			}
		}
	r1.close();

	ed25519_pubkey2(sk2,pk);
	hexprint("pk ",pk,32);
	hexprint("sk2",sk2,64);
	std::cout << make_onion(pk) << std::endl;
	exit(0);
*/
	
	//get 32 initial bytes from /dev/random
	std::ifstream r;
	r.open("/dev/random");
		r.get((char*)sk,sizeof(sk)+1);
	r.close();

	uint8_t mask[] = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};

	uint8_t filter[] = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};

	decroc32("cow",filter,mask);
	
	uint64_t M = ( (uint64_t*)(mask) )[0];
	std::cout << std::bitset<64>(M) << std::endl; 
	uint64_t F = ( (uint64_t*)(filter) )[0];
	std::cout << std::bitset<64>(F) << std::endl; 
	
	uint8_t* PK = (uint8_t*)pk;
	uint8_t* SK = (uint8_t*)sk;
	uint8_t* swap;
	while(1){
		ed25519_pubkey(SK,PK);
		uint64_t compare = ( (uint64_t*)(PK) )[0];
		if( (compare&M) == F ){
			hexprint("pk",PK,32);
			hexprint("sk",SK,32);
			std::cout << make_onion(PK) << std::endl;
			std::filesystem::create_directory(make_onion(PK));
			std::ofstream hn;
			hn.open(make_onion(PK)+"/hostname",std::ofstream::out);
				hn << make_onion(PK) + "\n";
			hn.close();
			std::ofstream sk_file,pk_file;
			sk_file.open(make_onion(PK)+"/hs_ed25519_secret_key",std::ofstream::out);
				sha512_hash(az,SK,32);
				az[0] &= 248;
				az[31] &= 63;
				az[31] |= 64;
				sk_file << "== ed25519v1-secret: type0 ==" << char(0x00) << char(0x00) << char(0x00);
				for(int i = 0; i < 64; i++){
					sk_file << char(az[i]);
				}
			sk_file.close();

			pk_file.open(make_onion(PK)+"/hs_ed25519_public_key",std::ofstream::out);
				pk_file << "== ed25519v1-public: type0 ==" << char(0x00) << char(0x00) << char(0x00);
				for(int i = 0; i < 32; i++){
					pk_file << char(PK[i]);
				}
			pk_file.close();
			pk_file.flush();
			sk_file.flush();
			hn.flush();
			std::cout << "shrub\n";
			return 0;
		}
		swap = SK;
		SK = PK;
		PK = swap;
	}
	
	return 0;
}
