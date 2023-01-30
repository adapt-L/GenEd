#include <cctype>
#include <string>
#include <iostream>
#include <fstream>
#include <chrono>

#define CL_HPP_ENABLE_EXCEPTIONS
#define CL_HPP_TARGET_OPENCL_VERSION 200
#include "opencl.hpp"

/*
	todo:
		monero prefix/directory
		args management
		event based buffer read
		make onion w/ proper directory structure
		make monero_seed
		legal, constants, cleanup, divide files
		optimize, benchmark w/, without sha
*/

void stuff(cl_event e, cl_int i, void * dat){
	std::cout << "callback" << std::endl;
	//return nullptr;
}

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

bool plat_set = false;
uint64_t plat_int;
cl::Platform plat;
auto dev_type = CL_DEVICE_TYPE_ALL;
cl::Device dev;
cl::Context ctx;
cl::CommandQueue cq;
cl::Program::Sources ksrc;
cl::Program prog;
cl::Kernel kern;

void load_source(cl::Program::Sources& sources, std::string file_name) {
	std::ifstream file(file_name);
	std::string* source_code = new std::string(std::istreambuf_iterator<char>(file), (std::istreambuf_iterator<char>()));
	sources.push_back((*source_code).c_str());
}

int main(int argc, char** argv){
	
	for(auto i = 1; i < argc; i++){
		std::string p(argv[i]);
		std::string n = p;
		std::string v;
		for(auto j = 0; j < p.size(); j++){
			if(p[j] == '='){
				n = p.substr(0,j);
				if( j < p.size()-1 ){
					v = p.substr(j+1,p.size()-1);
				}
				break;
			}
		}
		if(n == "plat"){
			plat_int = std::stoul(v);
			plat_set = true;
		}if(n == "dev"){
			if(v == "cpu"){
				dev_type = CL_DEVICE_TYPE_CPU;
			}else if(v == "gpu"){
				dev_type = CL_DEVICE_TYPE_GPU;
			}
		}
	}
	
	std::vector<cl::Platform> all_platforms;
	cl::Platform::get(&all_platforms);
	if(plat_set){
		plat = all_platforms[plat_int];
		std::cout << "plat: " << plat.getInfo<CL_PLATFORM_NAME>() << std::endl;
	}else{
		for(auto i = 0; i < all_platforms.size(); i++){
			std::cout << "plat #" << i << ": "<< all_platforms[i].getInfo<CL_PLATFORM_NAME>() << std::endl;
		}
		throw std::runtime_error("no plat selected");
	}
	
	std::vector<cl::Device> all_devices;
	plat.getDevices(dev_type, &all_devices);
	if(all_devices.size() == 0){
		throw std::runtime_error("no dev found");
	}else{
		dev = all_devices[0];
		std::cout << "dev: "<< dev.getInfo<CL_DEVICE_NAME>() << std::endl;
	}
	ctx = cl::Context({dev});
	cq = cl::CommandQueue(ctx);
	
	load_source(ksrc,"kernel_kern.c");
	prog = cl::Program(ctx,ksrc);
	std::chrono::time_point<std::chrono::system_clock> build_start;
	try{
		std::cout << "building... " << std::flush;
		build_start = std::chrono::system_clock::now();
		prog.build();
	}catch(...){
		std::cout << "Build Status: " << prog.getBuildInfo<CL_PROGRAM_BUILD_STATUS>(ctx.getInfo<CL_CONTEXT_DEVICES>()[0]) << std::endl;
		std::cout << "Build Options:\t" << prog.getBuildInfo<CL_PROGRAM_BUILD_OPTIONS>(ctx.getInfo<CL_CONTEXT_DEVICES>()[0]) << std::endl;
		std::cout << "Build Log:\t " << prog.getBuildInfo<CL_PROGRAM_BUILD_LOG>(ctx.getInfo<CL_CONTEXT_DEVICES>()[0]) << std::endl;
		throw;
	}
	std::chrono::time_point<std::chrono::system_clock> build_end;
	build_end = std::chrono::system_clock::now();
	std::chrono::duration<double> build_time = build_end - build_start;
	std::cout << "(took " << build_time.count() << "s)" << std::endl;
	std::cout << "running... " << std::flush;
	
	uint64_t chunksize =  1*1000*1000;
	//uint8_t rand[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	
	uint8_t rand[32];
	std::ifstream rand_file;
	rand_file.open("/dev/random");
	rand_file.get((char*)rand,sizeof(rand)+1);
	rand_file.close();
	

	uint64_t mask =   0xFFFFFF;
	uint64_t mask_len = 16;
	uint64_t filter = 0xefcdab;
	uint64_t keystore = 1;
	uint32_t keycount = 0;
	
	cl::Buffer outkey_buffer(ctx, CL_MEM_WRITE_ONLY, (32*keystore) + 1);
	std::vector<uint8_t> outkeys(32*keystore);
	cl::Buffer keycount_buffer(ctx, CL_MEM_READ_WRITE, 4);
	cq.enqueueWriteBuffer(keycount_buffer, CL_TRUE, 0, 4, &keycount);
	cl::Buffer rand_buffer(ctx, CL_MEM_READ_ONLY, 32);
	cq.enqueueWriteBuffer(rand_buffer, CL_TRUE, 0, 32, rand);

	kern = cl::Kernel(prog, "kern");
	kern.setArg(0, outkey_buffer);
	kern.setArg(1, keycount_buffer); //keycount
	kern.setArg(2, rand_buffer);
	kern.setArg(3, mask);
	kern.setArg(4, filter);
	for(auto i = 0; i < 1; i++){
		std::chrono::time_point<std::chrono::system_clock> run_start;
		run_start = std::chrono::system_clock::now();

		cq.enqueueNDRangeKernel(kern, cl::NDRange(i*chunksize), cl::NDRange(chunksize));
		cq.finish();
		std::chrono::time_point<std::chrono::system_clock> eq_end;
		eq_end = std::chrono::system_clock::now();
		std::chrono::duration<double> eq_time = eq_end - run_start;
		std::cout << "(took " << eq_time.count() << "s, " << std::flush;
		
		cq.enqueueReadBuffer(outkey_buffer, CL_TRUE, 1, (32*keystore), outkeys.data());
		std::chrono::time_point<std::chrono::system_clock> run_end;
		run_end = std::chrono::system_clock::now();
		std::chrono::duration<double> run_time = run_end - run_start;
		std::cout << run_time.count() << "s)" << std::endl;
		std::cout << "rate: " << double(chunksize)/double(run_time.count()*1000000) << "M" << std::endl;
	}

	//check for effectiveness and backtrack? or just use atomics?
	//uint32_t iter = 0;
	uint32_t iter = 1;
	//cq.enqueueReadBuffer(keycount_buffer, CL_TRUE, 0, 4, &iter);
	for(auto i = 0; i < iter; i++){
		
		hexprint("",&(outkeys[i*32]), 32);
	}
	std::cout << "iter: " << iter << std::endl;
	
	return 0;
}
