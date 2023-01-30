Introduction
	This directory contains the source code of "GenEd", an experiment in creating an Ed25519 vanity generator using OpenCL. I stopped working on this back in 2021 because the performance was just so abysmal. I don't fully remember how it works. This current version just seems to spit out the public key on success.
	The TestEd subdirectory contains source code for other experiments in creating a vanity generator, such as the code needed to filter keypairs and format the onion directory.
	The kernel (contained in kernel_kern.c) is based on SUPERCOP's portable ref10 implementation (mirror here: https://github.com/floodyberry/supercop/tree/master/crypto_sign/ed25519/ref10 ). I'm pretty sure that I remember testing this kernel against other ed25519 implementations, so it should work.
Compiling and Running GenEd
	The makefile shows you how to compile this program with GCC. You will also need to follow your distro's instructions on OpenCL, which will depend on your hardware.
	Running the program with no arguments like so will list the OpenCL platforms:
		./gened
	You can select the platform by passing plat=M argument, where M is the platform number in the previous list. for example,
		./gened plat=1
	You can also force it to select a CPU or GPU device with the dev=N, like so:
		./gened plat=1 dev=cpu
		./gened plat=3 dev=gpu
Notes on Performance
	The kernel is probably slow because branching and stuff. I don't know, maybe GPUs just don't like this sort of work with integer operations.
	I have only tested this on the integrated graphics on my laptop. Maybe it's not so shitty if you test it on a "real" dedicated GPU.
	Because the keypairs are filtered on the GPU side, it's going to output a variable number of keypairs, which sort of becomes a problem. I think this is what the comments on line 189 of gened.cpp and commented code after line 2651 of kernel_kern.c were reffering to. You have to do something like:
		Send all the keypairs back in a static array and the CPU has to go through <chunksize> keypairs (where you lose paralellism benefits of filtering).
		OR Use atomics/global writes to a counter like keycount (which I assume is expensive for GPUs) so you can return a dynamic sized array.
		OR Return only a single keypair. It might get messed up by asyncronous writes if multiple instances of the kernel find a keypair at the same time and write over each other, but the mask bits should still match because they are the same. On the CPU side, you just check if these mask bits are good, and if so, you can just go over the chunk again with a fine tooth comb, because you know where it is. (I think this is what it is currently set up to do)
	An alternative to ref10 here would be ed25519-donna (mirror: https://github.com/floodyberry/ed25519-donna). This may result in a slight performance gain. I think I tried to switch to donna at some point but I gave up.
	The work may signifigantly benefit from being split up differently. For example, maybe the CPU can do the SHA512 hash in bulk before passing it to the GPU, or perhaps the GPU should just generate the keypairs; the CPU filters them instead.
