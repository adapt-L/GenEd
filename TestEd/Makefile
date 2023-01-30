.PHONY: clean default
default:
	make clean
	make tested
	./tested
tested: tested.cpp
	c++ -Wno-narrowing -lcryptopp ed25519-donna/ed25519.o tested.cpp -o tested
clean:
	rm -f tested
