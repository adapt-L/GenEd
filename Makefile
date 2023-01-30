.PHONY: clean
gened: gened.cpp
	c++ -lOpenCL gened.cpp -o gened
clean:
	rm -f gened
