all:logger.cpp sample.cpp
	g++ -o logger.so -shared -fPIC logger.cpp -ldl
	g++ -o logger logger.cpp -ldl
	g++ -o sample sample.cpp
clean:
	rm -f logger logger.so sample
