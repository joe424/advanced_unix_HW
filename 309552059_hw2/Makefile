all:logger.cpp
	g++ -o logger.so -shared -fPIC logger.cpp -ldl
	g++ -o logger logger.cpp -ldl
clean:
	rm -f logger logger.so
