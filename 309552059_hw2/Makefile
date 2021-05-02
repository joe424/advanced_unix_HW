all:hw2.cpp
	g++ -o logger.so -shared -fPIC hw2.cpp -ldl
	g++ -o logger hw2.cpp -ldl
clean:
	rm -f logger logger.so
