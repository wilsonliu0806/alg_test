all:main.o event.o pri_queue.o
	gcc -o alg_test main.c event.c pri_queue.c
clean:
	rm alg_est
debug:main.o event.o pri_queue.o
	gcc -g -o alg_test main.c event.c pri_queue.c
