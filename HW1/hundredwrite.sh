# !bin/bash

for foo in {1..100}
do
	./client -h 127.0.0.1 -p 1234 -o 0 -s 5 < test-vector/test-vector/5M.txt > $foo.txt &
done
exit 0
