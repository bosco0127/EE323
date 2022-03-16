# !bin/bash

for foo in {1..100}
do
	diff -c $foo.txt test-vector/test-vector-result/5M.txt
done
exit 0
