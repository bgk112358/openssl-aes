#!/bin/bash

cd build
./bin/smoking_test
lcov -d ./ -d ../ -c -o init.info
lcov -a init.info -o total.info
lcov --remove total.info '*/usr/include/*' '*/smoking/*' '*/build/*' -o final.info
genhtml -o cover_report --legend --title "lcov"  --prefix=./ final.info

# lcov --remove total.info '*/usr/include/*' '*/usr/lib/*' '*/usr/lib64/*' '*/src/log/*' '*/tests/*' '*/usr/local/include/*' '*/usr/local/lib/*' '*/usr/local/lib64/*' '*/third/*' '*/it/*' '*/smoking/*' -o final.info
