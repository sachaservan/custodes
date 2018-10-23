cd ../
make

cd ../cmd/bin

for i in {0..4} ; do
    echo "$i"
    ./hypocert -parties 3 -threshold 2 -rootdir "/home/ez/go/src/hypocert" -netlat 1 -runId "$i" -save -chisqtest
    ./hypocert -parties 5 -threshold 3 -rootdir "/home/ez/go/src/hypocert" -netlat 1 -runId "$i" -save -chisqtest
    ./hypocert -parties 11 -threshold 6 -rootdir "/home/ez/go/src/hypocert" -netlat 1 -runId "$i" -save -chisqtest
done
