cd ../
make

cd ../cmd/bin

for i in {0..0} ; do
    echo "$i"
    ./hypocert -parties 3 -threshold 2 -rootdir "/data/ez/go/src/hypocert" -netlat 1 -runId "$i" -save
    ./hypocert -parties 5 -threshold 3 -rootdir "/data/ez/go/src/hypocert" -netlat 1 -runId "$i" -save
    ./hypocert -parties 10 -threshold 6 -rootdir "/data/ez/go/src/hypocert" -netlat 1 -runId "$i" -save
done
