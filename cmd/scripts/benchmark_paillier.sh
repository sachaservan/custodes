cd ../
make

cd ../cmd/bin

for i in {0..0} ; do
    echo "$i"
    ./hypocert -parties 4 -threshold 2 -rootdir "/data/ez/go/src/hypocert" -netlat 1 -runId "$i" -save
    ./hypocert -parties 8 -threshold 4 -rootdir "/data/ez/go/src/hypocert" -netlat 1 -runId "$i" -save
    ./hypocert -parties 16 -threshold 8 -rootdir "/data/ez/go/src/hypocert" -netlat 1 -runId "$i" -save
done
