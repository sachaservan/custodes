cd ../cmd
make

cd ../benchmark


for i in {0..1} ; do
    echo "$i"
    ../cmd/hypocert -parties 4 -threshold 2 -rootdir "/data/ez/go/src/hypocert" -netlat 0 -runid "$i"
    ../cmd/hypocert -parties 8 -threshold 4 -rootdir "/data/ez/go/src/hypocert" -netlat 0 -runid "$i"
    ../cmd/hypocert -parties 16 -threshold 8 -rootdir "/data/ez/go/src/hypocert" -netlat 0 -runid "$i"
done
