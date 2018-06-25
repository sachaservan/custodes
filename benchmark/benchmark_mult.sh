cd ../cmd
make

cd ../benchmark


for i in {0..0} ; do
    echo "$i"
    ../cmd/hypocert -parties 3 -threshold 2 -rootdir "/data/ez/go/src/hypocert" -netlat 0 -runid "$i" -shares -justmult
    ../cmd/hypocert -parties 5 -threshold 3 -rootdir "/data/ez/go/src/hypocert" -netlat 0 -runid "$i" -shares -justmult
    ../cmd/hypocert -parties 9 -threshold 5 -rootdir "/data/ez/go/src/hypocert" -netlat 0 -runid "$i" -shares -justmult
    ../cmd/hypocert -parties 17 -threshold 9 -rootdir "/data/ez/go/src/hypocert" -netlat 0 -runid "$i" -shares -justmult
    ../cmd/hypocert -parties 35 -threshold 17 -rootdir "/data/ez/go/src/hypocert" -netlat 0 -runid "$i" -shares -justmult
done
