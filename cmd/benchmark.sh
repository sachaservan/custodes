make

for i in {0..5} ; do
    echo "$i"
    ./hypocert -parties 4 -threshold 2 -rootdir "/data/ez/go/src/hypocert" -netlat 0 -runid "$i"
    ./hypocert -parties 8 -threshold 4 -rootdir "/data/ez/go/src/hypocert" -netlat 0 -runid "$i"
    ./hypocert -parties 16 -threshold 8 -rootdir "/data/ez/go/src/hypocert" -netlat 0 -runid "$i"
done
