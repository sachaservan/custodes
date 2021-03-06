# Custodes
## A system for certifying hypothesis testing procedures. 
See [custodes.pdf](http://sachaservanschreiber.com/thesis.pdf) for more details. 

## WARNING!! 
This system is intended as a proof-of-concept only!! This is purely research code which has not been fully tested and vetted by security experts. Please be aware of the risks of using *any* portion of this code for production systems. 

#### Implementation

Build the system:  
```
cd go/src/custodes/cmd
go get
make
```
Running examples:
```
cd bin
./custodes -example
./custodes -parties <num_parties> -threshold <corruption-threhsold> -rootdir <path-to-project dir>
```

# License

Copyright (c) 2018 Sacha Servan-Schreiber

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
