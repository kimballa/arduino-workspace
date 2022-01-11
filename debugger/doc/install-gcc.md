
Installing GCC and binutils cross-compiler
=============================================

```
### SETUP
mkdir -p /home/aaron/share/scratch # objdir
mkdir -p /home/aaron/share/scratch/gcc11avr
export PREFIX=/home/aaron/share/scratch/gcc11avr
export PATH="$PATH:$PREFIX/bin"

### BINUTILS
cd binutils-2.37
mkdir obj-avr
cd obj-avr
../configure --prefix=$PREFIX --target=avr --disable-nls
make -j 4
make install


### bootstrap: pre-copy avr system headers to destination dir

mkdir -p /home/aaron/share/scratch/gcc11avr/avr/usr/include
cd /home/aaron/share/avr-libc-2.0.0/include
cp -r * /home/aaron/share/scratch/gcc11avr/avr/usr/include
cd /home/aaron/share/scratch/gcc11avr/avr/usr/include
find . -name "Makefile*" -delete


### GCC
cd /home/aaron/share/gcc-11.2.0
./contrib/download_prerequisites

cd /home/aaron/share/scratch

../gcc-11.2.0/configure \
  --prefix=/home/aaron/share/scratch/gcc11avr \
  --exec-prefix=/home/aaron/share/scratch/gcc11avr/avr \
  --with-local-prefix=/home/aaron/share/scratch/gcc11avr/local \
  --enable-fixed-point \
  --enable-languages=c,c++ \
  --disable-nls \
  --disable-libssp \
  --disable-libada \
  --disable-shared \
  --disable-threads \
  --with-avrlibc \
  --with-dwarf2 \
  --disable-doc \
  --target=avr \
  --with-toolexeclibdir=/home/aaron/share/scratch/gcc11avr/avr/lib \
  --with-sysroot=/home/aaron/share/scratch/gcc11avr/avr \
  --with-avrlibc \
  --with-double=32

make -j 4 # make gcc.
make install

### AVR-LIBC
cd avr-libc-2.0.0
./configure --prefix=$PREFIX --build=`./config.guess` --host=avr
make -j 4
make install

### CLEANUP
cd /home/aaron/share/scratch
make clean
cd ../binutils-2.37/obj-avr
make clean
cd ../../avr-libc-2.0.0
make clean


echo ""
echo ""
echo ""
echo "avr-gcc toolchain is built in: $PREFIX"

```

